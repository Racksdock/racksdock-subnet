"""Validator neuron against a live marketplace + simulated host: admission, qualification, in-rental checks, scoring, readiness canary."""
import asyncio
import datetime as dt
import socket

import httpx
import pytest
import uvicorn
from racksdock_node.host_agent.agent import HostAgent
from racksdock_node.host_agent.config import HostAgentConfig
from racksdock_platform.marketplace.app import create_app
from racksdock_platform.marketplace.config import Settings

from racksdock_subnet.core.canonical import hash_obj
from racksdock_subnet.core.keys import SigningKey
from racksdock_subnet.core.nonce import new_nonce_hex
from racksdock_subnet.core.schemas import RegistrationRecord, VmResources
from racksdock_subnet.validator.config import ValidatorConfig
from racksdock_subnet.validator.neuron import Verifier
from racksdock_subnet.verifier.config import TrustConfig
from racksdock_subnet.verifier.devca import DevCA


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def wait_for(fn, timeout=90, interval=0.3, desc="condition"):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        v = fn()
        if asyncio.iscoroutine(v):
            v = await v
        if v:
            return v
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"timeout waiting for {desc}")
        await asyncio.sleep(interval)


@pytest.mark.asyncio
async def test_validator_neuron_end_to_end(tmp_path):
    ca = DevCA.create(tmp_path / "ca")
    trust = TrustConfig(mode="dev", dev_ca_dir=ca.dir)
    settings = Settings(db_url=f"sqlite:///{tmp_path}/m.db", base_url="http://test", chain_kind="mock", chain_file=tmp_path / "chain.json", probe_timeout_s=1.0, trust=trust)
    app = create_app(settings, background=False)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    srv_task = asyncio.create_task(server.serve())
    await wait_for(lambda: server.started, desc="server")
    base = f"http://127.0.0.1:{port}"
    chain = app.state.chain

    node_dir = ca.issue_node(tmp_path / "node")
    hcfg = HostAgentConfig(mode="sim", platform_ws=f"ws://127.0.0.1:{port}/v1/hosts/ws", state_dir=tmp_path / "hstate", key_path=tmp_path / "hstate" / "host.seed",
                           miner_hotkey="5Fminer", host_image_version="host_vtest", region="sim-1", image_dir=tmp_path / "img", vm_dir=tmp_path / "vms",
                           agent_transport="tcp", agent_port=0, heartbeat_interval_s=2.0, sim_node_dir=node_dir,
                           resources=VmResources(gpu_pci=[f"0000:{17 + i:02x}:00.0" for i in range(8)], nvme_pci=["0000:a0:00.0"], vcpus=120, memory_gb=1850), trust=trust)
    host = HostAgent(hcfg)
    host_task = asyncio.create_task(host.run())
    vcfg = ValidatorConfig(platform_url=base, state_dir=tmp_path / "vstate", hotkey="5Gval", chain_kind="mock", chain_file=tmp_path / "chain.json", runner="sim",
                           canary_mean_interval_s=2.0, canary_deadline_s=60, inrental_interval_s=0.0, microbench_interval_s=0.0, reachability_interval_s=0.0,
                           requal_interval_s=10 ** 9, tempo_s=10 ** 9, loop_interval_s=0.2, trust=trust)
    neuron = Verifier(vcfg)  # role 'all': verifies and scores in one process, as the e2e simulation needs
    try:
        async with httpx.AsyncClient(base_url=base, timeout=30) as c:
            await wait_for(lambda: host.key.public.hex in app.state.hosts.by_key, desc="host connected")
            # miner registration (what racksdock-miner does)
            await c.post(f"/v1/miners/bootstrap/{host.key.public.hex}")

            async def drafts():
                d = (await c.get(f"/v1/miners/identity-drafts/{host.key.public.hex}")).json()["drafts"]
                return d or None

            draft = (await wait_for(drafts, desc="identity draft"))[0]
            rec = RegistrationRecord.model_validate(draft["registration"])
            chain.register("5Fminer")
            chain.commit("5Fminer", hash_obj(rec.model_dump(by_alias=True)))
            assert (await c.post("/v1/miners/register", json={"envelope": draft["registration_envelope"]})).status_code == 201
            await wait_for(lambda: host.current is None, desc="bootstrap VM gone")

            # validator: enroll + first step -> admission test + full qualification
            await neuron.ensure_enrolled()
            await neuron.step()
            assert rec.node_id in neuron.busy

            async def qualified():
                nodes = await neuron.platform.nodes()
                return nodes[0]["status"] == "qualified" and rec.node_id not in neuron.busy

            await wait_for(qualified, timeout=180, desc="node qualified")
            ver = (await c.get(f"/v1/nodes/{rec.node_id}/verification")).json()
            kinds = [h["kind"] for h in ver["qualification_history"]]
            assert "admission" in kinds and "full" in kinds
            assert ver["perf"] > 0.95 and ver["qualification"]["spec_measured"]["cpu"]["vcpus"] == 120
            q_full = [h for h in ver["qualification_history"] if h["kind"] == "full"][0]
            full_rec = (await c.get(f"/v1/evidence/{q_full['hash']}")).json()["envelope"]["payload"]
            assert [ch["id"] for ch in full_rec["checks"]][:3] == ["Q1", "Q2", "Q3"] and all(ch["passed"] for ch in full_rec["checks"])

            # a tenant rents the node
            r = await c.post("/v1/account/signup", json={"email": "u@x.y", "password": "password1"})
            uh = {"X-API-KEY": r.json()["api_key"]}
            await c.post("/v1/sshkeys/add", json={"name": "k", "public_key": SigningKey.generate().public.ssh_public_line("c")}, headers=uh)
            await c.post("/v1/billing/credits/purchase", json={"cents": 50000}, headers=uh)
            r = await c.post("/v1/instances/create", json={"name": "t1", "node_id": rec.node_id, "tenant_nonce": new_nonce_hex()}, headers=uh)
            assert r.status_code == 201, r.text
            iid = r.json()["id"]

            async def active():
                return (await c.get(f"/v1/instances/{iid}/info", headers=uh)).json()["status"] == "active"

            await wait_for(active, desc="tenant active")
            # in-rental check + probe
            await neuron.step()

            async def inrental_published():
                recs = await neuron.platform.evidence(instance_id=iid, kind="inrental")
                return recs or None

            recs = await wait_for(inrental_published, desc="inrental record")
            pl = recs[-1]["envelope"]["payload"]
            assert pl["attestation_ok"] and pl["gpu_ids_match"] and pl["reachable"] and pl["error"] is None
            assert pl["health"]["microbench"] is not None and len(pl["health"]["gpus"]) == 8
            probes = await wait_for(lambda: neuron.platform.evidence(instance_id=iid, kind="probe"), desc="probe record")
            assert probes[-1]["envelope"]["payload"]["reachable"] is True

            # scoring: the node is rented and qualified -> funded, miner gets weight
            now = dt.datetime.now(dt.UTC)
            res = await neuron.score_and_set_weights(now, tempo_s=600)
            assert rec.node_id in res.funded and res.scores[rec.node_id] > 0.15
            assert res.details[rec.node_id]["R"] > 0 and res.details[rec.node_id]["P"] > 0.9
            w = chain.weights_of("5Gval")
            miner_uid = chain.uid_of("5Fminer")
            assert miner_uid in w and w[miner_uid] > 0
            scoring_recs = await neuron.platform.evidence(kind="scoring")
            assert scoring_recs and scoring_recs[-1]["signer"] == neuron.key.public.hex

            # tenant deletes -> readiness canary by the neuron relists the node
            await c.post(f"/v1/instances/{iid}/delete", headers=uh)

            async def deleted():
                return (await c.get(f"/v1/instances/{iid}/info", headers=uh)).json()["status"] == "deleted"

            await wait_for(deleted, desc="deleted")
            nodes = await neuron.platform.nodes()
            assert nodes[0]["needs_readiness"] is True
            await neuron.step()

            async def relisted():
                nodes = await neuron.platform.nodes()
                return (not nodes[0]["needs_readiness"]) and rec.node_id not in neuron.busy

            await wait_for(relisted, timeout=120, desc="readiness canary")
            cans = await neuron.platform.evidence(node_id=rec.node_id, kind="canary")
            assert cans and cans[-1]["envelope"]["payload"]["outcome"] == "pass"
            # idle canary fires after the Poisson wait (mean 2 s)
            n_before = len(cans)
            for _ in range(60):
                await neuron.step()
                cans = await neuron.platform.evidence(node_id=rec.node_id, kind="canary")
                if len(cans) > n_before and rec.node_id not in neuron.busy:
                    break
                await asyncio.sleep(0.5)
            assert len(cans) > n_before
            assert (await c.get("/v1/instances/types")).json()["instance_types"][0]["availability"][0]["available"] is True
    finally:
        neuron.stop()
        await neuron.platform.close()
        host.stop()
        host_task.cancel()
        server.should_exit = True
        await srv_task
        try:
            await host_task
        except (asyncio.CancelledError, Exception):
            pass
