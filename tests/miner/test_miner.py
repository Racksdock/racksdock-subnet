import asyncio
import socket

import pytest
import uvicorn
from racksdock_node.host_agent.agent import HostAgent
from racksdock_node.host_agent.config import HostAgentConfig
from racksdock_platform.marketplace.app import create_app
from racksdock_platform.marketplace.config import Settings
from racksdock_platform.marketplace.models import Node

from racksdock_subnet.core.schemas import VmResources
from racksdock_subnet.miner.neuron import MinerConfig, MinerNeuron
from racksdock_subnet.verifier.config import TrustConfig
from racksdock_subnet.verifier.devca import DevCA


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.asyncio
async def test_miner_bootstraps_and_registers_node(tmp_path):
    ca = DevCA.create(tmp_path / "ca")
    trust = TrustConfig(mode="dev", dev_ca_dir=ca.dir)
    settings = Settings(db_url=f"sqlite:///{tmp_path}/m.db", chain_kind="mock", chain_file=tmp_path / "chain.json", trust=trust)
    app = create_app(settings, background=False)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    srv = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    node_dir = ca.issue_node(tmp_path / "node")
    hcfg = HostAgentConfig(mode="sim", platform_ws=f"ws://127.0.0.1:{port}/v1/hosts/ws", state_dir=tmp_path / "hstate", key_path=tmp_path / "hstate" / "host.seed",
                           miner_hotkey="5Fminer", region="sim-1", vm_dir=tmp_path / "vms", agent_transport="tcp", agent_port=0, sim_node_dir=node_dir,
                           resources=VmResources(gpu_pci=[f"0000:{17 + i:02x}:00.0" for i in range(8)], nvme_pci=["0000:a0:00.0"]), trust=trust)
    host = HostAgent(hcfg)
    htask = asyncio.create_task(host.run())
    for _ in range(100):
        if host.key.public.hex in app.state.hosts.by_key:
            break
        await asyncio.sleep(0.1)
    mcfg = MinerConfig(platform_url=f"http://127.0.0.1:{port}", hotkey="5Fminer", chain_kind="mock", chain_file=tmp_path / "chain.json",
                       host_seed_path=hcfg.key_path, state_dir=tmp_path / "mstate", poll_s=0.3)
    miner = MinerNeuron(mcfg)
    try:
        rec = await miner.bootstrap(timeout_s=90)
        assert miner.node_id == rec.node_id and len(rec.gpu_ids) == 8
        with app.state.db.session() as s:
            n = s.get(Node, rec.node_id)
            assert n is not None and n.miner_hotkey == "5Fminer" and n.registered_block >= 0 and n.status == "registered"
        assert app.state.chain.commitments()[0].hotkey == "5Fminer"
        for _ in range(100):
            if rec.node_id in app.state.hosts.by_node:
                break
            await asyncio.sleep(0.1)
        assert rec.node_id in app.state.hosts.by_node
        await miner.announce_maintenance("2026-11-01T00:00:00Z", "2026-11-01T02:00:00Z")
        with app.state.db.session() as s:
            assert s.get(Node, rec.node_id).maintenance_until == "2026-11-01T02:00:00Z"
        # a mismatched hotkey is refused before anything is committed
        bad = MinerNeuron(MinerConfig(platform_url=f"http://127.0.0.1:{port}", hotkey="5Fother", chain_kind="mock", chain_file=tmp_path / "chain.json",
                                      host_seed_path=hcfg.key_path, state_dir=tmp_path / "mstate2", poll_s=0.3))
        drafts = (await bad.c.get(f"/v1/miners/identity-drafts/{host.key.public.hex}")).json()["drafts"]
        with pytest.raises(RuntimeError):
            await bad.register_draft(drafts[0])
        await bad.close()
    finally:
        await miner.close()
        host.stop()
        htask.cancel()
        server.should_exit = True
        await srv
        try:
            await htask
        except (asyncio.CancelledError, Exception):
            pass


@pytest.mark.asyncio
async def test_bootstrap_shows_host_notes_and_fails_fast_on_host_error(caplog):
    """While waiting for the identity draft the miner relays the host's progress notes and stops with the host's error text."""
    import logging

    from racksdock_subnet.miner import neuron as mn

    cls = next(c for c in vars(mn).values() if isinstance(c, type) and hasattr(c, "bootstrap"))

    class Resp:
        def __init__(self, status_code, body):
            self.status_code, self._body, self.text = status_code, body, str(body)

        def json(self):
            return self._body

    class FakeClient:
        def __init__(self):
            self.polls = 0

        async def post(self, path, **kw):
            return Resp(200, {"command_id": "cmd_x"})

        async def get(self, path):
            self.polls += 1
            notes = [{"command_id": "cmd_x", "kind": "log", "message": "waiting for catalog image verify_v2 (download in progress, 0s so far)", "at": "t1"}]
            if self.polls >= 2:
                notes.append({"command_id": "cmd_x", "kind": "error", "message": "launch failed: container image racksdock/verify:v2 not present on this host", "at": "t2"})
            return Resp(200, {"drafts": [], "notes": notes})

    class Cfg:
        poll_s = 0.01

    n = cls.__new__(cls)
    n.host_pubkey, n.c, n.cfg = "ab" * 32, FakeClient(), Cfg()
    with caplog.at_level(logging.INFO), pytest.raises(RuntimeError, match="not present on this host"):
        await cls.bootstrap(n, timeout_s=5)
    assert any("waiting for catalog image" in r.getMessage() for r in caplog.records)
