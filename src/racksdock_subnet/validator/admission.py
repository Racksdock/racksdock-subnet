"""Admission test (docs/03 §3): provision, deliver, recover, clean."""
from __future__ import annotations

import asyncio
import logging

from racksdock_subnet.core.envelope import utcnow_iso
from racksdock_subnet.core.schemas import AttestationSummary, CheckResult, PerformanceSummary, QualificationRecord
from racksdock_subnet.core.specdata import thresholds

from .inrental import probe
from .platform import PlatformClient
from .qualify import Sessions
from .suite.checks import Ctx, smoke

log = logging.getLogger("racksdock.validator.admission")


async def admission_test(cfg, platform: PlatformClient, sessions: Sessions, node: dict) -> QualificationRecord:
    started = utcnow_iso()
    checks: list[CheckResult] = []
    deadline = thresholds()["canary_deadline_s"]
    # 1. provision with our key
    sess = await sessions.open(node, deadline_s=deadline, name="admission")
    try:
        runner = sessions.runner(sess)
        try:
            who = await runner.run("echo racksdock-admission-ok")
            checks.append(CheckResult(id="A1", name="Provision with requester's SSH key", passed=who.rc == 0 and "racksdock-admission-ok" in who.stdout,
                                      details={"time_to_active_s": round(sess.time_to_active_s, 1)}))
            # 2. deliver 8-GPU configuration
            checks.append(CheckResult(id="A2", name="Deliver eight registered GPUs", passed=sess.boot.ok, details={"errors": sess.boot.errors}))
            # 4a. write markers before we delete
            await runner.run("racksdock-marker write; sudo fallocate -l 1G /data/racksdock-marker.bin || true")
            # 3. recover without tenant cooperation: stop the agent and sshd, then ask the platform to restart
            await runner.run("sudo systemctl stop racksdock-node-agent || true")
            await runner.run("sudo systemctl stop ssh || true")
        finally:
            await runner.close()
        try:
            await platform.restart_instance_as_user(sess.instance_id)
            recovered = False
            deadline_t = asyncio.get_running_loop().time() + 180
            while asyncio.get_running_loop().time() < deadline_t:
                info = await platform.instance(sess.instance_id)
                if info["status"] in ("active", "degraded") and info.get("ip"):
                    ok, _ = await probe(info["ip"], info["ssh_port"]) if cfg.runner != "sim" else (True, None)
                    if ok:
                        recovered = True
                        break
                await asyncio.sleep(sessions.poll_s)
            checks.append(CheckResult(id="A3", name="Recover without tenant cooperation", passed=recovered, details={"ssh_reachable_after_restart": recovered}))
        except RuntimeError as e:
            checks.append(CheckResult(id="A3", name="Recover without tenant cooperation", passed=False, error=str(e)))
    finally:
        await sessions.close(sess)
    # 4b. fresh instance: same gpu set, no markers
    sess2 = await sessions.open(node, deadline_s=deadline, name="admission-clean")
    try:
        runner = sessions.runner(sess2)
        try:
            ctx = Ctx(runner=runner, reference=cfg.reference_set, dev_mode=cfg.trust.dev, claimed_vcpus=0)
            sm = await smoke(ctx)
            same_gpus = set(sess2.boot.gpu_ids) == set(sess.boot.gpu_ids) and sess2.boot.ok
            clean = sm.get("marker") == "absent" and sm.get("gpu_memory_verify") == "ok"
            checks.append(CheckResult(id="A4", name="Clean environment for the next tenant", passed=same_gpus and clean, details={"smoke": sm, "same_gpu_set": same_gpus}))
        finally:
            await runner.close()
    finally:
        await sessions.close(sess2)
    failing = [c.id for c in checks if not c.passed]
    rec = QualificationRecord(kind="admission", node_id=node["node_id"], validator_hotkey=cfg.hotkey, validator_key=platform.key.public.hex, instance_id=sess.instance_id,
                              verify_image=sess.info["attestation"].get("image_version") or "verify", started_at=started, finished_at=utcnow_iso(),
                              outcome="pass" if not failing else "quarantined", failing_checks=failing, checks=checks,
                              attestation=AttestationSummary(gpu_ids=sess.boot.gpu_ids), performance=PerformanceSummary(perf=1.0 if not failing else 0.0), reference_set=cfg.reference_set)
    await platform.publish("qualification", rec.model_dump(by_alias=True, mode="json"))
    return rec
