"""Admission test (docs/03 §3): provision, deliver, recover, clean."""
from __future__ import annotations

import asyncio
import logging

from racksdock_subnet.core.envelope import utcnow_iso
from racksdock_subnet.core.schemas import AttestationSummary, CheckResult, PerformanceSummary, QualificationRecord
from racksdock_subnet.core.specdata import thresholds

from .inrental import probe
from .platform import PlatformClient
from .qualify import Sessions, node_profile
from .suite.checks import Ctx, smoke

log = logging.getLogger("racksdock.validator.admission")


async def admission_test(cfg, platform: PlatformClient, sessions: Sessions, node: dict) -> QualificationRecord:
    from .qualify import Progress
    from .suite.checks import CHECK_NAMES

    started = utcnow_iso()
    checks: list[CheckResult] = []
    deadline = thresholds()["canary_deadline_s"]
    prog = Progress(platform, node["node_id"], "admission")
    await prog.plan(["B0", "A1", "A2", "A3", "A4"] + (["A5"] if (node.get("registration") or {}).get("deployment") == "dual" else []))
    # 1. provision with our key
    await prog.start("B0", CHECK_NAMES["B0"])
    try:
        sess = await sessions.open(node, deadline_s=deadline, name="admission")
    except Exception as e:
        await prog.done(CheckResult(id="B0", name=CHECK_NAMES["B0"], passed=False, error=str(e)[:200]))
        await prog.finish("quarantined")
        raise
    await prog.done(CheckResult(id="B0", name=CHECK_NAMES["B0"], passed=True, details={"time_to_active_s": round(sess.time_to_active_s, 1)}))
    await prog.start("A1", CHECK_NAMES["A1"])
    try:
        runner = sessions.runner(sess)
        try:
            who = await runner.run("echo racksdock-admission-ok")
            checks.append(CheckResult(id="A1", name="Provision with requester's SSH key", passed=who.rc == 0 and "racksdock-admission-ok" in who.stdout,
                                      details={"time_to_active_s": round(sess.time_to_active_s, 1)}))
            await prog.done(checks[-1])
            # 2. deliver 8-GPU configuration
            await prog.start("A2", CHECK_NAMES["A2"])
            checks.append(CheckResult(id="A2", name="Deliver eight registered GPUs", passed=sess.boot.ok, details={"errors": sess.boot.errors}))
            await prog.done(checks[-1])
            # 4a. write markers before we delete
            await runner.run("racksdock-marker write; sudo fallocate -l 1G /data/racksdock-marker.bin || true")
            # 3. recover without tenant cooperation: stop the agent and sshd, then ask the platform to restart
            await prog.start("A3", CHECK_NAMES["A3"])
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
            await prog.done(checks[-1])
        except RuntimeError as e:
            checks.append(CheckResult(id="A3", name="Recover without tenant cooperation", passed=False, error=str(e)))
            await prog.done(checks[-1])
    finally:
        await sessions.close(sess)
    # 4b. fresh instance: same gpu set, no markers
    await prog.start("A4", CHECK_NAMES["A4"])
    sess2 = await sessions.open(node, deadline_s=deadline, name="admission-clean")
    try:
        runner = sessions.runner(sess2)
        try:
            ctx = Ctx(runner=runner, reference=cfg.reference_set or node_profile(node).reference_set, dev_mode=cfg.trust.dev, claimed_vcpus=0, profile=node_profile(node))
            ctx.extra["iperf_endpoints"] = list(cfg.iperf_endpoints)
            sm = await smoke(ctx)
            same_gpus = set(sess2.boot.gpu_ids) == set(sess.boot.gpu_ids) and sess2.boot.ok
            clean = sm.get("marker") == "absent" and sm.get("gpu_memory_verify") == "ok"
            checks.append(CheckResult(id="A4", name="Clean environment for the next tenant", passed=same_gpus and clean, details={"smoke": sm, "same_gpu_set": same_gpus}))
            await prog.done(checks[-1])
        finally:
            await runner.close()
    finally:
        await sessions.close(sess2)
    # 5. a dual node must deliver its second mode too: a container rental boots, attests the same GPU set and takes our key
    if (node.get("registration") or {}).get("deployment") == "dual":
        try:
            await prog.start("A5", CHECK_NAMES["A5"])
            sess3 = await sessions.open(node, deadline_s=deadline, name="admission-container", deployment="container")
            try:
                runner = sessions.runner(sess3)
                try:
                    who = await runner.run("echo racksdock-admission-ok; cat /proc/1/cgroup | head -1")
                finally:
                    await runner.close()
                same = set(sess3.boot.gpu_ids) == set(sess.boot.gpu_ids) and sess3.boot.ok
                checks.append(CheckResult(id="A5", name="Container mode delivers the same GPUs", passed=same and who.rc == 0, details={"time_to_active_s": round(sess3.time_to_active_s, 1), "same_gpu_set": same}))
                await prog.done(checks[-1])
            finally:
                await sessions.close(sess3)
        except RuntimeError as e:
            checks.append(CheckResult(id="A5", name="Container mode delivers the same GPUs", passed=False, error=str(e)[:200]))
            await prog.done(checks[-1])
    failing = [c.id for c in checks if not c.passed]
    rec = QualificationRecord(kind="admission", node_id=node["node_id"], validator_hotkey=cfg.hotkey, validator_key=platform.key.public.hex, instance_id=sess.instance_id,
                              verify_image=sess.info["attestation"].get("image_version") or "verify", started_at=started, finished_at=utcnow_iso(),
                              outcome="pass" if not failing else "quarantined", failing_checks=failing, checks=checks,
                              attestation=AttestationSummary(gpu_ids=sess.boot.gpu_ids), performance=PerformanceSummary(perf=1.0 if not failing else 0.0), reference_set=cfg.reference_set)
    await platform.publish("qualification", rec.model_dump(by_alias=True, mode="json"))
    await prog.finish(rec.outcome)
    return rec
