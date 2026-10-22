"""Qualification session: rent the node with the verify image, verify attestation independently, run the suite, publish."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from racksdock_subnet.core.envelope import utcnow_iso
from racksdock_subnet.core.nonce import new_nonce_hex
from racksdock_subnet.core.profile import Profile
from racksdock_subnet.core.profile import current as current_profile
from racksdock_subnet.core.profile import get as profile_get
from racksdock_subnet.core.schemas import (
    AttestationSummary,
    CheckResult,
    CpuMeasured,
    GpuSpecMeasured,
    NetworkMeasured,
    NvlinkMeasured,
    NvmeMeasured,
    PerformanceSummary,
    PowerProfileMeasured,
    QualificationRecord,
    SpecMeasured,
)
from racksdock_subnet.core.specdata import thresholds

from .config import ValidatorConfig
from .evidence import verify_boot_evidence
from .platform import PlatformClient
from .suite.checks import Ctx, run_suite
from .suite.reference import gate_ok, perf_score, ratios
from .suite.runner import SimProfile, SimRunner, SSHRunner

log = logging.getLogger("racksdock.validator.qualify")


@dataclass
class Session:
    instance_id: str
    info: dict
    tenant_nonce: str
    boot: object  # BootCheck
    time_to_active_s: float


class Sessions:
    """Creates verify instances and waits for them to become active; shared by qualify, admission and canary."""

    def __init__(self, cfg: ValidatorConfig, platform: PlatformClient, verifier, ssh_pub_line: str, ssh_key_path: str | None, poll_s: float = 1.0):
        self.cfg, self.platform, self.verifier, self.ssh_pub_line, self.ssh_key_path, self.poll_s = cfg, platform, verifier, ssh_pub_line, ssh_key_path, poll_s
        self._verifiers: dict[int, object] = {}

    def verifier_for(self, node: dict):
        """Evidence verifier expecting the node's own GPU count (nodes of different profiles share one validator)."""
        from racksdock_subnet.verifier.verifiers import build_verifier

        n = node_profile(node).gpu_count
        if n == current_profile().gpu_count:
            return self.verifier
        if n not in self._verifiers:
            self._verifiers[n] = build_verifier(self.cfg.trust, expected_devices=n)
        return self._verifiers[n]

    async def open(self, node: dict, deadline_s: float, name: str = "verify", deployment: str | None = None) -> Session:
        tn = new_nonce_hex()
        t0 = time.monotonic()
        iid = await self.platform.create_verify_instance(node["node_id"], [self.ssh_pub_line], tn, name=name, deployment=deployment)
        info = None
        while time.monotonic() - t0 < deadline_s:
            info = await self.platform.instance(iid)
            if info["status"] in ("active", "error", "deleting", "deleted"):
                break
            await asyncio.sleep(self.poll_s)
        tta = time.monotonic() - t0
        if info is None or info["status"] != "active":
            att = (info or {}).get("attestation") or {}
            why = (info or {}).get("status_details")
            if att.get("errors"):
                why = f"{why} | attestation: {'; '.join(att['errors'])}"
            raise TimeoutError(f"instance {iid} not active after {tta:.0f}s (status {info and info.get('status')}): {why}")
        # independent attestation verification from the evidence feed
        recs = await self.platform.evidence(instance_id=iid, kind="boot_evidence")
        if not recs:
            raise RuntimeError("no boot evidence published for our instance")
        boot = verify_boot_evidence(self.verifier_for(node), recs[-1]["envelope"], expected_tenant_nonce=tn, user_data=info.get("user_data"), expected_gpu_count=node_profile(node).gpu_count,
                                    registration_gpu_ids=node["registration"]["gpu_ids"], expected_image_version=info["attestation"].get("image_version"))
        return Session(instance_id=iid, info=info, tenant_nonce=tn, boot=boot, time_to_active_s=tta)

    def runner(self, sess: Session):
        if self.cfg.runner == "sim":
            return SimRunner(SimProfile.load(self.cfg.sim_profile))
        return SSHRunner(sess.info["ip"], sess.info["ssh_port"], self.cfg.ssh_user, self.ssh_key_path or "", sess.info["host_key_line"])

    async def close(self, sess: Session) -> None:
        try:
            await self.platform.delete_instance(sess.instance_id)
        except RuntimeError as e:
            log.warning("delete failed: %s", e)
        for _ in range(120):
            info = await self.platform.instance(sess.instance_id)
            if info["status"] in ("deleted", "error"):
                return
            await asyncio.sleep(self.poll_s)


def node_profile(node: dict) -> Profile:
    return profile_get((node.get("registration") or {}).get("profile"))


def spec_from_measured(m: dict[str, float], extra: dict, prof: Profile | None = None) -> SpecMeasured:
    def g(k: str) -> float:
        return float(m.get(k, 0.0))

    prof = prof or current_profile()
    return SpecMeasured(
        gpu=GpuSpecMeasured(model=prof.gpu_model, count=prof.gpu_count, vram_gb_usable_min=g("gpu.vram_gb_usable_min"), vram_gb_total=g("gpu.vram_gb_total"), board_part=extra.get("gpu_board_part", ""),
                            vbios=extra.get("gpu_vbios", ""), pci_device_id=extra.get("gpu_pci_id", "")),
        nvlink=NvlinkMeasured(d2d_gbps_min_pair=g("nvlink.d2d_gbps_min_pair"), d2d_gbps_aggregate=g("nvlink.d2d_gbps_aggregate"), allreduce_1gb_busbw_gbps=g("nvlink.allreduce_1gb_busbw_gbps")),
        cpu=CpuMeasured(model=extra.get("cpu_model", ""), vcpus=int(m.get("cpu.vcpus", 0)), stream_gbps=g("cpu.stream_gbps"), sysbench=g("cpu.sysbench")),
        memory_gb=g("memory_gb"), hbm_write_gbps=g("hbm_write_gbps"),
        nvme=NvmeMeasured(capacity_tb=g("nvme.capacity_tb"), seq_read_gbps=g("nvme.seq_read_gbps"), seq_write_gbps=g("nvme.seq_write_gbps"), rand_read_kiops=g("nvme.rand_read_kiops"),
                          rand_write_kiops=g("nvme.rand_write_kiops"), sustained_write_gbps=g("nvme.sustained_write_gbps")),
        network=NetworkMeasured(down_gbps=g("network.down_gbps"), up_gbps=g("network.up_gbps"), endpoints=extra.get("network_endpoints", [])),
        power_profile=PowerProfileMeasured(limit_w=g("power_profile.limit_w"), approved=bool(extra.get("power_approved", False))),
        training_tokens_per_s=g("training_tokens_per_s"), inference_tokens_per_s=g("inference_tokens_per_s"),
    )


IDENTITY_CHECKS = {"Q1", "Q2", "Q3"}  # a failure here always means a full re-run (docs/03 §4)


def plan_targeted_retry(last: dict | None, planned: list[str] | None = None) -> set[str] | None:
    """Which checks a quarantined node's retry must re-run. A quarantine caused by non-identity checks re-runs those plus every
    planned check the previous session never reached (a fail-fast on topology cuts the suite short); the passes of that session
    stand. Identity/SKU failures, perf gate failures and incomplete runs re-run everything (None)."""
    if not last or last.get("kind") != "full" or last.get("outcome") != "quarantined":
        return None
    failing = list(last.get("failing_checks") or [])
    if not failing or any(f.startswith("perf<") or f in IDENTITY_CHECKS for f in failing):
        return None
    if any(c.get("skipped") for c in last.get("checks") or [] if c.get("id") in failing):
        return None
    ran = {c.get("id") for c in last.get("checks") or []}
    never_ran = {c for c in (planned or []) if c not in ran and c != "Q1"}
    return set(failing) | never_ran


def merge_measured(base: dict, new: dict) -> dict:
    """Overlay freshly measured values on a previous record's structure: a value counts as fresh unless it is unset (0, '', [], None)."""
    out = dict(base)
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge_measured(out[k], v)
        elif v not in (0, 0.0, "", [], None, False):
            out[k] = v
    return out


class Progress:
    """Reports a verification session's steps to the platform as they happen (docs/03 §5.1): plan, start, done, finish.
    Every call is best effort; the console shows the steps, the signed record stays the source of truth."""

    def __init__(self, platform: PlatformClient, node_id: str, session_kind: str):
        self.platform = platform
        self.node_id = node_id
        self.session_kind = session_kind
        self.session_id = f"{platform.key.public.hex[:8]}:{utcnow_iso()}"

    def _msg(self, **kw) -> dict:
        return {"node_id": self.node_id, "session_kind": self.session_kind, "session_id": self.session_id, "validator_key": self.platform.key.public.hex, "at": utcnow_iso(), **kw}

    async def plan(self, step_ids: list[str]) -> None:
        from .suite.checks import CHECK_NAMES

        await self.platform.progress(self._msg(plan=[{"id": s, "name": CHECK_NAMES.get(s, s)} for s in step_ids]))

    async def start(self, step_id: str, name: str) -> None:
        await self.platform.progress(self._msg(step_id=step_id, step_name=name, state="running"))

    async def done(self, res: CheckResult) -> None:
        detail = res.error or ("skipped" if res.skipped else "")
        if not detail and res.details:
            detail = ", ".join(f"{k}={v}" for k, v in list(res.details.items())[:4] if not isinstance(v, (dict, list)))[:200]
        await self.platform.progress(self._msg(step_id=res.id, step_name=res.name, state="skipped" if res.skipped else ("pass" if res.passed else "fail"),
                                               detail=detail, duration_s=res.duration_s))

    async def finish(self, outcome: str) -> None:
        await self.platform.progress(self._msg(outcome=outcome))


async def qualify_node(cfg: ValidatorConfig, platform: PlatformClient, sessions: Sessions, node: dict, kind: str = "full",
                       only: set[str] | None = None, base: dict | None = None) -> QualificationRecord:
    from .suite.checks import planned_checks

    started = utcnow_iso()
    prof = node_profile(node)
    prog = Progress(platform, node["node_id"], kind)
    await prog.plan(["B0", "Q1"] + [c for c in planned_checks(prof, kind, only) if c != "Q1"])
    await prog.start("B0", "Boot the verify instance")
    try:
        sess = await sessions.open(node, deadline_s=thresholds()["canary_deadline_s"], name=f"qualify-{kind}")
    except Exception as e:
        await prog.done(CheckResult(id="B0", name="Boot the verify instance", passed=False, error=str(e)[:200]))
        await prog.finish("quarantined")
        raise
    await prog.done(CheckResult(id="B0", name="Boot the verify instance", passed=True, details={"time_to_active_s": round(sess.time_to_active_s, 1)}))
    checks: list[CheckResult] = [CheckResult(id="Q1", name="GPU authenticity and identity", passed=sess.boot.ok, details={"errors": sess.boot.errors, "gpu_ids": sess.boot.gpu_ids,
                                                                                                                             "measurements_hash": sess.boot.result.measurements_hash if sess.boot.result else None})]
    await prog.done(checks[0])
    measured: dict[str, float] = {}
    extra: dict = {}
    try:
        if sess.boot.ok:
            runner = sessions.runner(sess)
            ctx = Ctx(runner=runner, reference=cfg.reference_set or prof.reference_set, dev_mode=cfg.trust.dev, claimed_vcpus=int(node["registration"]["claimed_spec"]["vcpus"]), profile=prof,
                      calibration=prof.name in cfg.calibration_profiles)
            ctx.extra["iperf_endpoints"] = list(cfg.iperf_endpoints)
            try:
                checks += await run_suite(ctx, kind=kind, only=only, progress=prog)
            finally:
                await runner.close()
            measured, extra = ctx.measured, ctx.extra
    finally:
        await sessions.close(sess)
    r = ratios(measured, cfg.reference_set or prof.reference_set)
    retried: list[str] = []
    spec_base: dict | None = None
    if only is not None and base is not None:
        # targeted retry: previous results stand for everything that was not re-run
        retried = sorted(only)
        reran = {c.id for c in checks}
        checks += [CheckResult.model_validate(c) for c in base.get("checks", []) if c.get("id") not in reran]
        checks.sort(key=lambda c: int(c.id[1:]) if c.id[1:].isdigit() else 99)
        r = {**(base.get("performance") or {}).get("ratios", {}), **r}
        spec_base = base.get("spec_measured")
    perf = perf_score(r)
    calibration = prof.name in cfg.calibration_profiles
    if calibration:
        gate, below = True, []  # reference values unconfirmed for this class: the record carries the measurements, nothing gates
    else:
        gate, below = gate_ok({k: v for k, v in r.items() if k in thresholds()["core_perf_metrics"]})
    failing = [c.id for c in checks if not c.passed]
    incomplete = any(c.skipped for c in checks)
    if failing or not gate:
        outcome = "quarantined"
    elif incomplete:
        outcome = "incomplete"
    else:
        outcome = "pass"
    rec = QualificationRecord(
        kind=kind, node_id=node["node_id"], validator_hotkey=cfg.hotkey, validator_key=platform.key.public.hex, instance_id=sess.instance_id,
        verify_image=sess.info["attestation"].get("image_version") or "verify", started_at=started, finished_at=utcnow_iso(), outcome=outcome,
        failing_checks=failing + ([f"perf<{thresholds()['ratio_floor']}:{','.join(below)}"] if below else []), checks=checks, retried_checks=retried,
        attestation=AttestationSummary(gpu_ids=sess.boot.gpu_ids, measurements_hash=(sess.boot.result.measurements_hash if sess.boot.result else None), verifier_version=sess.boot.result.verifier if sess.boot.result else ""),
        spec_measured=(SpecMeasured.model_validate(merge_measured(spec_base, spec_from_measured(measured, extra, prof).model_dump())) if spec_base else spec_from_measured(measured, extra, prof)),
        performance=PerformanceSummary(ratios={k: round(v, 4) for k, v in r.items()}, perf=round(perf, 4)),
        reference_set=("calibration:" + (cfg.reference_set or prof.reference_set)) if calibration else cfg.reference_set, evidence_bundle=f"{platform.base_url}/v1/evidence?instance_id={sess.instance_id}",
    )
    await platform.publish("qualification", rec.model_dump(by_alias=True, mode="json"))
    log.info("qualified %s: %s perf=%.3f failing=%s%s", node["node_id"][:16], outcome, perf, failing, f" (re-ran only {retried})" if retried else "")
    await prog.finish(rec.outcome)
    return rec
