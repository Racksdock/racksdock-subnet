"""Qualification session: rent the node with the verify image, verify attestation independently, run the suite, publish."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from racksdock_subnet.core.envelope import utcnow_iso
from racksdock_subnet.core.nonce import new_nonce_hex
from racksdock_subnet.core.profile import current as current_profile
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

    async def open(self, node: dict, deadline_s: float, name: str = "verify") -> Session:
        tn = new_nonce_hex()
        t0 = time.monotonic()
        iid = await self.platform.create_verify_instance(node["node_id"], [self.ssh_pub_line], tn, name=name)
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
        boot = verify_boot_evidence(self.verifier, recs[-1]["envelope"], expected_tenant_nonce=tn, user_data=info.get("user_data"),
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


def spec_from_measured(m: dict[str, float], extra: dict) -> SpecMeasured:
    def g(k: str) -> float:
        return float(m.get(k, 0.0))

    return SpecMeasured(
        gpu=GpuSpecMeasured(vram_gb_usable_min=g("gpu.vram_gb_usable_min"), board_part=extra.get("gpu_board_part", ""), vbios=extra.get("gpu_vbios", ""), pci_device_id=extra.get("gpu_pci_id", "")),
        nvlink=NvlinkMeasured(d2d_gbps_min_pair=g("nvlink.d2d_gbps_min_pair"), d2d_gbps_aggregate=g("nvlink.d2d_gbps_aggregate"), allreduce_1gb_busbw_gbps=g("nvlink.allreduce_1gb_busbw_gbps")),
        cpu=CpuMeasured(model=extra.get("cpu_model", ""), vcpus=int(m.get("cpu.vcpus", 0)), stream_gbps=g("cpu.stream_gbps"), sysbench=g("cpu.sysbench")),
        memory_gb=g("memory_gb"), hbm_write_gbps=g("hbm_write_gbps"),
        nvme=NvmeMeasured(capacity_tb=g("nvme.capacity_tb"), seq_read_gbps=g("nvme.seq_read_gbps"), seq_write_gbps=g("nvme.seq_write_gbps"), rand_read_kiops=g("nvme.rand_read_kiops"),
                          rand_write_kiops=g("nvme.rand_write_kiops"), sustained_write_gbps=g("nvme.sustained_write_gbps")),
        network=NetworkMeasured(down_gbps=g("network.down_gbps"), up_gbps=g("network.up_gbps"), endpoints=extra.get("network_endpoints", [])),
        power_profile=PowerProfileMeasured(limit_w=g("power_profile.limit_w"), approved=bool(extra.get("power_approved", False))),
        training_tokens_per_s=g("training_tokens_per_s"), inference_tokens_per_s=g("inference_tokens_per_s"),
    )


async def qualify_node(cfg: ValidatorConfig, platform: PlatformClient, sessions: Sessions, node: dict, kind: str = "full") -> QualificationRecord:
    started = utcnow_iso()
    sess = await sessions.open(node, deadline_s=thresholds()["canary_deadline_s"], name=f"qualify-{kind}")
    checks: list[CheckResult] = [CheckResult(id="Q1", name="GPU authenticity and identity", passed=sess.boot.ok, details={"errors": sess.boot.errors, "gpu_ids": sess.boot.gpu_ids,
                                                                                                                             "measurements_hash": sess.boot.result.measurements_hash if sess.boot.result else None})]
    measured: dict[str, float] = {}
    extra: dict = {}
    try:
        if sess.boot.ok:
            runner = sessions.runner(sess)
            ctx = Ctx(runner=runner, reference=cfg.reference_set or current_profile().reference_set, dev_mode=cfg.trust.dev, claimed_vcpus=int(node["registration"]["claimed_spec"]["vcpus"]))
            ctx.extra["iperf_endpoints"] = list(cfg.iperf_endpoints)
            try:
                checks += await run_suite(ctx, kind=kind)
            finally:
                await runner.close()
            measured, extra = ctx.measured, ctx.extra
    finally:
        await sessions.close(sess)
    r = ratios(measured, cfg.reference_set or current_profile().reference_set)
    perf = perf_score(r)
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
        failing_checks=failing + ([f"perf<{thresholds()['ratio_floor']}:{','.join(below)}"] if below else []), checks=checks,
        attestation=AttestationSummary(gpu_ids=sess.boot.gpu_ids, measurements_hash=(sess.boot.result.measurements_hash if sess.boot.result else None), verifier_version=sess.boot.result.verifier if sess.boot.result else ""),
        spec_measured=spec_from_measured(measured, extra), performance=PerformanceSummary(ratios={k: round(v, 4) for k, v in r.items()}, perf=round(perf, 4)),
        reference_set=cfg.reference_set, evidence_bundle=f"{platform.base_url}/v1/evidence?instance_id={sess.instance_id}",
    )
    await platform.publish("qualification", rec.model_dump(by_alias=True, mode="json"))
    log.info("qualified %s: %s perf=%.3f failing=%s", node["node_id"][:16], outcome, perf, failing)
    return rec
