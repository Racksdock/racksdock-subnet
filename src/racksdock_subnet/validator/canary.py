"""Idle and readiness canaries (docs/03 §6)."""
from __future__ import annotations

import logging
import random

from racksdock_subnet.core.envelope import utcnow_iso
from racksdock_subnet.core.schemas import CanaryResult
from racksdock_subnet.core.specdata import thresholds

from .platform import PlatformClient
from .qualify import Sessions
from .suite.checks import Ctx, smoke

log = logging.getLogger("racksdock.validator.canary")


class CanaryScheduler:
    def __init__(self, mean_interval_s: float, seed: int | None = None):
        self.mean = mean_interval_s
        self.next_at: dict[str, float] = {}
        self.rng = random.Random(seed)

    def due(self, node_id: str, now: float) -> bool:
        t = self.next_at.get(node_id)
        if t is None:
            self.next_at[node_id] = now + self.rng.expovariate(1 / self.mean)
            return False
        return now >= t

    def schedule_next(self, node_id: str, now: float) -> None:
        self.next_at[node_id] = now + max(1800.0 if self.mean > 3600 else 1.0, self.rng.expovariate(1 / self.mean))


async def run_canary(cfg, platform: PlatformClient, sessions: Sessions, node: dict, kind: str = "idle") -> CanaryResult:
    started = utcnow_iso()
    deadline = thresholds()["canary_deadline_s"] if cfg.canary_deadline_s is None else cfg.canary_deadline_s
    try:
        sess = await sessions.open(node, deadline_s=deadline, name=f"canary-{kind}")
    except TimeoutError as e:
        res = CanaryResult(node_id=node["node_id"], validator_key=platform.key.public.hex, started_at=started, finished_at=utcnow_iso(), outcome="fail", reason=str(e)[:200])
        await platform.publish("canary", res.model_dump(by_alias=True, mode="json"))
        return res
    except RuntimeError as e:
        outcome = "preempted" if "node_busy" in str(e) else "refused"
        res = CanaryResult(node_id=node["node_id"], validator_key=platform.key.public.hex, started_at=started, finished_at=utcnow_iso(), outcome=outcome, reason=str(e)[:200])
        if outcome == "refused":
            await platform.publish("canary", res.model_dump(by_alias=True, mode="json"))
        return res
    metrics: dict = {}
    try:
        runner = sessions.runner(sess)
        try:
            ctx = Ctx(runner=runner, reference=cfg.reference_set, dev_mode=cfg.trust.dev, claimed_vcpus=0)
            ctx.extra["iperf_endpoints"] = list(cfg.iperf_endpoints)
            metrics = await smoke(ctx)
        finally:
            await runner.close()
    finally:
        await sessions.close(sess)
    ok = sess.boot.ok and metrics.get("nccl_wrong", 1) == 0 and metrics.get("marker") == "absent" and metrics.get("gpu_memory_verify") == "ok"
    res = CanaryResult(node_id=node["node_id"], validator_key=platform.key.public.hex, instance_id=sess.instance_id, started_at=started, finished_at=utcnow_iso(),
                       outcome="pass" if ok else "fail", gpu_ids_match=sess.boot.ok, time_to_active_s=round(sess.time_to_active_s, 1), smoke_metrics=metrics,
                       reason=None if ok else ("; ".join(sess.boot.errors) or "smoke failed")[:200])
    await platform.publish("canary", res.model_dump(by_alias=True, mode="json"))
    return res
