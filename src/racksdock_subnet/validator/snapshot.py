"""Build scorer inputs from the public evidence feed for one tempo window."""
from __future__ import annotations

import datetime as dt

from .scorer import NodeInputs, decayed_strikes


def _ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _overlap_minutes(a0: dt.datetime, a1: dt.datetime, b0: dt.datetime, b1: dt.datetime) -> float:
    lo, hi = max(a0, b0), min(a1, b1)
    return max(0.0, (hi - lo).total_seconds() / 60)


def build_inputs(nodes: list[dict], leases: list[dict], evidence: list[dict], verification: dict[str, dict], window_start: dt.datetime, window_end: dt.datetime,
                 validator_key: str, previously_funded: set[str] | None = None) -> list[NodeInputs]:
    """nodes/leases from the validator endpoints; evidence = canary + inrental + probe records in the window (all validators pooled)."""
    tempo_minutes = (window_end - window_start).total_seconds() / 60
    out = []
    inrental_by_instance: dict[str, list[dict]] = {}
    canaries_by_node: dict[str, list[dict]] = {}
    for e in evidence:
        pl = e["envelope"]["payload"]
        if e["kind"] == "inrental":
            inrental_by_instance.setdefault(pl["instance_id"], []).append(pl)
        elif e["kind"] == "canary":
            canaries_by_node.setdefault(pl["node_id"], []).append(pl)
    for n in nodes:
        nid = n["node_id"]
        q = n.get("qualification") or {}
        # rented minutes: tenant leases overlapping the window whose in-rental checks (ours) passed
        rented = 0.0
        last_att_ok = True
        for lease in leases:
            if lease["node_id"] != nid or lease["is_validator"] or not lease.get("active_at"):
                continue
            a0, a1 = _ts(lease["active_at"]), _ts(lease["released_at"]) if lease.get("released_at") else window_end
            checks = inrental_by_instance.get(lease["instance_id"], [])
            mine = [c for c in checks if c["validator_key"] == validator_key]
            observed = mine or checks
            if observed and all(c["attestation_ok"] and c["gpu_ids_match"] for c in observed):
                rented += _overlap_minutes(a0, a1, window_start, window_end)
            elif observed:
                last_att_ok = False
        # available minutes: idle time covered by a passed canary in the window or within 6h before it
        cans = canaries_by_node.get(nid, [])
        failed = [c for c in cans if c["outcome"] in ("fail", "refused") and window_start <= _ts(c["finished_at"]) <= window_end]
        passed = [c for c in cans if c["outcome"] == "pass" and _ts(c["finished_at"]) >= window_start - dt.timedelta(hours=6)]
        idle = max(0.0, tempo_minutes - rented)
        if failed:
            available, failed_min = 0.0, idle
        elif passed:
            available, failed_min = idle, 0.0
        else:
            available, failed_min = 0.0, 0.0  # no evidence of availability -> no idle pay
        ver = verification.get(nid, {})
        strikes = decayed_strikes([{"at": s["at"], "weight": s["weight"]} for s in ver.get("strikes", [])], window_end)
        can_total = ver.get("canaries", {}).get("total") or 0
        can_pass = ver.get("canaries", {}).get("passed") or 0
        out.append(NodeInputs(
            node_id=nid, hotkey=n["miner_hotkey"], qualified_at=n.get("qualified_at"), qualification_outcome=q.get("outcome") if n.get("status") == "qualified" else None,
            perf=float(n.get("perf") or 0.0), last_attestation_ok=last_att_ok and not n.get("critical_fault"), critical_fault=bool(n.get("critical_fault")),
            duplicate_dispute=False, minutes_rented=rented, minutes_available=available, minutes_failed=failed_min,
            minutes_maintenance=tempo_minutes if n.get("maintenance_until") and _ts(n["maintenance_until"]) > window_start else 0.0,
            strikes=strikes, canary_pass_rate_30d=(can_pass / can_total) if can_total else 1.0, registered_block=int(n.get("registered_block") or 0),
            previously_funded=nid in (previously_funded or set()),
        ))
    return out
