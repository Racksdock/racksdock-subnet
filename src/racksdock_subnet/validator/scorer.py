"""Deterministic scorer (docs/04). Pure functions over a snapshot of public evidence.

Every validator that fetches the same evidence with the same cut-off produces the same weights.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from racksdock_subnet.core.profile import deployment_factor


@dataclass
class Params:
    w_a: float = 0.50
    w_p: float = 0.20
    w_r: float = 0.30
    perf_floor: float = 0.90
    qualification_validity_s: float = 7 * 86400
    hotkey_cap: float = 0.25
    funded_slots: int = 64
    strike_decay_days: float = 30
    exclusion_strikes: float = 3.0
    hysteresis_tempos: int = 3


@dataclass
class NodeInputs:
    node_id: str
    hotkey: str
    qualified_at: str | None
    qualification_outcome: str | None
    perf: float
    last_attestation_ok: bool
    critical_fault: bool
    duplicate_dispute: bool
    minutes_rented: float          # validator-observed tenant-bound minutes
    minutes_available: float       # idle minutes covered by passed canaries / recent passed canary
    minutes_failed: float          # canary failed/refused, heartbeat lost
    minutes_maintenance: float
    strikes: float                 # decayed active strike weight
    canary_pass_rate_30d: float
    registered_block: int
    previously_funded: bool = False
    deployment: str = "vm"         # vm | container | static: container and static tiers score at half (docs/04 §3)


@dataclass
class TempoResult:
    tempo_minutes: float
    scores: dict[str, float] = field(default_factory=dict)       # node_id -> S
    funded: list[str] = field(default_factory=list)
    hotkey_weights: dict[str, float] = field(default_factory=dict)
    burn: float = 0.0
    details: dict[str, dict] = field(default_factory=dict)


def _age_s(ts: str | None, now: dt.datetime) -> float:
    if not ts:
        return float("inf")
    return (now - dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds()


def adaptive_weights(p: Params, utilization: float) -> tuple[float, float, float]:
    """docs/04 §3.2: above 50% utilization, w_A moves 0.50 -> 0.35 and w_R 0.30 -> 0.45 as utilization reaches 80%."""
    if utilization <= 0.5:
        return p.w_a, p.w_p, p.w_r
    f = min(1.0, (utilization - 0.5) / 0.3)
    return p.w_a - 0.15 * f, p.w_p, p.w_r + 0.15 * f


def score_tempo(nodes: list[NodeInputs], now: dt.datetime, tempo_minutes: float, p: Params, utilization_7d: float = 0.0) -> TempoResult:
    res = TempoResult(tempo_minutes=tempo_minutes)
    w_a, w_p, w_r = adaptive_weights(p, utilization_7d)
    # eligibility (everything in the gate except the funded slot)
    eligible: list[NodeInputs] = []
    for n in nodes:
        reasons = []
        if n.qualification_outcome != "pass" or _age_s(n.qualified_at, now) > p.qualification_validity_s:
            reasons.append("qualification missing or stale")
        if not n.last_attestation_ok:
            reasons.append("last attestation failed")
        if n.critical_fault:
            reasons.append("critical fault open")
        if n.duplicate_dispute:
            reasons.append("duplicate identity dispute")
        if n.strikes >= p.exclusion_strikes:
            reasons.append("strike exclusion")
        if n.perf < p.perf_floor:
            reasons.append("perf below floor")
        res.details[n.node_id] = {"gate_reasons": reasons}
        if not reasons:
            eligible.append(n)
    # funded slots: rank by strikes asc, canary pass rate desc, perf desc, registration block asc; previously funded first within ties (hysteresis)
    ranked = sorted(eligible, key=lambda n: (round(n.strikes, 3), -round(n.canary_pass_rate_30d, 4), -round(n.perf, 4), 0 if n.previously_funded else 1, n.registered_block))
    funded = ranked[: p.funded_slots]
    res.funded = [n.node_id for n in funded]
    for n in funded:
        denom = max(tempo_minutes - n.minutes_maintenance, 1.0)
        a = min(1.0, (n.minutes_rented + n.minutes_available) / denom)
        pp = min(1.0, max(0.0, (n.perf - p.perf_floor) / (1.0 - p.perf_floor)))
        r = min(1.0, n.minutes_rented / tempo_minutes)
        tier = deployment_factor(n.deployment)
        s = (w_a * a + w_p * pp + w_r * r) * tier
        if n.minutes_rented + n.minutes_available <= 0:
            # nothing attested this tempo (host offline, failed canary, no evidence): the performance term alone pays nothing
            s = 0.0
            res.details[n.node_id]["gate_reasons"].append("no attested availability in the window")
        res.scores[n.node_id] = round(s, 6)
        res.details[n.node_id].update({"A": round(a, 4), "P": round(pp, 4), "R": round(r, 4), "S": round(s, 6), "weights": [w_a, w_p, w_r], "tier": n.deployment, "tier_factor": tier})
    # hotkey aggregation with soft cap and burn for unfilled slots
    by_hk: dict[str, float] = {}
    for n in funded:
        by_hk[n.hotkey] = by_hk.get(n.hotkey, 0.0) + res.scores[n.node_id]
    total = sum(by_hk.values())
    if total <= 0:
        res.burn = 1.0
        return res
    cap = p.hotkey_cap * total
    capped = {hk: min(v, cap) for hk, v in by_hk.items()}
    excess = total - sum(capped.values())
    # redistribute excess proportionally among uncapped hotkeys (one pass; remainder burns)
    uncapped = {hk: v for hk, v in capped.items() if 0 < v < cap}  # a zero-score hotkey cannot absorb anything
    if excess > 0 and uncapped:
        u_total = sum(uncapped.values())
        for hk in uncapped:
            add = excess * uncapped[hk] / u_total
            capped[hk] = min(cap, capped[hk] + add)
        excess = total - sum(capped.values())
    unfilled_fraction = max(0.0, (p.funded_slots - len(funded)) / p.funded_slots) if p.funded_slots else 0.0
    burn_share = excess / total + unfilled_fraction * (1 - excess / total)
    scale = (1 - burn_share) / sum(capped.values()) if sum(capped.values()) > 0 else 0.0
    res.hotkey_weights = {hk: round(v * scale, 8) for hk, v in capped.items()}
    res.burn = round(1 - sum(res.hotkey_weights.values()), 8)
    return res


def decayed_strikes(strikes: list[dict], now: dt.datetime, days: float = 30) -> float:
    total = 0.0
    for s in strikes:
        age = _age_s(s["at"], now) / 86400
        if age < days:
            total += float(s.get("weight", 1.0)) * (1 - age / days)
    return total
