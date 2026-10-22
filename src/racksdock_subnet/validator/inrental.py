"""In-rental checks (docs/03 §7): attestation + allowlisted health via relayed challenge, and reachability probes."""
from __future__ import annotations

import asyncio
import logging

from racksdock_subnet.core.envelope import SignedEnvelope, utcnow_iso
from racksdock_subnet.core.identity import gpu_set_hash
from racksdock_subnet.core.nonce import new_nonce_hex
from racksdock_subnet.core.schemas import Challenge, ChallengeResponse, InRentalCheckResult, ReachabilityProbe

from .platform import PlatformClient

log = logging.getLogger("racksdock.validator.inrental")

# NVML clocksThrottleReasons bits that mean the GPU is being slowed down by a fault or by the facility: HW slowdown (0x8),
# SW thermal (0x20), HW thermal (0x40), HW power brake (0x80). NOT 0x4 (SW power cap): every GPU reports it whenever a
# workload drives it to its power limit; that is normal operation, not a problem (seen as 8 bogus strikes/min on the 8x4090 test).
THROTTLE_MASK = 0x8 | 0x20 | 0x40 | 0x80


async def probe(ip: str, port: int, timeout: float = 3.0) -> tuple[bool, float | None]:
    import time

    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        try:
            banner = await asyncio.wait_for(r.readline(), timeout)
        finally:
            w.close()
        return banner.startswith(b"SSH-"), (time.perf_counter() - t0) * 1000
    except Exception:
        return False, None


async def check_instance(cfg, platform: PlatformClient, verifier, lease: dict, node: dict, include_microbench: bool, approved_power_w: float) -> InRentalCheckResult:
    iid, node_id = lease["instance_id"], lease["node_id"]
    nonce = new_nonce_hex()
    fields = ["attestation", "health"] + (["microbench"] if include_microbench else [])
    ch = Challenge(instance_id=iid, nonce=nonce, fields=fields, validator_key=platform.key.public.hex)
    reachable, _ = await probe(lease["ip"], lease["ssh_port"]) if lease.get("ip") else (None, None)
    try:
        raw = await platform.challenge(node_id, ch.model_dump())
        if not isinstance(raw, dict) or "payload" not in raw:
            # the host could not reach the node-agent (VM frozen, agent stopped): the platform answers {"error": ...}
            raise RuntimeError((raw or {}).get("error", "no response") if isinstance(raw, dict) else "malformed response")
        resp_env = SignedEnvelope.model_validate(raw)
    except Exception as e:
        # no answer from the node-agent: inconclusive, not a failure. A tenant may stop the agent (docs/03 §7); the node is then
        # scored on reachability and the last conclusive attestation. Only a conclusive mismatch counts against the miner.
        result = InRentalCheckResult(node_id=node_id, instance_id=iid, validator_key=platform.key.public.hex, checked_at=utcnow_iso(), attestation_ok=False,
                                     gpu_ids_match=False, reachable=reachable, agent_reachable=False, error=f"challenge failed: {e}"[:200])
        await platform.publish("inrental", result.model_dump(by_alias=True, mode="json"))
        return result
    errors = []
    expected_signer = lease.get("node_agent_pubkey")
    if not resp_env.verify(expected_signer=expected_signer) or resp_env.kind != "challenge_response":
        errors.append("response not signed by the attested node-agent key")
    resp = ChallengeResponse.model_validate(resp_env.payload)
    if resp.error:
        errors.append(resp.error)
    att_ok, ids_match = False, False
    if resp.bundle is not None and not errors:
        res = verifier.verify(resp.bundle, nonce)
        att_ok = res.ok
        ids_match = set(res.gpu_ids) == set(node["registration"]["gpu_ids"])
        if not att_ok:
            errors.extend(res.errors)
    health = resp.health
    if health is not None:
        if health.gpu_ids_hash != gpu_set_hash(node["registration"]["gpu_ids"]):
            errors.append("health gpu_ids_hash != registration")
        for g in health.gpus:
            if g.clocks_throttle_reasons & THROTTLE_MASK:
                errors.append(f"gpu {g.index} throttled (0x{g.clocks_throttle_reasons:x})")
            if approved_power_w and g.power_limit_w < approved_power_w - 1:
                errors.append(f"gpu {g.index} power limit {g.power_limit_w} < approved {approved_power_w}")
            if g.ecc_uncorrectable_total > 0:
                errors.append(f"gpu {g.index} uncorrectable ECC {g.ecc_uncorrectable_total}")
    result = InRentalCheckResult(node_id=node_id, instance_id=iid, validator_key=platform.key.public.hex, checked_at=utcnow_iso(), attestation_ok=att_ok, gpu_ids_match=ids_match,
                                 health=health, reachable=reachable, agent_reachable=True, error="; ".join(errors)[:300] if errors else None)
    await platform.publish("inrental", result.model_dump(by_alias=True, mode="json"))
    # consequences (docs/04 §7): a lowered power limit is the miner's doing (strike); thermal/HW slowdowns are a facility problem
    # worth an incident but not a strike per check; ECC faults are hardware incidents.
    if att_ok and not ids_match:
        await platform.incident(iid, "identity_change", "attested GPU set differs from registration", strike=True)
    elif health is not None and any("power limit" in e for e in errors):
        await platform.incident(iid, "power_profile", "; ".join(errors)[:200], strike=True)
    elif health is not None and any("throttled" in e for e in errors):
        await platform.incident(iid, "gpu_throttle", "; ".join(errors)[:200], strike=False)
    elif health is not None and any("ECC" in e for e in errors):
        await platform.incident(iid, "gpu_fault", "; ".join(errors)[:200], strike=False)
    return result


async def probe_lease(platform: PlatformClient, lease: dict) -> ReachabilityProbe:
    ok, lat = await probe(lease["ip"], lease["ssh_port"]) if lease.get("ip") else (False, None)
    p = ReachabilityProbe(node_id=lease["node_id"], instance_id=lease["instance_id"], validator_key=platform.key.public.hex, probed_at=utcnow_iso(), reachable=ok, latency_ms=lat)
    await platform.publish("probe", p.model_dump(mode="json"))
    return p
