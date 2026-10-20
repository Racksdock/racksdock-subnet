from __future__ import annotations

import logging

from racksdock_subnet.core.chainclient import ChainClient

from .scorer import TempoResult

log = logging.getLogger("racksdock.validator.weights")


def set_weights(chain: ChainClient, validator_hotkey: str, result: TempoResult, burn_uid: int = 0) -> dict[int, float]:
    uid_by_hotkey = {n.hotkey: n.uid for n in chain.neurons()}
    weights: dict[int, float] = {}
    unknown = 0.0
    for hk, w in result.hotkey_weights.items():
        uid = uid_by_hotkey.get(hk)
        if uid is None:
            unknown += w
            continue
        weights[uid] = weights.get(uid, 0.0) + w
    burn = result.burn + unknown
    if burn > 0:
        weights[burn_uid] = weights.get(burn_uid, 0.0) + burn
    total = sum(weights.values())
    if total > 0:
        weights = {u: w / total for u, w in weights.items()}
    chain.set_weights(validator_hotkey, weights)
    log.info("weights set: %s", {u: round(w, 4) for u, w in weights.items()})
    return weights
