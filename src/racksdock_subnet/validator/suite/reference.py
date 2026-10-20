"""Reference baselines and the performance score (docs/03 §5)."""
from __future__ import annotations

import math

from racksdock_subnet.core import specdata


def ratios(measured: dict[str, float], reference_name: str) -> dict[str, float]:
    ref = specdata.reference_set(reference_name)["values"]
    out = {}
    for k, v in measured.items():
        if ref.get(k):
            out[k] = min(1.0, float(v) / float(ref[k]))
    return out


def perf_score(r: dict[str, float]) -> float:
    core = specdata.thresholds()["core_perf_metrics"]
    vals = [r[k] for k in core if k in r]
    if not vals:
        return 0.0
    return math.exp(sum(math.log(max(v, 1e-9)) for v in vals) / len(vals))


def gate_ok(r: dict[str, float]) -> tuple[bool, list[str]]:
    floor = specdata.thresholds()["ratio_floor"]
    bad = [k for k, v in r.items() if v < floor]
    return (not bad), bad
