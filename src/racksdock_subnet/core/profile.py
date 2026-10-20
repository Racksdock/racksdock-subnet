"""Hardware profile: the one place that says how many GPUs a node has and which checks apply.

Production is `b300x8`. Other profiles exist only for workflow testing on different hardware and are
selected with RACKSDOCK_PROFILE. Everything that previously assumed eight GPUs reads `current().gpu_count`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

PROFILE_ENV = "RACKSDOCK_PROFILE"
DEFAULT_PROFILE = "b300x8"


@dataclass(frozen=True)
class Profile:
    name: str
    gpu_count: int
    gpu_model: str
    instance_type: str
    interconnect: str
    reference_set: str
    checks: tuple[str, ...]            # qualification checks that run (Q1 attestation always runs)
    weekly_checks: tuple[str, ...]
    dcgm_level: int
    dcgm_level_weekly: int
    power_limit_w: float               # approved GPU power limit; 0 = do not enforce
    allowlist_entries: tuple[dict, ...]  # extra allowlist entries accepted in dev trust mode
    fio_dir: str = "/data"
    sim_pci_id: str = "10de:b300"
    production: bool = False
    notes: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def nccl_gpus(self) -> int:
        return self.gpu_count

    def enabled(self, check_id: str, kind: str = "full") -> bool:
        return check_id in (self.weekly_checks if kind == "weekly" else self.checks)


def available() -> list[str]:
    return sorted(p.name[:-5] for p in resources.files("racksdock_subnet.core.spec.profiles").iterdir() if p.name.endswith(".json"))


@cache
def load(name: str) -> Profile:
    with resources.files("racksdock_subnet.core.spec.profiles").joinpath(f"{name}.json").open("r", encoding="utf-8") as f:
        d = json.load(f)
    return Profile(
        name=d["name"], gpu_count=int(d["gpu_count"]), gpu_model=d["gpu_model"], instance_type=d["instance_type"], interconnect=d.get("interconnect", "nvlink"),
        reference_set=d["reference_set"], checks=tuple(d["checks"]), weekly_checks=tuple(d["weekly_checks"]), dcgm_level=int(d.get("dcgm_level", 3)),
        dcgm_level_weekly=int(d.get("dcgm_level_weekly", 2)), power_limit_w=float(d.get("power_limit_w", 0)), allowlist_entries=tuple(d.get("allowlist_entries", [])),
        fio_dir=d.get("fio_dir", "/data"), sim_pci_id=d.get("sim_pci_id", "10de:b300"), production=bool(d.get("production", False)), notes=d.get("notes", ""),
        extra=d.get("extra", {}),
    )


def current() -> Profile:
    return load(os.environ.get(PROFILE_ENV, DEFAULT_PROFILE))
