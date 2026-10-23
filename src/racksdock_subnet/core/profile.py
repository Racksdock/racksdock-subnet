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
    dcgm_level: int
    power_limit_w: float               # approved GPU power limit; 0 = do not enforce
    allowlist_entries: tuple[dict, ...]  # extra allowlist entries accepted in dev trust mode
    fio_dir: str = "/data"
    sim_pci_id: str = "10de:b300"
    sim_reference_set: str = ""        # values the simulated runner emits; empty -> reference_set
    production: bool = False
    notes: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def nccl_gpus(self) -> int:
        return self.gpu_count

    def enabled(self, check_id: str) -> bool:
        return check_id in self.checks


def available() -> list[str]:
    return sorted(p.name[:-5] for p in resources.files("racksdock_subnet.core.spec.profiles").iterdir() if p.name.endswith(".json"))


@cache
def load(name: str) -> Profile:
    with resources.files("racksdock_subnet.core.spec.profiles").joinpath(f"{name}.json").open("r", encoding="utf-8") as f:
        d = json.load(f)
    return Profile(
        name=d["name"], gpu_count=int(d["gpu_count"]), gpu_model=d["gpu_model"], instance_type=d["instance_type"], interconnect=d.get("interconnect", "nvlink"),
        reference_set=d["reference_set"], checks=tuple(d["checks"]), dcgm_level=int(d.get("dcgm_level", 3)),
        power_limit_w=float(d.get("power_limit_w", 0)), allowlist_entries=tuple(d.get("allowlist_entries", [])),
        fio_dir=d.get("fio_dir", "/data"), sim_pci_id=d.get("sim_pci_id", "10de:b300"), sim_reference_set=d.get("sim_reference_set", ""), production=bool(d.get("production", False)), notes=d.get("notes", ""),
        extra=d.get("extra", {}),
    )


def current() -> Profile:
    return load(os.environ.get(PROFILE_ENV, DEFAULT_PROFILE))


def get(name: str | None) -> Profile:
    """The profile a node registered with (nodes of several hardware classes share one platform and one validator);
    the environment's default profile when no name is given."""
    if name and name in available():
        return load(name)
    return current()


# How a node delivers the rental (docs/01 §4, docs/04 §3): a KVM VM with a dedicated kernel, a Docker container on the host's
# kernel (nested Docker, root inside), or the machine itself (lab workflow tests only). Validators score the weaker tiers at half.
DEPLOYMENTS = ("vm", "container", "static", "dual")
DEPLOYMENT_SCORE_FACTOR = {"vm": 1.0, "container": 0.5, "static": 0.5, "dual": 1.0}  # a node offering the VM tier earns the VM factor


def deployment_factor(deployment: str | None) -> float:
    return DEPLOYMENT_SCORE_FACTOR.get(deployment or "vm", 0.5)


def deployment_modes(deployment: str | None) -> list[str]:
    """The rental modes a node with this registered deployment can deliver."""
    return ["vm", "container"] if deployment == "dual" else [deployment or "vm"]
