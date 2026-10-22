"""Loaders for the machine-readable Provider Acceptance Spec data shipped with the package."""
from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any

PKG = "racksdock_subnet.core.spec"


def _load(name: str) -> Any:
    with resources.files(PKG).joinpath(name).open("r", encoding="utf-8") as f:
        return json.load(f)


@cache
def allowlist() -> dict:
    return _load("racksdock-allowlist.json")


@cache
def platforms() -> dict:
    return _load("platforms.json")


@cache
def thresholds() -> dict:
    return _load("thresholds.json")


@cache
def reference_set(name: str) -> dict:
    return _load(f"reference-sets/{name}.json")


def approved_gpu_entries(dev_mode: bool = False) -> list[dict]:
    """Approved SKUs: the global allowlist plus every profile's entries (one platform serves several hardware classes)."""
    from .profile import available, load

    entries = list(allowlist()["gpus"])
    seen = {e["pci_device_id"].lower() for e in entries}
    for name in available():
        for e in load(name).allowlist_entries:
            if e["pci_device_id"].lower() not in seen:
                entries.append(e)
                seen.add(e["pci_device_id"].lower())
    return [e for e in entries if dev_mode or not e.get("sim", False)]


def is_pci_id_approved(pci_device_id: str, dev_mode: bool = False) -> bool:
    return any(e["pci_device_id"].lower() == pci_device_id.lower() for e in approved_gpu_entries(dev_mode))


def hbm_floor_gb(pci_device_id: str, dev_mode: bool = False) -> float | None:
    for e in approved_gpu_entries(dev_mode):
        if e["pci_device_id"].lower() == pci_device_id.lower():
            return float(e["hbm_usable_floor_gb"])
    return None
