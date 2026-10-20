"""SKU allowlist checks (docs/03 §4 Q2) against NVML inventory."""
from __future__ import annotations

from racksdock_subnet.core import specdata

from .inventory import GpuInventory


def check_sku(inventory: list[GpuInventory], dev_mode: bool, expected: int | None = None) -> tuple[bool, list[str], dict]:
    from racksdock_subnet.core.profile import current

    n = expected if expected is not None else current().gpu_count
    errors: list[str] = []
    if len(inventory) != n:
        errors.append(f"expected {n} GPUs in inventory, got {len(inventory)}")
    entries = specdata.approved_gpu_entries(dev_mode)
    details = {"pci_device_ids": sorted({g.pci_device_id for g in inventory}), "board_parts": sorted({g.board_part for g in inventory})}
    for g in inventory:
        match = [e for e in entries if e["pci_device_id"].lower() == g.pci_device_id.lower()]
        if not match:
            errors.append(f"gpu {g.index}: pci id {g.pci_device_id} not in allowlist")
            continue
        e = match[0]
        if e.get("board_part_numbers") and g.board_part and g.board_part not in e["board_part_numbers"]:
            errors.append(f"gpu {g.index}: board part {g.board_part} not approved")
        if e.get("vbios_min") and g.vbios and not (e["vbios_min"] <= g.vbios <= e["vbios_max"]):
            errors.append(f"gpu {g.index}: vbios {g.vbios} outside approved range")
        floor = float(e.get("hbm_usable_floor_gb") or 0)
        if floor and g.memory_total_mib / 1024 < floor:
            errors.append(f"gpu {g.index}: memory {g.memory_total_mib / 1024:.1f} GB below floor {floor}")
    return (not errors), errors, details
