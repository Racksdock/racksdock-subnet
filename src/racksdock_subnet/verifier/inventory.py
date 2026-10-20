"""GPU inventory (what NVML reports). Used for SKU checks and listing data, never for identity."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel


class GpuInventory(BaseModel):
    index: int
    name: str = ""
    serial: str = ""
    pci_device_id: str = ""
    board_part: str = ""
    vbios: str = ""
    memory_total_mib: int = 0
    power_limit_w: float = 0


def load_sim_inventory(node_dir: str | Path) -> list[GpuInventory]:
    data = json.loads((Path(node_dir) / "inventory.json").read_text())
    return [GpuInventory.model_validate(g) for g in data["gpus"]]


def nvidia_smi_inventory(binary: str = "nvidia-smi") -> list[GpuInventory]:
    """Real inventory via nvidia-smi CSV query (works inside the VM where the guest driver is loaded)."""
    if shutil.which(binary) is None:
        raise RuntimeError("nvidia-smi not found")
    fields = "index,name,serial,pci.device_id,vbios_version,memory.total,power.limit"
    out = subprocess.run([binary, f"--query-gpu={fields}", "--format=csv,noheader,nounits"], check=True, capture_output=True, text=True).stdout
    gpus = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue
        pci = parts[3].lower()  # e.g. 0x2B0010DE -> normalise to 10de:2b00
        if pci.startswith("0x") and len(pci) == 10:
            pci = f"{pci[6:10]}:{pci[2:6]}"
        gpus.append(GpuInventory(
            index=int(parts[0]), name=parts[1], serial=parts[2], pci_device_id=pci, vbios=parts[4],
            memory_total_mib=int(float(parts[5])), power_limit_w=float(parts[6]) if parts[6] not in ("[N/A]", "N/A") else 0,
        ))
    # board part number is only in -q output
    try:
        q = subprocess.run([binary, "-q"], check=True, capture_output=True, text=True).stdout
        parts_found = [line.split(":", 1)[1].strip() for line in q.splitlines() if "Board Part Number" in line]
        for g, bp in zip(gpus, parts_found):
            g.board_part = bp
    except Exception:
        pass
    return gpus
