"""Evidence collectors: produce an EvidenceBundle for a given nonce."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from racksdock_subnet.core.canonical import canonical_bytes
from racksdock_subnet.core.schemas import DeviceEvidence, EvidenceBundle

from .devca import SIM_ARCH, SIM_HWMODEL, DevCA
from .inventory import GpuInventory, load_sim_inventory


class EvidenceCollector(Protocol):
    name: str

    def collect(self, nonce_hex: str) -> EvidenceBundle: ...

    def inventory(self) -> list[GpuInventory]: ...


class SimulatedCollector:
    """Signs nonce-bound evidence with the node's simulated device keys."""

    name = "sim"

    def __init__(self, ca: DevCA, node_dir: str | Path, tamper: dict | None = None):
        self.ca = ca
        self.node_dir = Path(node_dir)
        self.tamper = tamper or {}
        self._inv = load_sim_inventory(self.node_dir)

    def inventory(self) -> list[GpuInventory]:
        return list(self._inv)

    def collect(self, nonce_hex: str) -> EvidenceBundle:
        rim = self.ca.rim()
        chain_tail = self.ca.device_ca_pem.decode() + self.ca.root_pem.decode()
        devices = []
        for g in self._inv:
            key = serialization.load_pem_private_key((self.node_dir / "devices" / f"{g.index}.key").read_bytes(), password=None)
            leaf_pem = (self.node_dir / "devices" / f"{g.index}.pem").read_text()
            measurements = list(rim["measurements"])
            if self.tamper.get("bad_measurement"):
                measurements[0] = "ff" * 48
            body = {
                "nonce": self.tamper.get("nonce_override", nonce_hex),
                "arch": self.tamper.get("arch", SIM_ARCH),
                "hwmodel": SIM_HWMODEL,
                "measurements": measurements,
                "serial": g.serial,
                "pci_device_id": g.pci_device_id,
                "vbios": g.vbios,
                "memory_total_mib": g.memory_total_mib,
            }
            body_bytes = canonical_bytes(body)
            sig = key.sign(body_bytes, ec.ECDSA(hashes.SHA384()))
            if self.tamper.get("bad_signature"):
                sig = bytes([sig[0] ^ 1]) + sig[1:]
            blob = base64.b64encode(json.dumps({"body": base64.b64encode(body_bytes).decode(), "sig": base64.b64encode(sig).decode()}).encode()).decode()
            devices.append(DeviceEvidence(arch=SIM_ARCH, nonce=nonce_hex, evidence=blob, certificate=leaf_pem + chain_tail, index=g.index))
        return EvidenceBundle(nonce=nonce_hex, devices=devices, collector=self.name)


class NvattestCliCollector:
    """Shells out to NVIDIA's nvattest (Attestation SDK 2.x CLI).

    Command (to confirm against the pinned SDK release):
      nvattest collect-evidence --device gpu --nonce <hex> --gpu-evidence-source nvml --format json
    Output: {"evidences": [{"arch","nonce","evidence","certificate"}...], "result_code", "result_message"}
    """

    name = "nvattest"

    def __init__(self, binary: str = "nvattest", evidence_source: str = "nvml", gpu_architecture: str | None = None):
        self.binary = binary
        self.evidence_source = evidence_source
        self.gpu_architecture = gpu_architecture

    def inventory(self) -> list[GpuInventory]:
        from .inventory import nvidia_smi_inventory

        return nvidia_smi_inventory()

    def collect(self, nonce_hex: str) -> EvidenceBundle:
        if shutil.which(self.binary) is None:
            raise RuntimeError(f"{self.binary} not found")
        cmd = [self.binary, "--format", "json", "collect-evidence", "--device", "gpu", "--nonce", nonce_hex,
               "--gpu-evidence-source", self.evidence_source]
        if self.evidence_source == "corelib" and self.gpu_architecture:
            cmd += ["--gpu-architecture", self.gpu_architecture]
        out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120).stdout
        data = json.loads(out)
        if str(data.get("result_code", "0")) not in ("0", "SUCCESS", "success"):
            raise RuntimeError(f"nvattest collect-evidence failed: {data.get('result_message')}")
        devices = []
        for i, e in enumerate(data.get("evidences", [])):
            devices.append(DeviceEvidence(arch=e.get("arch", ""), nonce=e.get("nonce", nonce_hex), evidence=e.get("evidence", ""),
                                          certificate=e.get("certificate", ""), index=i))
        return EvidenceBundle(nonce=nonce_hex, devices=devices, collector=self.name)
