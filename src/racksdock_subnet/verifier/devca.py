"""Simulated device PKI and reference measurements for development and tests.

Layout of a DevCA directory:
  root.key / root.pem          simulated NVIDIA root
  device_ca.key / device_ca.pem simulated device identity CA
  rim.json                     simulated reference measurements for arch "blackwell", hwmodel "SIM-B300"
Layout of a node directory issued by DevCA.issue_node:
  devices/0..7.key / .pem      per-GPU device keys and leaf certificates
  inventory.json               simulated NVML inventory (pci id, board part, vbios, memory)
"""
from __future__ import annotations

import datetime as dt
import json
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SIM_ARCH = "blackwell"
SIM_HWMODEL = "SIM-B300"
SIM_PCI_ID = "10de:b300"
SIM_BOARD_PART = "SIM-B300-8GPU"
SIM_VBIOS = "99.00.00.00.01"
SIM_MEMORY_MIB = 270 * 1024


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    path.chmod(0o600)


def _load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "racksdock dev CA (NOT NVIDIA)"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pubkey, signer, ca: bool, days: int, serial: int | None = None) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pubkey)
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return b.sign(signer, hashes.SHA384())


class DevCA:
    def __init__(self, root_dir: str | Path):
        self.dir = Path(root_dir)

    # ---- creation ----------------------------------------------------------
    @classmethod
    def create(cls, root_dir: str | Path, measurements: list[str] | None = None) -> DevCA:
        d = Path(root_dir)
        d.mkdir(parents=True, exist_ok=True)
        root_key = ec.generate_private_key(ec.SECP384R1())
        root_cert = _cert(_name("sim root"), _name("sim root"), root_key.public_key(), root_key, True, 3650)
        dev_key = ec.generate_private_key(ec.SECP384R1())
        dev_cert = _cert(_name("sim device CA"), root_cert.subject, dev_key.public_key(), root_key, True, 3650)
        _write_key(d / "root.key", root_key)
        (d / "root.pem").write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
        _write_key(d / "device_ca.key", dev_key)
        (d / "device_ca.pem").write_bytes(dev_cert.public_bytes(serialization.Encoding.PEM))
        rim = {
            "schema": "racksdock.sim-rim.v1",
            "arch": SIM_ARCH,
            "hwmodel": SIM_HWMODEL,
            "measurements": measurements or [secrets.token_hex(48) for _ in range(4)],
            "vbios": SIM_VBIOS,
        }
        (d / "rim.json").write_text(json.dumps(rim, indent=1))
        return cls(d)

    @property
    def root_pem(self) -> bytes:
        return (self.dir / "root.pem").read_bytes()

    @property
    def device_ca_pem(self) -> bytes:
        return (self.dir / "device_ca.pem").read_bytes()

    def rim(self) -> dict:
        return json.loads((self.dir / "rim.json").read_text())

    # ---- node issuance -----------------------------------------------------
    def issue_node(self, node_dir: str | Path, count: int | None = None, pci_id: str | None = None, board_part: str = SIM_BOARD_PART,
                   vbios: str = SIM_VBIOS, memory_mib: int = SIM_MEMORY_MIB, power_limit_w: int = 1400) -> Path:
        from racksdock_subnet.core.profile import current

        count = count if count is not None else current().gpu_count
        pci_id = pci_id or current().sim_pci_id
        nd = Path(node_dir)
        (nd / "devices").mkdir(parents=True, exist_ok=True)
        dev_key = _load_key(self.dir / "device_ca.key")
        dev_cert = x509.load_pem_x509_certificate(self.device_ca_pem)
        inventory = []
        for i in range(count):
            k = ec.generate_private_key(ec.SECP384R1())
            serial = secrets.token_hex(8).upper()
            c = _cert(_name(f"sim gpu {serial}"), dev_cert.subject, k.public_key(), dev_key, False, 3650)
            _write_key(nd / "devices" / f"{i}.key", k)
            (nd / "devices" / f"{i}.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
            inventory.append({
                "index": i, "serial": serial, "pci_device_id": pci_id, "board_part": board_part, "vbios": vbios,
                "memory_total_mib": memory_mib, "power_limit_w": power_limit_w, "name": "NVIDIA B300 (simulated)",
            })
        (nd / "inventory.json").write_text(json.dumps({"gpus": inventory}, indent=1))
        return nd
