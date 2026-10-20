"""GPU and node identity derivation (docs/03 §2)."""
from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .canonical import sha256_prefixed


def gpu_id_from_public_key_der(spki_der: bytes) -> str:
    return sha256_prefixed(spki_der)


def gpu_id_from_cert_pem(pem: str | bytes) -> str:
    """gpu_id = sha256(DER(SubjectPublicKeyInfo of the device leaf certificate))."""
    data = pem.encode() if isinstance(pem, str) else pem
    cert = x509.load_pem_x509_certificate(data)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return gpu_id_from_public_key_der(spki)


def node_id_from_gpu_ids(gpu_ids: list[str], expected: int | None = None) -> str:
    """node_id over the sorted GPU identities. `expected` (default: the current profile's gpu_count) enforces the count."""
    from .profile import current

    n = expected if expected is not None else current().gpu_count
    if len(gpu_ids) != n:
        raise ValueError(f"node_id requires exactly {n} gpu_ids, got {len(gpu_ids)}")
    if len(set(gpu_ids)) != len(gpu_ids):
        raise ValueError("gpu_ids must be distinct")
    h = hashlib.sha256()
    for g in sorted(gpu_ids):
        h.update(g.encode("utf-8"))
    return "sha256:" + h.hexdigest()


def gpu_set_hash(gpu_ids: list[str]) -> str:
    """Order-independent hash of a GPU set; used in in-rental checks."""
    h = hashlib.sha256()
    for g in sorted(gpu_ids):
        h.update(g.encode("utf-8"))
    return "sha256:" + h.hexdigest()
