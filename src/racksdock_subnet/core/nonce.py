"""Nonce composition (docs/05 §5): nonce = SHA256(tenant_nonce || ssh_host_key_public || SHA256(user_data))."""
from __future__ import annotations

import hashlib
import secrets


def new_nonce_hex() -> str:
    return secrets.token_hex(32)


def compose_boot_nonce(tenant_nonce_hex: str, ssh_host_key_public: bytes, user_data: bytes) -> str:
    tn = bytes.fromhex(tenant_nonce_hex)
    if len(tn) != 32:
        raise ValueError("tenant_nonce must be 32 bytes")
    h = hashlib.sha256()
    h.update(tn)
    h.update(ssh_host_key_public)
    h.update(hashlib.sha256(user_data).digest())
    return h.hexdigest()


def ssh_host_key_bytes_from_line(line: str) -> bytes:
    """Take 'ssh-ed25519 AAAA... comment' and return the raw base64-decoded key blob."""
    import base64

    parts = line.strip().split()
    if len(parts) < 2:
        raise ValueError("malformed ssh public key line")
    return base64.b64decode(parts[1])


def ssh_fingerprint(line: str) -> str:
    import base64

    blob = ssh_host_key_bytes_from_line(line)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
