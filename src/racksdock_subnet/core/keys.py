"""Ed25519 service keys. Validators, node-agents, host-agents, the platform and the catalog signer each hold one."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass(frozen=True)
class PublicKey:
    raw: bytes  # 32 bytes

    @property
    def hex(self) -> str:
        return self.raw.hex()

    @classmethod
    def from_hex(cls, h: str) -> PublicKey:
        raw = bytes.fromhex(h)
        if len(raw) != 32:
            raise ValueError("ed25519 public key must be 32 bytes")
        return cls(raw)

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(self.raw).verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def ssh_public_line(self, comment: str = "") -> str:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(self.raw)
        line = pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        return f"{line} {comment}".strip()


class SigningKey:
    def __init__(self, private: ed25519.Ed25519PrivateKey):
        self._priv = private

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> SigningKey:
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_seed_hex(cls, h: str) -> SigningKey:
        return cls.from_seed(bytes.fromhex(h))

    @property
    def seed_hex(self) -> str:
        return self._priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        ).hex()

    @property
    def public(self) -> PublicKey:
        return PublicKey(self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    # --- persistence -------------------------------------------------------
    @classmethod
    def load_or_create(cls, path: str | Path) -> SigningKey:
        p = Path(path)
        if p.exists():
            return cls.from_seed_hex(p.read_text().strip())
        p.parent.mkdir(parents=True, exist_ok=True)
        key = cls.generate()
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.seed_hex + "\n")
        return key

    def to_openssh_private(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        )
