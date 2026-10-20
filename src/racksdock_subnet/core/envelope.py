"""SignedEnvelope: the single signed message format used across the system."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from .canonical import canonical_bytes, hash_obj
from .keys import PublicKey, SigningKey


def utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class SignedEnvelope(BaseModel):
    """payload is signed as canonical JSON of {"kind", "payload", "signer", "created_at"}."""

    kind: str
    payload: dict[str, Any]
    signer: str = Field(description="hex ed25519 public key of the signer")
    created_at: str = Field(default_factory=utcnow_iso)
    signature: str = Field(default="", description="hex ed25519 signature")

    def signing_bytes(self) -> bytes:
        return canonical_bytes({"kind": self.kind, "payload": self.payload, "signer": self.signer, "created_at": self.created_at})

    @classmethod
    def create(cls, kind: str, payload: dict[str, Any], key: SigningKey) -> SignedEnvelope:
        env = cls(kind=kind, payload=payload, signer=key.public.hex)
        env.signature = key.sign(env.signing_bytes()).hex()
        return env

    def verify(self, expected_signer: str | None = None) -> bool:
        if expected_signer is not None and expected_signer != self.signer:
            return False
        try:
            return PublicKey.from_hex(self.signer).verify(bytes.fromhex(self.signature), self.signing_bytes())
        except (ValueError, TypeError):
            return False

    @property
    def content_hash(self) -> str:
        return hash_obj(self.model_dump())


def require_valid(env: SignedEnvelope, kind: str, expected_signer: str | None = None) -> dict[str, Any]:
    if env.kind != kind:
        raise ValueError(f"envelope kind {env.kind!r} != {kind!r}")
    if not env.verify(expected_signer):
        raise ValueError("invalid envelope signature")
    return env.payload
