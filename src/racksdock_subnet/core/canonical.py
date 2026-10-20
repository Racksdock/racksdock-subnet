"""Canonical JSON and hashing. Every hash and signature in the system is computed over these bytes."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def hash_obj(obj: Any) -> str:
    """'sha256:<hex>' of the canonical JSON of obj."""
    return sha256_prefixed(canonical_bytes(obj))


def strip_prefix(h: str) -> str:
    return h.split(":", 1)[1] if h.startswith("sha256:") else h
