"""Signed catalog manifest shared by racksdock-images (producer) and racksdock-host-agent (consumer)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

from .envelope import SignedEnvelope, utcnow_iso
from .keys import PublicKey, SigningKey


class ImageEntry(BaseModel):
    os: str
    version: str
    file: str
    sha256: str
    size_bytes: int
    driver: str = ""
    fabric_manager: str = ""
    cuda: str = ""
    node_agent: str = ""
    validator_only: bool = False


class CatalogManifest(BaseModel):
    schema_: str = Field(default="racksdock.catalog-manifest.v1", alias="schema")
    release: str
    created_at: str = Field(default_factory=utcnow_iso)
    images: list[ImageEntry]
    host_image: ImageEntry | None = None

    model_config = {"populate_by_name": True}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_manifest(m: CatalogManifest, key: SigningKey) -> SignedEnvelope:
    return SignedEnvelope.create("catalog_manifest", m.model_dump(by_alias=True), key)


def load_signed_manifest(path: Path, catalog_pubkey: str) -> CatalogManifest:
    env = SignedEnvelope.model_validate_json(Path(path).read_text())
    if not env.verify(expected_signer=catalog_pubkey) or env.kind != "catalog_manifest":
        raise ValueError("catalog manifest signature invalid")
    return CatalogManifest.model_validate(env.payload)


def verify_image_file(manifest: CatalogManifest, image_path: Path, os_name: str, version: str) -> ImageEntry:
    for e in manifest.images + ([manifest.host_image] if manifest.host_image else []):
        if e.os == os_name and e.version == version:
            if sha256_file(image_path) != e.sha256:
                raise ValueError(f"image digest mismatch for {os_name} {version}")
            return e
    raise ValueError(f"{os_name} {version} not in manifest")


def catalog_pubkey_hex(key_path: Path) -> str:
    return PublicKey.from_hex(Path(key_path).read_text().strip()).hex
