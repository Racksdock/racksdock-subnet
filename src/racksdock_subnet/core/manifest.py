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
    file: str  # VM: qcow2 file name; container: docker tag (repo/os:release)
    sha256: str  # VM: file digest; container: the docker image id (sha256:...)
    size_bytes: int
    kind: str = "vm"  # vm | container
    driver: str = ""
    fabric_manager: str = ""
    cuda: str = ""
    node_agent: str = ""
    validator_only: bool = False
    # template metadata (docs/07): what the launch form shows; derived from the name by template_meta() when not given
    label: str = ""
    base_os: str = ""
    pytorch: str = ""
    # container images travel as `docker save` archives in the platform's image store
    archive: str = ""  # file name in the store, e.g. verify_v2026.10.1.container.tar
    archive_sha256: str = ""


def template_meta(os_name: str) -> dict:
    """Label, base OS, CUDA and PyTorch versions encoded in a template name: ubuntu24.04, ubuntu24.04-cuda13.0,
    pytorch-2.9-cuda13.0 (Ubuntu 24.04 unless the name says otherwise), verify."""
    import re as _re

    base = "ubuntu24.04"
    m = _re.search(r"ubuntu(\d\d\.\d\d)", os_name)
    if m:
        base = f"ubuntu{m.group(1)}"
    cuda = (_re.search(r"cuda(\d+\.\d+)", os_name) or [None, ""])[1]
    pytorch = (_re.search(r"pytorch-(\d+\.\d+(?:\.\d+)?)", os_name) or [None, ""])[1]
    if os_name == "verify":
        label = "Validator verify image"
    else:
        parts = []
        if pytorch:
            parts.append(f"PyTorch {pytorch}")
        if cuda:
            parts.append(f"CUDA {cuda}")
        parts.append(f"Ubuntu {base[len('ubuntu'):]}")
        label = ", ".join(parts)
    return {"label": label, "base_os": base, "cuda": cuda, "pytorch": pytorch}


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
        if e.os == os_name and e.version == version and e.kind == "vm":
            if sha256_file(image_path) != e.sha256:
                raise ValueError(f"image digest mismatch for {os_name} {version}")
            return e
    raise ValueError(f"{os_name} {version} not in manifest")


def verify_container_image(manifest: CatalogManifest, os_name: str, version: str, image_id: str) -> ImageEntry:
    """A container catalog entry pins the docker image id; the host-agent compares it with `docker image inspect`."""
    for e in manifest.images:
        if e.os == os_name and e.version == version and e.kind == "container":
            if image_id.strip() != e.sha256:
                raise ValueError(f"container image id mismatch for {os_name} {version}: {image_id[:24]} != {e.sha256[:24]}")
            return e
    raise ValueError(f"container image {os_name} {version} not in manifest")


def catalog_pubkey_hex(key_path: Path) -> str:
    return PublicKey.from_hex(Path(key_path).read_text().strip()).hex
