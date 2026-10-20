"""Verifiers: check an EvidenceBundle against an expected nonce and produce a VerificationResult."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from racksdock_subnet.core.identity import gpu_id_from_cert_pem
from racksdock_subnet.core.profile import current
from racksdock_subnet.core.schemas import EvidenceBundle, VerificationResult

from .devca import SIM_ARCH, DevCA

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class Verifier(Protocol):
    name: str

    def verify(self, bundle: EvidenceBundle, expected_nonce: str) -> VerificationResult: ...


def split_chain(pem_chain: str | bytes) -> list[x509.Certificate]:
    data = pem_chain.encode() if isinstance(pem_chain, str) else pem_chain
    return [x509.load_pem_x509_certificate(m) for m in PEM_RE.findall(data)]


def _verify_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    pub = issuer.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            return False
        return True
    except InvalidSignature:
        return False


def verify_chain(chain: list[x509.Certificate], trusted_root: x509.Certificate) -> tuple[bool, str | None]:
    """leaf -> ... -> root. Every cert must be signed by the next; last must be signed by the trusted root (or be it)."""
    if not chain:
        return False, "empty chain"
    now = dt.datetime.now(dt.UTC)
    for c in chain:
        if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc):
            return False, f"certificate {c.subject.rfc4514_string()} outside validity"
    for child, parent in zip(chain, chain[1:]):
        if child.issuer != parent.subject or not _verify_signed_by(child, parent):
            return False, f"{child.subject.rfc4514_string()} not signed by {parent.subject.rfc4514_string()}"
    last = chain[-1]
    if last.fingerprint(hashes.SHA256()) == trusted_root.fingerprint(hashes.SHA256()):
        return True, None
    if last.issuer == trusted_root.subject and _verify_signed_by(last, trusted_root):
        return True, None
    return False, "chain does not terminate at the trusted root"


def measurements_hash(per_device: list[list[str]]) -> str:
    h = hashlib.sha256()
    for ms in per_device:
        h.update(",".join(sorted(ms)).encode())
        h.update(b"|")
    return "sha256:" + h.hexdigest()


class SimVerifier:
    """Dev-mode verifier for evidence produced by SimulatedCollector. Never trusted in prod."""

    name = "sim"

    def __init__(self, ca: DevCA, expected_devices: int | None = None):
        self.ca = ca
        self.root = x509.load_pem_x509_certificate(ca.root_pem)
        self.rim = ca.rim()
        self.expected = expected_devices if expected_devices is not None else current().gpu_count

    def verify(self, bundle: EvidenceBundle, expected_nonce: str) -> VerificationResult:
        res = VerificationResult(ok=False, verifier=self.name, nonce_ok=True, chain_ok=True, measurements_ok=True, arch_ok=True)
        if bundle.nonce != expected_nonce:
            res.nonce_ok = False
            res.errors.append("bundle nonce != expected nonce")
        if len(bundle.devices) != self.expected:
            res.errors.append(f"expected {self.expected} devices, got {len(bundle.devices)}")
        per_dev_meas: list[list[str]] = []
        allowed = set(self.rim["measurements"])
        for d in bundle.devices:
            chain = split_chain(d.certificate)
            ok, err = verify_chain(chain, self.root)
            if not ok:
                res.chain_ok = False
                res.errors.append(f"device {d.index}: {err}")
                continue
            leaf = chain[0]
            try:
                outer = json.loads(base64.b64decode(d.evidence))
                body_bytes = base64.b64decode(outer["body"])
                sig = base64.b64decode(outer["sig"])
                leaf.public_key().verify(sig, body_bytes, ec.ECDSA(hashes.SHA384()))
                body = json.loads(body_bytes)
            except (InvalidSignature, ValueError, KeyError) as e:
                res.chain_ok = False
                res.errors.append(f"device {d.index}: evidence signature invalid ({type(e).__name__})")
                continue
            if body.get("nonce") != expected_nonce or d.nonce != expected_nonce:
                res.nonce_ok = False
                res.errors.append(f"device {d.index}: nonce mismatch")
            if body.get("arch") != SIM_ARCH or d.arch != SIM_ARCH:
                res.arch_ok = False
                res.errors.append(f"device {d.index}: arch {body.get('arch')!r}")
            if not set(body.get("measurements", [])) <= allowed or not body.get("measurements"):
                res.measurements_ok = False
                res.errors.append(f"device {d.index}: measurements not in RIM")
            per_dev_meas.append(list(body.get("measurements", [])))
            res.gpu_ids.append(gpu_id_from_cert_pem(chain[0].public_bytes(serialization.Encoding.PEM)))
            res.arch = body.get("arch")
            res.hwmodel = body.get("hwmodel")
        if len(set(res.gpu_ids)) != len(res.gpu_ids):
            res.errors.append("duplicate device identities in bundle")
        res.measurements_hash = measurements_hash(per_dev_meas) if per_dev_meas else None
        res.ok = not res.errors and res.nonce_ok and res.chain_ok and res.measurements_ok and res.arch_ok and len(res.gpu_ids) == self.expected
        return res


class NvattestVerifier:
    """Production verifier using NVIDIA's nvattest CLI on a saved evidence file.

    Command (to confirm against the pinned SDK release):
      nvattest --format json attest --device gpu --gpu-evidence-source file --gpu-evidence-file <f> --nonce <hex> --verifier local
    Claim names assumed in the JSON output (to confirm): per-GPU entries carrying
      "x-nvidia-gpu-arch-check", "measres", "hwmodel", "x-nvidia-gpu-nonce-match" (or "eat_nonce"), and an overall result.
    gpu_ids are derived locally from the leaf certificate in each device's certificate chain and do not depend on claim names.
    """

    name = "nvattest"
    ARCH_OK_KEYS = ("x-nvidia-gpu-arch-check", "x-nvidia-gpu-arch-check-passed")
    MEAS_KEYS = ("measres", "x-nvidia-gpu-measurements-match")
    NONCE_KEYS = ("x-nvidia-gpu-nonce-match", "eat_nonce")

    def __init__(self, binary: str = "nvattest", remote: bool = False, nras_url: str | None = None, rim_url: str | None = None,
                 ocsp_url: str | None = None, policy_path: str | None = None, trusted_root_pem: bytes | None = None, expected_devices: int | None = None):
        self.expected = expected_devices if expected_devices is not None else current().gpu_count
        self.binary = binary
        self.remote = remote
        self.nras_url = nras_url
        self.rim_url = rim_url
        self.ocsp_url = ocsp_url
        self.policy_path = policy_path
        self.trusted_root = x509.load_pem_x509_certificate(trusted_root_pem) if trusted_root_pem else None

    def _write_evidence_file(self, bundle: EvidenceBundle, path: Path) -> None:
        data = {"evidences": [{"arch": d.arch, "nonce": d.nonce, "evidence": d.evidence, "certificate": d.certificate} for d in bundle.devices]}
        path.write_text(json.dumps(data))

    @staticmethod
    def _truthy(v) -> bool:
        return v is True or (isinstance(v, str) and v.lower() in ("true", "success", "pass", "passed", "ok"))

    def verify(self, bundle: EvidenceBundle, expected_nonce: str) -> VerificationResult:
        res = VerificationResult(ok=False, verifier=self.name)
        if shutil.which(self.binary) is None:
            res.errors.append(f"{self.binary} not found")
            return res
        if bundle.nonce != expected_nonce:
            res.errors.append("bundle nonce != expected nonce")
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "evidence.json"
            self._write_evidence_file(bundle, f)
            cmd = [self.binary, "--format", "json", "attest", "--device", "gpu", "--gpu-evidence-source", "file",
                   "--gpu-evidence-file", str(f), "--nonce", expected_nonce, "--verifier", "remote" if self.remote else "local"]
            if self.remote and self.nras_url:
                cmd += ["--nras-url", self.nras_url]
            if self.rim_url:
                cmd += ["--rim-url", self.rim_url]
            if self.ocsp_url:
                cmd += ["--ocsp-url", self.ocsp_url]
            if self.policy_path:
                cmd += ["--relying-party-policy", self.policy_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            try:
                out = json.loads(proc.stdout) if proc.stdout.strip() else {}
            except json.JSONDecodeError:
                out = {"raw": proc.stdout}
            res.raw_claims = out if isinstance(out, dict) else {"raw": out}
            overall = out.get("result", out.get("attestation_result", out.get("overall_result"))) if isinstance(out, dict) else None
            overall_ok = proc.returncode == 0 and (overall is None or self._truthy(overall))
            if proc.returncode != 0:
                res.errors.append(f"nvattest exit {proc.returncode}: {proc.stderr.strip()[:400]}")
            # per-device claims (shape varies by SDK version; be permissive)
            claims_list = []
            if isinstance(out, dict):
                for k in ("claims", "gpu_claims", "detached_claims", "devices", "submods"):
                    v = out.get(k)
                    if isinstance(v, list):
                        claims_list = v
                        break
                    if isinstance(v, dict):
                        claims_list = list(v.values())
                        break
            arch_ok = meas_ok = nonce_ok = True
            for c in claims_list:
                if not isinstance(c, dict):
                    continue
                for k in self.ARCH_OK_KEYS:
                    if k in c and not self._truthy(c[k]):
                        arch_ok = False
                for k in self.MEAS_KEYS:
                    if k in c and not self._truthy(c[k]):
                        meas_ok = False
                for k in self.NONCE_KEYS:
                    if k in c and isinstance(c[k], bool) and not c[k]:
                        nonce_ok = False
                    if k == "eat_nonce" and isinstance(c.get(k), str) and c[k].lower() != expected_nonce.lower():
                        nonce_ok = False
                if "hwmodel" in c and res.hwmodel is None:
                    res.hwmodel = str(c["hwmodel"])
            res.arch_ok, res.measurements_ok, res.nonce_ok = arch_ok, meas_ok, nonce_ok and bundle.nonce == expected_nonce
            res.chain_ok = overall_ok
        # identities from the certificate chains, independent of nvattest claim names
        for d in bundle.devices:
            try:
                chain = split_chain(d.certificate)
                if self.trusted_root is not None:
                    ok, err = verify_chain(chain, self.trusted_root)
                    if not ok:
                        res.chain_ok = False
                        res.errors.append(f"device {d.index}: {err}")
                res.gpu_ids.append(gpu_id_from_cert_pem(chain[0].public_bytes(serialization.Encoding.PEM)))
                res.arch = res.arch or d.arch
            except Exception as e:
                res.errors.append(f"device {d.index}: cannot parse certificate ({e})")
        if len(res.gpu_ids) != self.expected:
            res.errors.append(f"expected {self.expected} device identities, got {len(res.gpu_ids)}")
        res.ok = overall_ok and res.arch_ok and res.measurements_ok and res.nonce_ok and res.chain_ok and len(res.gpu_ids) == self.expected and not res.errors
        return res


def build_verifier(cfg) -> Verifier:
    """Factory from TrustConfig."""
    if cfg.dev:
        if cfg.dev_ca_dir is None:
            raise RuntimeError("RACKSDOCK_DEV_CA_DIR is required in dev trust mode")
        from pathlib import Path as _P

        missing = [f for f in ("root.pem", "rim.json") if not (_P(cfg.dev_ca_dir) / f).exists()]
        if missing:
            raise RuntimeError(f"dev CA incomplete in {cfg.dev_ca_dir} (missing {', '.join(missing)}): copy root.pem, device_ca.pem and rim.json "
                               f"from the node's /etc/racksdock/devca, or create one with `racksdock-verify devca init {cfg.dev_ca_dir}`")
        return SimVerifier(DevCA(cfg.dev_ca_dir))
    return NvattestVerifier(binary=cfg.nvattest_bin, remote=cfg.nras_url is not None, nras_url=cfg.nras_url, rim_url=cfg.rim_url)


def build_collector(cfg, node_dir: str | Path | None = None):
    from .collectors import NvattestCliCollector, SimulatedCollector

    if cfg.dev:
        if cfg.dev_ca_dir is None or node_dir is None:
            raise RuntimeError("dev collector needs RACKSDOCK_DEV_CA_DIR and a node dir")
        return SimulatedCollector(DevCA(cfg.dev_ca_dir), node_dir)
    return NvattestCliCollector(binary=cfg.nvattest_bin)
