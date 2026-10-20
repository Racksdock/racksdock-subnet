"""Independent verification of boot evidence (the validator never trusts the platform's verdict)."""
from __future__ import annotations

from dataclasses import dataclass

from racksdock_subnet.core.envelope import SignedEnvelope
from racksdock_subnet.core.nonce import compose_boot_nonce, ssh_host_key_bytes_from_line
from racksdock_subnet.core.profile import current as current_profile
from racksdock_subnet.core.schemas import BootEvidence, VerificationResult


@dataclass
class BootCheck:
    ok: bool
    errors: list[str]
    evidence: BootEvidence | None
    result: VerificationResult | None

    @property
    def gpu_ids(self) -> list[str]:
        return self.result.gpu_ids if self.result else []


def verify_boot_evidence(verifier, envelope: dict, *, expected_tenant_nonce: str, user_data: str | None, registration_gpu_ids: list[str],
                         expected_image_version: str | None = None) -> BootCheck:
    errors: list[str] = []
    env = SignedEnvelope.model_validate(envelope)
    if not env.verify() or env.kind != "boot_evidence":
        return BootCheck(False, ["bad boot_evidence envelope"], None, None)
    ev = BootEvidence.model_validate(env.payload)
    if env.signer != ev.node_agent_pubkey:
        errors.append("envelope signer != node_agent_pubkey")
    if ev.tenant_nonce != expected_tenant_nonce:
        errors.append("tenant nonce mismatch")
    if user_data is not None:
        expected = compose_boot_nonce(expected_tenant_nonce, ssh_host_key_bytes_from_line(ev.ssh_host_key_line), user_data.encode())
        if expected != ev.boot_nonce:
            errors.append("boot nonce does not bind our tenant nonce, the host key and the user-data")
    if expected_image_version and ev.image_version != expected_image_version:
        errors.append(f"image version {ev.image_version} != {expected_image_version}")
    res = verifier.verify(ev.bundle, ev.boot_nonce)
    if not res.ok:
        errors.extend(res.errors or ["attestation failed"])
    if set(res.gpu_ids) != set(registration_gpu_ids) or len(res.gpu_ids) != current_profile().gpu_count:
        errors.append("GPU identities do not match registration")
    return BootCheck(not errors, errors, ev, res)
