# verifier (`racksdock_subnet.verifier`)

Collects and verifies NVIDIA GPU attestation evidence (docs/03 §4 Q1, docs/05 §5).

Two trust modes, selected by `RACKSDOCK_TRUST_MODE`:

- `prod`: `NvattestCliCollector` shells out to NVIDIA's `nvattest collect-evidence`; `NvattestVerifier` runs `nvattest attest` against the local RIM verifier (or NRAS with `--verifier remote`) on the saved evidence and the expected nonce, then derives each `gpu_id` from the device leaf certificate in the evidence bundle.
- `dev`: `DevCA` issues a simulated device PKI (root → device CA → eight device leaf certs per node) and a simulated RIM; `SimulatedCollector` produces nonce-bound, device-signed evidence; `SimVerifier` checks chain, signature, nonce, architecture and measurements. This is what the simulator and the test-suite use. It is never accepted by a production verifier.

Both paths produce the same `VerificationResult` from `racksdock_subnet.core.schemas`.

The claim names parsed from `nvattest` output are listed in `nvattest.py` and marked "to confirm" against the pinned SDK release.
