# validator (`racksdock_subnet.validator`)

The validator neuron (docs/03, docs/04). It never trusts the platform's verdicts: it re-verifies every boot evidence envelope with its own verifier, measures from inside a VM it rented through the public API, and computes weights from public evidence with a pure, deterministic scorer.

- `platform.py`: HTTP client for the validator endpoints.
- `suite/`: the qualification suite. `checks.py` defines Q1–Q16 (commands, parser, pass rule); `parsers.py` parses the real tool outputs; `runner.py` runs commands over SSH with the attested host key pinned, or against `SimRunner`, which emits the same formats from a node profile (used by the simulator and tests).
- `qualify.py`: rents the node with the `verify` image, verifies the attestation independently, runs the suite, publishes a signed `QualificationRecord`.
- `admission.py`: the four admission demonstrations (provision, deliver, recover, clean).
- `canary.py`: Poisson-scheduled idle canaries and post-rental readiness canaries.
- `inrental.py`: 10-minute attestation + allowlisted health challenges and reachability probes for tenant instances.
- `scorer.py`: `score_tempo(snapshot, params)` — the only scoring implementation; `tests/vectors/` holds test vectors every fork must reproduce.
- `neuron.py`: the loop. `cli.py`: `racksdock-validator enroll | run | qualify | canary | score`.

Modes: `RACKSDOCK_RUNNER=ssh|sim`, `RACKSDOCK_TRUST_MODE=prod|dev`, `RACKSDOCK_CHAIN=subtensor|mock`.
