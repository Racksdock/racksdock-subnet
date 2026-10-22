# validator (`racksdock_subnet.validator`)

The validator neuron (docs/03, docs/04). It never trusts the platform's verdicts: it re-verifies every boot evidence envelope with its own verifier, measures from inside a VM it rented through the public API, and computes weights from public evidence with a pure, deterministic scorer.

- `platform.py`: HTTP client for the validator endpoints.
- `suite/`: the qualification suite. `checks.py` defines Q1–Q16 (commands, parser, pass rule); `parsers.py` parses the real tool outputs; `runner.py` runs commands over SSH with the attested host key pinned, or against `SimRunner`, which emits the same formats from a node profile (used by the simulator and tests).
- `qualify.py`: rents the node with the `verify` image, verifies the attestation independently, runs the suite, publishes a signed `QualificationRecord`.
- `admission.py`: the four admission demonstrations (provision, deliver, recover, clean).
- `canary.py`: Poisson-scheduled idle canaries and post-rental readiness canaries.
- `inrental.py`: 10-minute attestation + allowlisted health challenges and reachability probes for tenant instances.
- `scorer.py`: `score_tempo(snapshot, params)` — the only scoring implementation; `tests/vectors/` holds test vectors every fork must reproduce.
- `neuron.py`: the verifier loop. `validator.py`: the validator. `cli.py`: `racksdock-validator verify | run | audit | all-in-one | enroll | qualify | canary | score`.

Modes: `RACKSDOCK_RUNNER=ssh|sim`, `RACKSDOCK_TRUST_MODE=prod|dev`, `RACKSDOCK_CHAIN=subtensor|mock`.

## Roles (decided 2026-10-22)

- **Verifier** (`racksdock-validator verify`, `RACKSDOCK_ROLE=verifier`, class `Verifier` in `neuron.py`): operated by the
  platform, enrolled with its own key. Runs admission tests, the qualification suite, canaries and in-rental checks and publishes
  the signed records. It never scores, never sets weights and needs no wallet or chain access. Enrolment of further verifier keys
  is closed (`RACKSDOCK_VALIDATOR_ENROLL=0`).
- **Validators** (`racksdock-validator run`, class `Validator` in `validator.py`): every subnet validator; the platform team runs one like everybody else.
  Needs no SSH key, no API key and no node access: every `RACKSDOCK_TEMPO_S` it fetches `GET /v1/scoring/snapshot`, checks the
  signature against the pinned platform key (`<state_dir>/platform.pub`, or `RACKSDOCK_PLATFORM_PUBKEY`), runs the deterministic
  `score_tempo` and sets weights with its own hotkey; `last_scoring.json` in the state dir records what it submitted. Every
  validator sees the same signed inputs, so their weights are identical.
- `racksdock-validator audit`: rebuilds the current snapshot from the public endpoints alone and compares it with the signed
  one, then compares its own weights with the platform's recorded round. Any difference is printed; none means the platform's
  snapshot is exactly what its public records say.
- `racksdock-validator all-in-one` (verify + score in one process) remains for simulations and tests only.

## Calibration of a new hardware class

The first real node of a class has no confirmed reference values and its SKU may still be `to_confirm` in the allowlist. Set
`RACKSDOCK_CALIBRATION_PROFILES=b300x8` on the verifier: for that profile every check still runs and every value is recorded,
but no reference ratio gates the outcome (`reference_set` in the record reads `calibration:<set>`), and in dev trust mode an
unconfirmed allowlist entry matches by model name while the record lists the PCI id, board part and VBIOS to confirm. Build the
real reference set from the record's `spec_measured`, confirm the allowlist entry, remove the profile from the variable.
