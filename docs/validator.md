# validator (`racksdock_subnet.validator`)

The validator neuron (docs/03, docs/04). It never trusts the platform's verdicts: it re-verifies every boot evidence envelope with its own verifier, measures from inside a VM it rented through the public API, and computes weights from public evidence with a pure, deterministic scorer.

- `platform.py`: HTTP client for the validator endpoints.
- `suite/`: the qualification suite. `checks.py` defines Q1–Q16 (commands, parser, pass rule); `parsers.py` parses the real tool outputs; `runner.py` runs commands over SSH with the attested host key pinned, or against `SimRunner`, which emits the same formats from a node profile (used by the simulator and tests).
- `qualify.py`: rents the node with the `verify` image, verifies the attestation independently, runs the suite, publishes a signed `QualificationRecord`.
- `admission.py`: the four admission demonstrations (provision, deliver, recover, clean).
- `canary.py`: Poisson-scheduled idle canaries and post-rental readiness canaries.
- `inrental.py`: 10-minute attestation + allowlisted health challenges and reachability probes for tenant instances.
- `scorer.py`: `score_tempo(snapshot, params)` — the only scoring implementation; `tests/vectors/` holds test vectors every fork must reproduce.
- `neuron.py`: the loop. `cli.py`: `racksdock-validator verify | light | run | enroll | qualify | canary | score`.

Modes: `RACKSDOCK_RUNNER=ssh|sim`, `RACKSDOCK_TRUST_MODE=prod|dev`, `RACKSDOCK_CHAIN=subtensor|mock`.

## Light validator

`racksdock-validator light` needs no SSH key, no API key and no node access: every `RACKSDOCK_TEMPO_S` it fetches the platform's
signed scoring snapshot (`GET /v1/scoring/snapshot`), verifies it against the platform key pinned on first contact
(`<state_dir>/platform.pub`, or `RACKSDOCK_PLATFORM_PUBKEY`), runs the same deterministic `score_tempo` the verifying validator
runs, and sets weights with `RACKSDOCK_HOTKEY`. Environment: `RACKSDOCK_PLATFORM_URL`, `RACKSDOCK_HOTKEY`, `RACKSDOCK_CHAIN`
(+ `RACKSDOCK_CHAIN_FILE` for the mock chain, wallet settings for subtensor), `RACKSDOCK_STATE_DIR`, `RACKSDOCK_TEMPO_S`.
It writes `<state_dir>/last_scoring.json` (inputs' window, scores, funded set, hotkey weights, burn, uid weights) after every
tempo. Requirements: one CPU core and a validator permit. Docs/04 §3.5 explains what it does and does not attest to.

## Step progress

Every admission and qualification session reports its steps to the platform (`PlatformClient.progress`, `qualify.Progress`:
plan → running → pass/fail → outcome) so the console can show them live; see docs/03 "live step progress". Best effort: a failed
report is logged at debug level and never affects the session or the signed record. `Q4` (DCGM) starts the host engine and
retries once when the first `dcgmi diag` ran no tests, and records DCGM's `runtime_error` as the check's error.

## Roles (decided 2026-10-22)

- **Platform verifier** (`racksdock-validator verify`, `RACKSDOCK_ROLE=verifier`): operated by the platform, enrolled with its own
  key. Runs admission tests, the qualification suite, canaries and in-rental checks and publishes the signed records. It never
  scores, never sets weights and needs no wallet or chain access. Validator enrolment on the platform is closed
  (`RACKSDOCK_VALIDATOR_ENROLL=0`), so this is the only full validator.
- **Validators** (`racksdock-validator light`): every subnet validator, including the owner's. Fetches the platform-signed scoring
  snapshot each tempo, recomputes the weights with the public scorer, sets them. Needs only the wallet with the validator hotkey.
- `run` (verify + score in one process) remains for simulations and tests.
