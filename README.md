# racksdock-subnet

The Bittensor side of the 8×B300 dedicated-compute subnet: the shared protocol, attestation verification, and the validator and miner neurons. One Python package, `racksdock_subnet`, installed as `racksdock-subnet`.

```
src/racksdock_subnet/
  core/        schemas for every record and message, canonical JSON, Ed25519 envelopes, gpu_id/node_id, boot-nonce composition,
               deterministic cloud-init rendering, spec data (allowlist, thresholds, reference sets), chain client, catalog manifest
  verifier/    GPU attestation evidence collection + verification (nvattest adapters; dev CA simulator), SKU allowlist
  validator/   admission test, qualification suite Q1–Q15 with real-format parsers, canaries, in-rental checks, deterministic scorer, weights, neuron
  miner/       identity bootstrap, on-chain commitment, registration, maintenance announcements
tests/         one directory per subpackage; tests/validator/vectors/ holds the scorer test vectors every fork must reproduce
docs/          per-subpackage notes
```

Install and test:

```
pip install -e ".[validator,test]"      # validators; add [chain] for the bittensor SDK
pytest
ruff check src tests
```

Entry points: `racksdock-validator`, `racksdock-miner`, `racksdock-verify`. Configuration is by environment variables (`RACKSDOCK_PLATFORM_URL`, `RACKSDOCK_CHAIN=mock|subtensor`, `RACKSDOCK_TRUST_MODE=dev|prod`, `RACKSDOCK_RUNNER=ssh|sim`, …); see `docs/validator.md` and `docs/miner.md`.

Design documents live in the workspace `docs/` folder (03 verification protocol, 04 incentive mechanism).
