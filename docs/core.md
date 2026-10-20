# core (`racksdock_subnet.core`)

Shared foundation for every other `racksdock-*` repository.

- `racksdock_subnet.core.canonical`: canonical JSON bytes and SHA-256 helpers (every signature and hash in the system uses these).
- `racksdock_subnet.core.keys`: Ed25519 service keys (generate, load, sign, verify).
- `racksdock_subnet.core.envelope`: `SignedEnvelope`, the one signed message format used between validators, node-agents, host-agents and the platform.
- `racksdock_subnet.core.schemas`: pydantic models for all records and protocol messages (registration, qualification, canary, lease, instance, launch configuration, host commands and events, challenges).
- `racksdock_subnet.core.identity`: `gpu_id` from a device certificate and `node_id` from eight `gpu_id`s.
- `racksdock_subnet.core.nonce`: boot nonce composition `SHA256(tenant_nonce || ssh_host_key || SHA256(user_data))`.
- `racksdock_subnet.core.userdata`: deterministic cloud-init `#cloud-config` rendering so client, platform and VM compute the same `user_data_hash`.
- `racksdock_subnet.core.specdata`: loaders for the allowlist, platform list, thresholds and reference sets shipped in `racksdock_subnet.core/spec/`.

Design documents: `/workspace/docs`.
