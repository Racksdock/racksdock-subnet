# miner (`racksdock_subnet.miner`)

The miner neuron (docs/02 §6 steps 1–2, docs/03 §2). Runs on the host image next to `racksdock-host-agent`.

- `racksdock-miner bootstrap`: asks the platform to have this host boot a verify VM and produce its identity draft (eight GPU identities), commits `sha256(registration_record)` on-chain with the miner hotkey, then submits the host-signed registration envelope to the platform. Saves `node_id`.
- `racksdock-miner run`: keeps the node registered (re-registers after a repair changes the GPU set) and the hotkey registered on the subnet.
- `racksdock-miner maintenance --starts ... --ends ...`: announces maintenance (signed with the host's service key so the platform knows it came from this node).

Miners do not serve an axon: validators reach nodes through the platform and the host-agent, never directly. Emissions are credited to the hotkey by the chain.

`RACKSDOCK_CHAIN=subtensor` uses the bittensor SDK with the wallet in `RACKSDOCK_WALLET_NAME`/`RACKSDOCK_WALLET_HOTKEY`; `mock` uses the shared JSON chain of the simulator.
