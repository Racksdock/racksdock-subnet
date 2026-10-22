# miner (`racksdock_subnet.miner`)

The miner neuron (docs/02 §6 steps 1–2, docs/03 §2). Runs on the host image next to `racksdock-host-agent`.

- `racksdock-miner bootstrap`: asks the platform to have this host boot a verify VM and produce its identity draft (eight GPU identities), commits `sha256(registration_record)` on-chain with the miner hotkey, then submits the host-signed registration envelope to the platform. Saves `node_id`.
- `racksdock-miner run`: keeps the node registered (re-registers after a repair changes the GPU set) and the hotkey registered on the subnet.
- `racksdock-miner maintenance --starts ... --ends ...`: announces maintenance (signed with the host's service key so the platform knows it came from this node).

Miners do not serve an axon: validators reach nodes through the platform and the host-agent, never directly. Emissions are credited to the hotkey by the chain.

`RACKSDOCK_CHAIN=subtensor` uses the bittensor SDK with the wallet in `RACKSDOCK_WALLET_NAME`/`RACKSDOCK_WALLET_HOTKEY`; `mock` uses the shared JSON chain of the simulator.

## Registering a new server (current workflow)

1. Register the miner hotkey on the subnet with btcli (`btcli subnet register --netuid <netuid> --network <net> --wallet.name <coldkey> --wallet.hotkey <hotkey>`), on the machine that holds the wallet. GPU servers never hold wallets.
2. On the server (root): clone the repos and run `DEPLOYMENT=vm|container|dual PLATFORM_URL=http://<platform>:8000 PUBLIC_IP=<ip> PROFILE=<profile> MINER_HOTKEY=<ss58> [REGION=<label>] TRUST_MODE=<prod|dev> REPOS=/root/racksdock bash racksdock-node/host-image/scripts/setup-host.sh`. The node's location (country, continent, approximate city) is detected by the platform from the address the host agent connects from, so nothing has to be typed; `REGION` is an optional label (datacenter or city, e.g. `de-fra-1`) shown alongside, never overriding the detected country; reboot once for vm/dual (IOMMU + hugepages). The host-agent starts, connects, and syncs the platform's image catalog by itself (no image builds).
3. Print the host's service key on the server: `set -a; . /etc/racksdock/host-agent.env; set +a; /opt/racksdock/venv/bin/racksdock-host-agent --show-key`.
4. Bootstrap, on the machine that holds the miner hotkey. Either the GPU server itself (the setup script installs the chain extra; use `/opt/racksdock/venv/bin/racksdock-miner`, `RACKSDOCK_PLATFORM_URL=http://<platform>:8000` and, if the wallet is not under `~/.bittensor/wallets`, `RACKSDOCK_WALLET_PATH`) or a separate wallet machine (`racksdock-subnet[chain]` installed): `RACKSDOCK_PLATFORM_URL=http://<platform>:8000 RACKSDOCK_HOTKEY=<ss58> RACKSDOCK_CHAIN=subtensor RACKSDOCK_CHAIN_NETWORK=<net> RACKSDOCK_NETUID=<netuid> RACKSDOCK_WALLET_NAME=<coldkey> RACKSDOCK_WALLET_HOTKEY=<hotkey> racksdock-miner bootstrap --host-pubkey <key from step 3>` (boots a verify instance, derives the GPU identities, commits the registration hash on chain, registers with the platform). `--reuse-identity` later re-signs the same identity after a change of tier, profile or hotkey.
5. Wait for the verifier: admission + full qualification (15–60 min by hardware), then the node is listed; the console shows "waiting for verification" / "verifying" meanwhile.
