from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from racksdock_subnet.core.canonical import hash_obj
from racksdock_subnet.core.chainclient import build_chain
from racksdock_subnet.core.envelope import SignedEnvelope
from racksdock_subnet.core.keys import SigningKey
from racksdock_subnet.core.schemas import RegistrationRecord

log = logging.getLogger("racksdock.miner")


@dataclass
class MinerConfig:
    platform_url: str = "http://127.0.0.1:8000"
    hotkey: str = "5Fminer"
    netuid: int = 1
    chain_kind: str = "mock"
    chain_file: Path = Path("./chain.json")
    chain_network: str = "finney"
    wallet_name: str = "default"
    wallet_hotkey: str = "default"
    host_seed_path: Path = Path("/var/lib/racksdock-host-agent/host.seed")
    state_dir: Path = Path("/var/lib/racksdock-miner")
    network_gbps: float = 25.0
    poll_s: float = 2.0
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> MinerConfig:
        e = os.environ.get
        return cls(platform_url=e("RACKSDOCK_PLATFORM_URL", "http://127.0.0.1:8000"), hotkey=e("RACKSDOCK_HOTKEY", "5Fminer"), netuid=int(e("RACKSDOCK_NETUID", "1")),
                   chain_kind=e("RACKSDOCK_CHAIN", "mock"), chain_file=Path(e("RACKSDOCK_CHAIN_FILE", "./chain.json")), chain_network=e("RACKSDOCK_CHAIN_NETWORK", "finney"),
                   wallet_name=e("RACKSDOCK_WALLET_NAME", "default"), wallet_hotkey=e("RACKSDOCK_WALLET_HOTKEY", "default"),
                   host_seed_path=Path(e("RACKSDOCK_HOST_SEED", "/var/lib/racksdock-host-agent/host.seed")), state_dir=Path(e("RACKSDOCK_STATE_DIR", "/var/lib/racksdock-miner")),
                   network_gbps=float(e("RACKSDOCK_NETWORK_GBPS", "25")), poll_s=float(e("RACKSDOCK_POLL_S", "2")))


class MinerNeuron:
    def __init__(self, cfg: MinerConfig, host_pubkey: str | None = None):
        self.cfg = cfg
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.chain = build_chain(cfg.chain_kind, path=cfg.chain_file, netuid=cfg.netuid, network=cfg.chain_network)
        self.host_key: SigningKey | None = SigningKey.load_or_create(cfg.host_seed_path) if cfg.host_seed_path.exists() else None
        self.host_pubkey = host_pubkey or (self.host_key.public.hex if self.host_key else None)
        self.c = httpx.AsyncClient(base_url=cfg.platform_url.rstrip("/"), timeout=60)

    async def close(self) -> None:
        await self.c.aclose()

    @property
    def node_id(self) -> str | None:
        p = self.cfg.state_dir / "node_id"
        return p.read_text().strip() if p.exists() else None

    def ensure_hotkey_registered(self) -> None:
        try:
            self.chain.register(self.cfg.hotkey)
        except NotImplementedError:
            log.info("register the hotkey with btcli: btcli subnet register --netuid %s", self.cfg.netuid)

    async def bootstrap(self, timeout_s: float = 900) -> RegistrationRecord:
        """Boot a verify VM via the platform, wait for the identity draft produced by that request, commit, register."""
        if not self.host_pubkey:
            raise RuntimeError("host public key unknown: set RACKSDOCK_HOST_SEED or pass --host-pubkey")
        deadline = asyncio.get_running_loop().time() + timeout_s
        # the host-agent may still be connecting; retry while the platform reports it unknown
        while True:
            r = await self.c.post(f"/v1/miners/bootstrap/{self.host_pubkey}")
            if r.status_code < 400:
                break
            if r.status_code == 404 and asyncio.get_running_loop().time() < deadline:
                log.info("host not connected yet; retrying bootstrap")
                await asyncio.sleep(self.cfg.poll_s)
                continue
            raise RuntimeError(f"bootstrap request failed: {r.status_code} {r.text[:200]}")
        command_id = r.json().get("command_id")
        draft = None
        while asyncio.get_running_loop().time() < deadline:
            drafts = (await self.c.get(f"/v1/miners/identity-drafts/{self.host_pubkey}")).json()["drafts"]
            mine = [d for d in drafts if d.get("command_id") == command_id] if command_id else drafts
            if mine:
                draft = mine[0]
                break
            await asyncio.sleep(self.cfg.poll_s)
        if draft is None:
            raise TimeoutError("no identity draft from host-agent (is racksdock-host-agent running on the node and connected to this platform?)")
        if draft.get("verified") is False:
            raise RuntimeError("the platform rejected this node's identity evidence: " + "; ".join(draft.get("errors", []))
                               + ". The node's simulated identity was not issued by this platform's dev CA: on the node, re-run setup-box.sh with PLATFORM_URL pointing here, then bootstrap again.")
        return await self.register_draft(draft)

    async def register_draft(self, draft: dict) -> RegistrationRecord:
        env = SignedEnvelope.model_validate(draft["registration_envelope"])
        if not env.verify(expected_signer=self.host_pubkey):
            raise RuntimeError("identity draft not signed by our host")
        rec = RegistrationRecord.model_validate(env.payload)
        if rec.miner_hotkey != self.cfg.hotkey:
            raise RuntimeError(f"draft hotkey {rec.miner_hotkey} != configured {self.cfg.hotkey} (fix RACKSDOCK_MINER_HOTKEY on the host)")
        self.ensure_hotkey_registered()
        block = self.chain.commit(self.cfg.hotkey, hash_obj(rec.model_dump(by_alias=True)))
        log.info("committed registration hash at block %s", block)
        r = await self.c.post("/v1/miners/register", json={"envelope": env.model_dump()})
        if r.status_code >= 400:
            raise RuntimeError(f"platform registration failed: {r.status_code} {r.text[:300]}")
        (self.cfg.state_dir / "node_id").write_text(rec.node_id + "\n")
        (self.cfg.state_dir / "registration.json").write_text(env.model_dump_json(indent=1))
        log.info("registered node %s", rec.node_id)
        return rec

    async def announce_maintenance(self, starts_at: str, ends_at: str) -> None:
        if not self.host_key or not self.node_id:
            raise RuntimeError("need host key and node_id")
        env = SignedEnvelope.create("maintenance", {"node_id": self.node_id, "starts_at": starts_at, "ends_at": ends_at}, self.host_key)
        r = await self.c.post("/v1/miners/maintenance", json={"node_id": self.node_id, "starts_at": starts_at, "ends_at": ends_at, "envelope": env.model_dump()})
        if r.status_code >= 400:
            raise RuntimeError(r.text[:300])

    async def run(self) -> None:
        """Register if needed; afterwards re-register when the host publishes a new identity draft (repair)."""
        if self.node_id is None:
            await self.bootstrap()
        seen = {hash_obj(d) for d in (await self.c.get(f"/v1/miners/identity-drafts/{self.host_pubkey}")).json()["drafts"]}
        while True:
            await asyncio.sleep(60)
            try:
                drafts = (await self.c.get(f"/v1/miners/identity-drafts/{self.host_pubkey}")).json()["drafts"]
                for d in drafts:
                    h = hash_obj(d)
                    if h not in seen:
                        seen.add(h)
                        rec = RegistrationRecord.model_validate(d["registration"])
                        if rec.node_id != self.node_id:
                            log.info("new identity draft (gpu set changed); re-registering")
                            await self.register_draft(d)
            except Exception as e:
                log.warning("miner loop: %s", e)
