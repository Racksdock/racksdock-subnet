"""Light validator (docs/04 §6): no SSH, no verify sessions. Every tempo it fetches the platform-signed scoring snapshot (what
the verifying validators observed per node), checks the signature against the pinned platform key, runs the same deterministic
scorer and sets weights with its own hotkey. It attests to the platform's verification, not to the nodes themselves."""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import time

import httpx

from racksdock_subnet.core.chainclient import build_chain
from racksdock_subnet.core.envelope import SignedEnvelope

from .config import ValidatorConfig
from .scorer import NodeInputs, Params, TempoResult, score_tempo
from .weights import set_weights

log = logging.getLogger("racksdock.validator.light")
SNAPSHOT_KIND = "scoring_snapshot"


def inputs_from_snapshot(payload: dict) -> list[NodeInputs]:
    fields = NodeInputs.__dataclass_fields__
    return [NodeInputs(**{k: v for k, v in d.items() if k in fields}) for d in payload.get("inputs", [])]


def score_snapshot(payload: dict, now: dt.datetime | None = None) -> TempoResult:
    """The deterministic part: the same scorer the verifying validator runs, over the snapshot's inputs and parameters."""
    now = now or dt.datetime.fromisoformat(payload["window_end"])
    inputs = inputs_from_snapshot(payload)
    prev = set(payload.get("previously_funded") or [])
    for i in inputs:
        i.previously_funded = i.node_id in prev
    return score_tempo(inputs, now, float(payload["tempo_s"]) / 60, Params(funded_slots=int(payload.get("funded_slots", 64))),
                       utilization_7d=float(payload.get("utilization_7d", 0.0)))


class LightValidator:
    def __init__(self, cfg: ValidatorConfig):
        self.cfg = cfg
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.c = httpx.AsyncClient(base_url=cfg.platform_url.rstrip("/"), timeout=60)
        self.chain = build_chain(cfg.chain_kind, path=cfg.chain_file, netuid=cfg.netuid, network=cfg.chain_network, wallet_name=cfg.wallet_name, wallet_hotkey=cfg.wallet_hotkey, wallet_path=cfg.wallet_path)
        self.pin = cfg.state_dir / "platform.pub"
        self._stop = asyncio.Event()

    async def platform_key(self) -> str:
        """Pinned on first contact (or set RACKSDOCK_PLATFORM_PUBKEY); a changed key is refused until the operator replaces the pin."""
        if self.cfg.platform_pubkey:
            return self.cfg.platform_pubkey
        r = await self.c.get("/v1/platform/key")
        r.raise_for_status()
        pub = r.json()["platform_key"]
        if self.pin.exists():
            pinned = self.pin.read_text().strip()
            if pinned != pub:
                raise RuntimeError(f"platform key changed ({pub[:12]} != pinned {pinned[:12]}); replace {self.pin} to accept it")
        else:
            self.pin.write_text(pub + "\n")
        return pub

    async def fetch_snapshot(self) -> dict:
        pub = await self.platform_key()
        r = await self.c.get("/v1/scoring/snapshot", params={"tempo_s": self.cfg.tempo_s})
        r.raise_for_status()
        env = SignedEnvelope.model_validate(r.json()["envelope"])
        if env.kind != SNAPSHOT_KIND or not env.verify(expected_signer=pub):
            raise RuntimeError("scoring snapshot signature invalid")
        return env.payload

    async def score_once(self) -> TempoResult:
        payload = await self.fetch_snapshot()
        result = score_snapshot(payload)
        weights = set_weights(self.chain, self.cfg.hotkey, result)
        (self.cfg.state_dir / "last_scoring.json").write_text(json.dumps({"window_end": payload["window_end"], "scores": result.scores, "funded": result.funded,
                                                                            "hotkey_weights": result.hotkey_weights, "burn": result.burn, "weights": {str(k): v for k, v in weights.items()}}, indent=1))
        log.info("light scoring: %d node(s), funded %s, burn %.4f, weights %s", len(result.scores), [n[:16] for n in result.funded], result.burn, weights)
        return result

    async def run(self) -> None:
        log.info("light validator started: hotkey=%s platform=%s tempo=%ss", self.cfg.hotkey, self.cfg.platform_url, int(self.cfg.tempo_s))
        while not self._stop.is_set():
            t0 = time.time()
            try:
                await self.score_once()
            except Exception as e:
                log.warning("light scoring failed: %s", str(e)[:300])
            delay = max(5.0, self.cfg.tempo_s - (time.time() - t0))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                pass
        await self.c.aclose()

    def stop(self) -> None:
        self._stop.set()
