"""The validator (docs/04 §6): no SSH, no verify sessions. Every tempo it fetches the platform-signed scoring snapshot (what
the verifier observed per node), checks the signature against the pinned platform key, runs the deterministic scorer and sets
weights with its own hotkey. It attests to the platform's verification, not to the nodes themselves."""
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

log = logging.getLogger("racksdock.validator")
SNAPSHOT_KIND = "scoring_snapshot"


def inputs_from_snapshot(payload: dict) -> list[NodeInputs]:
    fields = NodeInputs.__dataclass_fields__
    return [NodeInputs(**{k: v for k, v in d.items() if k in fields}) for d in payload.get("inputs", [])]


def score_snapshot(payload: dict, now: dt.datetime | None = None) -> TempoResult:
    """The deterministic part: the public scorer over the snapshot's inputs and parameters."""
    now = now or dt.datetime.fromisoformat(payload["window_end"])
    inputs = inputs_from_snapshot(payload)
    return score_tempo(inputs, now, float(payload["tempo_s"]) / 60, Params(), utilization_7d=float(payload.get("utilization_7d", 0.0)))


def rebuild_inputs(fetch_json, payload: dict) -> list[NodeInputs]:
    """Rebuild a snapshot's inputs from the PUBLIC endpoints alone (docs/04 §6): nodes, each node's verification page, the lease
    ledger and the evidence in the shared per-kind window, then the same build_inputs the platform used. fetch_json(path, params)
    returns parsed JSON. Equal to the snapshot's inputs when the platform told the truth."""
    import datetime as dt

    from .snapshot import build_inputs, evidence_window

    window_start = dt.datetime.fromisoformat(payload["window_start"])
    window_end = dt.datetime.fromisoformat(payload["window_end"])
    nodes, verification = [], {}
    for row in fetch_json("/v1/nodes", {"include_offline": "true"})["nodes"]:
        v = fetch_json(f"/v1/nodes/{row['node_id']}/verification", {})
        verification[row["node_id"]] = v
        nodes.append({"node_id": row["node_id"], "miner_hotkey": v.get("miner_hotkey"), "status": v.get("status"), "qualified_at": v.get("qualified_at"),
                      "qualification": v.get("qualification"), "perf": v.get("perf"), "critical_fault": v.get("critical_fault"), "maintenance_until": v.get("maintenance_until"),
                      "registered_block": v.get("registered_block"), "registration": {"deployment": v.get("deployment")}, "host_connected": v.get("host_connected"),
                      "offline_since": v.get("offline_since"), "outages": v.get("outages") or []})
    leases = fetch_json("/v1/leases", {"since": window_start.isoformat()})["leases"]
    evidence = []
    for kind, since in evidence_window(window_start).items():
        evidence += fetch_json("/v1/evidence", {"kind": kind, "since": since, "limit": 1000, "desc": "true"})["records"]
    evidence.sort(key=lambda e: e["id"])
    return build_inputs(nodes, leases, evidence, verification, window_start, window_end, "")


def compare_inputs(snapshot_inputs: list[NodeInputs], rebuilt: list[NodeInputs]) -> list[str]:
    """Field-level differences between two input sets, empty when they agree."""
    from dataclasses import asdict

    a = {i.node_id: asdict(i) for i in snapshot_inputs}
    b = {i.node_id: asdict(i) for i in rebuilt}
    diffs = [f"{n}: only in {'snapshot' if n in a else 'public rebuild'}" for n in sorted(set(a) ^ set(b))]
    for n in sorted(set(a) & set(b)):
        for k in a[n]:
            va, vb = a[n][k], b[n].get(k)
            same = abs(va - vb) < 1e-6 if isinstance(va, float) and isinstance(vb, float) else va == vb
            if not same:
                diffs.append(f"{n[:16]} {k}: snapshot={va!r} public={vb!r}")
    return diffs


class Validator:
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

    async def audit(self) -> list[str]:
        """Fetch the snapshot, rebuild its inputs from the public endpoints and report every difference (empty = the platform's
        snapshot is exactly what its public records say)."""
        payload = await self.fetch_snapshot()

        async def fetch_async(path, params):
            r = await self.c.get(path, params=params)
            r.raise_for_status()
            return r.json()

        # rebuild_inputs is synchronous; run the fetches through a small cache filled up front
        cache: dict[tuple, dict] = {}
        nodes = await fetch_async("/v1/nodes", {"include_offline": "true"})
        cache[("/v1/nodes", (("include_offline", "true"),))] = nodes
        for row in nodes["nodes"]:
            cache[(f"/v1/nodes/{row['node_id']}/verification", ())] = await fetch_async(f"/v1/nodes/{row['node_id']}/verification", {})
        from .snapshot import evidence_window

        ws = payload["window_start"]
        cache[("/v1/leases", (("since", ws),))] = await fetch_async("/v1/leases", {"since": ws})
        import datetime as dt

        for kind, since in evidence_window(dt.datetime.fromisoformat(ws)).items():
            params = {"kind": kind, "since": since, "limit": 1000, "desc": "true"}
            cache[("/v1/evidence", tuple(sorted((k, str(v)) for k, v in params.items())))] = await fetch_async("/v1/evidence", params)

        def fetch_json(path, params):
            key = (path, tuple(sorted((k, str(v)) for k, v in params.items())))
            return cache[key]

        diffs = compare_inputs(inputs_from_snapshot(payload), rebuild_inputs(fetch_json, payload))
        result = score_snapshot(payload)
        rounds = (await fetch_async("/v1/scoring/rounds", {"limit": 5}))["rounds"]
        mine = next((r for r in rounds if r["window_end"] == payload["window_end"]), None)
        if mine is not None and (mine["scored"] != result.scored or {k: round(v, 8) for k, v in mine["hotkey_weights"].items()} != {k: round(v, 8) for k, v in result.hotkey_weights.items()}):
            diffs.append(f"platform round for {payload['window_end']}: scored={mine['scored']} weights={mine['hotkey_weights']} vs ours scored={result.scored} weights={result.hotkey_weights}")
        return diffs

    async def score_once(self) -> TempoResult:
        payload = await self.fetch_snapshot()
        result = score_snapshot(payload)
        weights = set_weights(self.chain, self.cfg.hotkey, result)
        (self.cfg.state_dir / "last_scoring.json").write_text(json.dumps({"window_end": payload["window_end"], "scores": result.scores, "scored": result.scored,
                                                                            "hotkey_weights": result.hotkey_weights, "burn": result.burn, "weights": {str(k): v for k, v in weights.items()}}, indent=1))
        log.info("scoring: %d node(s), scored %s, burn %.4f, weights %s", len(result.scores), [n[:16] for n in result.scored], result.burn, weights)
        return result

    async def run(self) -> None:
        log.info("validator started: hotkey=%s platform=%s tempo=%ss", self.cfg.hotkey, self.cfg.platform_url, int(self.cfg.tempo_s))
        while not self._stop.is_set():
            t0 = time.time()
            try:
                await self.score_once()
            except Exception as e:
                log.warning("scoring failed: %s", str(e)[:300])
            delay = max(5.0, self.cfg.tempo_s - (time.time() - t0))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                pass
        await self.c.aclose()

    def stop(self) -> None:
        self._stop.set()
