"""Chain access abstraction shared by validator, miner and marketplace.

MockChain: JSON-file backed, safe for several local processes (file lock), used by the simulator and tests.
SubtensorChain: thin wrapper over the bittensor SDK (imported lazily; optional dependency).
"""
from __future__ import annotations

import fcntl
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class Commitment:
    hotkey: str
    block: int
    data: str  # hex / string committed on-chain (we commit 'sha256:<hex>' of the registration record)


@dataclass
class Neuron:
    uid: int
    hotkey: str
    stake: float
    is_validator: bool


class ChainClient(Protocol):
    netuid: int

    def current_block(self) -> int: ...

    def commit(self, hotkey: str, data: str) -> int: ...

    def commitments(self) -> list[Commitment]: ...

    def neurons(self) -> list[Neuron]: ...

    def set_weights(self, validator_hotkey: str, weights: dict[int, float]) -> bool: ...

    def register(self, hotkey: str, is_validator: bool = False, stake: float = 0.0) -> int: ...

    def weights_of(self, validator_hotkey: str) -> dict[int, float]: ...


class MockChain:
    """Deterministic in-file chain. Blocks advance with wall-clock time (one block per `block_time_s`)."""

    def __init__(self, path: str | Path, netuid: int = 1, block_time_s: float = 12.0):
        self.path = Path(path)
        self.netuid = netuid
        self.block_time_s = block_time_s
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._write({"genesis": time.time(), "neurons": [], "commitments": [], "weights": {}, "burn_uid": 0})

    def _read(self) -> dict:
        with self.path.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1))
        tmp.replace(self.path)

    def _update(self, fn):
        lock = self.path.with_suffix(".lock")
        with lock.open("w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                data = json.loads(self.path.read_text())
                out = fn(data)
                self._write(data)
                return out
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def current_block(self) -> int:
        d = self._read()
        return int((time.time() - d["genesis"]) / self.block_time_s)

    def advance(self, blocks: int) -> None:
        self._update(lambda d: d.__setitem__("genesis", d["genesis"] - blocks * self.block_time_s))

    def register(self, hotkey: str, is_validator: bool = False, stake: float = 0.0) -> int:
        def fn(d):
            for n in d["neurons"]:
                if n["hotkey"] == hotkey:
                    n["is_validator"] = n["is_validator"] or is_validator
                    n["stake"] = max(n["stake"], stake)
                    return n["uid"]
            uid = len(d["neurons"]) + 1  # uid 0 is the burn uid
            d["neurons"].append({"uid": uid, "hotkey": hotkey, "stake": stake, "is_validator": is_validator})
            return uid

        return self._update(fn)

    def commit(self, hotkey: str, data: str) -> int:
        block = self.current_block()

        def fn(d):
            d["commitments"].append({"hotkey": hotkey, "block": block, "data": data, "seq": len(d["commitments"])})
            return block

        return self._update(fn)

    def commitments(self) -> list[Commitment]:
        d = self._read()
        return [Commitment(c["hotkey"], c["block"], c["data"]) for c in sorted(d["commitments"], key=lambda c: (c["block"], c["seq"]))]

    def neurons(self) -> list[Neuron]:
        return [Neuron(n["uid"], n["hotkey"], n["stake"], n["is_validator"]) for n in self._read()["neurons"]]

    def uid_of(self, hotkey: str) -> int | None:
        for n in self.neurons():
            if n.hotkey == hotkey:
                return n.uid
        return None

    def set_weights(self, validator_hotkey: str, weights: dict[int, float]) -> bool:
        def fn(d):
            d["weights"][validator_hotkey] = {str(k): v for k, v in weights.items()}
            d["weights_block_" + validator_hotkey] = self.current_block()
            return True

        return self._update(fn)

    def weights_of(self, validator_hotkey: str) -> dict[int, float]:
        return {int(k): v for k, v in self._read()["weights"].get(validator_hotkey, {}).items()}


class SubtensorChain:
    """bittensor SDK wrapper. Requires `pip install bittensor`. Methods map 1:1 to MockChain."""

    def __init__(self, network: str, netuid: int, wallet=None):
        import bittensor as bt  # type: ignore

        self._bt = bt
        self.subtensor = bt.subtensor(network=network)
        self.netuid = netuid
        self.wallet = wallet

    def current_block(self) -> int:
        return int(self.subtensor.get_current_block())

    def commit(self, hotkey: str, data: str) -> int:
        self.subtensor.commit(self.wallet, self.netuid, data)
        return self.current_block()

    def commitments(self) -> list[Commitment]:
        out = []
        meta = self.subtensor.metagraph(self.netuid)
        for hk in meta.hotkeys:
            try:
                data = self.subtensor.get_commitment(self.netuid, meta.hotkeys.index(hk))
            except Exception:
                continue
            if data:
                out.append(Commitment(hk, 0, data))  # block of commitment: query storage if needed
        return out

    def neurons(self) -> list[Neuron]:
        meta = self.subtensor.metagraph(self.netuid)
        return [Neuron(int(u), hk, float(meta.S[i]), bool(meta.validator_permit[i])) for i, (u, hk) in enumerate(zip(meta.uids, meta.hotkeys))]

    def set_weights(self, validator_hotkey: str, weights: dict[int, float]) -> bool:
        uids = list(weights.keys())
        vals = [weights[u] for u in uids]
        ok, _ = self.subtensor.set_weights(wallet=self.wallet, netuid=self.netuid, uids=uids, weights=vals, wait_for_inclusion=True)
        return bool(ok)

    def register(self, hotkey: str, is_validator: bool = False, stake: float = 0.0) -> int:
        raise NotImplementedError("register with btcli")

    def weights_of(self, validator_hotkey: str) -> dict[int, float]:
        raise NotImplementedError


def build_chain(kind: str, **kw) -> ChainClient:
    if kind == "mock":
        return MockChain(kw["path"], netuid=kw.get("netuid", 1), block_time_s=kw.get("block_time_s", 12.0))
    return SubtensorChain(kw["network"], kw["netuid"], kw.get("wallet"))
