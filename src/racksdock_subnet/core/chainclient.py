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
    """bittensor SDK (>= 11) wrapper; methods map 1:1 to MockChain. Reads go through the SDK's namespaced reads, registrations
    through a raw `Commitments.set_commitment` call (hotkey-signed, "sha256:..." as one Raw field) and weights through the
    `set_weights` tool, which conforms them to the subnet's hyperparameters and uses commit-reveal when the subnet runs it.
    The wallet is optional for read-only use (the platform); miners and validators give wallet name/hotkey/path."""

    def __init__(self, network: str, netuid: int, wallet=None, wallet_name: str | None = None, wallet_hotkey: str | None = None, wallet_path: str | None = None):
        try:
            import bittensor as bt  # type: ignore
        except ImportError as e:
            raise RuntimeError("RACKSDOCK_CHAIN=subtensor needs the bittensor SDK: pip install 'racksdock-subnet[chain]' in this environment. "
                               "Miners: run `racksdock-miner bootstrap` on the machine that holds your wallet (not on the GPU server); "
                               "the host-agent itself never needs the SDK or a wallet.") from e

        self._bt = bt
        self.subtensor = bt.Subtensor(network=network)
        self.netuid = netuid
        if wallet is None and wallet_name:
            kw = {"name": wallet_name, "hotkey": wallet_hotkey or "default"}
            if wallet_path:
                kw["path"] = wallet_path
            wallet = bt.Wallet(**kw)
        self.wallet = wallet

    def _need_wallet(self):
        if self.wallet is None:
            raise RuntimeError("this operation signs a transaction: set RACKSDOCK_WALLET_NAME / RACKSDOCK_WALLET_HOTKEY")
        return self.wallet

    def current_block(self) -> int:
        return int(self.subtensor.block)

    @staticmethod
    def commitment_info(data: str) -> dict:
        raw = data.encode()
        if len(raw) > 128:
            raise ValueError("commitment data must be at most 128 bytes")
        return {"fields": [{f"Raw{len(raw)}": "0x" + raw.hex()}]}

    def commit(self, hotkey: str, data: str) -> int:
        from bittensor import calls  # type: ignore

        wallet = self._need_wallet()
        call = calls.Commitments.set_commitment(self.netuid, self.commitment_info(data))
        self.subtensor.submit_call(call, wallet, signer="hotkey")
        c = self.subtensor.identity.commitment(self.netuid, wallet.hotkey.ss58_address)
        return int(getattr(c, "block", 0) or 0) or self.current_block()

    def commitments(self) -> list[Commitment]:
        out = []
        for row in self.subtensor.identity.commitments(self.netuid) or []:
            data = row.get("commitment") if isinstance(row, dict) else getattr(row, "commitment", None)
            if not data:
                continue
            hk = row.get("hotkey") if isinstance(row, dict) else getattr(row, "hotkey", "")
            block = row.get("block") if isinstance(row, dict) else getattr(row, "block", 0)
            out.append(Commitment(hk, int(block or 0), str(data)))
        return out

    @staticmethod
    def _stake_float(v) -> float:
        """Stake as a plain number in the subnet's own unit (alpha on dynamic subnets); Balance objects refuse cross-unit reads."""
        for attr in ("rao", "alpha", "tao"):
            try:
                x = getattr(v, attr)
            except Exception:
                continue
            return float(x) / 1e9 if attr == "rao" else float(x)
        try:
            return float(v)
        except (TypeError, ValueError):
            return float(str(v).replace(",", "").rstrip("Ττ ") or 0.0)

    def neurons(self) -> list[Neuron]:
        mg = self.subtensor.subnets.metagraph(self.netuid)
        return [Neuron(int(n.uid), n.hotkey, self._stake_float(getattr(n, "total_stake", 0.0)), bool(getattr(n, "validator_permit", False))) for n in mg.neurons]

    def set_weights(self, validator_hotkey: str, weights: dict[int, float]) -> bool:
        wallet = self._need_wallet()
        total = sum(weights.values()) or 1.0
        mapping = {int(u): float(w) / total for u, w in weights.items() if w > 0}
        res = self.subtensor.execute_tool("set_weights", {"netuid": self.netuid, "weights": mapping}, wallet)
        ok = getattr(res, "ok", None)
        return bool(ok if ok is not None else res)

    def register(self, hotkey: str, is_validator: bool = False, stake: float = 0.0) -> int:
        raise NotImplementedError("register with btcli (burned_register)")

    def weights_of(self, validator_hotkey: str) -> dict[int, float]:
        raise NotImplementedError


def build_chain(kind: str, **kw) -> ChainClient:
    if kind == "mock":
        return MockChain(kw["path"], netuid=kw.get("netuid", 1), block_time_s=kw.get("block_time_s", 12.0))
    return SubtensorChain(kw["network"], kw["netuid"], kw.get("wallet"), wallet_name=kw.get("wallet_name"), wallet_hotkey=kw.get("wallet_hotkey"), wallet_path=kw.get("wallet_path"))
