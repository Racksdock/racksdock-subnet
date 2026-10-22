"""SubtensorChain against a fake bittensor SDK 11: commitment encoding, metagraph mapping, weight submission."""
import sys
import types

import pytest


class _Stake:
    def __init__(self, tao):
        self.tao = tao


class _Neuron:
    def __init__(self, uid, hotkey, stake, permit):
        self.uid, self.hotkey, self.total_stake, self.validator_permit = uid, hotkey, _Stake(stake), permit


class _Metagraph:
    def __init__(self):
        self.neurons = [_Neuron(0, "5Fowner", 7301.5, True), _Neuron(1, "5Fval", 0.0, False), _Neuron(2, "5Fm1", 0.0, False)]


class _Commitment:
    def __init__(self, block):
        self.block = block


class _FakeSubtensor:
    def __init__(self, network):
        self.network = network
        self.block = 8273910
        self.submitted = []
        self.tool_calls = []
        self.rows = []
        outer = self
        self.subnets = types.SimpleNamespace(metagraph=lambda netuid: _Metagraph())
        self.identity = types.SimpleNamespace(commitments=lambda netuid: outer.rows, commitment=lambda netuid, hk: _Commitment(8273911))

    def submit_call(self, call, wallet, **kw):
        self.submitted.append((call, wallet, kw))
        self.rows.append({"hotkey": wallet.hotkey.ss58_address, "uid": 2, "commitment": "sha256:" + "a" * 64, "block": 8273911})
        return types.SimpleNamespace(ok=True)

    def execute_tool(self, op, args, wallet, **kw):
        self.tool_calls.append((op, args, wallet))
        return types.SimpleNamespace(ok=True)


class _Call:
    def __init__(self, module, function, params):
        self.module, self.function, self.params = module, function, params


@pytest.fixture
def fake_sdk(monkeypatch):
    bt = types.ModuleType("bittensor")
    bt.Subtensor = _FakeSubtensor
    bt.Wallet = lambda name="default", hotkey="default", path=None: types.SimpleNamespace(name=name, hotkey=types.SimpleNamespace(ss58_address="5Fm1"), path=path)
    calls = types.ModuleType("bittensor.calls")
    calls.Commitments = types.SimpleNamespace(set_commitment=lambda netuid, info: _Call("Commitments", "set_commitment", {"netuid": netuid, "info": info}))
    bt.calls = calls
    monkeypatch.setitem(sys.modules, "bittensor", bt)
    monkeypatch.setitem(sys.modules, "bittensor.calls", calls)
    return bt


def test_subtensor_chain_commit_neurons_and_weights(fake_sdk):
    from racksdock_subnet.core.chainclient import SubtensorChain, build_chain

    ch = build_chain("subtensor", network="test", netuid=596, wallet_name="test_miner1", wallet_hotkey="miner1_hotkey")
    assert isinstance(ch, SubtensorChain) and ch.wallet.name == "test_miner1" and ch.current_block() == 8273910
    data = "sha256:" + "a" * 64
    assert SubtensorChain.commitment_info(data) == {"fields": [{"Raw71": "0x" + data.encode().hex()}]}
    block = ch.commit("5Fm1", data)
    call, wallet, kw = ch.subtensor.submitted[0]
    assert call.module == "Commitments" and call.function == "set_commitment" and call.params["netuid"] == 596 and kw == {"signer": "hotkey"} and block == 8273911
    cs = ch.commitments()
    assert len(cs) == 1 and cs[0].hotkey == "5Fm1" and cs[0].data == data and cs[0].block == 8273911
    ns = ch.neurons()
    assert [(n.uid, n.hotkey, n.stake, n.is_validator) for n in ns] == [(0, "5Fowner", 7301.5, True), (1, "5Fval", 0.0, False), (2, "5Fm1", 0.0, False)]
    assert ch.set_weights("5Fowner", {2: 0.25, 3: 0.25, 0: 0.5}) is True
    op, args, _ = ch.subtensor.tool_calls[0]
    assert op == "set_weights" and args["netuid"] == 596 and args["weights"] == {2: 0.25, 3: 0.25, 0: 0.5}
    with pytest.raises(ValueError):
        SubtensorChain.commitment_info("x" * 129)
    ro = build_chain("subtensor", network="test", netuid=596)
    with pytest.raises(RuntimeError, match="signs a transaction"):
        ro.commit("5Fm1", data)
