"""The validator loop backs a node off after a failed admission instead of retrying it every iteration."""
import asyncio
import types

from racksdock_subnet.validator import neuron as neuron_mod
from racksdock_subnet.validator.neuron import Verifier

NODE = {"node_id": "sha256:" + "ab" * 32, "status": "registered", "host_connected": True}


class FakePlatform:
    def __init__(self, nodes):
        self._nodes = nodes

    async def nodes(self):
        return self._nodes

    async def leases(self, live_only=True):
        return []


def make(nodes, retry_s=600.0) -> Verifier:
    v = Verifier.__new__(Verifier)
    v.cfg = types.SimpleNamespace(retry_quarantined_s=retry_s, qualification_full=True, role="verifier", tempo_s=10**9,
                                  reachability_interval_s=60, inrental_interval_s=60, microbench_interval_s=60)
    v.platform, v.sessions, v.canaries = FakePlatform(nodes), None, None
    v.busy, v.last_requal, v.last_inrental, v.last_microbench, v.last_probe = set(), {}, {}, {}, {}
    v.tempo_start = 10**12
    v._save_state = lambda: None
    v.spawned = []

    def _spawn(nid, coro):
        v.spawned.append(nid)
        coro.close()

    v._spawn = _spawn
    return v


def test_a_registered_node_is_admitted_once_per_retry_interval():
    v = make([dict(NODE)])
    asyncio.run(v.step(now=1000.0))
    assert v.spawned == [NODE["node_id"]]
    v.last_requal[NODE["node_id"]] = 1000.0  # what a failed admission or a crashed task records
    asyncio.run(v.step(now=1100.0))
    assert len(v.spawned) == 1  # seen before: one error instance every 4 s while the verify image was missing
    asyncio.run(v.step(now=1601.0))
    assert len(v.spawned) == 2


def test_a_failed_admission_records_the_backoff(monkeypatch):
    v = make([dict(NODE)])

    async def failing(cfg, platform, sessions, node):
        return types.SimpleNamespace(outcome="quarantined", failing_checks=["B0"])

    monkeypatch.setattr(neuron_mod, "admission_test", failing)
    asyncio.run(v._admit_and_qualify(dict(NODE)))
    assert NODE["node_id"] in v.last_requal
