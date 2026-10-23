"""In-rental check robustness and the Q7 host-device outlier check (regressions from the 8x4090 rental)."""
import asyncio

import pytest

from racksdock_subnet.core.keys import SigningKey
from racksdock_subnet.validator import inrental
from racksdock_subnet.validator.suite import parsers as P
from racksdock_subnet.validator.suite.checks import q7_h2d
from racksdock_subnet.validator.suite.runner import CmdResult


def test_throttle_mask_ignores_the_normal_power_cap():
    """0x4 = SW power cap: every GPU reports it under a full-power workload. Only slowdowns (HW, thermal, power brake) count."""
    assert inrental.THROTTLE_MASK & 0x4 == 0
    for bit in (0x8, 0x20, 0x40, 0x80):
        assert inrental.THROTTLE_MASK & bit


class FakePlatform:
    def __init__(self, response):
        self.key = SigningKey.generate()
        self.response = response
        self.published = []
        self.incidents = []

    async def challenge(self, node_id, payload):
        return self.response

    async def publish(self, kind, payload):
        self.published.append((kind, payload))

    async def incident(self, iid, klass, details, strike):
        self.incidents.append((klass, strike))


def test_check_instance_records_a_failed_check_when_the_host_cannot_reach_the_agent():
    """A frozen VM made the platform answer {"error": "node-agent unreachable"}; the check must record reachable/attestation
    failure instead of dying with a validation error (which left a 12-minute freeze invisible in the evidence)."""
    pf = FakePlatform({"error": "node-agent unreachable"})
    lease = {"instance_id": "inst_x", "node_id": "sha256:n", "ip": None, "ssh_port": 22}
    res = asyncio.run(inrental.check_instance(None, pf, None, lease, {"registration": {"gpu_ids": []}}, False, 0.0))
    assert res.attestation_ok is False and "node-agent unreachable" in (res.error or "")
    assert pf.published and pf.published[0][0] == "inrental"


class H2DRunner:
    def __init__(self, per_gpu, links):
        self.per_gpu, self.links = per_gpu, links

    async def run(self, cmd, timeout=None):
        if "nvbandwidth" in cmd:
            n = len(self.per_gpu)
            hdr = "memcpy CE CPU(row) -> GPU(column) bandwidth (GB/s)\n        " + "".join(f"{j:>10}" for j in range(n)) + "\n"
            row = f"{0:>8}" + "".join(f"{v:>10.2f}" for v in self.per_gpu)
            return CmdResult(0, hdr + row + f"\n\nSUM host_to_device_memcpy_ce {sum(self.per_gpu):.2f}\n")
        if "pcie.link" in cmd:
            return CmdResult(0, self.links)
        return CmdResult(127, "", "unknown")


class Ctx:
    def __init__(self, runner):
        self.runner, self.measured = runner, {}


def test_q7_flags_a_gpu_on_a_degraded_link():
    links_ok = "\n".join(f"{i}, 16, 16, 4, 4" for i in range(8))
    good = asyncio.run(q7_h2d(Ctx(H2DRunner([25.0] * 8, links_ok))))
    assert good.passed and good.details["slow_gpus"] == [] and good.details["narrow_link_gpus"] == []
    links_bad = "0, 8, 16, 4, 4\n" + "\n".join(f"{i}, 16, 16, 4, 4" for i in range(1, 8))
    bad = asyncio.run(q7_h2d(Ctx(H2DRunner([13.0] + [25.0] * 7, links_bad))))
    assert not bad.passed and bad.details["slow_gpus"] == [0] and bad.details["narrow_link_gpus"] == [0]
    # simulation / unsupported query: no link rows, no false failure
    sim = asyncio.run(q7_h2d(Ctx(H2DRunner([52.0] * 8, "sim: unknown"))))
    assert sim.passed and sim.details["links"] == []
    assert P.parse_pcie_links("N/A, N/A, N/A, N/A, N/A") == []


def test_q12_targets_a_port_and_retries_a_busy_iperf_server():
    from racksdock_subnet.validator.suite.checks import iperf_target, q12_network

    assert iperf_target("203.0.113.10") == "-c 203.0.113.10" and iperf_target("203.0.113.10:5202") == "-c 203.0.113.10 -p 5202"
    assert iperf_target("iperf.example.net") == "-c iperf.example.net"
    busy = '{"error": "the server is busy running a test. try again later"}'
    good = '{"end": {"sum_sent": {"bits_per_second": 2.0e10}, "sum_received": {"bits_per_second": 1.5e10}, "sum": {"lost_percent": 0.0}}}'

    class Runner:
        def __init__(self):
            self.calls = []

        async def run(self, cmd, timeout=None):
            self.calls.append(cmd)
            return CmdResult(0, busy if len(self.calls) == 1 else good)

    class Ctx:
        def __init__(self, runner):
            self.runner, self.measured, self.extra, self.floor = runner, {}, {}, 0.9

        def ref(self, k):
            return {"network.down_gbps": 1.0, "network.up_gbps": 1.0}[k]

    import asyncio
    from unittest import mock

    rn = Runner()
    with mock.patch("asyncio.sleep", new=mock.AsyncMock()):
        res = asyncio.run(q12_network(Ctx(rn), endpoints=["203.0.113.10:5202"], seconds=1))
    assert res.passed and res.details["endpoints"][0]["down_gbps"] == 15.0 and "error" not in res.details["endpoints"][0]
    assert "-c 203.0.113.10 -p 5202" in rn.calls[0] and len(rn.calls) == 3  # busy once, then up and down


def test_q12_serializes_sessions_on_one_endpoint():
    import asyncio

    from racksdock_subnet.validator.suite.checks import _iperf_lock

    lock = _iperf_lock("203.0.113.10")
    assert lock is _iperf_lock("203.0.113.10") and lock is not _iperf_lock("203.0.113.10:5202")
    assert isinstance(lock, asyncio.Lock)


def test_meminfo_respects_a_container_memory_limit():
    assert P.parse_meminfo("MemTotal:       123731968 kB\n")["total_gb"] == 118.0
    m = P.parse_meminfo("MemTotal:       123731968 kB\nCGROUP_LIMIT=109521666048\n")
    assert round(m["total_gb"]) == 102 and round(m["host_total_gb"]) == 118
    assert P.parse_meminfo("MemTotal:       123731968 kB\nCGROUP_LIMIT=max\n")["total_gb"] == 118.0


def test_targeted_retry_plan_and_merge():
    """A quarantine caused only by environment checks re-runs just those; identity, perf-gate or incomplete runs redo everything."""
    from racksdock_subnet.validator.qualify import merge_measured, plan_targeted_retry

    last = {"kind": "full", "outcome": "quarantined", "failing_checks": ["Q12"], "checks": [{"id": "Q12", "passed": False, "skipped": False}]}
    assert plan_targeted_retry(last) == {"Q12"}
    assert plan_targeted_retry({**last, "failing_checks": ["Q11", "Q12"]}) == {"Q11", "Q12"}
    assert plan_targeted_retry({**last, "failing_checks": ["Q3"]}) is None
    assert plan_targeted_retry({**last, "failing_checks": ["Q12", "perf<0.9:cpu.sysbench"]}) is None
    assert plan_targeted_retry({**last, "checks": [{"id": "Q12", "passed": False, "skipped": True}]}) is None
    assert plan_targeted_retry({**last, "kind": "weekly"}) is None and plan_targeted_retry(None) is None
    base = {"gpu": {"model": "RTX 4090", "count": 8, "vram_gb_usable_min": 21.0}, "cpu": {"vcpus": 120, "stream_gbps": 45.0}, "network": {"down_gbps": 0.0, "up_gbps": 0.0}, "memory_gb": 431.0}
    new = {"gpu": {"model": "RTX 4090", "count": 8, "vram_gb_usable_min": 0.0}, "cpu": {"vcpus": 0, "stream_gbps": 0.0}, "network": {"down_gbps": 16.5, "up_gbps": 32.0}, "memory_gb": 0.0}
    m = merge_measured(base, new)
    assert m["network"] == {"down_gbps": 16.5, "up_gbps": 32.0} and m["cpu"]["stream_gbps"] == 45.0 and m["gpu"]["vram_gb_usable_min"] == 21.0 and m["memory_gb"] == 431.0


def test_run_suite_only_runs_the_requested_checks():
    import asyncio

    from racksdock_subnet.core.profile import load
    from racksdock_subnet.validator.suite.checks import Ctx as SuiteCtx
    from racksdock_subnet.validator.suite.checks import run_suite
    from racksdock_subnet.validator.suite.runner import SimRunner

    prof = load("rtx4090x8-dev")
    ctx = SuiteCtx(runner=SimRunner(), reference=prof.reference_set, dev_mode=True, claimed_vcpus=8, profile=prof)
    ctx.extra["iperf_endpoints"] = ["127.0.0.1"]
    res = asyncio.run(run_suite(ctx, kind="full", only={"Q12", "Q9"}))
    assert sorted(c.id for c in res) == ["Q12", "Q9"]


def test_sessions_verifier_matches_the_node_gpu_count(tmp_path):
    """In-rental checks (like admission and qualification) must verify evidence with the node's own GPU count, not the
    validator's default profile: a 1-GPU container node on an 8-GPU platform failed every check with 'expected 8 devices, got 1'."""
    from racksdock_subnet.validator.config import ValidatorConfig
    from racksdock_subnet.validator.qualify import Sessions
    from racksdock_subnet.verifier.config import TrustConfig
    from racksdock_subnet.verifier.devca import DevCA
    from racksdock_subnet.verifier.verifiers import build_verifier

    ca = tmp_path / "devca"
    DevCA.create(ca)
    cfg = ValidatorConfig.from_env()
    cfg.state_dir = tmp_path
    cfg.trust = TrustConfig(mode="dev", dev_ca_dir=ca)
    default = build_verifier(cfg.trust, expected_devices=8)
    sess = Sessions(cfg, None, default, "ssh-ed25519 AAAA test", str(tmp_path / "key"))
    v8 = sess.verifier_for({"node_id": "n8", "registration": {"profile": "b300x8"}})
    v1 = sess.verifier_for({"node_id": "n1", "registration": {"profile": "a100-dev"}})
    assert v8.expected == 8 and v1.expected == 1 and v1 is not v8


def test_validators_score_a_snapshot_deterministically(tmp_path):
    """Two validators with the same snapshot set identical weights; the mock chain maps hotkeys to uids and burns the rest."""
    from racksdock_subnet.core.chainclient import build_chain
    from racksdock_subnet.validator.validator import score_snapshot
    from racksdock_subnet.validator.weights import set_weights

    now = "2026-10-22T02:00:00+00:00"
    inp = {"node_id": "sha256:n1", "hotkey": "5Fm1", "qualified_at": "2026-10-22T01:00:00Z", "qualification_outcome": "pass", "perf": 1.0, "last_attestation_ok": True,
           "critical_fault": False, "duplicate_dispute": False, "minutes_rented": 5.0, "minutes_available": 0.0, "minutes_failed": 0.0, "minutes_maintenance": 0.0,
           "strikes": 0.0, "canary_pass_rate_30d": 1.0, "registered_block": 10, "deployment": "vm"}
    inp2 = {**inp, "node_id": "sha256:n2", "hotkey": "5Fm2", "deployment": "container", "registered_block": 11}
    payload = {"schema": "racksdock.scoring-snapshot.v1", "window_start": "2026-10-22T01:55:00+00:00", "window_end": now, "tempo_s": 300,
               "utilization_7d": 1.0, "inputs": [inp, inp2]}
    r1, r2 = score_snapshot(payload), score_snapshot(payload)
    assert r1.hotkey_weights == r2.hotkey_weights and r1.scored == r2.scored
    # the container node scores at half (S 0.5 vs 1.0); weights are proportional, no cap, nothing burns while nodes are scored
    assert r1.scores["sha256:n1"] == 1.0 and r1.scores["sha256:n2"] == 0.5
    assert abs(r1.hotkey_weights["5Fm1"] - 2 / 3) < 1e-6 and abs(r1.hotkey_weights["5Fm2"] - 1 / 3) < 1e-6 and r1.burn == 0.0
    chain = build_chain("mock", path=tmp_path / "chain.json", netuid=1, network="x")
    chain.register("5GvalLight", is_validator=True)
    chain.register("5Fm1")
    chain.register("5Fm2")
    w = set_weights(chain, "5GvalLight", r1)
    uid = {n.hotkey: n.uid for n in chain.neurons()}
    assert abs(sum(w.values()) - 1.0) < 1e-6 and abs(w[uid["5Fm1"]] - 2 / 3) < 1e-6 and abs(w[uid["5Fm2"]] - 1 / 3) < 1e-6 and 0 not in w  # nothing to the burn uid


def test_old_failed_in_rental_checks_do_not_gate_a_node_forever():
    """Only the scoring window's in-rental checks decide 'last attestation ok' and rented minutes; stale failures age out."""
    import datetime as dt

    from racksdock_subnet.validator.snapshot import build_inputs

    end = dt.datetime(2026, 10, 22, 0, 0, tzinfo=dt.UTC)
    start = end - dt.timedelta(minutes=5)
    node = {"node_id": "n1", "miner_hotkey": "5Fm", "status": "qualified", "qualified_at": "2026-10-21T20:00:00Z", "qualification": {"outcome": "pass"}, "perf": 1.0,
            "registration": {"deployment": "container"}, "registered_block": 3, "critical_fault": None}
    lease = {"node_id": "n1", "instance_id": "i1", "is_validator": False, "active_at": "2026-10-21T20:00:00Z", "released_at": None}

    def chk(at, ok):
        return {"kind": "inrental", "envelope": {"payload": {"instance_id": "i1", "node_id": "n1", "validator_key": "v", "checked_at": at, "attestation_ok": ok, "gpu_ids_match": True}}}

    old_fail = [chk("2026-10-21T21:00:00Z", False)] * 3
    recent_ok = [chk("2026-10-21T23:57:00Z", True), chk("2026-10-21T23:58:00Z", True)]
    (i,) = build_inputs([node], [lease], old_fail + recent_ok, {"n1": {}}, start, end, "v")
    assert i.last_attestation_ok is True and abs(i.minutes_rented - 5.0) < 1e-6
    (j,) = build_inputs([node], [lease], old_fail, {"n1": {}}, start, end, "v")  # nothing in the window: the latest check decides
    assert j.last_attestation_ok is False and j.minutes_rented == 0.0
    (k,) = build_inputs([node], [lease], [*recent_ok, chk("2026-10-21T23:59:00Z", False)], {"n1": {}}, start, end, "v")
    assert k.last_attestation_ok is False


@pytest.mark.asyncio
async def test_suite_reports_each_step_to_the_progress_hook(monkeypatch):
    """run_suite tells the progress reporter when a check starts and how it ended; planned_checks lists the same ids."""
    from racksdock_subnet.core.schemas import CheckResult
    from racksdock_subnet.validator.suite import checks as ck

    async def q98_fake(ctx):
        return CheckResult(id="Q98", name="fake ok", passed=True, details={"x": 1})

    async def q99_boom(ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(ck, "FULL_ORDER", [q98_fake, q99_boom])

    class Prof:
        def enabled(self, cid):
            return True

    class Prog:
        def __init__(self):
            self.events = []

        async def start(self, cid, name):
            self.events.append(("start", cid, name))

        async def done(self, res):
            self.events.append(("done", res.id, res.passed, res.error))

    class Ctx:
        profile = Prof()

    prog = Prog()
    results = await ck.run_suite(Ctx(), kind="full", progress=prog)
    assert [r.id for r in results] == ["Q98", "Q99"] and results[1].error.startswith("RuntimeError")
    assert prog.events == [("start", "Q98", "q98_fake"), ("done", "Q98", True, None), ("start", "Q99", "q99_boom"), ("done", "Q99", False, "RuntimeError: boom")]
    assert ck.planned_checks(Prof(), "full") == ["Q98", "Q99"] and ck.planned_checks(Prof(), "full", only={"Q99"}) == ["Q99"]


@pytest.mark.asyncio
async def test_progress_reporter_messages():
    from racksdock_subnet.core.keys import SigningKey
    from racksdock_subnet.core.schemas import CheckResult
    from racksdock_subnet.validator.qualify import Progress

    sent = []

    class FakePlatform:
        key = SigningKey.generate()

        async def progress(self, payload):
            sent.append(payload)

    p = Progress(FakePlatform(), "sha256:n", "full")
    await p.plan(["B0", "Q1", "Q12"])
    await p.start("Q12", "Network")
    await p.done(CheckResult(id="Q12", name="Network", passed=False, error="iperf timeout", duration_s=61.0))
    await p.finish("quarantined")
    assert [m.get("plan") and len(m["plan"]) for m in sent][0] == 3 and sent[0]["plan"][0] == {"id": "B0", "name": "Boot the verify instance"}
    assert sent[1]["step_id"] == "Q12" and sent[1]["state"] == "running"
    assert sent[2]["state"] == "fail" and sent[2]["detail"] == "iperf timeout" and sent[2]["duration_s"] == 61.0
    assert sent[3]["outcome"] == "quarantined" and all(m["session_id"] == sent[0]["session_id"] for m in sent)


def test_q4_records_the_dcgm_runtime_error_and_retries_after_starting_the_engine():
    """A diag that could not run (host engine down) comes back as JSON with a runtime_error and no tests: Q4 starts the engine,
    runs once more and, when it still ran nothing, fails with that reason instead of a bare 'missing mandatory' record."""
    from racksdock_subnet.validator.suite.checks import q4_dcgm

    down = '{"DCGM Diagnostic": {"runtime_error": "Error: unable to establish a connection to the specified host: localhost"}}'
    good = ('{"DCGM Diagnostic": {"test_categories": [{"category": "Deployment", "tests": [{"name": "Software", "results": [{"status": "Pass"}]}]},'
            '{"category": "Hardware", "tests": [{"name": "GPU Memory", "results": [{"gpu_ids": "0", "status": "Pass"}]}, {"name": "PCIe", "results": [{"gpu_ids": "0", "status": "Pass"}]}]}]}}')

    class Runner:
        def __init__(self, second):
            self.calls, self.second = [], second

        async def run(self, cmd, timeout=None):
            self.calls.append(cmd)
            if "dcgmi diag" not in cmd:
                return CmdResult(0, "nv-hostengine: started\nactive\n")
            return CmdResult(0, down if len([c for c in self.calls if "dcgmi diag" in c]) == 1 else self.second)

    class Prof:
        extra = {}

    class Ctx:
        def __init__(self, runner):
            self.runner, self.profile, self.measured, self.extra, self.floor = runner, Prof(), {}, {}, 0.9

    rn = Runner(good)
    res = asyncio.run(q4_dcgm(Ctx(rn), level=2))
    assert res.passed and sorted(res.details["ran"]) == ["gpumemory", "pcie", "software"] and len(rn.calls) == 3 and "nv-hostengine" in rn.calls[1]
    rn = Runner(down)
    res = asyncio.run(q4_dcgm(Ctx(rn), level=2))
    assert not res.passed and not res.skipped and "unable to establish a connection" in res.error and "active" in res.details["engine"]


def test_step_name_table_matches_the_checks():
    """The console shows CHECK_NAMES while a step runs and the check's own name when it ends: they must agree."""
    import re
    from pathlib import Path

    from racksdock_subnet.validator.suite import checks as ck

    src = "".join(Path(ck.__file__).parent.parent.joinpath(f).read_text() for f in ("suite/checks.py", "admission.py"))
    actual = dict(re.findall(r'CheckResult\(id="([ABQ]\d+)", name="([^"]*)"', src))
    assert actual and all(ck.CHECK_NAMES[k] == v for k, v in actual.items()), {k: (ck.CHECK_NAMES.get(k), v) for k, v in actual.items() if ck.CHECK_NAMES.get(k) != v}


def test_host_outages_score_as_failed_not_idle_or_rented():
    """Platform-recorded host outages: offline minutes are removed from rented time (the tenant was not served) and from idle
    pay, and count as failed availability; a node dropped and still offline counts up to the window end."""
    import datetime as dt

    from racksdock_subnet.validator.snapshot import build_inputs

    start, end = dt.datetime(2026, 10, 22, 4, 0, tzinfo=dt.UTC), dt.datetime(2026, 10, 22, 5, 0, tzinfo=dt.UTC)
    canary = {"kind": "canary", "envelope": {"payload": {"node_id": "n1", "outcome": "pass", "finished_at": "2026-10-22T04:05:00Z"}}}
    base = {"node_id": "n1", "miner_hotkey": "hk", "status": "qualified", "qualified_at": "2026-10-22T00:00:00Z", "qualification": {"outcome": "pass"}, "perf": 1.0}
    # idle node, offline 04:20 -> 04:50 (30 min): 30 available, 30 failed
    (a,) = build_inputs([{**base, "outages": [{"started_at": "2026-10-22T04:20:00Z", "ended_at": "2026-10-22T04:50:00Z"}]}], [], [canary], {"n1": {}}, start, end, "v")
    assert (a.minutes_available, a.minutes_failed, a.minutes_rented) == (30.0, 30.0, 0.0)
    # still offline (dropped at 04:40, no outage row yet): offline to the window end
    (b,) = build_inputs([{**base, "offline_since": "2026-10-22T04:40:00Z"}], [], [canary], {"n1": {}}, start, end, "v")
    assert (b.minutes_available, b.minutes_failed) == (40.0, 20.0)
    # rented all hour with passing checks, host offline 04:30 -> 04:45: 45 rented, 15 failed, nothing idle
    lease = {"node_id": "n1", "instance_id": "i1", "is_validator": False, "active_at": "2026-10-22T03:00:00Z", "released_at": None}
    chk = {"kind": "inrental", "envelope": {"payload": {"instance_id": "i1", "validator_key": "v", "attestation_ok": True, "gpu_ids_match": True, "checked_at": "2026-10-22T04:10:00Z"}}}
    (c,) = build_inputs([{**base, "outages": [{"started_at": "2026-10-22T04:30:00Z", "ended_at": "2026-10-22T04:45:00Z"}]}], [lease], [chk, canary], {"n1": {}}, start, end, "v")
    assert (c.minutes_rented, c.minutes_failed, c.minutes_available) == (45.0, 15.0, 0.0)
    # no outage data at all: unchanged behaviour
    (d,) = build_inputs([base], [lease], [chk, canary], {"n1": {}}, start, end, "v")
    assert (d.minutes_rented, d.minutes_failed, d.minutes_available) == (60.0, 0.0, 0.0)


def test_no_attested_availability_pays_nothing_and_fresh_qualification_counts():
    """A node with neither rented nor attested-available minutes (host offline all tempo) scores 0 even with perfect perf,
    and the redistribution survives a zero-score hotkey; a node qualified within 6 h is available until its first canary."""
    import datetime as dt

    from racksdock_subnet.validator.scorer import NodeInputs, Params, score_tempo
    from racksdock_subnet.validator.snapshot import build_inputs

    now = dt.datetime(2026, 10, 22, 5, 0, tzinfo=dt.UTC)

    def ni(nid, hk, rented, avail):
        return NodeInputs(node_id=nid, hotkey=hk, qualified_at="2026-10-22T02:38:47Z", qualification_outcome="pass", perf=1.0, last_attestation_ok=True, critical_fault=False,
                          duplicate_dispute=False, minutes_rented=rented, minutes_available=avail, minutes_failed=0.0, minutes_maintenance=0.0, strikes=0.0,
                          canary_pass_rate_30d=1.0, registered_block=1, deployment="container")

    res = score_tempo([ni("off", "hk2", 0.0, 0.0), ni("on", "hk3", 0.0, 21.0)], now, 21.0, Params())
    assert "off" not in res.scored and "no attested availability in the window" in res.details["off"]["gate_reasons"]  # takes no slot
    # the single scored node's hotkey gets everything: no cap, and nothing burns while a node is scored
    assert res.scores["on"] > 0 and res.hotkey_weights.get("hk2", 0.0) == 0.0 and abs(res.hotkey_weights["hk3"] - 1.0) < 1e-6 and res.burn == 0.0
    # freshly qualified, no canary yet: idle minutes count as available
    start, end = now - dt.timedelta(minutes=21), now
    base = {"node_id": "n1", "miner_hotkey": "hk", "status": "qualified", "qualified_at": "2026-10-22T04:50:00Z", "qualification": {"outcome": "pass"}, "perf": 1.0}
    (a,) = build_inputs([base], [], [], {"n1": {}}, start, end, "v")
    assert a.minutes_available == 21.0
    (b,) = build_inputs([{**base, "qualified_at": "2026-10-21T14:00:00Z"}], [], [], {"n1": {}}, start, end, "v")
    assert b.minutes_available == 0.0  # older than the look-back: a canary must vouch for it


def test_evidence_window_bounds_are_shared_and_deterministic():
    import datetime as dt

    from racksdock_subnet.validator.snapshot import evidence_window

    w = evidence_window(dt.datetime(2026, 10, 22, 9, 0, tzinfo=dt.UTC))
    assert w == {"canary": "2026-10-21T21:00:00Z", "inrental": "2026-10-21T21:00:00Z", "probe": "2026-10-22T09:00:00Z"}


def test_verifier_role_never_builds_a_chain_or_scores(monkeypatch, tmp_path):
    """RACKSDOCK_ROLE=verifier: the platform's verifier verifies and publishes but has no chain client and refuses to score."""
    import asyncio

    from racksdock_subnet.validator import neuron as vn
    from racksdock_subnet.validator.config import ValidatorConfig
    from racksdock_subnet.verifier.devca import DevCA

    ca = DevCA.create(tmp_path / "ca")
    monkeypatch.setenv("RACKSDOCK_ROLE", "verifier")
    monkeypatch.setenv("RACKSDOCK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RACKSDOCK_RUNNER", "sim")
    monkeypatch.setenv("RACKSDOCK_TRUST_MODE", "dev")
    monkeypatch.setenv("RACKSDOCK_DEV_CA_DIR", str(ca.dir))
    cfg = ValidatorConfig.from_env()
    assert cfg.role == "verifier"
    monkeypatch.setattr(vn, "build_chain", lambda *a, **k: (_ for _ in ()).throw(AssertionError("chain built for a verifier")))
    n = vn.Verifier(cfg)
    assert n.chain is None
    with pytest.raises(RuntimeError, match="never scores"):
        asyncio.run(n.score_and_set_weights(None))


def test_compare_inputs_reports_field_differences():
    from racksdock_subnet.validator.scorer import NodeInputs
    from racksdock_subnet.validator.validator import compare_inputs

    def ni(nid, avail):
        return NodeInputs(node_id=nid, hotkey="hk", qualified_at=None, qualification_outcome="pass", perf=1.0, last_attestation_ok=True, critical_fault=False,
                          duplicate_dispute=False, minutes_rented=0.0, minutes_available=avail, minutes_failed=0.0, minutes_maintenance=0.0, strikes=0.0,
                          canary_pass_rate_30d=1.0, registered_block=1)

    assert compare_inputs([ni("a", 21.0)], [ni("a", 21.0)]) == []
    d = compare_inputs([ni("a", 21.0), ni("b", 0.0)], [ni("a", 20.0)])
    assert d == ["b: only in snapshot", "a minutes_available: snapshot=21.0 public=20.0"]


def test_unanswered_inrental_checks_are_inconclusive_not_failures():
    """The tenant stopped the node-agent: checks come back agent_reachable=False. They neither gate the node nor stop rented
    minutes while the instance's SSH port answers and the last conclusive attestation passed; a conclusive mismatch still gates."""
    import datetime as dt

    from racksdock_subnet.validator.snapshot import build_inputs

    start, end = dt.datetime(2026, 10, 22, 12, 0, tzinfo=dt.UTC), dt.datetime(2026, 10, 22, 13, 0, tzinfo=dt.UTC)
    node = {"node_id": "n1", "miner_hotkey": "hk", "status": "qualified", "qualified_at": "2026-10-22T00:00:00Z", "qualification": {"outcome": "pass"}, "perf": 1.0}
    lease = {"node_id": "n1", "instance_id": "i1", "is_validator": False, "active_at": "2026-10-21T17:00:00Z", "released_at": None}

    def chk(at, ok, agent=True, port=True):
        return {"kind": "inrental", "envelope": {"payload": {"instance_id": "i1", "validator_key": "v", "attestation_ok": ok, "gpu_ids_match": ok, "checked_at": at,
                                                             "agent_reachable": agent, "reachable": port}}}

    good_before = chk("2026-10-22T04:30:00Z", True)
    unanswered = [chk(f"2026-10-22T12:{m:02d}:00Z", False, agent=False) for m in range(0, 60, 10)]
    (a,) = build_inputs([node], [lease], [good_before, *unanswered], {"n1": {}}, start, end, "v")
    assert a.minutes_rented == 60.0 and a.last_attestation_ok is True
    # same but the SSH port is dead too: nothing served
    dead = [chk(f"2026-10-22T12:{m:02d}:00Z", False, agent=False, port=False) for m in range(0, 60, 10)]
    (b,) = build_inputs([node], [lease], [good_before, *dead], {"n1": {}}, start, end, "v")
    assert b.minutes_rented == 0.0 and b.last_attestation_ok is True
    # a conclusive mismatch in the window gates the node
    (c,) = build_inputs([node], [lease], [good_before, *unanswered, chk("2026-10-22T12:45:00Z", False, agent=True)], {"n1": {}}, start, end, "v")
    assert c.minutes_rented == 0.0 and c.last_attestation_ok is False
    # legacy records without agent_reachable behave as before (conclusive)
    legacy = {"kind": "inrental", "envelope": {"payload": {"instance_id": "i1", "validator_key": "v", "attestation_ok": False, "gpu_ids_match": False, "checked_at": "2026-10-22T12:30:00Z"}}}
    (d,) = build_inputs([node], [lease], [good_before, legacy], {"n1": {}}, start, end, "v")
    assert d.last_attestation_ok is False


def test_a_crashed_session_backs_the_node_off(monkeypatch, tmp_path):
    """A verification task that raises (host unreachable) stamps last_requal, so the loop does not spawn it again at once."""
    import asyncio
    import time

    from racksdock_subnet.validator import neuron as vn
    from racksdock_subnet.validator.config import ValidatorConfig
    from racksdock_subnet.verifier.devca import DevCA

    ca = DevCA.create(tmp_path / "ca")
    monkeypatch.setenv("RACKSDOCK_ROLE", "verifier")
    monkeypatch.setenv("RACKSDOCK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RACKSDOCK_RUNNER", "sim")
    monkeypatch.setenv("RACKSDOCK_TRUST_MODE", "dev")
    monkeypatch.setenv("RACKSDOCK_DEV_CA_DIR", str(ca.dir))
    n = vn.Verifier(ValidatorConfig.from_env())

    async def boom():
        raise RuntimeError("instance not active after 0s (status error): provider_unreachable")

    t0 = time.time()
    asyncio.run(n._guard("sha256:dead", boom()))
    assert n.last_requal["sha256:dead"] >= t0 and "sha256:dead" not in n.busy


def test_calibration_profile_disables_ratio_floors(monkeypatch):
    from racksdock_subnet.validator.config import ValidatorConfig
    from racksdock_subnet.validator.suite.checks import Ctx

    monkeypatch.setenv("RACKSDOCK_CALIBRATION_PROFILES", "b300x8, gb200x8")
    cfg = ValidatorConfig.from_env()
    assert cfg.calibration_profiles == ("b300x8", "gb200x8")
    assert Ctx(runner=None, reference="ref_dev_v0", dev_mode=True, claimed_vcpus=1).floor == 0.9
    assert Ctx(runner=None, reference="ref_dev_v0", dev_mode=True, claimed_vcpus=1, calibration=True).floor == 0.0


def test_topology_failure_retry_reruns_failed_and_cut_off_checks_only():
    from racksdock_subnet.validator.qualify import plan_targeted_retry

    last = {"kind": "full", "outcome": "quarantined", "failing_checks": ["Q5"],
            "checks": [{"id": i, "passed": i != "Q5"} for i in ("Q1", "Q2", "Q3", "Q4", "Q5")]}
    planned = ["Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8", "Q9", "Q10", "Q11", "Q12", "Q13", "Q14", "Q15"]
    assert plan_targeted_retry(last, planned) == {"Q5", "Q6", "Q7", "Q8", "Q9", "Q10", "Q11", "Q12", "Q13", "Q14", "Q15"}
    assert plan_targeted_retry({**last, "failing_checks": ["Q2"]}, planned) is None  # identity/SKU: full rerun
    # a power-profile failure resumes at Q13: the workload checks after it run again too
    all_ran = {**last, "failing_checks": ["Q13"], "checks": [{"id": i, "passed": i != "Q13"} for i in ["Q1", *planned]]}
    assert plan_targeted_retry(all_ran, planned) == {"Q13", "Q14", "Q15"}


def test_q13_uses_the_skus_own_power_limit_and_q14_without_benchmark_is_skipped():
    import asyncio

    from racksdock_subnet.core.profile import load as load_profile
    from racksdock_subnet.validator.suite.checks import Ctx, q13_power, q14_training
    from racksdock_subnet.validator.suite.runner import CmdResult

    sample = "".join(f"{i}, 1100.00, 1980\n" for i in range(8)) + "Clocks Event Reasons\n    Idle : Not Active\n---SAMPLE---\n"

    class R:
        async def run(self, cmd, timeout=None):
            if "train-bench" in cmd and "seq" in cmd:
                return CmdResult(0, "LOAD=started\n" + sample * 3)
            return CmdResult(125, "", "Unable to find image 'racksdock/train-bench:pinned'")

    ctx = Ctx(runner=R(), reference="ref_dev_v0", dev_mode=True, claimed_vcpus=1, profile=load_profile("b300x8"))
    ctx.extra["gpu_pci_id"] = "10de:3182"
    r13 = asyncio.run(q13_power(ctx, minutes=1))
    assert r13.details["approved_w"] == 1100.0 and r13.details["under_load"] is True
    r14 = asyncio.run(q14_training(ctx, minutes=1))
    assert r14.skipped and not r14.passed and "not available" in r14.error


def test_b300_reference_rates_the_first_real_node_at_one():
    """ref_b300_v1 is built from the first real B300: its own measurements rate ~1.0, and a targeted retry rates the merged spec
    against the current reference (not the base record's older ratios)."""

    from racksdock_subnet.core.profile import load as load_profile
    from racksdock_subnet.validator.qualify import _flat_measured
    from racksdock_subnet.validator.suite.reference import perf_score, ratios

    assert load_profile("b300x8").reference_set == "ref_b300_v1"
    spec = {"gpu": {"model": "B300", "count": 8, "vram_gb_usable_min": 253.5}, "nvlink": {"d2d_gbps_min_pair": 764.16, "d2d_gbps_aggregate": 42849.47, "allreduce_1gb_busbw_gbps": 718.38},
            "cpu": {"model": "Intel(R) Xeon(R) 6776P", "vcpus": 192, "stream_gbps": 29.8352, "sysbench": 300406.78}, "memory_gb": 2660.0, "hbm_write_gbps": 6551.0,
            "nvme": {"capacity_tb": 3.84, "seq_read_gbps": 4.8, "seq_write_gbps": 0.3756, "rand_read_kiops": 255.7, "rand_write_kiops": 14.68, "sustained_write_gbps": 0.428},
            "network": {"down_gbps": 2.53, "up_gbps": 2.38}, "power_profile": {"limit_w": 1100.0}, "training_tokens_per_s": 0.0, "inference_tokens_per_s": 0.0}
    flat = _flat_measured(spec)
    assert "training_tokens_per_s" not in flat and flat["nvme.seq_write_gbps"] == 0.3756
    r = ratios(flat, "ref_b300_v1")
    assert perf_score(r) > 0.99 and all(v > 0.99 for v in r.values())


def test_a_released_rentals_last_failed_check_does_not_gate_the_node_later():
    """Seen on the 8x4090: the tenant's VM stopped answering attestation challenges in its last minutes, the rental ended, the node
    passed a full qualification and a canary, and four hours later it still showed 'last attestation failed'. An ended rental's
    checks count only inside their own window; a live rental's latest check still carries forward."""
    import datetime as dt

    from racksdock_subnet.validator.snapshot import build_inputs

    end = dt.datetime(2026, 10, 23, 17, 5, tzinfo=dt.UTC)
    start = end - dt.timedelta(minutes=5)
    node = {"node_id": "n1", "miner_hotkey": "hk", "status": "qualified", "qualified_at": "2026-10-23T13:12:50Z", "qualification": {"outcome": "pass"}, "perf": 1.0}
    failed_check = {"kind": "inrental", "node_id": "n1", "instance_id": "inst_old", "validator_key": "v", "checked_at": "2026-10-23T12:17:00Z",
                    "attestation_ok": False, "gpu_ids_match": False, "reachable": True, "agent_reachable": True, "error": "challenge failed"}
    canary = {"kind": "canary", "node_id": "n1", "outcome": "pass", "finished_at": "2026-10-23T16:06:00Z"}
    evidence = [{"kind": "inrental", "envelope": {"payload": failed_check}}, {"kind": "canary", "envelope": {"payload": canary}}]
    ended = {"lease_id": "l1", "node_id": "n1", "instance_id": "inst_old", "is_validator": False, "active_at": "2026-10-23T09:00:00Z", "released_at": "2026-10-23T12:20:00Z", "status": "deleted"}
    (a,) = build_inputs([node], [ended], evidence, {"n1": {}}, start, end, "v")
    assert a.last_attestation_ok is True and a.minutes_rented == 0.0 and a.minutes_available == 5.0  # idle, vouched for by the canary
    live = {**ended, "released_at": None, "status": "active"}
    (b,) = build_inputs([node], [live], evidence, {"n1": {}}, start, end, "v")
    assert b.last_attestation_ok is False and b.minutes_rented == 0.0  # still rented and still failing: gated, as before
