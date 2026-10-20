import datetime as dt
import json
from pathlib import Path

from racksdock_subnet.validator.scorer import NodeInputs, Params, adaptive_weights, decayed_strikes, score_tempo

NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.UTC)
Q = "2026-10-19T00:00:00Z"


def node(nid, hk, rented, avail, perf=0.97, strikes=0.0, q=Q, outcome="pass", att=True, fault=False, failed=0.0, block=10):
    return NodeInputs(node_id=nid, hotkey=hk, qualified_at=q, qualification_outcome=outcome, perf=perf, last_attestation_ok=att, critical_fault=fault, duplicate_dispute=False,
                      minutes_rented=rented, minutes_available=avail, minutes_failed=failed, minutes_maintenance=0.0, strikes=strikes, canary_pass_rate_30d=1.0, registered_block=block)


def test_worked_examples_from_docs_04():
    p = Params(funded_slots=10, hotkey_cap=1.0)  # cap not binding; see test_funded_slots_rank_and_hotkey_cap
    nodes = [node("rented", "hk1", 72, 0), node("idle", "hk2", 0, 72), node("refused", "hk3", 0, 42, failed=30), node("lost", "hk4", 52, 0)]
    r = score_tempo(nodes, NOW, 72, p)
    assert r.scores["rented"] == 0.94 and r.scores["idle"] == 0.64
    assert abs(r.scores["refused"] - (0.50 * 42 / 72 + 0.14)) < 1e-6
    assert abs(r.scores["lost"] - (0.50 * 52 / 72 + 0.14 + 0.30 * 52 / 72)) < 1e-6
    assert abs(sum(r.hotkey_weights.values()) + r.burn - 1.0) < 1e-6
    # four nodes in ten slots -> 60% of emissions burn
    assert abs(r.burn - 0.6) < 1e-6


def test_gate_closes_for_stale_qualification_fault_perf_and_strikes():
    p = Params(funded_slots=10)
    nodes = [node("stale", "a", 72, 0, q="2026-10-01T00:00:00Z"), node("fault", "b", 72, 0, fault=True), node("slow", "c", 72, 0, perf=0.85),
             node("struck", "d", 72, 0, strikes=3.0), node("badatt", "e", 72, 0, att=False), node("ok", "f", 72, 0)]
    r = score_tempo(nodes, NOW, 72, p)
    assert list(r.scores) == ["ok"]
    assert "qualification missing or stale" in r.details["stale"]["gate_reasons"]
    assert "perf below floor" in r.details["slow"]["gate_reasons"]


def test_funded_slots_rank_and_hotkey_cap():
    p = Params(funded_slots=2, hotkey_cap=0.25)
    nodes = [node("n1", "whale", 72, 0, strikes=0.0, block=1), node("n2", "whale", 72, 0, block=2), node("n3", "small", 0, 72, strikes=0.5, block=3)]
    r = score_tempo(nodes, NOW, 72, p)
    assert r.funded == ["n1", "n2"]  # fewer strikes rank first; small loses the slot
    # single hotkey holds everything -> capped at 25%, rest burns
    assert r.hotkey_weights["whale"] <= 0.25 + 1e-9 and r.burn >= 0.75 - 1e-9
    p2 = Params(funded_slots=3, hotkey_cap=0.6)
    r2 = score_tempo(nodes, NOW, 72, p2)
    assert set(r2.funded) == {"n1", "n2", "n3"}
    assert r2.hotkey_weights["whale"] > r2.hotkey_weights["small"]
    assert abs(sum(r2.hotkey_weights.values()) + r2.burn - 1.0) < 1e-6


def test_adaptive_weights_and_strike_decay():
    assert adaptive_weights(Params(), 0.3) == (0.5, 0.2, 0.3)
    wa, wp, wr = adaptive_weights(Params(), 0.8)
    assert abs(wa - 0.35) < 1e-9 and abs(wr - 0.45) < 1e-9
    strikes = [{"at": "2026-10-05T12:00:00Z", "weight": 1.0}, {"at": "2026-09-01T00:00:00Z", "weight": 1.0}]
    assert abs(decayed_strikes(strikes, NOW) - 0.5) < 1e-9


def test_vectors_are_reproduced():
    """Test vectors every scorer fork must reproduce. Regenerate only with a documented scoring change."""
    vec_path = Path(__file__).parent / "vectors" / "tempo_basic.json"
    nodes = [node("a", "hk1", 72, 0), node("b", "hk2", 30, 42), node("c", "hk3", 0, 72, perf=0.93), node("d", "hk3", 0, 0), node("e", "hk4", 72, 0, perf=0.88)]
    r = score_tempo(nodes, NOW, 72, Params(funded_slots=4))
    got = {"scores": r.scores, "funded": r.funded, "hotkey_weights": r.hotkey_weights, "burn": r.burn}
    if not vec_path.exists():
        vec_path.write_text(json.dumps(got, indent=1, sort_keys=True))
    assert json.loads(vec_path.read_text()) == json.loads(json.dumps(got))
