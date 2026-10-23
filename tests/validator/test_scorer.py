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
    p = Params()
    nodes = [node("rented", "hk1", 72, 0), node("idle", "hk2", 0, 72), node("refused", "hk3", 0, 42, failed=30), node("lost", "hk4", 52, 0)]
    r = score_tempo(nodes, NOW, 72, p)
    assert r.scores["rented"] == 0.94 and r.scores["idle"] == 0.64
    assert abs(r.scores["refused"] - (0.50 * 42 / 72 + 0.14)) < 1e-6
    assert abs(r.scores["lost"] - (0.50 * 52 / 72 + 0.14 + 0.30 * 52 / 72)) < 1e-6
    assert abs(sum(r.hotkey_weights.values()) + r.burn - 1.0) < 1e-6
    # nothing burns while a node is scored; weights are proportional to the hotkeys' scores
    assert r.burn == 0.0 and abs(sum(r.hotkey_weights.values()) - 1.0) < 1e-6


def test_gate_closes_for_fault_perf_strikes_and_missing_qualification():
    """A qualification never expires: canaries and in-rental checks keep a node honest after it passed once."""
    p = Params()
    nodes = [node("old", "a", 72, 0, q="2026-01-01T00:00:00Z"), node("none", "a2", 72, 0, outcome=None), node("fault", "b", 72, 0, fault=True), node("slow", "c", 72, 0, perf=0.85),
             node("struck", "d", 72, 0, strikes=3.0), node("badatt", "e", 72, 0, att=False), node("ok", "f", 72, 0)]
    r = score_tempo(nodes, NOW, 72, p)
    assert sorted(r.scores) == ["ok", "old"] and sorted(r.scored) == ["ok", "old"]
    assert "no passing qualification" in r.details["none"]["gate_reasons"]
    assert "perf below floor" in r.details["slow"]["gate_reasons"]


def test_every_eligible_node_is_scored_and_nothing_is_capped():
    """No slots: every node through the gate is paid in proportion to its score, however many miners there are."""
    nodes = [node("n1", "whale", 72, 0, block=1), node("n2", "whale", 72, 0, block=2), node("n3", "small", 0, 72, strikes=0.5, block=3)]
    r = score_tempo(nodes, NOW, 72, Params())
    assert set(r.scored) == {"n1", "n2", "n3"}
    assert r.hotkey_weights["whale"] > r.hotkey_weights["small"] > 0 and r.burn == 0.0
    assert abs(sum(r.hotkey_weights.values()) - 1.0) < 1e-6
    only = score_tempo(nodes[:2], NOW, 72, Params())
    assert abs(only.hotkey_weights["whale"] - 1.0) < 1e-9 and only.burn == 0.0  # one hotkey holds everything: no cap
    assert score_tempo([node("x", "hk", 72, 0, perf=0.5)], NOW, 72, Params()).burn == 1.0  # nobody eligible: everything burns


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
    r = score_tempo(nodes, NOW, 72, Params())
    got = {"scores": r.scores, "scored": r.scored, "hotkey_weights": r.hotkey_weights, "burn": r.burn}
    if not vec_path.exists():
        vec_path.write_text(json.dumps(got, indent=1, sort_keys=True))
    assert json.loads(vec_path.read_text()) == json.loads(json.dumps(got))
