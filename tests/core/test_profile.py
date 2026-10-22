"""Hardware profiles: production b300x8 and the A100-only workflow-test profile."""
import asyncio

import pytest

from racksdock_subnet.core import profile, specdata
from racksdock_subnet.core.identity import node_id_from_gpu_ids
from racksdock_subnet.core.nonce import new_nonce_hex
from racksdock_subnet.verifier.collectors import SimulatedCollector
from racksdock_subnet.verifier.devca import DevCA
from racksdock_subnet.verifier.sku import check_sku
from racksdock_subnet.verifier.verifiers import SimVerifier


@pytest.fixture
def a100(monkeypatch):
    monkeypatch.setenv(profile.PROFILE_ENV, "a100-dev")
    specdata.allowlist.cache_clear()
    yield profile.current()
    monkeypatch.delenv(profile.PROFILE_ENV)


def test_profiles_available_and_defaults():
    assert set(profile.available()) >= {"b300x8", "a100-dev"}
    p = profile.current()
    assert p.name == "b300x8" and p.gpu_count == 8 and p.production and p.enabled("Q8") and not p.enabled("Q14", "weekly")


def test_a100_profile_is_one_gpu_and_excludes_multi_gpu_checks(a100):
    assert a100.gpu_count == 1 and not a100.production and a100.instance_type == "A100x1-DEV"
    for cid in ("Q5", "Q6", "Q7", "Q8", "Q14", "Q15"):
        assert not a100.enabled(cid)
    for cid in ("Q2", "Q3", "Q4", "Q9", "Q10", "Q11", "Q12", "Q13"):
        assert a100.enabled(cid)
    assert specdata.is_pci_id_approved("10de:20b2", dev_mode=True) and not specdata.is_pci_id_approved("10de:20b2", dev_mode=False)
    assert specdata.reference_set(a100.reference_set)["values"]["cpu.vcpus"] == 4


def test_one_gpu_identity_attestation_and_sku(a100, tmp_path):
    ca = DevCA.create(tmp_path / "ca")
    nd = ca.issue_node(tmp_path / "node")  # count and pci id follow the profile
    c = SimulatedCollector(ca, nd)
    inv = c.inventory()
    assert len(inv) == 1 and inv[0].pci_device_id == "10de:20b2"
    assert check_sku(inv, dev_mode=True)[0]
    n = new_nonce_hex()
    res = SimVerifier(ca).verify(c.collect(n), n)
    assert res.ok and len(res.gpu_ids) == 1
    nid = node_id_from_gpu_ids(res.gpu_ids)
    assert nid.startswith("sha256:")
    with pytest.raises(ValueError):
        node_id_from_gpu_ids(res.gpu_ids, expected=8)
    # an eight-device bundle is rejected under the one-GPU profile
    nd8 = ca.issue_node(tmp_path / "node8", count=8)
    res8 = SimVerifier(ca).verify(SimulatedCollector(ca, nd8).collect(n), n)
    assert not res8.ok and any("expected 1 devices" in e for e in res8.errors)


def test_a100_suite_passes_in_simulation(a100):
    from racksdock_subnet.validator.suite.checks import Ctx, run_suite, smoke
    from racksdock_subnet.validator.suite.reference import gate_ok, perf_score, ratios
    from racksdock_subnet.validator.suite.runner import SimRunner

    ctx = Ctx(runner=SimRunner(), reference=a100.reference_set, dev_mode=True, claimed_vcpus=4, profile=a100)
    results = asyncio.run(run_suite(ctx, kind="full"))
    assert [r.id for r in results] == ["Q2", "Q3", "Q4", "Q9", "Q10", "Q11", "Q12", "Q13"]
    assert all(r.passed for r in results), [(r.id, r.details, r.error) for r in results if not r.passed]
    r = ratios(ctx.measured, a100.reference_set)
    assert gate_ok({k: v for k, v in r.items() if k in r})[0] and perf_score(r) > 0.9
    sm = asyncio.run(smoke(Ctx(runner=SimRunner(), reference=a100.reference_set, dev_mode=True, claimed_vcpus=0, profile=a100)))
    assert sm["marker"] == "absent" and sm["nccl_wrong"] == 0


def test_rtx4090_profile_is_eight_gpu_pcie_and_excludes_checks_geforce_cannot_run(monkeypatch):
    """TEMPORARY (delete with the profile): the 8x RTX 4090 bare-metal VM test profile."""
    monkeypatch.setenv(profile.PROFILE_ENV, "rtx4090x8-dev")
    p = profile.current()
    assert p.gpu_count == 8 and not p.production and p.interconnect == "pcie" and p.instance_type == "RTX4090x8-DEV"
    for cid in ("Q4", "Q5", "Q6", "Q14", "Q15"):
        assert not p.enabled(cid)
    for cid in ("Q2", "Q3", "Q7", "Q8", "Q9", "Q10", "Q11", "Q12", "Q13"):
        assert p.enabled(cid)
    assert p.power_limit_w == 0 and p.sim_pci_id == "10de:2684" and p.extra["fio_size_gb"] == 2
    assert specdata.reference_set(p.reference_set)["values"]["gpu.vram_gb_usable_min"] == 20


def test_profile_get_and_deployment_tiers(monkeypatch):
    from racksdock_subnet.core import profile as pr
    from racksdock_subnet.core.specdata import approved_gpu_entries

    monkeypatch.setenv(pr.PROFILE_ENV, "b300x8")
    assert pr.get("a100-dev").gpu_count == 1 and pr.get("rtx4090x8-dev").gpu_count == 8
    assert pr.get(None).name == "b300x8" and pr.get("no-such-profile").name == "b300x8"  # unknown/empty -> environment default
    assert pr.deployment_factor("vm") == 1.0 and pr.deployment_factor("container") == 0.5 and pr.deployment_factor("static") == 0.5 and pr.deployment_factor(None) == 1.0
    ids = {e["pci_device_id"] for e in approved_gpu_entries(dev_mode=True)}
    assert {"10de:20b5", "10de:2684"} <= ids  # the allowlist spans every profile's SKUs


def test_scorer_halves_container_and_static_tiers():
    import datetime as dt

    from racksdock_subnet.validator.scorer import NodeInputs, Params, score_tempo

    def node(nid, dep):
        return NodeInputs(node_id=nid, hotkey=f"hk-{nid}", qualified_at=dt.datetime.now(dt.UTC).isoformat(), qualification_outcome="pass", perf=1.0, last_attestation_ok=True, critical_fault=False,
                          duplicate_dispute=False, minutes_rented=72, minutes_available=0, minutes_failed=0, minutes_maintenance=0, strikes=0, canary_pass_rate_30d=1.0,
                          registered_block=1, deployment=dep)

    res = score_tempo([node("vm", "vm"), node("ct", "container"), node("st", "static")], dt.datetime.now(dt.UTC), 72, Params(funded_slots=8))
    assert res.scores["ct"] == res.scores["st"] and abs(res.scores["vm"] - 2 * res.scores["ct"]) < 1e-6
    assert res.details["ct"]["tier_factor"] == 0.5 and res.details["vm"]["tier"] == "vm"
