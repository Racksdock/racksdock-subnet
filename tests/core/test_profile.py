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
