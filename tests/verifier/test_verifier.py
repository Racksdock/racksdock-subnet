import pytest

from racksdock_subnet.core.identity import node_id_from_gpu_ids
from racksdock_subnet.core.nonce import new_nonce_hex
from racksdock_subnet.verifier.collectors import SimulatedCollector
from racksdock_subnet.verifier.devca import DevCA
from racksdock_subnet.verifier.sku import check_sku
from racksdock_subnet.verifier.verifiers import SimVerifier


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    return DevCA.create(tmp_path_factory.mktemp("ca"))


@pytest.fixture(scope="module")
def node_dir(ca, tmp_path_factory):
    return ca.issue_node(tmp_path_factory.mktemp("node"))


def test_collect_and_verify_ok(ca, node_dir):
    nonce = new_nonce_hex()
    bundle = SimulatedCollector(ca, node_dir).collect(nonce)
    res = SimVerifier(ca).verify(bundle, nonce)
    assert res.ok, res.errors
    assert len(res.gpu_ids) == 8 and len(set(res.gpu_ids)) == 8
    assert res.arch == "blackwell" and res.hwmodel == "SIM-B300"
    assert res.measurements_hash.startswith("sha256:")


def test_gpu_ids_are_stable_across_collections(ca, node_dir):
    c = SimulatedCollector(ca, node_dir)
    n1, n2 = new_nonce_hex(), new_nonce_hex()
    g1 = SimVerifier(ca).verify(c.collect(n1), n1).gpu_ids
    g2 = SimVerifier(ca).verify(c.collect(n2), n2).gpu_ids
    assert sorted(g1) == sorted(g2)
    assert node_id_from_gpu_ids(g1) == node_id_from_gpu_ids(g2)


def test_wrong_nonce_rejected(ca, node_dir):
    bundle = SimulatedCollector(ca, node_dir).collect(new_nonce_hex())
    res = SimVerifier(ca).verify(bundle, new_nonce_hex())
    assert not res.ok and not res.nonce_ok


def test_replayed_nonce_inside_evidence_rejected(ca, node_dir):
    n = new_nonce_hex()
    bundle = SimulatedCollector(ca, node_dir, tamper={"nonce_override": "00" * 32}).collect(n)
    res = SimVerifier(ca).verify(bundle, n)
    assert not res.ok and not res.nonce_ok


def test_tampered_signature_rejected(ca, node_dir):
    n = new_nonce_hex()
    bundle = SimulatedCollector(ca, node_dir, tamper={"bad_signature": True}).collect(n)
    res = SimVerifier(ca).verify(bundle, n)
    assert not res.ok and not res.chain_ok


def test_unknown_measurement_rejected(ca, node_dir):
    n = new_nonce_hex()
    bundle = SimulatedCollector(ca, node_dir, tamper={"bad_measurement": True}).collect(n)
    res = SimVerifier(ca).verify(bundle, n)
    assert not res.ok and not res.measurements_ok


def test_wrong_arch_rejected(ca, node_dir):
    n = new_nonce_hex()
    bundle = SimulatedCollector(ca, node_dir, tamper={"arch": "hopper"}).collect(n)
    res = SimVerifier(ca).verify(bundle, n)
    assert not res.ok and not res.arch_ok


def test_foreign_ca_rejected(ca, node_dir, tmp_path):
    other = DevCA.create(tmp_path / "other")
    n = new_nonce_hex()
    bundle = SimulatedCollector(ca, node_dir).collect(n)
    res = SimVerifier(other).verify(bundle, n)
    assert not res.ok and not res.chain_ok


def test_seven_gpu_node_fails(ca, tmp_path):
    nd = ca.issue_node(tmp_path / "n7", count=7)
    n = new_nonce_hex()
    res = SimVerifier(ca).verify(SimulatedCollector(ca, nd).collect(n), n)
    assert not res.ok and any("8 devices" in e for e in res.errors)


def test_sku_check(ca, node_dir):
    inv = SimulatedCollector(ca, node_dir).inventory()
    ok, errors, details = check_sku(inv, dev_mode=True)
    assert ok, errors
    ok2, errors2, _ = check_sku(inv, dev_mode=False)
    assert not ok2 and "not in allowlist" in errors2[0]
    inv[0].memory_total_mib = 100 * 1024
    ok3, errors3, _ = check_sku(inv, dev_mode=True)
    assert not ok3 and "below floor" in errors3[0]


def test_unconfirmed_sku_matches_by_model_name_in_dev_mode_only():
    """A production allowlist entry still marked to_confirm (pci id TBD) accepts a GPU by model name in dev trust mode, and
    records what must be confirmed; in prod trust mode the unknown pci id is an error."""
    from racksdock_subnet.verifier.inventory import GpuInventory
    from racksdock_subnet.verifier.sku import check_sku

    inv = [GpuInventory(index=i, name="NVIDIA B300", serial=f"S{i}", pci_device_id="10de:2b45", vbios="97.10.3A.00.01", memory_total_mib=288 * 1024, power_limit_w=1400.0,
                        board_part="900-2G530-0040-000") for i in range(8)]
    ok, errors, details = check_sku(inv, dev_mode=True, expected=8)
    assert ok and not errors and len(details["unconfirmed_sku"]) == 8 and details["unconfirmed_sku"][0]["pci_device_id"] == "10de:2b45"
    ok, errors, _ = check_sku(inv, dev_mode=False, expected=8)
    assert not ok and "not in allowlist" in errors[0]
