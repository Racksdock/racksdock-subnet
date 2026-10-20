import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from racksdock_subnet.core import canonical, identity, nonce, specdata, userdata
from racksdock_subnet.core.envelope import SignedEnvelope, require_valid
from racksdock_subnet.core.keys import PublicKey, SigningKey
from racksdock_subnet.core.schemas import (
    ClaimedSpec,
    CreateInstanceRequest,
    DockerConfiguration,
    EnvVar,
    LaunchConfiguration,
    LaunchType,
    Networking,
    RegistrationRecord,
    UfwRule,
    UserDataInput,
)


def test_canonical_is_deterministic():
    a = canonical.canonical_bytes({"b": 1, "a": [1, 2, {"z": None, "y": "é"}]})
    b = canonical.canonical_bytes({"a": [1, 2, {"y": "é", "z": None}], "b": 1})
    assert a == b
    assert canonical.hash_obj({"x": 1}).startswith("sha256:")


def test_sign_verify_envelope_roundtrip():
    key = SigningKey.generate()
    env = SignedEnvelope.create("test", {"hello": "world"}, key)
    assert env.verify()
    assert env.verify(expected_signer=key.public.hex)
    assert not env.verify(expected_signer="00" * 32)
    tampered = env.model_copy(update={"payload": {"hello": "mars"}})
    assert not tampered.verify()
    assert require_valid(env, "test") == {"hello": "world"}
    with pytest.raises(ValueError):
        require_valid(env, "other")


def test_key_persistence(tmp_path):
    p = tmp_path / "k.seed"
    k1 = SigningKey.load_or_create(p)
    k2 = SigningKey.load_or_create(p)
    assert k1.public.hex == k2.public.hex
    assert PublicKey.from_hex(k1.public.hex).verify(k1.sign(b"m"), b"m")
    assert k1.public.ssh_public_line("c").startswith("ssh-ed25519 ")


def _self_signed_cert() -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim gpu")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA384())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_gpu_and_node_identity():
    certs = [_self_signed_cert() for _ in range(8)]
    ids = [identity.gpu_id_from_cert_pem(c) for c in certs]
    assert len(set(ids)) == 8
    nid = identity.node_id_from_gpu_ids(ids)
    assert nid == identity.node_id_from_gpu_ids(list(reversed(ids)))
    with pytest.raises(ValueError):
        identity.node_id_from_gpu_ids(ids[:7])
    assert identity.gpu_set_hash(ids) == identity.gpu_set_hash(sorted(ids))


def test_boot_nonce_composition():
    tn = nonce.new_nonce_hex()
    key = SigningKey.generate()
    line = key.public.ssh_public_line("host")
    hk = nonce.ssh_host_key_bytes_from_line(line)
    n1 = nonce.compose_boot_nonce(tn, hk, b"#cloud-config\n")
    n2 = nonce.compose_boot_nonce(tn, hk, b"#cloud-config\n")
    n3 = nonce.compose_boot_nonce(tn, hk, b"#cloud-config\nx")
    assert n1 == n2 != n3
    assert nonce.ssh_fingerprint(line).startswith("SHA256:")
    with pytest.raises(ValueError):
        nonce.compose_boot_nonce("abcd", hk, b"")


def test_userdata_render_is_deterministic_and_complete():
    inp = UserDataInput(
        ssh_public_keys=["ssh-ed25519 AAAA a", "ssh-ed25519 BBBB b"],
        launch_configuration=LaunchConfiguration(
            type=LaunchType.docker,
            docker_configuration=DockerConfiguration(
                image="vllm/vllm-openai:v0.1", args="--model x", envs=[EnvVar(name="HF_HOME", value="/data/hf")],
                port_mappings=[{"container_port": 8000, "host_port": 8000}],
            ),
        ),
        envs=[EnvVar(name="WANDB_MODE", value="offline")],
        networking=Networking(ufw_rules=[UfwRule(rule="allow", port="8000", proto="tcp", from_ip="203.0.113.0/24")]),
        enable_metrics=True,
    )
    r1 = userdata.render(inp)
    r2 = userdata.render(UserDataInput.model_validate(inp.model_dump()))
    assert r1 == r2
    assert r1.startswith("#cloud-config\n")
    assert "ssh-ed25519 AAAA a" in r1 and "WANDB_MODE" in r1
    assert "ufw allow from 203.0.113.0/24 to any port 8000 proto tcp" in r1
    assert "/etc/racksdock/launch.json" in r1 and "metrics.enabled" in r1
    assert userdata.user_data_hash(r1) == userdata.user_data_hash(r1.encode())
    assert userdata.user_data_hash(r1) != userdata.user_data_hash(userdata.render(UserDataInput()))


def test_launch_configuration_requires_matching_block():
    with pytest.raises(ValueError):
        LaunchConfiguration(type=LaunchType.docker)
    lc = LaunchConfiguration(type=LaunchType.script, script_configuration={"base64_script": base64.b64encode(b"echo hi").decode()})
    assert lc.type == LaunchType.script


def test_create_request_validation():
    req = CreateInstanceRequest(name="train-1", os="ubuntu24.04", tenant_nonce="ab" * 32)
    assert req.node_id == "auto"
    with pytest.raises(ValueError):
        CreateInstanceRequest(name="bad name!")
    with pytest.raises(ValueError):
        CreateInstanceRequest(name="x", tenant_nonce="zz")


def test_registration_record_schema_alias():
    rec = RegistrationRecord(
        node_id="sha256:x", gpu_ids=[f"sha256:{i}" for i in range(8)], miner_hotkey="5F", miner_service_key="00" * 32,
        claimed_spec=ClaimedSpec(vcpus=120, memory_gb=1850, nvme_tb=28, network_gbps=25, region="eu"), host_image_version="host_v1",
    )
    d = rec.model_dump(by_alias=True)
    assert d["schema"] == "racksdock.registration.v1"
    assert RegistrationRecord.model_validate(d).node_id == "sha256:x"


def test_specdata_loads():
    assert specdata.thresholds()["ratio_floor"] == 0.90
    assert specdata.is_pci_id_approved("10de:b300", dev_mode=True)
    assert not specdata.is_pci_id_approved("10de:b300", dev_mode=False)
    assert specdata.hbm_floor_gb("10de:b300", dev_mode=True) == 260
    assert specdata.reference_set("ref_dev_v0")["values"]["cpu.vcpus"] == 120
    assert specdata.platforms()["vm_floors"]["boot_to_active_limit_s"] == 600


def test_mock_chain(tmp_path):
    from racksdock_subnet.core.chainclient import MockChain

    c = MockChain(tmp_path / "chain.json", block_time_s=0.001)
    uid = c.register("5Fminer")
    assert uid == 1 and c.register("5Fminer") == 1
    v = c.register("5Gval", is_validator=True, stake=1000)
    b = c.commit("5Fminer", "sha256:abc")
    cs = c.commitments()
    assert cs[0].hotkey == "5Fminer" and cs[0].data == "sha256:abc" and cs[0].block == b
    assert c.set_weights("5Gval", {uid: 1.0})
    assert c.weights_of("5Gval") == {uid: 1.0}
    assert c.uid_of("5Gval") == v and c.uid_of("nobody") is None
    c.advance(100)
    assert c.current_block() >= 100
