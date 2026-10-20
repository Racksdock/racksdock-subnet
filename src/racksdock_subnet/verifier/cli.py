from __future__ import annotations

import json
from pathlib import Path

import typer

from racksdock_subnet.core.schemas import EvidenceBundle

from .collectors import SimulatedCollector
from .config import TrustConfig
from .devca import DevCA
from .verifiers import NvattestVerifier, SimVerifier

app = typer.Typer(help="racksdock attestation tools")
devca_app = typer.Typer(help="simulated device PKI for development")
app.add_typer(devca_app, name="devca")


@devca_app.command("init")
def devca_init(root_dir: Path):
    DevCA.create(root_dir)
    typer.echo(f"dev CA created in {root_dir}")


@devca_app.command("issue-node")
def devca_issue(root_dir: Path, node_dir: Path, count: int | None = None, pci_id: str | None = None, memory_mib: int | None = None):
    kw = {k: v for k, v in {"count": count, "pci_id": pci_id, "memory_mib": memory_mib}.items() if v is not None}
    DevCA(root_dir).issue_node(node_dir, **kw)
    typer.echo(f"issued {count} simulated devices in {node_dir}")


def fetch_devca(platform_url: str, out_dir: Path) -> Path:
    """Download the platform's public dev CA (root, device CA, reference measurements). Dev trust mode only."""
    import httpx

    r = httpx.get(platform_url.rstrip("/") + "/v1/dev/devca", timeout=30)
    r.raise_for_status()
    d = r.json()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "root.pem").write_text(d["root_pem"])
    (out_dir / "device_ca.pem").write_text(d["device_ca_pem"])
    (out_dir / "rim.json").write_text(json.dumps(d["rim"], indent=1))
    return out_dir


def fetch_node(platform_url: str, node_dir: Path, count: int | None = None, pci_id: str | None = None, memory_mib: int | None = None, board_part: str | None = None) -> Path:
    """Ask the platform to issue simulated GPU identities for this node (hardware without device attestation). Dev trust mode only."""
    import httpx

    body = {k: v for k, v in {"count": count, "pci_id": pci_id, "memory_mib": memory_mib, "board_part": board_part}.items() if v is not None}
    r = httpx.post(platform_url.rstrip("/") + "/v1/dev/issue-node", json=body, timeout=60)
    r.raise_for_status()
    d = r.json()
    (node_dir / "devices").mkdir(parents=True, exist_ok=True)
    for dev in d["devices"]:
        k = node_dir / "devices" / f"{dev['index']}.key"
        k.write_text(dev["key_pem"])
        k.chmod(0o600)
        (node_dir / "devices" / f"{dev['index']}.pem").write_text(dev["cert_pem"])
    (node_dir / "inventory.json").write_text(json.dumps(d["inventory"], indent=1))
    return node_dir


@devca_app.command("fetch")
def devca_fetch(platform_url: str, out_dir: Path):
    fetch_devca(platform_url, out_dir)
    typer.echo(f"public dev CA written to {out_dir}")


@devca_app.command("fetch-node")
def devca_fetch_node(platform_url: str, node_dir: Path, count: int | None = None, pci_id: str | None = None, memory_mib: int | None = None, board_part: str | None = None):
    fetch_node(platform_url, node_dir, count, pci_id, memory_mib, board_part)
    typer.echo(f"simulated device identities written to {node_dir}")


@app.command()
def collect(nonce: str, out: Path = Path("evidence.json"), sim_node: Path | None = None):
    cfg = TrustConfig.from_env()
    if cfg.dev:
        if sim_node is None or cfg.dev_ca_dir is None:
            raise typer.BadParameter("dev mode needs --sim-node and RACKSDOCK_DEV_CA_DIR")
        bundle = SimulatedCollector(DevCA(cfg.dev_ca_dir), sim_node).collect(nonce)
    else:
        from .collectors import NvattestCliCollector

        bundle = NvattestCliCollector(cfg.nvattest_bin).collect(nonce)
    out.write_text(bundle.model_dump_json(indent=1))
    typer.echo(f"wrote {out} ({len(bundle.devices)} devices)")


@app.command()
def verify(evidence: Path, nonce: str):
    cfg = TrustConfig.from_env()
    bundle = EvidenceBundle.model_validate_json(evidence.read_text())
    v = SimVerifier(DevCA(cfg.dev_ca_dir)) if cfg.dev else NvattestVerifier(cfg.nvattest_bin, remote=cfg.nras_url is not None, nras_url=cfg.nras_url)
    res = v.verify(bundle, nonce)
    typer.echo(json.dumps(res.model_dump(), indent=1))
    raise typer.Exit(0 if res.ok else 1)
