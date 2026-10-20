from __future__ import annotations

import asyncio
import logging

import typer

from .neuron import MinerConfig, MinerNeuron

app = typer.Typer(help="racksdock miner neuron")


def _neuron(host_pubkey: str | None = None) -> MinerNeuron:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    return MinerNeuron(MinerConfig.from_env(), host_pubkey)


@app.command()
def bootstrap(host_pubkey: str | None = typer.Option(None, help="host-agent service key (hex); default derives from RACKSDOCK_HOST_SEED")):
    n = _neuron(host_pubkey)

    async def go():
        try:
            rec = await n.bootstrap()
            typer.echo(f"registered node_id={rec.node_id}")
        finally:
            await n.close()

    asyncio.run(go())


@app.command()
def run(host_pubkey: str | None = None):
    n = _neuron(host_pubkey)
    try:
        asyncio.run(n.run())
    except KeyboardInterrupt:
        pass


@app.command()
def maintenance(starts: str, ends: str):
    n = _neuron()

    async def go():
        try:
            await n.announce_maintenance(starts, ends)
            typer.echo("maintenance announced")
        finally:
            await n.close()

    asyncio.run(go())


@app.command()
def status():
    n = _neuron()
    typer.echo(f"hotkey={n.cfg.hotkey} host_pubkey={n.host_pubkey} node_id={n.node_id}")
