from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging

import typer

from .config import ValidatorConfig
from .neuron import ValidatorNeuron

app = typer.Typer(help="racksdock validator")


def _neuron() -> ValidatorNeuron:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    return ValidatorNeuron(ValidatorConfig.from_env())


@app.command()
def light():
    """Run a light validator: fetch the platform-signed scoring snapshot every tempo, run the deterministic scorer, set weights.
    No SSH key, no API key, no verify sessions (docs/04 §6)."""
    from .light import LightValidator

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    v = LightValidator(ValidatorConfig.from_env())
    try:
        asyncio.run(v.run())
    except KeyboardInterrupt:
        pass


@app.command()
def enroll():
    n = _neuron()
    asyncio.run(n.ensure_enrolled())
    typer.echo(f"enrolled validator_key={n.key.public.hex} api_key stored in {n.cfg.state_dir / 'api_key'}")


@app.command()
def run():
    n = _neuron()
    try:
        asyncio.run(n.run())
    except KeyboardInterrupt:
        pass


@app.command()
def qualify(node_id: str, kind: str = "full"):
    n = _neuron()

    async def go():
        await n.ensure_enrolled()
        from .qualify import qualify_node

        nodes = {x["node_id"]: x for x in await n.platform.nodes()}
        rec = await qualify_node(n.cfg, n.platform, n.sessions, nodes[node_id], kind=kind)
        typer.echo(rec.model_dump_json(by_alias=True, indent=1))

    asyncio.run(go())


@app.command()
def canary(node_id: str):
    n = _neuron()

    async def go():
        await n.ensure_enrolled()
        from .canary import run_canary

        nodes = {x["node_id"]: x for x in await n.platform.nodes()}
        res = await run_canary(n.cfg, n.platform, n.sessions, nodes[node_id])
        typer.echo(res.model_dump_json(by_alias=True, indent=1))

    asyncio.run(go())


@app.command()
def score():
    n = _neuron()

    async def go():
        await n.ensure_enrolled()
        res = await n.score_and_set_weights(dt.datetime.now(dt.UTC))
        typer.echo(json.dumps({"scores": res.scores, "funded": res.funded, "hotkey_weights": res.hotkey_weights, "burn": res.burn}, indent=1))

    asyncio.run(go())
