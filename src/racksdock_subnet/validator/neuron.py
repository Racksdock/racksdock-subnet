"""Validator main loop."""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import time

from racksdock_subnet.core.chainclient import build_chain
from racksdock_subnet.core.keys import SigningKey
from racksdock_subnet.verifier.verifiers import build_verifier

from .admission import admission_test
from .canary import CanaryScheduler, run_canary
from .config import ValidatorConfig
from .inrental import check_instance, probe_lease
from .platform import PlatformClient
from .qualify import Sessions, qualify_node
from .scorer import Params, score_tempo
from .snapshot import build_inputs
from .weights import set_weights

log = logging.getLogger("racksdock.validator")


class ValidatorNeuron:
    def __init__(self, cfg: ValidatorConfig):
        self.cfg = cfg
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.key = SigningKey.load_or_create(cfg.state_dir / "validator.seed")
        self.ssh_key = SigningKey.load_or_create(cfg.state_dir / "ssh.seed")
        self.ssh_key_path = cfg.state_dir / "ssh_ed25519"
        if not self.ssh_key_path.exists():
            self.ssh_key_path.write_bytes(self.ssh_key.to_openssh_private())
            self.ssh_key_path.chmod(0o600)
        self.ssh_pub_line = self.ssh_key.public.ssh_public_line("racksdock-validator")
        self.platform = PlatformClient(cfg.platform_url, cfg.api_key, self.key)
        if cfg.trust.dev and cfg.trust.dev_ca_dir is not None and not (cfg.trust.dev_ca_dir / "root.pem").exists():
            from racksdock_subnet.verifier.cli import fetch_devca

            fetch_devca(cfg.platform_url, cfg.trust.dev_ca_dir)  # the platform publishes the simulated root (NVIDIA's role in dev mode)
            log.warning("dev trust mode: fetched the simulated device CA from %s", cfg.platform_url)
        self.verifier = build_verifier(cfg.trust)
        self.chain = build_chain(cfg.chain_kind, path=cfg.chain_file, netuid=cfg.netuid, network=cfg.chain_network)
        self.sessions = Sessions(cfg, self.platform, self.verifier, self.ssh_pub_line, str(self.ssh_key_path), poll_s=0.5 if cfg.runner == "sim" else 3.0)
        self.canaries = CanaryScheduler(cfg.canary_mean_interval_s)
        self.last_inrental: dict[str, float] = {}
        self.last_microbench: dict[str, float] = {}
        self.last_probe: dict[str, float] = {}
        self.last_requal: dict[str, float] = {}
        self.tempo_start = time.time()
        self.previously_funded: set[str] = set()
        self.busy: set[str] = set()
        self._stop = asyncio.Event()
        self._stats_path = cfg.state_dir / "state.json"
        self._load_state()

    def _load_state(self) -> None:
        try:
            st = json.loads(self._stats_path.read_text())
            self.last_requal = st.get("last_requal", {})
            self.previously_funded = set(st.get("previously_funded", []))
        except (OSError, ValueError):
            pass

    def _save_state(self) -> None:
        self._stats_path.write_text(json.dumps({"last_requal": self.last_requal, "previously_funded": sorted(self.previously_funded)}))

    async def ensure_enrolled(self) -> None:
        if not self.cfg.api_key:
            key_file = self.cfg.state_dir / "api_key"
            if key_file.exists():
                self.platform.c.headers["X-API-KEY"] = key_file.read_text().strip()
            else:
                k = await self.platform.enroll(self.cfg.hotkey)
                key_file.write_text(k)
            self.cfg.api_key = self.platform.c.headers["X-API-KEY"]
        try:
            self.chain.register(self.cfg.hotkey, is_validator=True, stake=1.0)
        except NotImplementedError:
            pass

    # ------------------------------------------------------------------ one iteration
    async def step(self, now: float | None = None) -> None:
        now = now or time.time()
        nodes = await self.platform.nodes()
        leases = await self.platform.leases(live_only=True)
        live_by_node = {lease["node_id"]: lease for lease in leases}
        for n in nodes:
            nid = n["node_id"]
            if nid in self.busy or not n.get("host_connected"):
                continue
            lease = live_by_node.get(nid)
            # new or quarantined node without a passing qualification -> admission + full qualification
            if n["status"] == "registered" and lease is None:
                self._spawn(nid, self._admit_and_qualify(n))
                continue
            # quarantined: retry a full qualification after the retry interval (the miner may have fixed the node)
            if n["status"] == "quarantined" and lease is None and now - self.last_requal.get(nid, 0) > self.cfg.retry_quarantined_s:
                self.last_requal[nid] = now
                self._save_state()
                self._spawn(nid, self._requal_full(n))
                continue
            if n["status"] == "qualified" and lease is None:
                # readiness canary after a tenant rental
                if n.get("needs_readiness"):
                    self._spawn(nid, run_canary(self.cfg, self.platform, self.sessions, n, kind="readiness"))
                    continue
                # weekly re-qualification
                if now - self.last_requal.get(nid, 0) > self.cfg.requal_interval_s:
                    self._spawn(nid, self._requal(n))
                    continue
                # idle canary
                if self.canaries.due(nid, now):
                    self.canaries.schedule_next(nid, now)
                    self._spawn(nid, run_canary(self.cfg, self.platform, self.sessions, n, kind="idle"))
                    continue
            if lease is not None and not lease["is_validator"] and lease.get("status") in ("active", "degraded"):
                iid = lease["instance_id"]
                if now - self.last_probe.get(iid, 0) >= self.cfg.reachability_interval_s:
                    self.last_probe[iid] = now
                    asyncio.create_task(probe_lease(self.platform, lease))
                if now - self.last_inrental.get(iid, 0) >= self.cfg.inrental_interval_s:
                    self.last_inrental[iid] = now
                    micro = now - self.last_microbench.get(iid, 0) >= self.cfg.microbench_interval_s
                    if micro:
                        self.last_microbench[iid] = now
                    approved = float(((n.get("qualification") or {}).get("spec_measured") or {}).get("power_profile", {}).get("limit_w") or 0)
                    asyncio.create_task(check_instance(self.cfg, self.platform, self.verifier, lease, n, micro, approved))
        if now - self.tempo_start >= self.cfg.tempo_s:
            self.tempo_start = now
            await self.score_and_set_weights(dt.datetime.now(dt.UTC))

    def _spawn(self, node_id: str, coro) -> asyncio.Task:
        self.busy.add(node_id)  # mark busy synchronously so a caller sees it before the task starts
        return asyncio.create_task(self._guard(node_id, coro))

    async def _guard(self, node_id: str, coro) -> None:
        try:
            await coro
        except Exception as e:
            log.exception("task for %s failed: %s", node_id[:16], e)
        finally:
            self.busy.discard(node_id)

    async def _admit_and_qualify(self, node: dict) -> None:
        if self.cfg.qualification_full:
            adm = await admission_test(self.cfg, self.platform, self.sessions, node)
            if adm.outcome != "pass":
                log.warning("admission failed for %s: %s", node["node_id"][:16], adm.failing_checks)
                return
        rec = await qualify_node(self.cfg, self.platform, self.sessions, node, kind="full")
        if rec.outcome == "pass":
            self.last_requal[node["node_id"]] = time.time()
            self._save_state()

    async def _requal_full(self, node: dict) -> None:
        rec = await qualify_node(self.cfg, self.platform, self.sessions, node, kind="full")
        log.info("retry of quarantined node %s -> %s %s", node["node_id"][:16], rec.outcome, rec.failing_checks)

    async def _requal(self, node: dict) -> None:
        rec = await qualify_node(self.cfg, self.platform, self.sessions, node, kind="weekly")
        self.last_requal[node["node_id"]] = time.time()
        self._save_state()
        log.info("weekly requal %s -> %s", node["node_id"][:16], rec.outcome)

    # ------------------------------------------------------------------ scoring
    async def score_and_set_weights(self, now: dt.datetime, tempo_s: float | None = None):
        tempo_s = tempo_s or self.cfg.tempo_s
        window_start = now - dt.timedelta(seconds=tempo_s)
        nodes = await self.platform.nodes()
        leases = await self.platform.leases(live_only=False)
        evidence = [e for e in await self.platform.evidence(limit=1000) if e["kind"] in ("canary", "inrental", "probe")]
        verification = {}
        for n in nodes:
            try:
                verification[n["node_id"]] = await self.platform.node_verification(n["node_id"])
            except RuntimeError:
                verification[n["node_id"]] = {}
        settings = await self.platform.settings()
        params = Params(funded_slots=int(settings.get("funded_slots", 64)))
        inputs = build_inputs(nodes, leases, evidence, verification, window_start, now, self.key.public.hex, self.previously_funded)
        rented = sum(i.minutes_rented for i in inputs)
        avail = sum(i.minutes_available for i in inputs)
        util = rented / (rented + avail) if (rented + avail) > 0 else 0.0
        result = score_tempo(inputs, now, tempo_s / 60, params, utilization_7d=util)
        self.previously_funded = set(result.funded)
        self._save_state()
        weights = set_weights(self.chain, self.cfg.hotkey, result)
        await self.platform.publish("scoring", {"window_start": window_start.isoformat(), "window_end": now.isoformat(), "scores": result.scores, "funded": result.funded,
                                                "hotkey_weights": result.hotkey_weights, "burn": result.burn, "details": result.details, "weights": {str(k): v for k, v in weights.items()}})
        return result

    async def run(self) -> None:
        await self.ensure_enrolled()
        while not self._stop.is_set():
            try:
                await self.step()
            except Exception as e:
                log.exception("step failed: %s", e)
            await asyncio.sleep(self.cfg.loop_interval_s)

    def stop(self) -> None:
        self._stop.set()
