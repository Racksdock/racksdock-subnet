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
from .snapshot import build_inputs, evidence_window
from .weights import set_weights

log = logging.getLogger("racksdock.validator")


class Verifier:
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
        # the platform's verifier (docs/03 §1): verifies nodes and publishes records, never scores or touches the chain
        self.chain = None if cfg.role == "verifier" else build_chain(cfg.chain_kind, path=cfg.chain_file, netuid=cfg.netuid, network=cfg.chain_network, wallet_name=cfg.wallet_name, wallet_hotkey=cfg.wallet_hotkey, wallet_path=cfg.wallet_path)
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
        if self.chain is not None:
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
            # new node -> admission + full qualification; admitted (admission passed, no full record yet, e.g. after a validator
            # restart in between) -> full qualification only
            if n["status"] in ("registered", "admitted") and lease is None:
                self._spawn(nid, self._admit_and_qualify(n, skip_admission=n["status"] == "admitted"))
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
                    asyncio.create_task(check_instance(self.cfg, self.platform, self.sessions.verifier_for(n), lease, n, micro, approved))  # the node's own GPU count
        if self.cfg.role != "verifier" and now - self.tempo_start >= self.cfg.tempo_s:
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
            # a session that could not even start (host unreachable, launch refused) must not be retried on the next loop
            # iteration: back the node off like a quarantine retry (seen: 48 error instances in two minutes on a dead host)
            self.last_requal[node_id] = time.time()
            self._save_state()
        finally:
            self.busy.discard(node_id)

    async def _admit_and_qualify(self, node: dict, skip_admission: bool = False) -> None:
        if self.cfg.qualification_full and not skip_admission:
            adm = await admission_test(self.cfg, self.platform, self.sessions, node)
            if adm.outcome != "pass":
                log.warning("admission failed for %s: %s", node["node_id"][:16], adm.failing_checks)
                return
        await qualify_node(self.cfg, self.platform, self.sessions, node, kind="full")
        # whatever the outcome: a quarantined first attempt waits retry_quarantined_s like any other retry (the miner needs time
        # to fix the node; re-running at once only repeats the failure)
        self.last_requal[node["node_id"]] = time.time()
        self._save_state()

    async def _requal_full(self, node: dict) -> None:
        """Retry a quarantined node. When the quarantine came from environment checks only (network, disk, CPU, RAM, power), re-run
        just those on a fresh session and keep the previous results for the rest; identity/GPU failures re-run the full suite."""
        from .qualify import plan_targeted_retry

        base = None
        try:
            recs = list(reversed(await self.platform.evidence(node_id=node["node_id"], kind="qualification", limit=50, desc="true")))
            fulls = [r["envelope"]["payload"] for r in recs if r["envelope"]["payload"].get("kind") == "full"]
            base = fulls[-1] if fulls else None
        except Exception as e:
            log.warning("could not fetch the last qualification of %s: %s", node["node_id"][:16], e)
        from racksdock_subnet.core.profile import load as load_profile

        from .suite.checks import planned_checks

        try:
            planned = planned_checks(load_profile(node.get("profile") or (node.get("registration") or {}).get("profile") or "b300x8"), "full")
        except Exception:
            planned = None
        only = plan_targeted_retry(base, planned)
        if only:
            log.info("retry of quarantined node %s: re-running only %s", node["node_id"][:16], sorted(only))
        rec = await qualify_node(self.cfg, self.platform, self.sessions, node, kind="full", only=only, base=base if only else None)
        log.info("retry of quarantined node %s -> %s %s", node["node_id"][:16], rec.outcome, rec.failing_checks)

    async def _requal(self, node: dict) -> None:
        try:
            rec = await qualify_node(self.cfg, self.platform, self.sessions, node, kind="weekly")
            log.info("weekly requal %s -> %s", node["node_id"][:16], rec.outcome)
        finally:
            self.last_requal[node["node_id"]] = time.time()  # pass, quarantine or crash: the next attempt waits the interval
            self._save_state()

    # ------------------------------------------------------------------ scoring
    async def score_and_set_weights(self, now: dt.datetime, tempo_s: float | None = None):
        if self.chain is None:
            raise RuntimeError("a verifier (RACKSDOCK_ROLE=verifier) never scores or sets weights; validators run `racksdock-validator run`")
        tempo_s = tempo_s or self.cfg.tempo_s
        window_start = now - dt.timedelta(seconds=tempo_s)
        nodes = await self.platform.nodes()
        leases = await self.platform.leases(live_only=False)
        # per kind, everything since the window's cut-off (docs/04): the same bounds the platform uses for the light snapshot
        evidence = []
        for kind, since in evidence_window(window_start).items():
            evidence += list(reversed(await self.platform.evidence(kind=kind, since=since, limit=1000, desc="true")))
        evidence.sort(key=lambda e: e["id"])
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

    async def reclaim_own_instances(self) -> None:
        """A validator restarted mid-session leaves its verify instance live on the node (lease held, VM running). Nobody else
        may delete it, so delete it ourselves at start; the node's readiness canary then clears the way (seen on the 8x4090 test)."""
        try:
            mine = await self.platform.instances()
        except Exception as e:
            log.warning("could not list own instances: %s", e)
            return
        for inst in mine:
            if inst.get("status") in ("creating", "pending_provider", "pending", "active", "degraded"):
                log.warning("reclaiming orphaned verify instance %s (%s) from a previous validator process", inst["id"], inst.get("status"))
                try:
                    await self.platform.delete_instance(inst["id"])
                except Exception as e:
                    log.warning("delete of %s failed: %s", inst["id"], e)

    async def run(self) -> None:
        await self.ensure_enrolled()
        await self.reclaim_own_instances()
        from racksdock_subnet.core.profile import current as current_profile

        prof = current_profile()
        log.info("%s started: key=%s hotkey=%s platform=%s profile=%s runner=%s trust=%s tempo=%ss canary_mean=%ss inrental=%ss",
                 "verifier" if self.cfg.role == "verifier" else "all-in-one (verify + score; simulations only)", self.key.public.hex[:12], self.cfg.hotkey, self.cfg.platform_url, prof.name, self.cfg.runner, self.cfg.trust.mode,
                 int(self.cfg.tempo_s), int(self.cfg.canary_mean_interval_s), int(self.cfg.inrental_interval_s))
        last_status = 0.0
        while not self._stop.is_set():
            try:
                await self.step()
            except Exception as e:
                log.exception("step failed: %s", e)
            if time.time() - last_status >= 60:
                last_status = time.time()
                await self._log_status()
            await asyncio.sleep(self.cfg.loop_interval_s)

    async def _log_status(self) -> None:
        """One line per minute so an idle validator is visibly alive."""
        try:
            nodes = await self.platform.nodes()
            leases = await self.platform.leases(live_only=True)
        except Exception as e:
            log.warning("status: platform unreachable (%s)", e)
            return
        by_status: dict[str, int] = {}
        for n in nodes:
            by_status[n["status"]] = by_status.get(n["status"], 0) + 1
        now = time.time()
        next_canary = min((t - now for t in self.canaries.next_at.values()), default=None)
        log.info("status: nodes=%d %s | live leases=%d (tenant %d) | busy=%d | %s | next idle canary in %s",
                 len(nodes), by_status, len(leases), sum(1 for lease in leases if not lease["is_validator"]), len(self.busy),
                 "verifier: no scoring" if self.cfg.role == "verifier" else f"next scoring in {int(self.cfg.tempo_s - (now - self.tempo_start))}s", f"{int(next_canary)}s" if next_canary is not None else "n/a")

    def stop(self) -> None:
        self._stop.set()


ValidatorNeuron = Verifier  # former name (the verifier used to score as well); kept for older scripts
