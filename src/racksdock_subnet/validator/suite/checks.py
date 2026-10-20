"""Qualification checks Q1–Q16 (docs/03 §4). Each check: commands -> parse -> evaluate against spec, reference and thresholds."""
from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from racksdock_subnet.core import specdata
from racksdock_subnet.core.profile import Profile
from racksdock_subnet.core.profile import current as current_profile
from racksdock_subnet.core.schemas import CheckResult
from racksdock_subnet.verifier.inventory import GpuInventory
from racksdock_subnet.verifier.sku import check_sku

from . import parsers as P
from .runner import CommandRunner

NVSMI_FIELDS = ["index", "name", "serial", "pci_device_id", "vbios", "memory_total_mib", "power_limit_w"]
WEEKLY = {"Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "Q9", "Q11", "Q12", "Q13"}


@dataclass
class Ctx:
    runner: CommandRunner
    reference: str
    dev_mode: bool
    claimed_vcpus: int
    measured: dict[str, float] = field(default_factory=dict)  # dotted metric -> value (feeds SpecMeasured and perf)
    extra: dict[str, Any] = field(default_factory=dict)
    profile: Profile = field(default_factory=current_profile)

    @property
    def gpu_count(self) -> int:
        return self.profile.gpu_count

    def ref(self, key: str) -> float:
        return float(specdata.reference_set(self.reference)["values"][key])

    @property
    def floor(self) -> float:
        return specdata.thresholds()["ratio_floor"]


def _norm_pci(pci: str) -> str:
    pci = pci.lower()
    if pci.startswith("0x") and len(pci) == 10:
        return f"{pci[6:10]}:{pci[2:6]}"
    return pci


# Q1 is attestation and is performed by qualify.py from the boot evidence; it is recorded as a CheckResult there.


async def q2_sku(ctx: Ctx) -> CheckResult:
    r = await ctx.runner.run(f"nvidia-smi --query-gpu={','.join(['index','name','serial','pci.device_id','vbios_version','memory.total','power.limit'])} --format=csv,noheader,nounits")
    rows = P.parse_nvidia_smi_csv(r.stdout, NVSMI_FIELDS)
    q = await ctx.runner.run("nvidia-smi -q")
    parts = P.parse_board_parts(q.stdout)
    inv = []
    for i, row in enumerate(rows):
        inv.append(GpuInventory(index=int(row["index"]), name=row["name"], serial=row["serial"], pci_device_id=_norm_pci(row["pci_device_id"]), vbios=row["vbios"],
                                memory_total_mib=int(float(row["memory_total_mib"])), power_limit_w=float(row["power_limit_w"]), board_part=parts[i] if i < len(parts) else ""))
    ok, errors, details = check_sku(inv, ctx.dev_mode, expected=ctx.gpu_count)
    ctx.extra["inventory"] = [g.model_dump() for g in inv]
    if inv:
        ctx.extra["gpu_board_part"] = inv[0].board_part
        ctx.extra["gpu_vbios"] = inv[0].vbios
        ctx.extra["gpu_pci_id"] = inv[0].pci_device_id
        ctx.measured["power_profile.limit_w"] = min(g.power_limit_w for g in inv)
    return CheckResult(id="Q2", name="SKU allowlist", passed=ok, details={**details, "errors": errors, "count": len(inv)})


async def q3_memory(ctx: Ctx) -> CheckResult:
    r = await ctx.runner.run("sudo docker run --rm --gpus all racksdock/memtest:pinned || racksdock-memtest", timeout=1800)
    kv = P.parse_kv_lines(r.stdout)
    usable = [float(v) for k, v in kv.items() if k.endswith(".usable_gb")]
    floor = specdata.hbm_floor_gb(ctx.extra.get("gpu_pci_id", ""), ctx.dev_mode) or ctx.ref("gpu.vram_gb_usable_min") * ctx.floor
    ok = len(usable) == ctx.gpu_count and min(usable) >= floor and kv.get("verify") == "ok"
    if usable:
        ctx.measured["gpu.vram_gb_usable_min"] = min(usable)
    if "hbm_write_gbps" in kv:
        ctx.measured["hbm_write_gbps"] = float(kv["hbm_write_gbps"])
    return CheckResult(id="Q3", name="GPU memory capacity", passed=ok, details={"usable_gb": usable, "floor_gb": floor, "verify": kv.get("verify")})


async def q4_dcgm(ctx: Ctx, level: int = 3) -> CheckResult:
    r = await ctx.runner.run(f"sudo dcgmi diag -r {level} -j", timeout=3 * 3600)
    try:
        d = P.parse_dcgm_diag(r.stdout)
    except ValueError:
        return CheckResult(id="Q4", name="DCGM diagnostics", passed=False, error="unparseable dcgmi output", details={"stderr": r.stderr[:300]})
    mandatory = {"Memory", "PCIe", "Targeted Stress", "Memory Bandwidth", "Diagnostic"} if level >= 3 else ({"Memory", "PCIe"} if level == 2 else set())
    missing = sorted(m for m in mandatory if m not in d["ran"])
    ok = not d["failed"] and not missing
    return CheckResult(id="Q4", name="DCGM diagnostics", passed=ok, skipped=bool(missing) and not d["failed"],
                       details={"failed": d["failed"], "skipped": d["skipped"], "missing_mandatory": missing, "ran": len(d["ran"])})


async def q5_topology(ctx: Ctx) -> CheckResult:
    r = await ctx.runner.run("nvidia-smi topo -m")
    t = P.parse_topo(r.stdout, expected_gpus=ctx.gpu_count)
    return CheckResult(id="Q5", name="NVLink/NVSwitch topology", passed=bool(t["full_nvlink"]), details=t)


async def q6_d2d(ctx: Ctx) -> CheckResult:
    r = await ctx.runner.run("nvbandwidth -t device_to_device_memcpy_read_ce", timeout=1800)
    b = P.parse_nvbandwidth(r.stdout)
    ref_pair = ctx.ref("nvlink.d2d_gbps_min_pair")
    ok = b["min_pair_gbps"] >= ref_pair * ctx.floor and (b["median_pair_gbps"] == 0 or b["min_pair_gbps"] >= b["median_pair_gbps"] * specdata.thresholds()["pair_outlier_floor_of_node_median"])
    ctx.measured["nvlink.d2d_gbps_min_pair"] = b["min_pair_gbps"]
    ctx.measured["nvlink.d2d_gbps_aggregate"] = b["aggregate_gbps"]
    return CheckResult(id="Q6", name="GPU-to-GPU bandwidth", passed=ok, details={"min_pair_gbps": b["min_pair_gbps"], "median_pair_gbps": b["median_pair_gbps"], "aggregate_gbps": b["aggregate_gbps"], "ref_pair": ref_pair})


async def q7_h2d(ctx: Ctx) -> CheckResult:
    r = await ctx.runner.run("nvbandwidth -t host_to_device_memcpy_ce", timeout=900)
    b = P.parse_nvbandwidth(r.stdout)
    return CheckResult(id="Q7", name="Host-device bandwidth", passed=True, details={"aggregate_gbps": b["aggregate_gbps"]})


async def q8_collectives(ctx: Ctx) -> CheckResult:
    results = {}
    ok = True
    for op in ("all_reduce", "all_gather", "reduce_scatter", "alltoall"):
        r = await ctx.runner.run(f"{op}_perf -b 1K -e 8G -f 2 -g {ctx.profile.nccl_gpus} -c 1", timeout=1800)
        n = P.parse_nccl_tests(r.stdout)
        results[op] = {"busbw_1gb": n["busbw_1gb"], "avg": n["avg_busbw_gbps"], "wrong": n["wrong"]}
        if n["wrong"] or not n["rows"]:
            ok = False
        if op == "all_reduce":
            ref = ctx.ref("nvlink.allreduce_1gb_busbw_gbps")
            if (n["busbw_1gb"] or 0) < ref * ctx.floor:
                ok = False
            ctx.measured["nvlink.allreduce_1gb_busbw_gbps"] = n["busbw_1gb"] or 0.0
    return CheckResult(id="Q8", name="NCCL collectives", passed=ok, details=results)


async def q9_cpu(ctx: Ctx) -> CheckResult:
    cpu = P.parse_lscpu((await ctx.runner.run("lscpu")).stdout)
    st = P.parse_stream((await ctx.runner.run("stream_c.exe 2>/dev/null || stream 2>/dev/null || racksdock-stream", timeout=600)).stdout)
    sb = P.parse_sysbench((await ctx.runner.run("sysbench cpu --threads=$(nproc) --time=60 run", timeout=600)).stdout)
    vcpus = cpu.get("cpus", 0)
    ctx.measured["cpu.vcpus"] = vcpus
    ctx.measured["cpu.stream_gbps"] = st.get("triad_gbps", 0.0)
    ctx.measured["cpu.sysbench"] = sb["events_per_s"]
    ctx.extra["cpu_model"] = cpu.get("model", "")
    ok = vcpus >= ctx.claimed_vcpus and st.get("triad_gbps", 0) >= ctx.ref("cpu.stream_gbps") * ctx.floor and sb["events_per_s"] >= ctx.ref("cpu.sysbench") * ctx.floor
    return CheckResult(id="Q9", name="CPU", passed=ok, details={"vcpus": vcpus, "claimed": ctx.claimed_vcpus, "stream_triad_gbps": st.get("triad_gbps"), "sysbench": sb["events_per_s"], "model": cpu.get("model")})


async def q10_ram(ctx: Ctx) -> CheckResult:
    m = P.parse_meminfo((await ctx.runner.run("cat /proc/meminfo")).stdout)
    t = P.parse_kv_lines((await ctx.runner.run("racksdock-ramtest --fraction 0.9 || sudo memtester 64G 1", timeout=3600)).stdout)
    ctx.measured["memory_gb"] = m["total_gb"]
    ok = m["total_gb"] >= ctx.ref("memory_gb") * ctx.floor and t.get("verify", "ok") == "ok"
    return CheckResult(id="Q10", name="RAM", passed=ok, details={"total_gb": round(m["total_gb"], 1), "verify": t.get("verify")})


async def q11_nvme(ctx: Ctx, sustained: bool = True) -> CheckResult:
    lb = P.parse_lsblk_json((await ctx.runner.run("lsblk -J -b -o NAME,SIZE,TYPE,MOUNTPOINT")).stdout)
    cmd = (f"mkdir -p {ctx.profile.fio_dir} && fio --output-format=json --directory={ctx.profile.fio_dir} --size=8G --direct=1 --ioengine=libaio "
           "--name=seqread --rw=read --bs=1M --iodepth=32 --runtime=60 --time_based "
           "--name=seqwrite --rw=write --bs=1M --iodepth=32 --runtime=60 --time_based "
           "--name=randread --rw=randread --bs=4k --iodepth=32 --numjobs=8 --group_reporting --runtime=60 --time_based "
           "--name=randwrite --rw=randwrite --bs=4k --iodepth=32 --numjobs=8 --group_reporting --runtime=60 --time_based")
    if sustained:
        cmd += f" --name=sustained --rw=write --bs=1M --iodepth=32 --runtime={int(ctx.profile.extra.get('fio_sustained_s', 600))} --time_based"
    f = P.parse_fio_json((await ctx.runner.run(cmd, timeout=3600)).stdout)
    data_tb = sum(d["size_bytes"] for d in lb["devices"] if d["mountpoint"] == ctx.profile.fio_dir) / 1e12
    if data_tb == 0:  # no dedicated data mount (dev profiles): use the largest block device
        data_tb = max((d["size_bytes"] for d in lb["devices"] if d["type"] in ("disk", "crypt")), default=0) / 1e12
    vals = {"nvme.capacity_tb": data_tb, "nvme.seq_read_gbps": f.get("seqread", {}).get("read_bw_gbps", 0), "nvme.seq_write_gbps": f.get("seqwrite", {}).get("write_bw_gbps", 0),
            "nvme.rand_read_kiops": f.get("randread", {}).get("read_iops", 0) / 1000, "nvme.rand_write_kiops": f.get("randwrite", {}).get("write_iops", 0) / 1000}
    if sustained:
        vals["nvme.sustained_write_gbps"] = f.get("sustained", {}).get("write_bw_gbps", 0)
    ctx.measured.update(vals)
    ok = all(v >= ctx.ref(k) * ctx.floor for k, v in vals.items())
    return CheckResult(id="Q11", name="NVMe", passed=ok, details={k: round(v, 2) for k, v in vals.items()})


async def q12_network(ctx: Ctx, endpoints: list[str] | None = None, seconds: int = 60) -> CheckResult:
    endpoints = endpoints or ctx.extra.get("iperf_endpoints") or ["iperf.racksdock-validator.local"]
    res = []
    for ep in endpoints:
        up = P.parse_iperf3_json((await ctx.runner.run(f"iperf3 -J -c {ep} -t {seconds} -P 8", timeout=seconds + 60)).stdout)
        down = P.parse_iperf3_json((await ctx.runner.run(f"iperf3 -J -c {ep} -t {seconds} -P 8 -R", timeout=seconds + 60)).stdout)
        res.append({"endpoint": ep, "up_gbps": round(up["sent_gbps"], 2), "down_gbps": round(down["received_gbps"], 2), "lost_percent": max(up["lost_percent"], down["lost_percent"])})
    best = max(res, key=lambda x: x["down_gbps"])
    ctx.measured["network.down_gbps"] = best["down_gbps"]
    ctx.measured["network.up_gbps"] = best["up_gbps"]
    ctx.extra["network_endpoints"] = res
    ok = best["down_gbps"] >= ctx.ref("network.down_gbps") * ctx.floor and best["up_gbps"] >= ctx.ref("network.up_gbps") * ctx.floor and best["lost_percent"] < 0.1
    return CheckResult(id="Q12", name="Network", passed=ok, details={"endpoints": res})


async def q13_power(ctx: Ctx, minutes: int | None = None) -> CheckResult:
    minutes = minutes or int(ctx.profile.extra.get("power_minutes", 20))
    cmd = (f"(sudo docker run -d --rm --name b300load --gpus all racksdock/train-bench:pinned --minutes {minutes} >/dev/null 2>&1 || true); "
           f"nvidia-smi --query-gpu=index,power.limit,clocks_throttle_reasons.active,clocks.sm --format=csv,noheader,nounits -l 10 -c {minutes * 6}")
    s = P.parse_power_samples((await ctx.runner.run(cmd, timeout=minutes * 60 + 120)).stdout)
    if ctx.profile.production:
        approved = specdata.allowlist()["power_profile"].get("sim_gpu_power_limit_w" if ctx.dev_mode else "gpu_power_limit_w") or ctx.ref("power_profile.limit_w")
    else:
        approved = ctx.profile.power_limit_w  # 0 = not enforced on dev hardware
    ok = s["min_limit_w"] >= approved - 1 and s["throttled_samples"] == 0 and s["samples"] > 0
    ctx.measured["power_profile.limit_w"] = s["min_limit_w"]
    ctx.extra["power_approved"] = ok
    return CheckResult(id="Q13", name="Power and clock profile", passed=ok, details={"min_limit_w": s["min_limit_w"], "approved_w": approved, "throttled_samples": s["throttled_samples"], "samples": s["samples"]})


async def q14_training(ctx: Ctx, minutes: int = 15) -> CheckResult:
    kv = P.parse_kv_lines((await ctx.runner.run(f"sudo docker run --rm --gpus all racksdock/train-bench:pinned --minutes {minutes} || racksdock-train-bench", timeout=minutes * 60 + 600)).stdout)
    tps = float(kv.get("tokens_per_s", 0))
    p50, p95 = float(kv.get("step_time_p50_ms", 1) or 1), float(kv.get("step_time_p95_ms", 0) or 0)
    ctx.measured["training_tokens_per_s"] = tps
    ok = tps >= ctx.ref("training_tokens_per_s") * ctx.floor and (p95 / p50) <= 1.15
    return CheckResult(id="Q14", name="Representative training", passed=ok, details={"tokens_per_s": tps, "p95_over_p50": round(p95 / p50, 3)})


async def q15_inference(ctx: Ctx, minutes: int = 10) -> CheckResult:
    kv = P.parse_kv_lines((await ctx.runner.run(f"sudo docker run --rm --gpus all racksdock/infer-bench:pinned --minutes {minutes} || racksdock-infer-bench", timeout=minutes * 60 + 600)).stdout)
    tps = float(kv.get("tokens_per_s", 0))
    ctx.measured["inference_tokens_per_s"] = tps
    return CheckResult(id="Q15", name="Representative inference", passed=tps >= ctx.ref("inference_tokens_per_s") * ctx.floor, details={"tokens_per_s": tps})


FULL_ORDER: list[Callable[[Ctx], Awaitable[CheckResult]]] = [q2_sku, q3_memory, q4_dcgm, q5_topology, q6_d2d, q7_h2d, q8_collectives, q9_cpu, q10_ram, q11_nvme, q12_network, q13_power, q14_training, q15_inference]


async def run_suite(ctx: Ctx, kind: str = "full") -> list[CheckResult]:
    """Runs the checks the profile enables for this kind (docs/03 §4; profile files in core/spec/profiles)."""
    results = []
    for fn in FULL_ORDER:
        cid = fn.__name__.split("_")[0].upper()
        if not ctx.profile.enabled(cid, kind):
            continue
        t0 = time.perf_counter()
        try:
            if fn is q4_dcgm:
                res = await q4_dcgm(ctx, level=ctx.profile.dcgm_level_weekly if kind == "weekly" else ctx.profile.dcgm_level)
            elif kind == "weekly" and fn is q11_nvme:
                res = await q11_nvme(ctx, sustained=False)
            elif kind == "weekly" and fn is q13_power:
                res = await q13_power(ctx, minutes=min(5, int(ctx.profile.extra.get("power_minutes", 20))))
            else:
                res = await fn(ctx)
        except Exception as e:
            res = CheckResult(id=cid, name=fn.__name__, passed=False, error=f"{type(e).__name__}: {e}")
        res.duration_s = round(time.perf_counter() - t0, 3)
        results.append(res)
        if cid in ("Q2", "Q3", "Q5") and not res.passed:
            break  # fail fast on identity/SKU/topology
    return results


async def smoke(ctx: Ctx) -> dict[str, Any]:
    """Canary smoke (docs/03 §6): one all_reduce at 1 GB, fio 30 s, iperf 10 s, memory residue check."""
    if ctx.profile.enabled("Q8"):
        n = P.parse_nccl_tests((await ctx.runner.run(f"all_reduce_perf -b 1G -e 1G -g {ctx.profile.nccl_gpus} -c 1", timeout=600)).stdout)
    else:
        n = {"busbw_1gb": None, "wrong": 0}
    f = P.parse_fio_json((await ctx.runner.run(f"mkdir -p {ctx.profile.fio_dir} && fio --output-format=json --directory={ctx.profile.fio_dir} --size=2G --direct=1 --ioengine=libaio --name=seqwrite --rw=write --bs=1M --iodepth=32 --runtime=30 --time_based", timeout=120)).stdout)
    ip = P.parse_iperf3_json((await ctx.runner.run("iperf3 -J -c iperf.racksdock-validator.local -t 10 -P 4 -R", timeout=60)).stdout)
    marker = P.parse_kv_lines((await ctx.runner.run("racksdock-marker check")).stdout)
    mem = P.parse_kv_lines((await ctx.runner.run("racksdock-memtest --quick")).stdout)
    return {"allreduce_1gb_busbw_gbps": n["busbw_1gb"], "nccl_wrong": n["wrong"], "fio_seq_write_gbps": f.get("seqwrite", {}).get("write_bw_gbps"),
            "iperf_down_gbps": ip["received_gbps"], "marker": marker.get("marker"), "gpu_memory_verify": mem.get("verify")}
