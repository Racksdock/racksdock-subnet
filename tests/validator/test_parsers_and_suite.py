import asyncio
import json

import pytest

from racksdock_subnet.validator.suite import parsers as P
from racksdock_subnet.validator.suite.checks import Ctx, run_suite, smoke
from racksdock_subnet.validator.suite.reference import gate_ok, perf_score, ratios
from racksdock_subnet.validator.suite.runner import SimProfile, SimRunner


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_parsers_on_simulated_real_formats():
    r = SimRunner()
    out = run(r.run("nvbandwidth -t device_to_device_memcpy_read_ce")).stdout
    b = P.parse_nvbandwidth(out)
    assert len(b["matrix"]) == 8 and b["min_pair_gbps"] > 700 and b["sums"]["device_to_device_memcpy_read_ce"] > 6000
    n = P.parse_nccl_tests(run(r.run("all_reduce_perf -b 1K -e 8G -f 2 -g 8 -c 1")).stdout)
    assert n["busbw_1gb"] and n["wrong"] == 0 and n["avg_busbw_gbps"] and 1073741824 in n["by_size"]
    d = P.parse_dcgm_diag(run(r.run("sudo dcgmi diag -r 3 -j")).stdout)
    assert "memory" in d["ran"] and not d["failed"]
    f = P.parse_fio_json(run(r.run("fio --output-format=json")).stdout)
    assert f["seqwrite"]["write_bw_gbps"] > 20 and f["randread"]["read_iops"] > 1e6
    i = P.parse_iperf3_json(run(r.run("iperf3 -J -c x -t 10 -R")).stdout)
    assert i["received_gbps"] > 20
    assert P.parse_stream(run(r.run("stream_c.exe")).stdout)["triad_gbps"] > 400
    assert P.parse_sysbench(run(r.run("sysbench cpu run")).stdout)["events_per_s"] > 100000
    t = P.parse_topo(run(r.run("nvidia-smi topo -m")).stdout)
    assert t["full_nvlink"] and t["nvlink_pairs"] == 56
    pw = P.parse_power_samples(run(r.run("for i in $(seq 6); do nvidia-smi --query-gpu=index,power.limit,clocks.sm --format=csv,noheader,nounits; nvidia-smi -q -d PERFORMANCE; echo ---SAMPLE---; sleep 10; done")).stdout)
    assert pw["min_limit_w"] == 1400 and pw["throttled_samples"] == 0 and pw["samples"] == 48
    real_q = "0, 300.00, 1410\nGPU 00000000:00:05.0\n    Clocks Event Reasons\n        Idle                              : Not Active\n        SW Power Cap                      : Active\n        HW Slowdown                       : Not Active\n---SAMPLE---\n"
    pq = P.parse_power_samples(real_q)
    assert pq["samples"] == 1 and pq["min_limit_w"] == 300.0 and pq["throttled_samples"] == 1
    assert P.parse_lscpu(run(r.run("lscpu")).stdout)["cpus"] == 120
    assert P.parse_meminfo(run(r.run("cat /proc/meminfo")).stdout)["total_gb"] > 1800
    assert P.parse_lsblk_json(run(r.run("lsblk -J -b -o NAME,SIZE,TYPE,MOUNTPOINT")).stdout)["total_tb"] > 28


def test_real_world_format_samples():
    nccl = """# nThread 1 nGpus 8 minBytes 1024 maxBytes 8589934592 step: 2(factor) warmup iters: 5 iters: 20 agg iters: 1 validation: 1 graph: 0
#
#       size         count      type   redop    root     time   algbw   busbw #wrong     time   algbw   busbw #wrong
#        (B)    (elements)                               (us)  (GB/s)  (GB/s)            (us)  (GB/s)  (GB/s)
        1024           256     float     sum      -1    18.52    0.06    0.10      0    18.11    0.06    0.10      0
  1073741824     268435456     float     sum      -1  2543.1  422.21  738.87      0  2540.9  422.58  739.52      0
# Out of bounds values : 0 OK
# Avg bus bandwidth    : 369.485
"""
    n = P.parse_nccl_tests(nccl)
    assert n["busbw_1gb"] == 738.87 and n["wrong"] == 0 and n["avg_busbw_gbps"] == 369.485
    dcgm = json.dumps({"DCGM GPU Diagnostic": {"test_categories": [{"category": "Deployment", "tests": [{"name": "Denylist", "results": [{"gpu_ids": "0,1", "status": "Pass"}]}]},
                                                                   {"category": "Hardware", "tests": [{"name": "Memory", "results": [{"gpu_id": "0", "status": "Pass"}, {"gpu_id": "1", "status": "Fail", "warnings": ["x"]}]}]}]}})
    d = P.parse_dcgm_diag(dcgm)
    assert d["failed"] == ["memory"] and "denylist" in d["ran"]
    stream = "Function    Best Rate MB/s  Avg time     Min time     Max time\nCopy:          412345.6     0.0405       0.0391       0.0421\nTriad:         423456.7     0.0590       0.0570       0.0612\n"
    assert P.parse_stream(stream)["triad_gbps"] == pytest.approx(423.4567)
    pci = P.parse_nvidia_smi_csv("0, NVIDIA B300, 1650001234, 0x2B0010DE, 99.00.00.00.01, 278528, 1400.00\n", ["index", "name", "serial", "pci_device_id", "vbios", "memory_total_mib", "power_limit_w"])
    assert pci[0]["pci_device_id"] == "0x2B0010DE"


def test_suite_passes_on_healthy_profile_and_quarantines_degraded():
    ctx = Ctx(runner=SimRunner(), reference="ref_dev_v0", dev_mode=True, claimed_vcpus=120)
    results = run(run_suite(ctx, kind="full"))
    ids = [r.id for r in results]
    assert ids == ["Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8", "Q9", "Q10", "Q11", "Q12", "Q13", "Q14", "Q15"]
    assert all(r.passed for r in results), [(r.id, r.details, r.error) for r in results if not r.passed]
    r = ratios(ctx.measured, "ref_dev_v0")
    assert perf_score(r) > 0.95 and gate_ok(r)[0]
    # degraded NVLink and throttling
    bad = SimProfile(scale={"nvlink.allreduce_1gb_busbw_gbps": 0.7, "nvlink.d2d_gbps_min_pair": 0.8}, throttle=True, dcgm_fail=["Memory"])
    ctx2 = Ctx(runner=SimRunner(bad), reference="ref_dev_v0", dev_mode=True, claimed_vcpus=120)
    res2 = {r.id: r for r in run(run_suite(ctx2, kind="full"))}
    assert not res2["Q4"].passed and not res2["Q6"].passed and not res2["Q8"].passed and not res2["Q13"].passed
    assert res2["Q9"].passed
    ok, below = gate_ok(ratios(ctx2.measured, "ref_dev_v0"))
    assert not ok and "nvlink.allreduce_1gb_busbw_gbps" in below
    # seven GPUs fails fast at SKU/topology
    ctx3 = Ctx(runner=SimRunner(SimProfile(missing_gpu=True)), reference="ref_dev_v0", dev_mode=True, claimed_vcpus=120)
    res3 = run(run_suite(ctx3, kind="full"))
    assert res3[0].id == "Q2" and not res3[0].passed and len(res3) == 1
    # weekly subset
    wk = [r.id for r in run(run_suite(Ctx(runner=SimRunner(), reference="ref_dev_v0", dev_mode=True, claimed_vcpus=120), kind="weekly"))]
    assert "Q14" not in wk and "Q4" in wk and "Q6" in wk
    sm = run(smoke(Ctx(runner=SimRunner(), reference="ref_dev_v0", dev_mode=True, claimed_vcpus=0)))
    assert sm["marker"] == "absent" and sm["nccl_wrong"] == 0 and sm["gpu_memory_verify"] == "ok"


def test_topo_counts_only_gpu_columns():
    """An HGX matrix lists NICs beside the GPUs; their PIX/NODE/SYS cells must not count as non-NVLink GPU pairs (first real B300)."""
    header = "        " + "  ".join(f"GPU{i}" for i in range(8)) + "  NIC0  NIC1  NIC2  NIC3  NIC4  CPU Affinity  NUMA Affinity  GPU NUMA ID\n"
    rows = []
    for i in range(8):
        cells = ["X" if j == i else "NV18" for j in range(8)] + ["PIX" if i % 2 == 0 else "NODE", "SYS", "SYS", "NODE", "SYS", "0-55", "0", "N/A"]
        rows.append(f"GPU{i}    " + "  ".join(cells) + "\n")
    legend = "\nLegend:\n\n  X    = Self\n  SYS  = Connection traversing PCIe as well as the SMP interconnect\n  NV#  = Connection traversing a bonded set of # NVLinks\n"
    t = P.parse_topo(header + "".join(rows) + legend, expected_gpus=8)
    assert t == {"gpus": 8, "nvlink_pairs": 56, "non_nvlink_pairs": 0, "full_nvlink": True}
    # a PCIe-only box (the 8x4090) is still not fully NVLinked
    rows_pcie = [f"GPU{i}    " + "  ".join("X" if j == i else "SYS" for j in range(8)) + "  0-127  0  N/A\n" for i in range(8)]
    assert P.parse_topo(header + "".join(rows_pcie), expected_gpus=8)["full_nvlink"] is False
