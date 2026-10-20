"""Parsers for the real tool outputs used by the qualification suite. Each returns plain dicts of metrics."""
from __future__ import annotations

import json
import re
from typing import Any


def parse_nvidia_smi_csv(out: str, fields: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= len(fields):
            rows.append(dict(zip(fields, parts)))
    return rows


def parse_board_parts(nvidia_smi_q: str) -> list[str]:
    return [line.split(":", 1)[1].strip() for line in nvidia_smi_q.splitlines() if "Board Part Number" in line]


def parse_topo(out: str, expected_gpus: int = 8) -> dict[str, Any]:
    """nvidia-smi topo -m: count NVLink (NVxx) pairs among GPUs."""
    gpus = 0
    nv_pairs = 0
    other = 0
    for line in out.splitlines():
        if not line.startswith("GPU"):
            continue
        cells = line.split()
        if len(cells) < 2:
            continue
        gpus += 1
        for cell in cells[1:]:
            if cell.startswith("NV"):
                nv_pairs += 1
            elif cell in ("SYS", "NODE", "PHB", "PXB", "PIX"):
                other += 1
    full = gpus == expected_gpus and other == 0 and nv_pairs == expected_gpus * (expected_gpus - 1)
    return {"gpus": gpus, "nvlink_pairs": nv_pairs, "non_nvlink_pairs": other, "full_nvlink": full}


def norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def parse_dcgm_diag(out: str) -> dict[str, Any]:
    """dcgmi diag -j output. Permissive across DCGM 3.x/4.x shapes; test names are normalized (lowercase, alphanumeric)."""
    data = json.loads(out)
    root = data.get("DCGM GPU Diagnostic") or data.get("DCGM Diagnostic") or data
    tests: dict[str, dict[str, str]] = {}
    for cat in root.get("test_categories", []):
        for t in cat.get("tests", []):
            name = norm_name(str(t.get("name", "?")))
            per_gpu: dict[str, str] = {}
            for r in t.get("results", []):
                status = str(r.get("status", "")).lower()
                ids = r.get("gpu_ids") or r.get("gpu_id") or "all"
                for g in str(ids).split(","):
                    per_gpu[g.strip()] = status
            tests[name] = per_gpu
    failed = [n for n, pg in tests.items() if any(s == "fail" for s in pg.values())]
    skipped = [n for n, pg in tests.items() if pg and all(s in ("skip", "skipped", "not run") for s in pg.values())]
    return {"tests": tests, "failed": failed, "skipped": skipped, "ran": [n for n in tests if n not in skipped]}


def parse_nvbandwidth(out: str) -> dict[str, Any]:
    """nvbandwidth matrix output: rows 'N  v  v ...' per GPU plus 'SUM <test> <value>'."""
    matrix: list[list[float | None]] = []
    sums: dict[str, float] = {}
    in_matrix = False
    for line in out.splitlines():
        s = line.strip()
        if re.match(r"^\s*0\s+1\s+2", line):
            in_matrix = True
            continue
        m = re.match(r"^SUM\s+(\S+)\s+([\d.]+)", s)
        if m:
            sums[m.group(1)] = float(m.group(2))
            in_matrix = False
            continue
        if in_matrix:
            parts = s.split()
            if parts and parts[0].isdigit():
                vals = []
                for p in parts[1:]:
                    vals.append(None if p in ("N/A", "-") else float(p))
                matrix.append(vals)
    off = [v for row in matrix for v in row if v is not None and v > 0]
    return {"matrix": matrix, "sums": sums, "min_pair_gbps": min(off) if off else 0.0, "median_pair_gbps": sorted(off)[len(off) // 2] if off else 0.0,
            "aggregate_gbps": sum(sums.values()) if sums else sum(off)}


def parse_nccl_tests(out: str) -> dict[str, Any]:
    """nccl-tests table: size count type redop root time algbw busbw #wrong time algbw busbw #wrong (out-of-place then in-place)."""
    rows = []
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) >= 12 and parts[0].isdigit():
            try:
                rows.append({"size": int(parts[0]), "busbw_gbps": float(parts[7]), "algbw_gbps": float(parts[6]), "wrong": int(parts[8]) if parts[8].isdigit() else 0,
                             "busbw_inplace_gbps": float(parts[11]), "wrong_inplace": int(parts[12]) if len(parts) > 12 and parts[12].isdigit() else 0})
            except ValueError:
                continue
    avg = None
    m = re.search(r"Avg bus bandwidth\s*:\s*([\d.]+)", out)
    if m:
        avg = float(m.group(1))
    wrong = sum(r["wrong"] + r["wrong_inplace"] for r in rows)
    by_size = {r["size"]: r["busbw_gbps"] for r in rows}
    return {"rows": rows, "avg_busbw_gbps": avg, "wrong": wrong, "busbw_1gb": by_size.get(1073741824), "by_size": by_size}


def parse_fio_json(out: str) -> dict[str, Any]:
    data = json.loads(out)
    res: dict[str, Any] = {}
    for job in data.get("jobs", []):
        name = job.get("jobname", "job")
        rd, wr = job.get("read", {}), job.get("write", {})
        res[name] = {"read_bw_gbps": rd.get("bw_bytes", 0) / 1e9, "write_bw_gbps": wr.get("bw_bytes", 0) / 1e9,
                     "read_iops": rd.get("iops", 0.0), "write_iops": wr.get("iops", 0.0)}
    return res


def parse_iperf3_json(out: str) -> dict[str, Any]:
    data = json.loads(out)
    end = data.get("end", {})
    sent = end.get("sum_sent", {}).get("bits_per_second", 0) / 1e9
    recv = end.get("sum_received", {}).get("bits_per_second", 0) / 1e9
    lost = end.get("sum", {}).get("lost_percent", 0.0)
    return {"sent_gbps": sent, "received_gbps": recv, "lost_percent": lost}


def parse_stream(out: str) -> dict[str, float]:
    res = {}
    for line in out.splitlines():
        m = re.match(r"^(Copy|Scale|Add|Triad):\s+([\d.]+)", line.strip())
        if m:
            res[m.group(1).lower() + "_gbps"] = float(m.group(2)) / 1000.0  # STREAM prints MB/s
    return res


def parse_sysbench(out: str) -> dict[str, float]:
    m = re.search(r"events per second:\s*([\d.]+)", out)
    return {"events_per_s": float(m.group(1)) if m else 0.0}


def parse_lscpu(out: str) -> dict[str, Any]:
    res: dict[str, Any] = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        if k == "CPU(s)":
            res["cpus"] = int(v)
        elif k == "Model name":
            res["model"] = v
        elif k == "NUMA node(s)":
            res["numa_nodes"] = int(v)
    return res


def parse_meminfo(out: str) -> dict[str, float]:
    for line in out.splitlines():
        if line.startswith("MemTotal:"):
            return {"total_gb": int(line.split()[1]) / (1024 * 1024)}
    return {"total_gb": 0.0}


def parse_lsblk_json(out: str) -> dict[str, Any]:
    data = json.loads(out)
    devs = []
    for d in data.get("blockdevices", []):
        devs.append({"name": d.get("name"), "size_bytes": int(d.get("size", 0)), "type": d.get("type"), "mountpoint": d.get("mountpoint")})
    return {"devices": devs, "total_tb": sum(d["size_bytes"] for d in devs if d["type"] in ("disk", "crypt")) / 1e12}


def parse_kv_lines(out: str) -> dict[str, str]:
    """Our own workload containers print 'key: value' lines."""
    res = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            res[k.strip()] = v.strip()
    return res


THROTTLE_KEYS = ("sw power cap", "hw slowdown", "hw thermal slowdown", "hw power brake slowdown", "sw thermal slowdown")


def parse_power_samples(out: str) -> dict[str, Any]:
    """Repeated samples of
         nvidia-smi --query-gpu=index,power.limit,clocks.sm --format=csv,noheader,nounits   (3 columns; a legacy 4th throttle-bitmask column is accepted)
         nvidia-smi -q -d PERFORMANCE                                                       ('<reason> : Active' lines mark throttling)
    """
    limits: dict[int, float] = {}
    throttled = 0
    samples = 0
    throttled_in_block = False
    for raw in out.splitlines():
        line = raw.strip()
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].replace(".", "", 1).replace("[N/A]", "").isdigit():
            samples += 1
            limits[int(parts[0])] = float(parts[1])
            if len(parts) >= 4 and parts[2].startswith("0x") and int(parts[2], 16) & (0x4 | 0x8 | 0x20 | 0x40 | 0x80):
                throttled += 1
            continue
        low = line.lower()
        if ":" in low and any(low.startswith(k) for k in THROTTLE_KEYS):
            state = low.split(":", 1)[1].strip()
            if state == "active":
                throttled_in_block = True
        if line == "---SAMPLE---":
            if throttled_in_block:
                throttled += 1
            throttled_in_block = False
    if throttled_in_block:
        throttled += 1
    return {"limits_w": limits, "min_limit_w": min(limits.values()) if limits else 0.0, "throttled_samples": throttled, "samples": samples}
