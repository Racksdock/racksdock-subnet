"""Command runners: SSH (host key pinned to the attested key) and a simulator emitting real tool output formats."""
from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from racksdock_subnet.core.profile import current as current_profile
from racksdock_subnet.core.specdata import reference_set


@dataclass
class CmdResult:
    rc: int
    stdout: str
    stderr: str = ""


class CommandRunner(Protocol):
    async def run(self, cmd: str, timeout: float = 600) -> CmdResult: ...

    async def close(self) -> None: ...


class SSHRunner:
    def __init__(self, host: str, port: int, username: str, client_key_path: str, host_key_line: str):
        self.host, self.port, self.username, self.client_key_path, self.host_key_line = host, port, username, client_key_path, host_key_line
        self._conn = None

    async def _connect(self):
        import asyncssh

        if self._conn is None:
            kh = asyncssh.import_known_hosts(f"[{self.host}]:{self.port} {self.host_key_line}\n")
            self._conn = await asyncssh.connect(self.host, port=self.port, username=self.username, client_keys=[self.client_key_path], known_hosts=kh, connect_timeout=30)
        return self._conn

    async def run(self, cmd: str, timeout: float = 600) -> CmdResult:
        conn = await self._connect()
        res = await asyncio.wait_for(conn.run(cmd, check=False), timeout)
        return CmdResult(res.exit_status or 0, res.stdout or "", res.stderr or "")

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


# --------------------------------------------------------------------------- simulator


@dataclass
class SimProfile:
    """Scales reference values; 1.0 = healthy reference node. Used by SimRunner to emit tool outputs."""

    scale: dict[str, float] = field(default_factory=dict)
    dcgm_fail: list[str] = field(default_factory=list)
    nccl_wrong: int = 0
    throttle: bool = False
    power_limit_w: float = 1400
    missing_gpu: bool = False
    marker_present: bool = False
    vcpus: int = 120
    board_part: str = "SIM-B300-8GPU"
    pci_id: str = ""
    vbios: str = "99.00.00.00.01"
    reference: str = ""
    gpus: int = 0

    def __post_init__(self):
        prof = current_profile()
        self.pci_id = self.pci_id or prof.sim_pci_id
        self.reference = self.reference or prof.reference_set
        self.gpus = self.gpus or prof.gpu_count

    def s(self, key: str) -> float:
        return self.scale.get(key, 1.0)

    def ref(self, key: str) -> float:
        return float(reference_set(self.reference)["values"][key])

    @classmethod
    def load(cls, path: str | Path | None) -> SimProfile:
        if not path:
            return cls()
        return cls(**json.loads(Path(path).read_text()))


class SimRunner:
    """Emits realistic outputs for the suite's commands. Pattern-matched on the command string."""

    def __init__(self, profile: SimProfile | None = None, seed: int = 1):
        self.p = profile or SimProfile()
        self.rng = random.Random(seed)
        self.state: dict[str, str] = {}

    async def close(self) -> None:
        return None

    def _jit(self, v: float, pct: float = 0.01) -> float:
        return v * (1 + self.rng.uniform(-pct, pct))

    async def run(self, cmd: str, timeout: float = 600) -> CmdResult:
        p = self.p
        n = p.gpus - 1 if p.missing_gpu else p.gpus
        if "--query-gpu=index,name,serial,pci.device_id,vbios_version,memory.total,power.limit" in cmd:
            vram = p.ref("gpu.vram_gb_usable_min") * p.s("gpu.vram_gb_usable_min")
            dev = p.pci_id.split(":")[1].upper()
            lines = [f"{i}, NVIDIA B300, 16{i:02d}0001234, 0x{dev}10DE, {p.vbios}, {int(vram * 1024 + 2048)}, {p.power_limit_w:.2f}" for i in range(n)]
            return CmdResult(0, "\n".join(lines) + "\n")
        if cmd.strip() == "nvidia-smi -q":
            return CmdResult(0, "\n".join([f"GPU 0000:{17 + i:02x}:00.0\n    Board Part Number : {p.board_part}" for i in range(n)]) + "\n")
        if "nvidia-smi topo -m" in cmd:
            hdr = "\t" + "\t".join(f"GPU{i}" for i in range(n))
            rows = []
            for i in range(n):
                cells = ["X" if i == j else "NV18" for j in range(n)]
                rows.append(f"GPU{i}\t" + "\t".join(cells))
            return CmdResult(0, hdr + "\n" + "\n".join(rows) + "\n")
        if "racksdock-memtest" in cmd:
            vram = p.ref("gpu.vram_gb_usable_min") * p.s("gpu.vram_gb_usable_min")
            lines = [f"gpu{i}.usable_gb: {vram - 0.5 + 0.1 * i:.1f}" for i in range(n)]
            lines.append(f"verify: {'ok' if not p.marker_present else 'marker_found'}")
            lines.append(f"hbm_write_gbps: {self._jit(p.ref('hbm_write_gbps') * p.s('hbm_write_gbps')):.0f}")
            return CmdResult(0, "\n".join(lines) + "\n")
        if "dcgmi diag" in cmd:
            names = ["Denylist", "NVML Library", "CUDA Main Library", "Permissions and OS Blocks", "Persistence Mode", "Environment Variables", "Page Retirement/Row Remap",
                     "Graphics Processes", "Inforom", "PCIe", "Memory", "Targeted Stress", "Targeted Power", "Memory Bandwidth", "Diagnostic"]
            cats = [{"category": "Hardware", "tests": []}]
            for nm in names:
                status = "Fail" if nm in p.dcgm_fail else "Pass"
                cats[0]["tests"].append({"name": nm, "results": [{"gpu_ids": ",".join(str(i) for i in range(n)), "status": status}]})
            return CmdResult(0, json.dumps({"DCGM GPU Diagnostic": {"test_categories": cats}}))
        if "nvbandwidth" in cmd and "device_to_device" in cmd:
            pair = p.ref("nvlink.d2d_gbps_min_pair") * p.s("nvlink.d2d_gbps_min_pair")
            hdr = "memcpy CE GPU(row) -> GPU(column) bandwidth (GB/s)\n" + "        " + "".join(f"{j:>10}" for j in range(n)) + "\n"
            rows = []
            total = 0.0
            for i in range(n):
                cells = []
                for j in range(n):
                    if i == j:
                        cells.append(f"{'N/A':>10}")
                    else:
                        v = self._jit(pair * (1 + 0.02 * ((i + j) % 3)))
                        total += v
                        cells.append(f"{v:>10.2f}")
                rows.append(f"{i:>8}" + "".join(cells))
            agg = p.ref("nvlink.d2d_gbps_aggregate") * p.s("nvlink.d2d_gbps_aggregate")
            return CmdResult(0, hdr + "\n".join(rows) + f"\n\nSUM device_to_device_memcpy_read_ce {agg:.2f}\n")
        if "nvbandwidth" in cmd:
            return CmdResult(0, "memcpy CE CPU(row) -> GPU(column) bandwidth (GB/s)\n" + "        " + "".join(f"{j:>10}" for j in range(n)) + "\n" + f"{0:>8}" + "".join(f"{self._jit(52.0):>10.2f}" for _ in range(n)) + "\n\nSUM host_to_device_memcpy_ce 410.00\n")
        if "_perf" in cmd and "-b" in cmd:  # nccl-tests
            bus = p.ref("nvlink.allreduce_1gb_busbw_gbps") * p.s("nvlink.allreduce_1gb_busbw_gbps")
            lines = ["#", "#       size         count      type   redop    root     time   algbw   busbw #wrong     time   algbw   busbw #wrong", "#        (B)    (elements)                               (us)  (GB/s)  (GB/s)            (us)  (GB/s)  (GB/s)"]
            size = 1024
            while size <= 8 * 1024 ** 3:
                frac = min(1.0, (size / (1024 ** 3)) ** 0.25)
                b = self._jit(bus * frac)
                t = size / 1e9 / max(b, 1e-3) * 1e6
                lines.append(f"{size:>12}{size // 4:>14}     float     sum      -1 {t:>8.1f} {b * 4 / 7:>7.2f} {b:>7.2f} {p.nccl_wrong:>6} {t:>8.1f} {b * 4 / 7:>7.2f} {b:>7.2f} {p.nccl_wrong:>6}")
                size *= 2
            lines.append(f"# Avg bus bandwidth    : {bus * 0.6:.3f}")
            return CmdResult(0, "\n".join(lines) + "\n")
        if cmd.startswith("lscpu"):
            return CmdResult(0, f"Architecture:        x86_64\nCPU(s):              {p.vcpus}\nModel name:          Simulated Xeon 6 (host-passthrough)\nNUMA node(s):        2\n")
        if "/proc/meminfo" in cmd:
            gb = p.ref("memory_gb") * p.s("memory_gb")
            return CmdResult(0, f"MemTotal:       {int(gb * 1024 * 1024)} kB\nMemFree:        {int(gb * 1024 * 1024 * 0.95)} kB\n")
        if "stream" in cmd.lower():
            tri = p.ref("cpu.stream_gbps") * p.s("cpu.stream_gbps") * 1000
            return CmdResult(0, f"Function    Best Rate MB/s  Avg time     Min time     Max time\nCopy:          {tri * 0.95:.1f}     0.1  0.1  0.1\nScale:         {tri * 0.93:.1f}     0.1  0.1  0.1\nAdd:           {tri * 1.02:.1f}     0.1  0.1  0.1\nTriad:         {tri:.1f}     0.1  0.1  0.1\n")
        if "sysbench" in cmd:
            return CmdResult(0, f"CPU speed:\n    events per second: {p.ref('cpu.sysbench') * p.s('cpu.sysbench'):.2f}\n")
        if "memtester" in cmd or "racksdock-ramtest" in cmd:
            return CmdResult(0, "allocated_gb: %.0f\nverify: ok\n" % (p.ref("memory_gb") * p.s("memory_gb") * 0.9))
        if cmd.startswith("lsblk") or " lsblk " in cmd:
            tb = p.ref("nvme.capacity_tb") * p.s("nvme.capacity_tb")
            return CmdResult(0, json.dumps({"blockdevices": [{"name": "vda", "size": 200 * 10 ** 9, "type": "disk", "mountpoint": "/"},
                                                                 {"name": "b300data", "size": int(tb * 1e12), "type": "crypt", "mountpoint": "/data"}]}))
        if cmd.startswith("fio") or " fio " in cmd:
            sr, sw = p.ref("nvme.seq_read_gbps") * p.s("nvme.seq_read_gbps"), p.ref("nvme.seq_write_gbps") * p.s("nvme.seq_write_gbps")
            rr, rw = p.ref("nvme.rand_read_kiops") * p.s("nvme.rand_read_kiops") * 1000, p.ref("nvme.rand_write_kiops") * p.s("nvme.rand_write_kiops") * 1000
            sus = p.ref("nvme.sustained_write_gbps") * p.s("nvme.sustained_write_gbps")
            jobs = [{"jobname": "seqread", "read": {"bw_bytes": int(sr * 1e9), "iops": sr * 1e9 / 1048576}, "write": {"bw_bytes": 0, "iops": 0}},
                    {"jobname": "seqwrite", "read": {"bw_bytes": 0, "iops": 0}, "write": {"bw_bytes": int(sw * 1e9), "iops": sw * 1e9 / 1048576}},
                    {"jobname": "randread", "read": {"bw_bytes": int(rr * 4096), "iops": rr}, "write": {"bw_bytes": 0, "iops": 0}},
                    {"jobname": "randwrite", "read": {"bw_bytes": 0, "iops": 0}, "write": {"bw_bytes": int(rw * 4096), "iops": rw}},
                    {"jobname": "sustained", "read": {"bw_bytes": 0, "iops": 0}, "write": {"bw_bytes": int(sus * 1e9), "iops": sus * 1e9 / 1048576}}]
            return CmdResult(0, json.dumps({"jobs": jobs}))
        if cmd.startswith("iperf3"):
            down, up = p.ref("network.down_gbps") * p.s("network.down_gbps"), p.ref("network.up_gbps") * p.s("network.up_gbps")
            rev = "-R" in cmd
            return CmdResult(0, json.dumps({"end": {"sum_sent": {"bits_per_second": (down if rev else up) * 1e9}, "sum_received": {"bits_per_second": (down if rev else up) * 1e9 * 0.995}, "sum": {"lost_percent": 0.0}}}))
        if "clocks_throttle_reasons.active" in cmd:
            lines = []
            for s_ in range(6):
                for i in range(n):
                    reasons = "0x0000000000000008" if p.throttle and s_ > 2 else "0x0000000000000000"
                    lines.append(f"{i}, {p.power_limit_w:.2f}, {reasons}, 1980")
            return CmdResult(0, "\n".join(lines) + "\n")
        if "racksdock-train-bench" in cmd:
            return CmdResult(0, f"tokens_per_s: {self._jit(p.ref('training_tokens_per_s') * p.s('training_tokens_per_s')):.0f}\nstep_time_p50_ms: 410\nstep_time_p95_ms: 440\nloss_final: 2.31\n")
        if "racksdock-infer-bench" in cmd:
            return CmdResult(0, f"tokens_per_s: {self._jit(p.ref('inference_tokens_per_s') * p.s('inference_tokens_per_s')):.0f}\nttft_p50_ms: 120\n")
        if "racksdock-marker" in cmd:
            if "write" in cmd:
                self.state["marker"] = "1"
                return CmdResult(0, "marker written\n")
            return CmdResult(0, "marker: present\n" if (self.state.get("marker") or p.marker_present) else "marker: absent\n")
        if cmd.startswith("sudo systemctl stop") or cmd.startswith("sudo rm") or cmd.startswith("sudo fallocate"):
            return CmdResult(0, "")
        if cmd.startswith("echo") or cmd.startswith("true"):
            return CmdResult(0, cmd.split(" ", 1)[1] + "\n" if " " in cmd else "\n")
        return CmdResult(127, "", f"sim: unknown command {cmd[:60]}")
