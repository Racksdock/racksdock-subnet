from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from racksdock_subnet.verifier.config import TrustConfig


@dataclass
class ValidatorConfig:
    platform_url: str = "http://127.0.0.1:8000"
    api_key: str | None = None
    state_dir: Path = field(default_factory=lambda: Path("~/.racksdock-validator").expanduser())
    hotkey: str = "5Gvalidator"
    netuid: int = 1
    chain_kind: str = "mock"
    chain_file: Path = Path("./chain.json")
    chain_network: str = "finney"
    wallet_name: str = "default"
    wallet_hotkey: str = "default"
    runner: str = "ssh"  # ssh | sim
    ssh_user: str = "ubuntu"
    sim_profile: Path | None = None
    reference_set: str = ""  # empty -> the active profile's reference set
    iperf_endpoints: tuple[str, ...] = ("iperf.racksdock-validator.local",)
    # cadence (seconds); the simulator shortens these
    canary_mean_interval_s: float = 10800
    canary_deadline_s: float = 600
    inrental_interval_s: float = 600
    microbench_interval_s: float = 1800
    reachability_interval_s: float = 60
    requal_interval_s: float = 7 * 86400
    tempo_s: float = 72 * 60
    loop_interval_s: float = 10
    qualification_full: bool = True
    trust: TrustConfig = field(default_factory=TrustConfig.from_env)

    def __post_init__(self) -> None:
        if not self.reference_set:
            from racksdock_subnet.core.profile import current

            self.reference_set = current().reference_set

    @classmethod
    def from_env(cls) -> ValidatorConfig:
        e = os.environ.get
        c = cls(
            platform_url=e("RACKSDOCK_PLATFORM_URL", "http://127.0.0.1:8000"), api_key=e("RACKSDOCK_API_KEY"),
            state_dir=Path(e("RACKSDOCK_STATE_DIR", "~/.racksdock-validator")).expanduser(), hotkey=e("RACKSDOCK_HOTKEY", "5Gvalidator"),
            netuid=int(e("RACKSDOCK_NETUID", "1")), chain_kind=e("RACKSDOCK_CHAIN", "mock"), chain_file=Path(e("RACKSDOCK_CHAIN_FILE", "./chain.json")),
            chain_network=e("RACKSDOCK_CHAIN_NETWORK", "finney"), runner=e("RACKSDOCK_RUNNER", "ssh"), ssh_user=e("RACKSDOCK_SSH_USER", "ubuntu"),
            sim_profile=Path(e("RACKSDOCK_SIM_PROFILE")) if e("RACKSDOCK_SIM_PROFILE") else None, reference_set=e("RACKSDOCK_REFERENCE_SET", ""),
            iperf_endpoints=tuple(x.strip() for x in e("RACKSDOCK_IPERF_ENDPOINTS", "iperf.racksdock-validator.local").split(",") if x.strip()),
            canary_mean_interval_s=float(e("RACKSDOCK_CANARY_MEAN_S", "10800")), canary_deadline_s=float(e("RACKSDOCK_CANARY_DEADLINE_S", "600")),
            inrental_interval_s=float(e("RACKSDOCK_INRENTAL_S", "600")), microbench_interval_s=float(e("RACKSDOCK_MICROBENCH_S", "1800")),
            reachability_interval_s=float(e("RACKSDOCK_REACH_S", "60")), requal_interval_s=float(e("RACKSDOCK_REQUAL_S", str(7 * 86400))),
            tempo_s=float(e("RACKSDOCK_TEMPO_S", str(72 * 60))), loop_interval_s=float(e("RACKSDOCK_LOOP_S", "10")),
            qualification_full=e("RACKSDOCK_QUAL_FULL", "1") == "1", trust=TrustConfig.from_env(),
        )
        return c
