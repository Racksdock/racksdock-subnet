from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TrustConfig:
    mode: str  # "dev" | "prod"
    dev_ca_dir: Path | None
    nvattest_bin: str = "nvattest"
    nras_url: str | None = None
    rim_url: str | None = None

    @property
    def dev(self) -> bool:
        return self.mode == "dev"

    @classmethod
    def from_env(cls) -> TrustConfig:
        mode = os.environ.get("RACKSDOCK_TRUST_MODE", "dev")
        ca = os.environ.get("RACKSDOCK_DEV_CA_DIR")
        return cls(
            mode=mode,
            dev_ca_dir=Path(ca) if ca else None,
            nvattest_bin=os.environ.get("RACKSDOCK_NVATTEST_BIN", "nvattest"),
            nras_url=os.environ.get("RACKSDOCK_NRAS_URL"),
            rim_url=os.environ.get("RACKSDOCK_RIM_URL"),
        )
