"""Deterministic cloud-init user-data rendering.

The client, the platform and the VM must all compute the same `user_data_hash`, so the
rendering here is the only allowed rendering. Do not reorder or reformat.
"""
from __future__ import annotations

import json

import yaml

from .canonical import sha256_prefixed
from .schemas import LaunchType, UserDataInput

LAUNCH_JSON_PATH = "/etc/racksdock/launch.json"
ENV_PATH = "/etc/racksdock/env.sh"
METRICS_FLAG_PATH = "/etc/racksdock/metrics.enabled"


def _ufw_cmd(rule) -> str:
    parts = ["ufw"]
    parts.append(rule.rule)
    if rule.from_ip:
        parts += ["from", rule.from_ip]
    if rule.to_ip:
        parts += ["to", rule.to_ip]
    elif rule.port or rule.proto:
        parts += ["to", "any"]
    if rule.port:
        parts += ["port", rule.port]
    if rule.proto:
        parts += ["proto", rule.proto]
    return " ".join(parts)


def build_cloud_config(inp: UserDataInput) -> dict:
    write_files = []
    runcmd: list[str] = []

    if inp.envs:
        lines = "".join(f"export {e.name}={json.dumps(e.value)}\n" for e in inp.envs)
        write_files.append({"path": ENV_PATH, "permissions": "0644", "content": lines})
        runcmd.append(f"grep -q 'source {ENV_PATH}' /etc/bash.bashrc || echo 'source {ENV_PATH}' >> /etc/bash.bashrc")

    if inp.launch_configuration is not None:
        lc = inp.launch_configuration
        launch = {"type": lc.type.value}
        if lc.type == LaunchType.docker and lc.docker_configuration:
            launch["docker"] = json.loads(lc.docker_configuration.model_dump_json(exclude_none=True))
        if lc.type == LaunchType.script and lc.script_configuration:
            launch["script"] = {"base64_script": lc.script_configuration.base64_script}
        write_files.append(
            {"path": LAUNCH_JSON_PATH, "permissions": "0600", "content": json.dumps(launch, sort_keys=True, indent=1) + "\n"}
        )
        runcmd.append("systemctl start racksdock-launch.service || /usr/local/bin/racksdock-launch")

    if inp.enable_metrics:
        write_files.append({"path": METRICS_FLAG_PATH, "permissions": "0644", "content": "1\n"})

    if inp.networking and inp.networking.ufw_rules:
        runcmd.append("ufw --force reset")
        runcmd.append("ufw default deny incoming")
        runcmd.append("ufw default allow outgoing")
        runcmd.append("ufw allow 22/tcp")
        for r in inp.networking.ufw_rules:
            runcmd.append(_ufw_cmd(r))
        runcmd.append("ufw --force enable")

    cfg: dict = {
        "users": [
            {
                "name": "ubuntu",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "shell": "/bin/bash",
                "groups": "docker",
                "lock_passwd": True,
                "ssh_authorized_keys": list(inp.ssh_public_keys),
            }
        ],
        "ssh_pwauth": False,
        "disable_root": True,
        "package_update": False,
    }
    if write_files:
        cfg["write_files"] = write_files
    if runcmd:
        cfg["runcmd"] = runcmd
    cfg["final_message"] = "racksdock: cloud-init finished"
    return cfg


def render(inp: UserDataInput) -> str:
    cfg = build_cloud_config(inp)
    body = yaml.safe_dump(cfg, sort_keys=True, default_flow_style=False, allow_unicode=True, width=10000)
    return "#cloud-config\n" + body


def render_bytes(inp: UserDataInput) -> bytes:
    return render(inp).encode("utf-8")


def user_data_hash(user_data: bytes | str) -> str:
    data = user_data.encode("utf-8") if isinstance(user_data, str) else user_data
    return sha256_prefixed(data)
