"""host-agent <-> node-agent protocol: newline-delimited JSON objects with a "type" field.

node-agent -> host-agent: hello, evidence, status, challenge_response, teardown_ack, log
host-agent -> node-agent: metadata, challenge, teardown, ping
Transport: AF_VSOCK (guest -> host CID 2, port VSOCK_PORT) on real hosts; TCP localhost in simulation.
"""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

VSOCK_PORT = 5300
HOST_CID = 2


class AgentMessage(BaseModel):
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)

    def encode(self) -> bytes:
        return (json.dumps({"type": self.type, "payload": self.payload}, separators=(",", ":")) + "\n").encode()

    @classmethod
    def decode(cls, line: bytes) -> AgentMessage:
        return cls.model_validate(json.loads(line.decode()))


class Metadata(BaseModel):
    """Sent by host-agent after hello. user_data is only used when the VM cannot read cloud-init's copy (simulation)."""

    instance_id: str
    node_id: str | None = None
    tenant_nonce: str
    mode: str
    image_version: str
    user_data: str | None = None
    ssh_port: int = 22
