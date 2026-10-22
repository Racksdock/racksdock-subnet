"""HTTP client for the marketplace validator endpoints."""
from __future__ import annotations

import logging
from typing import Any

import httpx

from racksdock_subnet.core.envelope import SignedEnvelope
from racksdock_subnet.core.keys import SigningKey


class PlatformClient:
    def __init__(self, base_url: str, api_key: str | None, key: SigningKey, timeout: float = 60):
        self.base_url = base_url.rstrip("/")
        self.key = key
        self.c = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, headers={"X-API-KEY": api_key} if api_key else {})

    async def close(self) -> None:
        await self.c.aclose()

    def _check(self, r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise RuntimeError(f"{r.request.method} {r.request.url.path} -> {r.status_code}: {r.text[:300]}")
        return r.json()

    async def enroll(self, hotkey: str) -> str:
        env = SignedEnvelope.create("validator_enroll", {"hotkey": hotkey}, self.key)
        data = self._check(await self.c.post("/v1/validators/enroll", json={"envelope": env.model_dump()}))
        self.c.headers["X-API-KEY"] = data["api_key"]
        return data["api_key"]

    async def nodes(self) -> list[dict]:
        return self._check(await self.c.get("/v1/validators/nodes"))["nodes"]

    async def create_verify_instance(self, node_id: str, ssh_public_keys: list[str], tenant_nonce: str, name: str = "verify", deployment: str | None = None) -> str:
        body = {"node_id": node_id, "ssh_public_keys": ssh_public_keys, "tenant_nonce": tenant_nonce, "name": name}
        if deployment:
            body["deployment"] = deployment
        return self._check(await self.c.post("/v1/validators/verify-instances", json=body))["id"]

    async def instances(self) -> list[dict]:
        """This validator's own instances (verify sessions), live and recent."""
        return self._check(await self.c.get("/v1/instances"))["instances"]

    async def instance(self, instance_id: str) -> dict:
        return self._check(await self.c.get(f"/v1/validators/instances/{instance_id}"))

    async def delete_instance(self, instance_id: str) -> None:
        self._check(await self.c.post(f"/v1/validators/instances/{instance_id}/delete"))

    async def restart_instance_as_user(self, instance_id: str) -> None:
        # validators own their verify instances through the user instance API as well
        self._check(await self.c.post(f"/v1/instances/{instance_id}/restart"))

    async def leases(self, live_only: bool = True) -> list[dict]:
        return self._check(await self.c.get("/v1/validators/leases", params={"live_only": live_only}))["leases"]

    async def publish(self, kind: str, payload: dict) -> str:
        env = SignedEnvelope.create(kind, payload, self.key)
        return self._check(await self.c.post("/v1/validators/records", json={"envelope": env.model_dump()}))["content_hash"]

    async def challenge(self, node_id: str, challenge_payload: dict) -> dict:
        env = SignedEnvelope.create("challenge", challenge_payload, self.key)
        return self._check(await self.c.post("/v1/validators/challenge", json={"node_id": node_id, "envelope": env.model_dump()}))["response"]

    async def strike(self, node_id: str, reason: str, weight: float = 1.0) -> None:
        self._check(await self.c.post("/v1/validators/strikes", json={"node_id": node_id, "reason": reason, "weight": weight}))

    async def progress(self, payload: dict) -> None:
        """Verification step progress for the console (docs/03 §5.1). Best effort: never fails a session."""
        try:
            await self.c.post("/v1/validators/progress", json=payload)
        except Exception as e:
            logging.getLogger("racksdock.validator").debug("progress not delivered: %s", e)

    async def incident(self, instance_id: str, klass: str, details: str, strike: bool) -> None:
        self._check(await self.c.post("/v1/validators/incidents", json={"instance_id": instance_id, "klass": klass, "details": details, "strike": strike}))

    async def recover(self, instance_id: str) -> None:
        self._check(await self.c.post(f"/v1/validators/incidents/{instance_id}/recover"))

    async def settings(self) -> dict:
        return self._check(await self.c.get("/v1/validators/settings"))

    async def evidence(self, **params) -> list[dict]:
        return self._check(await self.c.get("/v1/evidence", params={k: v for k, v in params.items() if v is not None}))["records"]

    async def node_verification(self, node_id: str) -> dict:
        return self._check(await self.c.get(f"/v1/nodes/{node_id}/verification"))
