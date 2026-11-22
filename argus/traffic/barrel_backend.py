"""Barrel proxy backend. Reuses barrel-mcp's capture tools over MCP."""

from __future__ import annotations

import json

from ..barrel_client import BarrelClient
from ..errors import BarrelError
from .models import TrafficRecord


class BarrelBackend:
    def __init__(self, client: BarrelClient):
        self.client = client

    async def start(self) -> dict:
        await self.client.traffic_start()
        return await self.status()

    async def stop(self) -> dict:
        await self.client.traffic_stop()
        return await self.status()

    async def status(self) -> dict:
        raw = await self.client.traffic_status_json()
        return json.loads(raw)

    async def entries(self, limit: int = 100) -> list[TrafficRecord]:
        raw = await self.client.traffic_entries_json(limit=limit)
        data = json.loads(raw)
        if not isinstance(data, list):
            raise BarrelError("traffic_entries_json did not return a list")
        return [TrafficRecord.model_validate(item) for item in data]

    async def entry(self, entry_id: int) -> TrafficRecord:
        raw = await self.client.traffic_entries_json(entry_id=entry_id)
        return TrafficRecord.model_validate(json.loads(raw))

    async def route(self, device: str) -> str:
        return await self.client.traffic_route_device(device)

    async def unroute(self, device: str) -> str:
        return await self.client.traffic_unroute_device(device)

    async def ensure_ca(self) -> str:
        return await self.client.traffic_ensure_ca()

    async def install_ca(self, device: str, method: str = "user") -> str:
        status = await self.status()
        ca_path = status.get("ca_path")
        if not ca_path:
            raise BarrelError("Barrel did not report a CA path")
        return await self.client.cert_install(device, ca_path, method)
