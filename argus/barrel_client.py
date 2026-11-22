"""Async MCP client for barrel-mcp. The only place Argus talks to a device."""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import AsyncExitStack
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .config import Config
from .errors import BarrelError, BarrelToolError
from .redact import redact_text


def _args(**kwargs) -> dict:
    return {key: value for key, value in kwargs.items() if value is not None}


class BarrelClient:
    def __init__(self, config: Config):
        self.config = config
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self._session is not None:
            return
        async with self._lock:
            if self._session is not None:
                return
            binary = Path(self.config.barrel_bin)
            if not binary.is_file():
                raise BarrelError(
                    f"barrel-mcp binary not found: {binary}. Build it with: "
                    "cargo build --features mcp-server --bin barrel-mcp"
                )
            if not os.access(binary, os.X_OK):
                raise BarrelError(f"barrel-mcp is not executable: {binary}")

            stack = AsyncExitStack()
            try:
                params = StdioServerParameters(command=str(binary), args=[])
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await asyncio.wait_for(
                    session.initialize(), timeout=self.config.call_timeout_s
                )
            except Exception as exc:
                await stack.aclose()
                raise BarrelError(
                    f"could not start barrel-mcp: {redact_text(str(exc))}"
                ) from exc
            self._stack = stack
            self._session = session

    async def close(self) -> None:
        stack, self._stack = self._stack, None
        self._session = None
        if stack is not None:
            try:
                await stack.aclose()
            except Exception:
                pass

    async def __aenter__(self) -> "BarrelClient":
        await self.start()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def call(
        self,
        name: str,
        arguments: dict | None = None,
        *,
        timeout_s: float | None = None,
    ) -> str:
        await self.start()
        if self._session is None:
            raise BarrelError("barrel client did not start")
        timeout = timeout_s or self.config.call_timeout_s
        try:
            result = await self._session.call_tool(
                name,
                arguments or {},
                read_timeout_seconds=timedelta(seconds=timeout),
            )
        except Exception as exc:
            raise BarrelError(
                f"barrel tool {name} failed: {redact_text(str(exc))}"
            ) from exc

        text = "\n".join(
            str(getattr(block, "text", ""))
            for block in result.content
            if getattr(block, "type", None) == "text"
        ).strip()
        if result.isError:
            message = text or f"barrel tool {name} returned an error"
            raise BarrelToolError(redact_text(message))
        if not text and result.structuredContent:
            text = json.dumps(result.structuredContent)
        return text

    async def list_tools(self) -> list[str]:
        await self.start()
        if self._session is None:
            raise BarrelError("barrel client did not start")
        result = await self._session.list_tools()
        return [tool.name for tool in result.tools]

    async def list_devices(self) -> str:
        return await self.call("list_devices")

    async def get_device_info(self, device: str | None = None) -> str:
        return await self.call("get_device_info", _args(device=device))

    async def install_apk(
        self,
        path: str,
        device: str | None = None,
        *,
        reinstall: bool = True,
        grant_permissions: bool = True,
        timeout_s: float = 240,
    ) -> str:
        return await self.call(
            "install_apk",
            _args(
                path=path,
                device=device,
                reinstall=reinstall,
                grant_permissions=grant_permissions,
            ),
            timeout_s=timeout_s,
        )

    async def launch_package(self, package: str, device: str | None = None) -> str:
        return await self.call("launch_package", _args(package=package, device=device))

    async def app_stop(self, package: str, device: str | None = None) -> str:
        return await self.call("app_stop", _args(package=package, device=device))

    async def ui_dump(self, device: str | None = None) -> str:
        return await self.call("ui_dump", _args(device=device))

    async def ui_tap(self, x: int, y: int, device: str | None = None) -> str:
        return await self.call("ui_tap", _args(x=x, y=y, device=device))

    async def ui_swipe(
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        duration_ms: int = 300,
        device: str | None = None,
    ) -> str:
        return await self.call(
            "ui_swipe",
            _args(x1=x1, y1=y1, x2=x2, y2=y2, duration_ms=duration_ms, device=device),
        )

    async def ui_set_text(
        self, text: str, submit: bool = False, device: str | None = None
    ) -> str:
        return await self.call(
            "ui_set_text", _args(text=text, submit=submit, device=device)
        )

    async def ui_key(self, keyevent: str, device: str | None = None) -> str:
        return await self.call("ui_key", _args(keyevent=keyevent, device=device))

    async def logcat_tail(
        self,
        lines: int = 200,
        filter: str | None = None,
        device: str | None = None,
    ) -> str:
        return await self.call(
            "logcat_tail", _args(lines=lines, filter=filter, device=device)
        )

    async def screenshot(self, local_path: str, device: str | None = None) -> str:
        return await self.call(
            "screenshot", _args(local_path=local_path, device=device)
        )

    async def traffic_start(self, port: int | None = None) -> str:
        return await self.call("traffic_start", _args(port=port))

    async def traffic_stop(self) -> str:
        return await self.call("traffic_stop")

    async def traffic_status(self) -> str:
        return await self.call("traffic_status")

    async def traffic_entries(self, limit: int = 100, entry_id: int | None = None) -> str:
        return await self.call(
            "traffic_entries", _args(limit=limit, entry_id=entry_id)
        )

    async def traffic_entries_json(
        self,
        limit: int = 100,
        entry_id: int | None = None,
        include_bodies: bool | None = None,
    ) -> str:
        return await self.call(
            "traffic_entries_json",
            _args(limit=limit, entry_id=entry_id, include_bodies=include_bodies),
        )

    async def traffic_status_json(self) -> str:
        return await self.call("traffic_status_json")

    async def cert_install(self, device: str, path: str, method: str = "user") -> str:
        return await self.call(
            "cert_install", {"device": device, "path": path, "method": method}
        )

    async def cert_inspect_device(self, device: str) -> str:
        return await self.call("cert_inspect_device", {"device": device})

    async def traffic_transparent_set(self, device: str) -> str:
        return await self.call("traffic_transparent_set", {"device": device})

    async def traffic_transparent_unset(self, device: str) -> str:
        return await self.call("traffic_transparent_unset", {"device": device})

    async def traffic_clear(self) -> str:
        return await self.call("traffic_clear")

    async def traffic_ensure_ca(self) -> str:
        return await self.call("traffic_ensure_ca")

    async def traffic_route_device(self, device: str) -> str:
        return await self.call("traffic_route_device", {"device": device})

    async def traffic_unroute_device(self, device: str) -> str:
        return await self.call("traffic_unroute_device", {"device": device})
