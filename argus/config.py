"""Runtime configuration. No secrets are read from or written to source code."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BARREL_BIN = "/home/ipsalmy/Test/Barrel/src-tauri/target/debug/barrel-mcp"
DEFAULT_DATA_DIR = "~/.local/share/argus"


@dataclass(frozen=True)
class Config:
    barrel_bin: Path
    data_dir: Path
    call_timeout_s: float = 60.0
    max_xml_bytes: int = 5_000_000
    redact_extra: tuple[str, ...] = ()

    @classmethod
    def load(cls) -> "Config":
        barrel = Path(os.environ.get("ARGUS_BARREL_BIN", DEFAULT_BARREL_BIN)).expanduser()
        data = Path(os.environ.get("ARGUS_DATA_DIR", DEFAULT_DATA_DIR)).expanduser()
        raw_timeout = os.environ.get("ARGUS_CALL_TIMEOUT", "60")
        try:
            timeout = float(raw_timeout)
        except ValueError as exc:
            raise ValueError(f"ARGUS_CALL_TIMEOUT is not a number: {raw_timeout!r}") from exc
        if not 0 < timeout <= 3600:
            raise ValueError("ARGUS_CALL_TIMEOUT must be between 0 and 3600 seconds")
        extra = tuple(
            item.strip()
            for item in os.environ.get("ARGUS_REDACT_EXTRA", "").split(",")
            if item.strip()
        )
        return cls(
            barrel_bin=barrel,
            data_dir=data,
            call_timeout_s=timeout,
            redact_extra=extra,
        )
