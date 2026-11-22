#!/usr/bin/env python3
"""Entry point for the Argus MCP server. Works without installing the package."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from argus.mcp_server import main

if __name__ == "__main__":
    main()
