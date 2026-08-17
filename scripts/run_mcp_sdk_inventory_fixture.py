from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from osai_security.mcp_sdk_inventory_fixture import run_sdk_inventory_fixture


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the independent official-SDK MCP inventory fixture")
    parser.add_argument("--mode", choices=("secure", "vulnerable"), required=True)
    parser.add_argument("--transport", choices=("streamable-http", "sse"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--dynamic", action="store_true")
    args = parser.parse_args()
    run_sdk_inventory_fixture(
        mode=args.mode,
        transport=args.transport,
        host=args.host,
        port=args.port,
        dynamic=args.dynamic,
    )


if __name__ == "__main__":
    main()
