from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.mcp_authorization_fixture import (
    MCP_AUTHORIZATION_FIXTURE_MODES,
    MCP_AUTHORIZATION_FIXTURE_TRANSPORTS,
    MCPAuthorizationFixtureServer,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an independent MCP authorization qualification target.")
    parser.add_argument("--mode", choices=sorted(MCP_AUTHORIZATION_FIXTURE_MODES), required=True)
    parser.add_argument("--transport", choices=sorted(MCP_AUTHORIZATION_FIXTURE_TRANSPORTS), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--runtime-info", type=Path)
    args = parser.parse_args()

    stopped = threading.Event()
    server = MCPAuthorizationFixtureServer(args.mode, args.transport, host=args.host, port=args.port).start()
    if args.runtime_info:
        args.runtime_info.parent.mkdir(parents=True, exist_ok=True)
        args.runtime_info.write_text(
            json.dumps({
                "base_url": server.base_url,
                "mode": args.mode,
                "transport": args.transport,
            }, indent=2),
            encoding="utf-8",
        )

    def stop(*_args: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    print(
        f"MCP authorization fixture ready at {server.base_url} "
        f"with {args.transport} in {args.mode} mode",
        flush=True,
    )
    try:
        stopped.wait()
    finally:
        server.close()
        if args.runtime_info:
            args.runtime_info.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
