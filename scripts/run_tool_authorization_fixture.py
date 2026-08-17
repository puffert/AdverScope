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

from osai_security.tool_authorization_fixture import (
    TOOL_AUTHORIZATION_FIXTURE_MODES,
    ToolAuthorizationFixtureServer,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an independent tool-authorization qualification target.")
    parser.add_argument("--mode", choices=sorted(TOOL_AUTHORIZATION_FIXTURE_MODES), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--runtime-info", type=Path)
    args = parser.parse_args()

    stopped = threading.Event()
    server = ToolAuthorizationFixtureServer(args.mode, host=args.host, port=args.port).start()
    if args.runtime_info:
        args.runtime_info.parent.mkdir(parents=True, exist_ok=True)
        args.runtime_info.write_text(
            json.dumps({"base_url": server.base_url, "mode": args.mode}, indent=2),
            encoding="utf-8",
        )

    def stop(*_args: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    print(f"Tool authorization fixture ready at {server.base_url} in {args.mode} mode", flush=True)
    try:
        stopped.wait()
    finally:
        server.close()
        if args.runtime_info:
            args.runtime_info.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
