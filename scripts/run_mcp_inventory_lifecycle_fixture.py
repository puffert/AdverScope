from __future__ import annotations

import argparse
import signal
import threading

from osai_security.mcp_inventory_lifecycle_fixture import MCPInventoryLifecycleFixtureServer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MCP inventory lifecycle qualification fixture")
    parser.add_argument("--mode", choices=("secure", "vulnerable"), required=True)
    parser.add_argument(
        "--transport",
        choices=("stateless-http", "streamable-http", "legacy-http-sse"),
        required=True,
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    stopped = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    fixture = MCPInventoryLifecycleFixtureServer(
        args.mode,
        args.transport,
        host=args.host,
        port=args.port,
    ).start()
    try:
        print(fixture.base_url, flush=True)
        stopped.wait()
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
