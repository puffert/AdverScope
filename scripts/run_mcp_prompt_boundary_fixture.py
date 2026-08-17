from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from osai_security.mcp_prompt_boundary_fixture import MCPPromptBoundaryFixtureServer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the raw MCP prompt inventory/access qualification fixture")
    parser.add_argument("--mode", choices=("secure", "vulnerable"), required=True)
    parser.add_argument("--transport", choices=("streamable-http", "legacy-http-sse"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_args: stop.set())
    signal.signal(signal.SIGTERM, lambda *_args: stop.set())
    server = MCPPromptBoundaryFixtureServer(args.mode, args.transport, host=args.host, port=args.port).start()
    try:
        stop.wait()
    finally:
        server.close()


if __name__ == "__main__":
    main()
