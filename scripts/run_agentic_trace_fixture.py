from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.agentic_trace_fixture import (
    AGENTIC_TRACE_FIXTURE_MODES,
    AgenticTraceFixtureServer,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the independent AdverScope agentic trace qualification fixture.")
    parser.add_argument("--mode", choices=sorted(AGENTIC_TRACE_FIXTURE_MODES), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    stopped = threading.Event()
    fixture = AgenticTraceFixtureServer(args.mode, host=args.host, port=args.port).start()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"Agentic trace fixture ({args.mode}) listening at {fixture.base_url}", flush=True)
    try:
        while not stopped.wait(0.5):
            pass
    finally:
        fixture.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
