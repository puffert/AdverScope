from __future__ import annotations

import argparse
import time

from osai_security.m4_control_fixture import M4ControlFixtureServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a synthetic Milestone 4 deterministic-control fixture.")
    parser.add_argument("--family", choices=("flat-v1", "nested-v2"), default="flat-v1")
    parser.add_argument("--mode", choices=("secure", "vulnerable"), default="secure")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    with M4ControlFixtureServer(args.family, args.mode, host=args.host, port=args.port) as server:
        print(f"M4 fixture listening at {server.base_url}", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
