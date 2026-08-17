from __future__ import annotations

import argparse
import signal
import threading

from osai_security.policy_gateway_fixture import POLICY_GATEWAY_MODES, PolicyGatewayFixtureServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an independent structured policy-gateway qualification target.")
    parser.add_argument("--mode", choices=sorted(POLICY_GATEWAY_MODES), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8097)
    args = parser.parse_args()
    stopped = threading.Event()
    server = PolicyGatewayFixtureServer(args.mode, host=args.host, port=args.port).start()

    def stop(*_args: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    print(f"Policy gateway fixture ready at {server.base_url} in {args.mode} mode", flush=True)
    try:
        stopped.wait()
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
