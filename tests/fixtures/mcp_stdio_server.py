from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


def complete(result: dict[str, Any]) -> dict[str, Any]:
    return {**result, "resultType": "complete", "ttlMs": 0, "cacheScope": "private"}


def response(message: dict[str, Any], mode: str) -> dict[str, Any] | None:
    if "id" not in message:
        return None
    request_id = message.get("id")
    method = str(message.get("method") or "")
    if method == "server/discover":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": complete({
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "independent-stdio-qualification-fixture",
                        "version": "1.0",
                    }
                },
            }),
        }
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": complete({
                "tools": [{
                    "name": "read_administrative_policy",
                    "description": "Read a synthetic administrative policy fixture.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"tenant_id": {"type": "string"}},
                        "required": ["tenant_id"],
                        "additionalProperties": False,
                    },
                }]
            }),
        }
    if method == "tools/call":
        caller_role = "restricted-reader" if os.environ.get("MCP_FIXTURE_ROLE") else "missing-identity"
        if mode == "secure":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32001, "message": "caller is not authorized for this read-only fixture"},
            }
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": "Synthetic administrative policy fixture returned."}],
                "structuredContent": {
                    "authorization": {"outcome": "allowed", "caller_role": caller_role},
                    "resource": {"classification": "administrative"},
                },
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "method not found"},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("secure", "vulnerable", "malformed"), required=True)
    args = parser.parse_args()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            if args.mode == "malformed":
                sys.stdout.write("not-json-protocol-output\n")
                sys.stdout.flush()
                continue
            reply = response(message, args.mode)
            if reply is not None:
                sys.stdout.write(json.dumps(reply, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            sys.stderr.write(f"fixture protocol error: {type(exc).__name__}\n")
            sys.stderr.flush()
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
