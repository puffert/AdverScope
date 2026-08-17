from __future__ import annotations

import argparse
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.http_app import Application, create_server
from osai_security.qualification_fixture import QualificationFixtureServer
from osai_security.tutorial import TUTORIAL_PROJECT_NAME


def _request_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"tutorial qualification request failed with HTTP {exc.code}: {detail}") from exc


def qualify(config_path: Path, *, fixture_port: int) -> dict[str, Any]:
    config = AppConfig.from_sources(config_path)
    repository = Repository(config.database_path)
    application = Application(repository, config=config)
    server = create_server(application, "127.0.0.1", 0)
    server_thread = threading.Thread(target=server.serve_forever, name="tutorial-qualification-app", daemon=True)
    fixture = QualificationFixtureServer("vulnerable", host="127.0.0.1", port=fixture_port)
    try:
        fixture.start()
        server_thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        runtime = _request_json(f"{base_url}/api/runtime")
        project_document = _request_json(f"{base_url}/api/projects")
        projects = project_document.get("projects") or []
        project = next((item for item in projects if item.get("name") == TUTORIAL_PROJECT_NAME), None)
        if project is None:
            raise RuntimeError("synthetic tutorial project is missing")
        if len(projects) != 1:
            raise RuntimeError("tutorial qualification state is not isolated")
        detail = _request_json(f"{base_url}/api/projects/{project['id']}")
        target = detail["targets"][0]
        objective = detail["objectives"][0]
        run = _request_json(
            f"{base_url}/api/projects/{project['id']}/runs",
            "POST",
            {
                "target_id": target["id"],
                "modules": ["prompt-injection", "sensitive-disclosure"],
                "objective_ids": [objective["id"]],
                "technique_ids": ["LLM01-DIRECT", "LLM02-SECRETS"],
                "model_mode": "asus",
                "attack_budget": 1,
            },
        )
        finished = _request_json(f"{base_url}/api/projects/{project['id']}/runs/{run['id']}")
        cases = finished.get("test_cases") or []
        summary = {
            "runtime_version": (runtime.get("build") or {}).get("version"),
            "run_status": finished.get("status"),
            "test_cases": len(cases),
            "findings": len(finished.get("findings") or []),
            "evidence_records": sum(len(item.get("evidence") or []) for item in cases),
            "isolated_project": True,
        }
        if summary["run_status"] != "completed":
            raise RuntimeError(f"tutorial assessment ended with status {summary['run_status']!r}")
        if not summary["test_cases"] or not summary["evidence_records"] or not summary["findings"]:
            raise RuntimeError(f"tutorial assessment did not produce complete result records: {summary}")
        return summary
    finally:
        server.shutdown()
        server.server_close()
        if server_thread.is_alive():
            server_thread.join(timeout=5)
        fixture.close()
        repository.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Qualify an installed AdverScope wheel with the synthetic tutorial")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--fixture-port", type=int, default=18765)
    args = parser.parse_args()
    print(json.dumps(qualify(args.config.resolve(), fixture_port=args.fixture_port), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
