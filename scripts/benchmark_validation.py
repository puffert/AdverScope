#!/usr/bin/env python3
"""Score selected AdverScope executions with a separate, non-secret oracle."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.benchmarking import BenchmarkConfigurationError, score_benchmark, validate_benchmark_definition


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(urljoin(self.base_url, path.lstrip("/")), data=body, method=method, headers={"Accept": "application/json", "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise BenchmarkConfigurationError(f"AdverScope returned HTTP {exc.code} for {method} {path}") from exc
        except URLError as exc:
            raise BenchmarkConfigurationError(f"AdverScope is unavailable at {self.base_url}") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, payload)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkConfigurationError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BenchmarkConfigurationError(f"{path} must contain a JSON object")
    return value


def _report_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        f"# {result['suite_id']} qualification report",
        "",
        f"- Campaign: `{result['campaign_id']}`",
        f"- Generated: {result['generated_at']}",
        f"- Projects: {summary['projects']}",
        f"- Gated expectations: {summary['gated_expectations']}",
        f"- Precision: {summary['precision'] if summary['precision'] is not None else 'not available'}",
        f"- Recall: {summary['recall'] if summary['recall'] is not None else 'not available'}",
        f"- Reproduction: {summary.get('reproduction_confirmed', 0)}/{summary.get('reproduction_required', 0)} required expectations" if summary.get("reproduction_required") else "- Reproduction: no gated expectation required automatic reproduction",
        "",
        "The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.",
        "",
        "## Results",
        "",
        "| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in result["rows"]:
        for item in row["expectations"]:
            execution = f"{item['execution_kind']} `{item['execution_id']}`" if item["execution_id"] else "none"
            lines.append(
                f"| {row['label']} | {item['title']} | {item['qualification_role']} | "
                f"{'yes' if item['required_for_gate'] else 'no'} | {item['expected_outcome']} | {item['observed_outcome']} | "
                f"{item['classification']} | {item['root_cause']} | {execution} |"
            )
    return "\n".join(lines) + "\n"


def _write_outputs(result: dict[str, Any], json_output: Path | None, markdown_output: Path | None) -> None:
    if json_output:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if markdown_output:
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(_report_markdown(result), encoding="utf-8")


def _record_adjudications(api: ApiClient, result: dict[str, Any]) -> int:
    recorded = 0
    for row in result["rows"]:
        for item in row["expectations"]:
            if not item["execution_id"] or item["classification"] == "not_applicable":
                continue
            endpoint = "runs" if item["execution_kind"] == "assessment" else "tool-runs"
            payload = {
                "source": "oracle",
                "expectation_id": item["id"],
                "expected_outcome": item["expected_outcome"],
                "observed_outcome": item["observed_outcome"],
                "classification": item["classification"],
                "root_cause": item["root_cause"],
                "notes": "Post-run benchmark oracle comparison. Oracle content was not supplied to AdverScope execution or evaluation.",
                "metadata": {"suite_id": result["suite_id"], "campaign_id": result["campaign_id"], "qualification_role": item["qualification_role"], "required_for_gate": item["required_for_gate"]},
            }
            if item.get("test_case_id") and endpoint == "runs":
                payload["test_case_id"] = item["test_case_id"]
            api.post(f"/api/projects/{row['project_id']}/{endpoint}/{item['execution_id']}/adjudications", payload)
            recorded += 1
    return recorded


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_benchmark_definition(load_json(args.campaign), load_json(args.oracle))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Benchmark campaign and isolated oracle are structurally valid.")
    return 0


def command_score(args: argparse.Namespace) -> int:
    campaign, oracle = load_json(args.campaign), load_json(args.oracle)
    api = ApiClient(args.api)
    api.get("/api/health")
    result = score_benchmark(
        campaign,
        oracle,
        project_loader=lambda project_id: api.get(f"/api/projects/{project_id}"),
        assessment_loader=lambda project_id, run_id: api.get(f"/api/projects/{project_id}/runs/{run_id}"),
        tool_loader=lambda project_id, run_id: api.get(f"/api/projects/{project_id}/tool-runs/{run_id}"),
    )
    result["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    recorded = _record_adjudications(api, result) if args.record_adjudications else 0
    _write_outputs(result, args.json_output, args.markdown_output)
    summary = result["summary"]
    print(f"Scored {summary['gated_expectations']} gated expectations across {summary['projects']} projects; precision={summary['precision']}, recall={summary['recall']}, recorded_adjudications={recorded}.")
    if args.require_gates:
        return int(
            summary["precision"] is None
            or summary["recall"] is None
            or summary["precision"] < args.minimum_precision
            or summary["recall"] < args.minimum_recall
            or summary["infrastructure_errors"]
            or summary["inconclusive"]
        )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("validate", "score"):
        command = commands.add_parser(name)
        command.add_argument("--campaign", type=Path, required=True)
        command.add_argument("--oracle", type=Path, required=True)
        if name == "validate":
            command.set_defaults(handler=command_validate)
        else:
            command.add_argument("--api", default="http://127.0.0.1:8091")
            command.add_argument("--json-output", type=Path)
            command.add_argument("--markdown-output", type=Path)
            command.add_argument("--record-adjudications", action="store_true")
            command.add_argument("--require-gates", action="store_true")
            command.add_argument("--minimum-precision", type=float, default=0.95)
            command.add_argument("--minimum-recall", type=float, default=0.95)
            command.set_defaults(handler=command_score)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.handler(args))
    except BenchmarkConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
