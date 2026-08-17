from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import unittest
from typing import Any


RELIABILITY_CORPUS_SCHEMA_VERSION = "1.0"
RELIABILITY_RESULT_SCHEMA_VERSION = "1.0"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_repository_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"reliability source escapes the repository: {relative}") from exc
    return candidate


def load_reliability_corpus(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("reliability corpus must contain a JSON object")
    return value


def validate_reliability_corpus(corpus: dict[str, Any], *, root: Path) -> dict[str, Any]:
    errors: list[str] = []
    if corpus.get("schema_version") != RELIABILITY_CORPUS_SCHEMA_VERSION:
        errors.append(f"schema_version must be {RELIABILITY_CORPUS_SCHEMA_VERSION}")
    if not str(corpus.get("corpus_id") or "").strip():
        errors.append("corpus_id is required")
    if not str(corpus.get("version") or "").strip():
        errors.append("version is required")
    if not str(corpus.get("frozen_at") or "").strip():
        errors.append("frozen_at is required")

    source_files = corpus.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        errors.append("source_files must contain at least one repository path")
        source_files = []
    seen_sources: set[str] = set()
    for relative in source_files:
        name = str(relative or "").strip().replace("\\", "/")
        if not name or name in seen_sources:
            errors.append("source_files must contain unique non-empty paths")
            continue
        seen_sources.add(name)
        path = _safe_repository_path(root, name)
        if not path.is_file():
            errors.append(f"reliability source is missing: {name}")

    workstreams = corpus.get("workstreams")
    if not isinstance(workstreams, list) or not workstreams:
        errors.append("workstreams must contain at least one gate")
        workstreams = []
    workstream_ids: set[str] = set()
    control_ids: set[str] = set()
    test_ids: set[str] = set()
    for workstream in workstreams:
        if not isinstance(workstream, dict):
            errors.append("every reliability workstream must be an object")
            continue
        workstream_id = str(workstream.get("id") or "").strip()
        if not workstream_id or workstream_id in workstream_ids:
            errors.append("workstream IDs must be non-empty and unique")
        workstream_ids.add(workstream_id)
        controls = workstream.get("controls")
        if not isinstance(controls, list) or not controls:
            errors.append(f"{workstream_id or 'workstream'} must contain controls")
            continue
        for control in controls:
            if not isinstance(control, dict):
                errors.append(f"{workstream_id} contains a non-object control")
                continue
            control_id = str(control.get("id") or "").strip()
            test_id = str(control.get("test") or "").strip()
            if not control_id or control_id in control_ids:
                errors.append("control IDs must be non-empty and globally unique")
            control_ids.add(control_id)
            if not test_id.startswith("tests.test_") or test_id.count(".") < 3:
                errors.append(f"{control_id or 'control'} has an invalid unittest selector")
            if test_id in test_ids:
                errors.append(f"duplicate unittest selector: {test_id}")
            test_ids.add(test_id)

    open_gates = corpus.get("open_gates")
    if not isinstance(open_gates, list) or not open_gates:
        errors.append("open_gates must identify qualification work that automation cannot close")
        open_gates = []
    open_ids: set[str] = set()
    for gate in open_gates:
        if not isinstance(gate, dict):
            errors.append("every open gate must be an object")
            continue
        gate_id = str(gate.get("id") or "").strip()
        if not gate_id or gate_id in open_ids or gate_id in workstream_ids:
            errors.append("open gate IDs must be non-empty and unique")
        if not str(gate.get("reason") or "").strip():
            errors.append(f"{gate_id or 'open gate'} must explain why it remains open")
        open_ids.add(gate_id)

    if errors:
        raise ValueError("invalid reliability corpus:\n- " + "\n- ".join(errors))
    return corpus


def _run_test(test_id: str) -> dict[str, Any]:
    suite = unittest.defaultTestLoader.loadTestsFromName(test_id)
    count = suite.countTestCases()
    stream = io.StringIO()
    captured = io.StringIO()
    with redirect_stdout(captured), redirect_stderr(captured):
        result = unittest.TextTestRunner(stream=stream, verbosity=0, failfast=False).run(suite)
    failure_text = "\n".join(text for _test, text in [*result.failures, *result.errors])
    return {
        "test": test_id,
        "test_cases": count,
        "status": "passed" if count == 1 and result.wasSuccessful() and not result.skipped else "failed",
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "diagnostic": (failure_text or captured.getvalue())[-2000:] if not result.wasSuccessful() else "",
    }


def evaluate_reliability_corpus(corpus: dict[str, Any], *, root: Path) -> dict[str, Any]:
    validated = validate_reliability_corpus(corpus, root=root)
    source_integrity = [
        {"path": str(item).replace("\\", "/"), "sha256": _sha256(_safe_repository_path(root, str(item)))}
        for item in validated["source_files"]
    ]
    workstreams: list[dict[str, Any]] = []
    for workstream in validated["workstreams"]:
        controls = []
        for control in workstream["controls"]:
            outcome = _run_test(str(control["test"]))
            controls.append({
                "id": str(control["id"]),
                "title": str(control["title"]),
                **outcome,
            })
        workstreams.append({
            "id": str(workstream["id"]),
            "title": str(workstream["title"]),
            "status": "passed" if all(item["status"] == "passed" for item in controls) else "failed",
            "controls": controls,
        })

    open_gates = [
        {
            "id": str(gate["id"]),
            "title": str(gate["title"]),
            "status": "open",
            "reason": str(gate["reason"]),
        }
        for gate in validated["open_gates"]
    ]
    passed_controls = sum(
        1 for workstream in workstreams for control in workstream["controls"] if control["status"] == "passed"
    )
    total_controls = sum(len(workstream["controls"]) for workstream in workstreams)
    failed_workstreams = [item["id"] for item in workstreams if item["status"] != "passed"]
    return {
        "schema_version": RELIABILITY_RESULT_SCHEMA_VERSION,
        "corpus_id": str(validated["corpus_id"]),
        "corpus_version": str(validated["version"]),
        "frozen_at": str(validated["frozen_at"]),
        "status": "in_progress" if open_gates or failed_workstreams else "complete",
        "summary": {
            "workstreams_passed": len(workstreams) - len(failed_workstreams),
            "workstreams_total": len(workstreams),
            "controls_passed": passed_controls,
            "controls_total": total_controls,
            "open_gates": len(open_gates),
        },
        "source_integrity": source_integrity,
        "workstreams": workstreams,
        "open_gates": open_gates,
    }


def render_reliability_report(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# AdverScope M5.4 reliability and evidence-custody qualification",
        "",
        "<!-- Generated by scripts/qualify_reliability.py; edit the frozen corpus or implementation, not this file. -->",
        "",
        f"Corpus `{result['corpus_id']}` version `{result['corpus_version']}` was frozen at `{result['frozen_at']}`. Current M5.4 status: **{result['status'].replace('_', ' ')}**.",
        "",
        "This gate executes the named controls. A listed pass is backed by the exact regression selector shown below; it is not inferred from source-code presence.",
        "",
        "## Current result",
        "",
        f"- {summary['controls_passed']} of {summary['controls_total']} executable reliability controls passed.",
        f"- {summary['workstreams_passed']} of {summary['workstreams_total']} automated workstreams passed.",
        f"- {summary['open_gates']} non-automated release gates remain open.",
        "",
        "## Automated workstreams",
        "",
        "| Workstream | Status | Controls |",
        "|---|---|---:|",
    ]
    for workstream in result["workstreams"]:
        lines.append(f"| {workstream['title']} | {workstream['status']} | {len(workstream['controls'])} |")
    for workstream in result["workstreams"]:
        lines.extend(["", f"### {workstream['title']}", "", "| Control | Result | Exact executable selector |", "|---|---|---|"])
        for control in workstream["controls"]:
            lines.append(f"| {control['title']} | {control['status']} | `{control['test']}` |")
    lines.extend(["", "## Gates that remain open", ""])
    for gate in result["open_gates"]:
        lines.append(f"- **{gate['title']}:** {gate['reason']}")
    lines.extend([
        "",
        "## Interpretation",
        "",
        "- This report qualifies deterministic implementation controls on the current source tree. It does not replace long-duration observation, platform release-matrix evidence, or an independent product-security review.",
        "- A failed or skipped selector fails its entire workstream. The gate never converts an execution error into a security pass.",
        "- Source hashes make the generated baseline stale whenever a covered implementation or test file changes.",
        "- Independent field applicability and multi-model quality are tracked separately by M5.1 and M5.2.",
        "",
    ])
    return "\n".join(lines)
