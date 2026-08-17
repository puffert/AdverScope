from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any
import zipfile

from . import build_identity
from .release import EVIDENCE_BUNDLE_SCHEMA_VERSION
from .reports import build_markdown_report
from .security import redact_text
from .telemetry import telemetry_export


BUNDLE_SCHEMA_VERSION = EVIDENCE_BUNDLE_SCHEMA_VERSION
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
_SENSITIVE_KEY = re.compile(r"(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|client_secret)", re.IGNORECASE)
_QUERY_SECRET = re.compile(r"(?i)([?&](?:access_token|token|api[_-]?key|key|secret|password)=)[^&#\s]+")


class EvidenceBundleError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _redact_value(value: Any, *, key: str = "") -> Any:
    if _SENSITIVE_KEY.search(key):
        if isinstance(value, (dict, list)):
            return "[REDACTED]"
        if value not in (None, "", False):
            return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact_value(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, key=key) for item in value]
    if isinstance(value, str):
        return _QUERY_SECRET.sub(r"\1[REDACTED]", redact_text(value, max(len(value), 1)))
    return value


def _json_bytes(value: Any, *, redacted: bool) -> bytes:
    document = _redact_value(value) if redacted else value
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-")
    return cleaned[:120] or "record"


def _scoped_finding(finding: dict[str, Any], run_id: str, allowed_evidence_ids: set[str]) -> dict[str, Any] | None:
    item = copy.deepcopy(finding)
    item["occurrences"] = [
        occurrence for occurrence in item.get("occurrences") or []
        if str(occurrence.get("run_id") or "") == run_id
    ]
    item["validations"] = [
        validation for validation in item.get("validations") or []
        if str(validation.get("run_id") or "") == run_id
    ]
    evidence = item.get("evidence") or {}
    if str(evidence.get("id") or "") not in allowed_evidence_ids:
        item.pop("evidence", None)
    if not item["occurrences"] and not item["validations"] and str(item.get("run_id") or "") != run_id:
        return None
    item["run_id"] = run_id
    return item


def _scoped_run_detail(detail: dict[str, Any]) -> dict[str, Any]:
    run_id = str(detail["id"])
    allowed_evidence_ids = {
        str(evidence.get("id") or "")
        for case in detail.get("test_cases") or []
        for evidence in case.get("evidence") or []
        if evidence.get("id")
    }
    findings = []
    for finding in detail.get("findings") or []:
        scoped = _scoped_finding(finding, run_id, allowed_evidence_ids)
        if scoped:
            findings.append(scoped)
    result = copy.deepcopy(detail)
    result["findings"] = findings
    return result


def _run_scoped_reasoning(reasoning: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    """Derive a bundle view without attributing another run's evidence to this run."""
    result = copy.deepcopy(reasoning)
    run_id = str(detail.get("id") or "")
    allowed_evidence_ids = {
        str(evidence.get("id") or "")
        for case in detail.get("test_cases") or []
        for evidence in case.get("evidence") or []
        if evidence.get("id")
    }
    omitted_refs = 0
    for collection in ("edges", "hypotheses"):
        for item in result.get(collection) or []:
            references = [str(value) for value in item.get("evidence_refs") or [] if str(value)]
            retained = [value for value in references if value in allowed_evidence_ids]
            omitted_refs += len(references) - len(retained)
            item["evidence_refs"] = retained
    checkpoints = list(result.get("checkpoints") or [])
    result["checkpoints"] = [
        item for item in checkpoints
        if (not item.get("run_id") or str(item.get("run_id")) == run_id)
        and (not item.get("evidence_id") or str(item.get("evidence_id")) in allowed_evidence_ids)
    ]
    omitted_checkpoints = len(checkpoints) - len(result["checkpoints"])
    result["omitted_external_evidence_refs"] = omitted_refs
    result["omitted_external_checkpoints"] = omitted_checkpoints
    result["bundle_scope_notice"] = (
        "Derived for this run only; evidence references and checkpoints linked to other runs were omitted."
    )
    source_sha256 = str(result.pop("snapshot_sha256", "") or "")
    if source_sha256:
        result["source_snapshot_sha256"] = source_sha256
    summary = dict(result.get("summary") or {})
    summary["checkpoints"] = len(result["checkpoints"])
    result["summary"] = summary
    canonical = _canonical_json(result)
    result["snapshot_sha256"] = _sha256(canonical)
    return result


def _project_snapshot(repo: Any, project_id: str, run_id: str | None) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    project = repo.get_project(project_id)
    if run_id:
        runs = [_scoped_run_detail(repo.get_run_detail(project_id, run_id))]
        tool_runs = [repo.get_tool_run(project_id, item) for item in repo.list_tool_run_ids(project_id, assessment_run_id=run_id)]
        selected_target_id = str(runs[0].get("target_id") or "")
        project["targets"] = [item for item in project.get("targets") or [] if str(item.get("id") or "") == selected_target_id]
        project["guardrails"] = [item for item in project.get("guardrails") or [] if str(item.get("target_id") or "") == selected_target_id]
        project["findings"] = runs[0]["findings"]
        tool_run_ids = {str(item.get("id") or "") for item in tool_runs}
        project["tool_findings"] = [item for item in project.get("tool_findings") or [] if str(item.get("tool_run_id") or "") in tool_run_ids]
        project["owasp_coverage"] = runs[0].get("owasp_coverage") or {}
        reasoning_snapshot = copy.deepcopy(
            (runs[0].get("assessment_plan") or {}).get("reasoning_snapshot") or {
                "advisory_only": True,
                "summary": {},
                "methodology_cards": [],
                "nodes": [],
                "edges": [],
                "hypotheses": [],
                "checkpoints": [],
            }
        )
        project["assessment_reasoning"] = _run_scoped_reasoning(reasoning_snapshot, runs[0])
    else:
        runs = [_scoped_run_detail(repo.get_run_detail(project_id, item)) for item in repo.list_run_ids(project_id)]
        tool_runs = [repo.get_tool_run(project_id, item) for item in repo.list_tool_run_ids(project_id)]
    project["runs"] = runs
    project["tool_runs"] = tool_runs
    project["report_review"] = repo.get_report_review(project_id)
    return project, runs, tool_runs


def _validate_evidence_links(project_id: str, runs: list[dict[str, Any]]) -> None:
    for run in runs:
        run_id = str(run.get("id") or "")
        evidence_by_case = {
            str(case.get("id") or ""): {
                str(evidence.get("id") or "")
                for evidence in case.get("evidence") or []
                if evidence.get("id")
            }
            for case in run.get("test_cases") or []
        }
        for finding in run.get("findings") or []:
            for occurrence in finding.get("occurrences") or []:
                case_id = str(occurrence.get("test_case_id") or "")
                evidence_id = str(occurrence.get("evidence_id") or "")
                if str(occurrence.get("run_id") or "") != run_id or evidence_id not in evidence_by_case.get(case_id, set()):
                    raise EvidenceBundleError(f"broken finding evidence link in {run_id}")
            for validation in finding.get("validations") or []:
                if str(validation.get("run_id") or "") != run_id:
                    raise EvidenceBundleError(f"cross-run validation link in {run_id}")
        for case in run.get("test_cases") or []:
            if str(case.get("project_id") or "") != project_id or str(case.get("run_id") or "") != run_id:
                raise EvidenceBundleError(f"cross-project or cross-run case in {run_id}")


def _add_entry(entries: dict[str, bytes], path: str, content: bytes) -> None:
    if path in entries:
        raise EvidenceBundleError(f"duplicate bundle path: {path}")
    normalized = Path(path)
    if normalized.is_absolute() or ".." in normalized.parts:
        raise EvidenceBundleError("bundle path escaped its archive root")
    entries[normalized.as_posix()] = content


def _evidence_index(runs: list[dict[str, Any]], assets: list[dict[str, Any]], *, include_binaries: bool) -> str:
    lines = [
        "# Evidence appendix",
        "",
        "Every record below belongs to the exported project and optional run boundary. Binary evidence is included only in full-internal mode.",
        "",
        "| Run | Case | Evidence | Kind | Recorded |",
        "|---|---|---|---|---|",
    ]
    for run in runs:
        for case in run.get("test_cases") or []:
            for evidence in case.get("evidence") or []:
                lines.append(
                    f"| `{run.get('id')}` | `{case.get('id')}` | `{evidence.get('id')}` | {evidence.get('kind')} | {evidence.get('created_at')} |"
                )
    lines.extend([
        "",
        "## Binary evidence assets",
        "",
        "| Asset | Run | Case | Kind | Attempt | SHA-256 | Included |",
        "|---|---|---|---|---|---|---|",
    ])
    for asset in assets:
        lines.append(
            f"| `{asset.get('id')}` | `{asset.get('run_id')}` | `{asset.get('test_case_id')}` | {asset.get('kind')} | {asset.get('attempt')} | `{asset.get('sha256')}` | {'yes' if include_binaries else 'no — redacted bundle'} |"
        )
    return "\n".join(lines) + "\n"


def build_evidence_bundle(
    repo: Any,
    evidence_store: Any,
    *,
    project_id: str,
    run_id: str | None = None,
    mode: str = "redacted",
) -> dict[str, Any]:
    if mode not in {"redacted", "full"}:
        raise EvidenceBundleError("evidence bundle mode must be redacted or full")
    project, runs, tool_runs = _project_snapshot(repo, project_id, run_id)
    _validate_evidence_links(project_id, runs)
    redacted = mode == "redacted"
    entries: dict[str, bytes] = {}
    assets = repo.list_evidence_assets(project_id, run_id=run_id)
    scope_label = f"run {run_id}" if run_id else "complete project"
    review = project.get("report_review") or {}
    report = build_markdown_report(_redact_value(project) if redacted else project)
    _add_entry(entries, "report/assessment-report.md", report.encode("utf-8"))
    _add_entry(entries, "report/evidence-appendix.md", _evidence_index(runs, assets, include_binaries=not redacted).encode("utf-8"))
    _add_entry(entries, "records/project.json", _json_bytes(project, redacted=redacted))
    for document in repo.list_documents(project_id):
        _add_entry(
            entries,
            f"records/documents/{_safe_component(str(document['id']))}-{_safe_component(str(document['filename']))}.json",
            _json_bytes(document, redacted=redacted),
        )
    for run in runs:
        run_path = _safe_component(str(run["id"]))
        _add_entry(entries, f"records/runs/{run_path}.json", _json_bytes(run, redacted=redacted))
        _add_entry(entries, f"records/telemetry/{run_path}.json", _json_bytes(telemetry_export(run, execution_kind="assessment"), redacted=redacted))
    for tool_run in tool_runs:
        tool_path = _safe_component(str(tool_run["id"]))
        _add_entry(entries, f"records/tool-runs/{tool_path}.json", _json_bytes(tool_run, redacted=redacted))
        _add_entry(entries, f"records/tool-telemetry/{tool_path}.json", _json_bytes(telemetry_export(tool_run, execution_kind="tool"), redacted=redacted))

    omitted_assets = []
    total_binary_bytes = 0
    for asset in assets:
        source = evidence_store.resolve(str(asset["relative_path"]))
        if not source.is_file():
            raise EvidenceBundleError(f"evidence asset is missing: {asset['id']}")
        content = source.read_bytes()
        if len(content) != int(asset["size_bytes"]) or _sha256(content) != str(asset["sha256"]):
            raise EvidenceBundleError(f"evidence asset integrity check failed: {asset['id']}")
        if redacted:
            omitted_assets.append({
                "id": asset["id"],
                "run_id": asset["run_id"],
                "test_case_id": asset["test_case_id"],
                "sha256": asset["sha256"],
                "size_bytes": asset["size_bytes"],
                "reason": "binary evidence omitted from shareable redacted bundle",
            })
            continue
        suffix = Path(str(asset["relative_path"])).suffix or ".bin"
        _add_entry(entries, f"evidence/assets/{_safe_component(str(asset['id']))}{suffix}", content)
        total_binary_bytes += len(content)

    artifact_ids: set[str] = set()
    if run_id:
        for run in runs:
            artifact_ids.update(
                str(item.get("artifact_id") or item.get("id") or "")
                for item in (run.get("assessment_plan") or {}).get("artifact_inventory") or []
            )
        artifacts = [item for item in repo.list_artifacts(project_id, include_archived=True) if str(item["id"]) in artifact_ids]
    else:
        artifacts = repo.list_artifacts(project_id, include_archived=True)
    omitted_artifacts = []
    _add_entry(entries, "records/artifacts.json", _json_bytes(artifacts, redacted=redacted))
    for artifact in artifacts:
        source = evidence_store.resolve(str(artifact["relative_path"]))
        if not source.is_file():
            raise EvidenceBundleError(f"project artifact is missing: {artifact['id']}")
        content = source.read_bytes()
        if len(content) != int(artifact["size_bytes"]) or _sha256(content) != str(artifact["sha256"]):
            raise EvidenceBundleError(f"project artifact integrity check failed: {artifact['id']}")
        if redacted:
            omitted_artifacts.append({
                "id": artifact["id"],
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "reason": "customer-supplied artifact omitted from shareable redacted bundle",
            })
            continue
        _add_entry(entries, f"artifacts/{_safe_component(str(artifact['id']))}/content.bin", content)
        total_binary_bytes += len(content)
    if sum(len(value) for value in entries.values()) > MAX_BUNDLE_BYTES:
        raise EvidenceBundleError("evidence bundle exceeds the local size limit")

    readme = (
        "# AdverScope evidence bundle\n\n"
        f"Scope: {scope_label}\n\n"
        f"Mode: {mode}\n\n"
        f"Report status: {review.get('effective_status') or 'draft'}\n\n"
        "Verify this archive before review with `python scripts/verify_evidence_bundle.py <bundle.zip>`. "
        "A redacted bundle intentionally omits binary screenshots and customer artifacts while retaining their original hashes.\n"
    )
    _add_entry(entries, "README.md", readme.encode("utf-8"))
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "framework": build_identity(),
        "project_id": project_id,
        "run_id": run_id or "",
        "scope": "run" if run_id else "project",
        "mode": mode,
        "report_status": str(review.get("effective_status") or "draft"),
        "report_review_current": bool(review.get("is_current")),
        "files": [
            {"path": path, "size_bytes": len(content), "sha256": _sha256(content)}
            for path, content in sorted(entries.items())
        ],
        "omitted_assets": omitted_assets,
        "omitted_artifacts": omitted_artifacts,
        "included_binary_bytes": total_binary_bytes,
    }
    manifest["manifest_sha256"] = _sha256(_canonical_json(manifest))
    manifest_bytes = _json_bytes(manifest, redacted=False)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path, content in sorted(entries.items()):
            bundle.writestr(path, content)
        bundle.writestr("manifest.json", manifest_bytes)
    content = archive.getvalue()
    safe_name = _safe_component(str(project.get("name") or project_id)).casefold()
    suffix = _safe_component(run_id) if run_id else "project"
    return {
        "filename": f"{safe_name}-{suffix}-{mode}-evidence.zip",
        "content": content,
        "size_bytes": len(content),
        "sha256": _sha256(content),
        "manifest": manifest,
    }


def verify_evidence_bundle(content: bytes, *, expected_project_id: str = "", expected_run_id: str = "") -> dict[str, Any]:
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as bundle:
            names = bundle.namelist()
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise EvidenceBundleError("bundle manifest is missing or archive paths are duplicated")
            for name in names:
                path = Path(name)
                if path.is_absolute() or ".." in path.parts:
                    raise EvidenceBundleError("bundle contains an unsafe archive path")
            manifest = json.loads(bundle.read("manifest.json").decode("utf-8"))
            if str(manifest.get("schema_version") or "") != BUNDLE_SCHEMA_VERSION:
                raise EvidenceBundleError("unsupported evidence bundle schema")
            if expected_project_id and str(manifest.get("project_id") or "") != expected_project_id:
                raise EvidenceBundleError("bundle belongs to a different project")
            if expected_run_id and str(manifest.get("run_id") or "") != expected_run_id:
                raise EvidenceBundleError("bundle belongs to a different run")
            claimed_manifest_hash = str(manifest.pop("manifest_sha256", ""))
            if claimed_manifest_hash != _sha256(_canonical_json(manifest)):
                raise EvidenceBundleError("bundle manifest integrity check failed")
            manifest["manifest_sha256"] = claimed_manifest_hash
            declared = {str(item["path"]): item for item in manifest.get("files") or []}
            actual = set(names) - {"manifest.json"}
            if set(declared) != actual:
                raise EvidenceBundleError("bundle file set does not match its manifest")
            for path, item in declared.items():
                file_content = bundle.read(path)
                if len(file_content) != int(item.get("size_bytes") or -1) or _sha256(file_content) != str(item.get("sha256") or ""):
                    raise EvidenceBundleError(f"bundle file integrity check failed: {path}")
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EvidenceBundleError("invalid evidence bundle") from exc
    return {
        "ok": True,
        "project_id": str(manifest.get("project_id") or ""),
        "run_id": str(manifest.get("run_id") or ""),
        "scope": str(manifest.get("scope") or ""),
        "mode": str(manifest.get("mode") or ""),
        "report_status": str(manifest.get("report_status") or "draft"),
        "file_count": len(manifest.get("files") or []),
        "manifest_sha256": claimed_manifest_hash,
        "bundle_sha256": _sha256(content),
    }
