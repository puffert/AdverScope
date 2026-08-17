from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable


MODEL_ROLE_CORPUS_SCHEMA_VERSION = "1.0"
MODEL_ROLE_RESULT_SCHEMA_VERSION = "1.0"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"model qualification source escapes the repository: {relative}") from exc
    return path


def load_model_role_corpus(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("model-role corpus must contain a JSON object")
    return value


def validate_model_role_corpus(corpus: dict[str, Any], *, root: Path) -> dict[str, Any]:
    errors: list[str] = []
    if corpus.get("schema_version") != MODEL_ROLE_CORPUS_SCHEMA_VERSION:
        errors.append(f"schema_version must be {MODEL_ROLE_CORPUS_SCHEMA_VERSION}")
    for key in ("corpus_id", "version", "frozen_at"):
        if not str(corpus.get(key) or "").strip():
            errors.append(f"{key} is required")
    required_roles = [str(item) for item in corpus.get("required_roles") or []]
    required_providers = [str(item) for item in corpus.get("required_provider_families") or []]
    if set(required_roles) != {"planner", "generator", "evaluator", "adjudicator"}:
        errors.append("required_roles must contain planner, generator, evaluator, and adjudicator")
    if len(required_providers) < 3 or len(set(required_providers)) != len(required_providers):
        errors.append("at least three unique provider families are required")

    sources = corpus.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("sources must contain frozen corpus and result records")
        sources = []
    source_ids: set[str] = set()
    source_providers: dict[str, str] = {}
    for source in sources:
        if not isinstance(source, dict):
            errors.append("every source must be an object")
            continue
        source_id = str(source.get("id") or "").strip()
        relative = str(source.get("path") or "").strip().replace("\\", "/")
        expected = str(source.get("sha256") or "").strip().casefold()
        if not source_id or source_id in source_ids:
            errors.append("source IDs must be non-empty and unique")
        source_ids.add(source_id)
        if len(expected) != 64:
            errors.append(f"{source_id or 'source'} must contain a SHA-256 digest")
        kind = str(source.get("kind") or "")
        provider_family = str(source.get("provider_family") or "")
        if kind.endswith("-result") and provider_family not in required_providers:
            errors.append(f"{source_id or 'result source'} must identify a declared provider family")
        source_providers[source_id] = provider_family
        path = _safe_path(root, relative)
        if not path.is_file():
            errors.append(f"model qualification source is missing: {relative}")
        elif _sha256(path) != expected:
            errors.append(f"model qualification source hash drifted: {relative}")

    candidates = corpus.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        errors.append("candidates must contain retained model-role evidence")
        candidates = []
    candidate_ids: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            errors.append("every candidate must be an object")
            continue
        candidate_id = str(candidate.get("id") or "").strip()
        roles = [str(item) for item in candidate.get("roles") or []]
        if not candidate_id or candidate_id in candidate_ids:
            errors.append("candidate IDs must be non-empty and unique")
        candidate_ids.add(candidate_id)
        if not str(candidate.get("model") or "").strip() or not str(candidate.get("model_family") or "").strip():
            errors.append(f"{candidate_id or 'candidate'} must identify model and model family")
        if str(candidate.get("provider_family") or "") not in required_providers:
            errors.append(f"{candidate_id or 'candidate'} uses an undeclared provider family")
        if not roles or not set(roles).issubset(required_roles):
            errors.append(f"{candidate_id or 'candidate'} contains invalid model roles")
        evidence = candidate.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"{candidate_id or 'candidate'} must map role evidence")
            continue
        for role in roles:
            source_id = str(evidence.get(role) or "")
            if source_id not in source_ids:
                errors.append(f"{candidate_id} role {role} does not reference a frozen source")
            elif source_providers.get(source_id) != str(candidate.get("provider_family") or ""):
                errors.append(f"{candidate_id} role {role} evidence belongs to another provider family")
    if errors:
        raise ValueError("invalid model-role corpus:\n- " + "\n- ".join(errors))
    return corpus


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 2)


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _telemetry(document: dict[str, Any]) -> dict[str, Any]:
    attempts = [
        item for item in _walk(document)
        if isinstance(item.get("duration_ms"), (int, float)) and isinstance(item.get("messages"), list)
    ]
    durations = [float(item["duration_ms"]) for item in attempts]
    with_usage = [item for item in attempts if isinstance(item.get("usage"), dict)]
    with_cost = [item for item in attempts if isinstance(item.get("cost_usd"), (int, float))]
    usage_totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for item in with_usage:
        usage = item["usage"]
        for key in usage_totals:
            usage_totals[key] += int(usage.get(key) or 0)
    return {
        "attempts": len(attempts),
        "latency_samples": len(durations),
        "latency_ms_p50": _percentile(durations, 0.50),
        "latency_ms_p95": _percentile(durations, 0.95),
        "usage_samples": len(with_usage),
        "usage_totals": usage_totals,
        "cost_samples": len(with_cost),
        "cost_usd": round(sum(float(item["cost_usd"]) for item in with_cost), 6),
    }


def _candidate_from_report(document: dict[str, Any], candidate_id: str) -> dict[str, Any] | None:
    return next((item for item in document.get("candidates") or [] if str(item.get("id")) == candidate_id), None)


def _role_passed(role: str, candidate: dict[str, Any] | None, source_kind: str) -> bool:
    if not candidate:
        return False
    summary = candidate.get("summary") or {}
    if source_kind == "evaluator-result":
        return role in {"evaluator", "adjudicator"} and bool(summary.get("qualified"))
    if source_kind == "attack-result":
        return role in {"planner", "generator"} and candidate.get("status") == "tested" and bool(summary.get("qualified"))
    return False


def evaluate_model_role_corpus(corpus: dict[str, Any], *, root: Path) -> dict[str, Any]:
    validated = validate_model_role_corpus(corpus, root=root)
    sources: dict[str, dict[str, Any]] = {}
    source_rows: list[dict[str, Any]] = []
    for item in validated["sources"]:
        path = _safe_path(root, str(item["path"]))
        document = json.loads(path.read_text(encoding="utf-8"))
        sources[str(item["id"])] = {"metadata": item, "document": document}
        source_rows.append({
            "id": str(item["id"]),
            "kind": str(item["kind"]),
            "path": str(item["path"]),
            "sha256": str(item["sha256"]),
        })

    candidate_rows: list[dict[str, Any]] = []
    qualified_roles: set[str] = set()
    qualified_providers: set[str] = set()
    qualified_models: set[str] = set()
    latency_samples = usage_samples = cost_samples = 0
    for configured in validated["candidates"]:
        role_rows = []
        candidate_documents: dict[str, dict[str, Any]] = {}
        for role in configured["roles"]:
            source_id = str(configured["evidence"][role])
            source = sources[source_id]
            retained = _candidate_from_report(source["document"], str(configured["result_candidate_id"]))
            passed = _role_passed(str(role), retained, str(source["metadata"]["kind"]))
            role_rows.append({"role": str(role), "status": "qualified" if passed else "not-qualified", "source_id": source_id})
            if passed:
                qualified_roles.add(str(role))
            if retained:
                candidate_documents[source_id] = retained
        telemetry = _telemetry({"sources": list(candidate_documents.values())})
        latency_samples += telemetry["latency_samples"]
        usage_samples += telemetry["usage_samples"]
        cost_samples += telemetry["cost_samples"]
        qualified = all(item["status"] == "qualified" for item in role_rows)
        if qualified:
            qualified_providers.add(str(configured["provider_family"]))
            qualified_models.add(str(configured["model_family"]))
        candidate_rows.append({
            "id": str(configured["id"]),
            "model": str(configured["model"]),
            "model_family": str(configured["model_family"]),
            "provider_family": str(configured["provider_family"]),
            "status": "qualified" if qualified else "partial",
            "roles": role_rows,
            "telemetry": telemetry,
        })

    required_roles = set(validated["required_roles"])
    required_providers = set(validated["required_provider_families"])
    minimum_model_families = int(validated["gates"]["minimum_model_families"])
    gates = [
        {"id": "frozen-source-integrity", "status": "passed", "value": len(source_rows), "threshold": len(source_rows)},
        {"id": "required-role-qualification", "status": "passed" if required_roles.issubset(qualified_roles) else "open", "value": len(qualified_roles & required_roles), "threshold": len(required_roles)},
        {"id": "provider-family-qualification", "status": "passed" if required_providers.issubset(qualified_providers) else "open", "value": len(qualified_providers & required_providers), "threshold": len(required_providers)},
        {"id": "distinct-model-family-qualification", "status": "passed" if len(qualified_models) >= minimum_model_families else "open", "value": len(qualified_models), "threshold": minimum_model_families},
        {"id": "latency-telemetry", "status": "passed" if latency_samples else "open", "value": latency_samples, "threshold": 1},
        {"id": "token-usage-telemetry", "status": "passed" if usage_samples else "open", "value": usage_samples, "threshold": 1},
        {"id": "provider-cost-telemetry", "status": "passed" if cost_samples else "open", "value": cost_samples, "threshold": 1},
    ]
    missing_roles = sorted(required_roles - qualified_roles)
    missing_providers = sorted(required_providers - qualified_providers)
    return {
        "schema_version": MODEL_ROLE_RESULT_SCHEMA_VERSION,
        "corpus_id": str(validated["corpus_id"]),
        "corpus_version": str(validated["version"]),
        "frozen_at": str(validated["frozen_at"]),
        "status": "complete" if all(item["status"] == "passed" for item in gates) else "in_progress",
        "summary": {
            "qualified_roles": len(qualified_roles & required_roles),
            "required_roles": len(required_roles),
            "qualified_provider_families": len(qualified_providers & required_providers),
            "required_provider_families": len(required_providers),
            "qualified_model_families": len(qualified_models),
            "minimum_model_families": minimum_model_families,
            "latency_samples": latency_samples,
            "usage_samples": usage_samples,
            "cost_samples": cost_samples,
        },
        "gates": gates,
        "sources": source_rows,
        "candidates": candidate_rows,
        "missing_roles": missing_roles,
        "missing_provider_families": missing_providers,
        "limitations": [str(item) for item in validated.get("limitations") or []],
    }


def render_model_role_report(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# AdverScope M5.2 repeated multi-model qualification",
        "",
        "<!-- Generated by scripts/qualify_model_roles.py; edit the frozen corpus or retained qualification records, not this file. -->",
        "",
        f"Corpus `{result['corpus_id']}` version `{result['corpus_version']}` was frozen at `{result['frozen_at']}`. Current M5.2 status: **{result['status'].replace('_', ' ')}**.",
        "",
        "This report describes retained model-role evidence. Provider configuration or a successful connection test never qualifies a model for professional conclusions.",
        "",
        "## Current result",
        "",
        f"- {summary['qualified_roles']} of {summary['required_roles']} required model roles have repeated retained qualification.",
        f"- {summary['qualified_provider_families']} of {summary['required_provider_families']} required provider families have retained qualification.",
        f"- {summary['qualified_model_families']} distinct model family is qualified; the gate requires {summary['minimum_model_families']}.",
        f"- {summary['latency_samples']} model-attempt latency samples are retained.",
        f"- Token-usage samples: {summary['usage_samples']}; provider-cost samples: {summary['cost_samples']}.",
        "",
        "## Gates",
        "",
        "| Gate | Result | Value | Threshold |",
        "|---|---|---:|---:|",
    ]
    for gate in result["gates"]:
        lines.append(f"| {gate['id']} | {gate['status'].upper()} | {gate['value']} | {gate['threshold']} |")
    lines.extend(["", "## Retained candidates", "", "| Candidate | Provider | Model family | Roles | Status |", "|---|---|---|---|---|"])
    for candidate in result["candidates"]:
        roles = ", ".join(f"{item['role']} ({item['status']})" for item in candidate["roles"])
        lines.append(f"| {candidate['model']} | {candidate['provider_family']} | {candidate['model_family']} | {roles} | {candidate['status']} |")
    lines.extend(["", "## Remaining qualification work", ""])
    if result["missing_roles"]:
        lines.append("- Missing role evidence: " + ", ".join(result["missing_roles"]) + ".")
    if result["missing_provider_families"]:
        lines.append("- Missing provider-family evidence: " + ", ".join(result["missing_provider_families"]) + ".")
    for limitation in result["limitations"]:
        lines.append(f"- {limitation}")
    lines.extend([
        "",
        "## Interpretation",
        "",
        "- The retained local Qwen runs qualify only the roles and corpus versions named here; they do not prove that every model or provider behaves equivalently.",
        "- OpenAI and Z.AI remain configurable but professionally unqualified until a tester supplies approved credentials, accepts the data-transfer boundary, and retains repeated corpus results.",
        "- Missing token or cost telemetry is reported as an open gate, never estimated from response length.",
        "- Target technique field qualification is tracked separately by M5.1.",
        "",
    ])
    return "\n".join(lines)
