from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .m4_security import public_m4_coverage
from .qualification_registry import build_qualification_registry, validate_qualification_registry


FIELD_CORPUS_SCHEMA_VERSION = "1.0"
FIELD_RESULT_SCHEMA_VERSION = "1.0"
VALID_AUTHORSHIP = {
    "external-third-party",
    "independently-developed-owned",
    "adverscope-qualification-fixture",
    "independent-sdk-fixture",
}
VALID_REPLAY_MODES = {"local-fixture", "local-container", "owned-remote-lab", "ephemeral-manual"}


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
        raise ValueError(f"field qualification source escapes the repository: {relative}") from exc
    return candidate


def load_field_corpus(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("field qualification corpus must contain a JSON object")
    return value


def validate_field_corpus(
    corpus: dict[str, Any],
    *,
    root: Path,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_registry = validate_qualification_registry(registry or build_qualification_registry())
    errors: list[str] = []
    if corpus.get("schema_version") != FIELD_CORPUS_SCHEMA_VERSION:
        errors.append(f"schema_version must be {FIELD_CORPUS_SCHEMA_VERSION}")
    if not str(corpus.get("corpus_id") or ""):
        errors.append("corpus_id is required")
    if not str(corpus.get("corpus_version") or ""):
        errors.append("corpus_version is required")
    if not str(corpus.get("frozen_at") or "").endswith("Z"):
        errors.append("frozen_at must be an explicit UTC timestamp")
    if corpus.get("status") != "frozen":
        errors.append("field corpus must be frozen before qualification")

    sources = corpus.get("frozen_sources")
    if not isinstance(sources, list) or not sources:
        errors.append("frozen_sources must be a non-empty list")
        sources = []
    source_ids = [str(item.get("id") or "") for item in sources if isinstance(item, dict)]
    if len(source_ids) != len(set(source_ids)) or any(not value for value in source_ids):
        errors.append("frozen_sources must have unique non-empty IDs")
    source_index = {str(item.get("id")): item for item in sources if isinstance(item, dict) and item.get("id")}
    for source_id, source in source_index.items():
        relative = str(source.get("path") or "")
        expected = str(source.get("sha256") or "")
        if not relative or len(expected) != 64:
            errors.append(f"{source_id} must define a path and SHA-256")
            continue
        try:
            path = _safe_repository_path(root, relative)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not path.is_file():
            errors.append(f"{source_id} is missing: {relative}")
        elif _sha256(path) != expected:
            errors.append(f"{source_id} SHA-256 does not match the frozen corpus")

    families = corpus.get("target_families")
    if not isinstance(families, list) or not families:
        errors.append("target_families must be a non-empty list")
        families = []
    family_ids = [str(item.get("id") or "") for item in families if isinstance(item, dict)]
    if len(family_ids) != len(set(family_ids)) or any(not value for value in family_ids):
        errors.append("target_families must have unique non-empty IDs")
    family_index = {str(item.get("id")): item for item in families if isinstance(item, dict) and item.get("id")}
    for family_id, family in family_index.items():
        authorship = str(family.get("authorship") or "")
        if authorship not in VALID_AUTHORSHIP:
            errors.append(f"{family_id} has invalid authorship {authorship!r}")
        replay_mode = str(family.get("replay_mode") or "")
        if replay_mode not in VALID_REPLAY_MODES:
            errors.append(f"{family_id} has invalid replay_mode {replay_mode!r}")
        if not isinstance(family.get("target_styles"), list) or not family.get("target_styles"):
            errors.append(f"{family_id} must declare at least one target style")
        for source_id in family.get("evidence_source_ids") or []:
            if str(source_id) not in source_index:
                errors.append(f"{family_id} references unknown frozen source {source_id!r}")
        independent = bool(family.get("independent_for_field_gate"))
        if independent and authorship not in {"external-third-party", "independently-developed-owned"}:
            errors.append(f"{family_id} cannot count for the field gate with authorship {authorship!r}")

    registry_families = {
        str(fixture.get("target_family") or "")
        for technique in resolved_registry["techniques"]
        for fixture in [*(technique.get("fixtures") or {}).get("secure", []), *(technique.get("fixtures") or {}).get("vulnerable", [])]
        if str(fixture.get("target_family") or "")
    }
    unclassified = sorted(registry_families - set(family_index))
    if unclassified:
        errors.append(f"qualification registry contains unclassified target families: {', '.join(unclassified)}")

    required_styles = corpus.get("required_target_styles")
    if not isinstance(required_styles, list) or not required_styles:
        errors.append("required_target_styles must be a non-empty list")
        required_styles = []
    if len(required_styles) != len(set(str(item) for item in required_styles)):
        errors.append("required_target_styles contains duplicates")
    declared_styles = {
        str(style)
        for family in family_index.values()
        for style in family.get("target_styles") or []
    }
    missing_styles = sorted(set(str(item) for item in required_styles) - declared_styles)
    if missing_styles:
        errors.append(f"required target styles have no implementation family: {', '.join(missing_styles)}")

    technique_ids = {str(item["id"]) for item in resolved_registry["techniques"]}
    claims = corpus.get("professional_technique_claims")
    if not isinstance(claims, list):
        errors.append("professional_technique_claims must be a list")
        claims = []
    unknown_claims = sorted(set(str(item) for item in claims) - technique_ids)
    if unknown_claims:
        errors.append(f"professional technique claims are not in the registry: {', '.join(unknown_claims)}")
    registry_qualified = [
        str(item["id"])
        for item in resolved_registry["techniques"]
        if item.get("qualification_status") == "qualified"
    ]
    if list(claims) != registry_qualified:
        errors.append("professional_technique_claims must exactly match the ordered qualified registry entries")

    independent_families = [item for item in family_index.values() if item.get("independent_for_field_gate") is True]
    if len(independent_families) < 3:
        errors.append("the frozen portfolio must include at least three non-framework target families")

    if errors:
        raise ValueError("invalid M5.1 field qualification corpus: " + "; ".join(errors))
    return deepcopy(corpus)


def evaluate_field_qualification(
    corpus: dict[str, Any],
    *,
    root: Path,
    registry: dict[str, Any] | None = None,
    m4_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_registry = validate_qualification_registry(registry or build_qualification_registry())
    resolved_corpus = validate_field_corpus(corpus, root=root, registry=resolved_registry)
    resolved_m4 = m4_coverage or public_m4_coverage()
    families = {str(item["id"]): item for item in resolved_corpus["target_families"]}
    claims = set(str(item) for item in resolved_corpus["professional_technique_claims"])
    policy = resolved_corpus.get("field_gate_policy") or {}
    min_family_pairs = int(policy.get("minimum_secure_vulnerable_families") or 2)
    min_field_pairs = int(policy.get("minimum_non_framework_secure_vulnerable_families") or 1)
    min_precision = float(policy.get("minimum_precision") or 0.95)
    min_recall = float(policy.get("minimum_supported_recall") or 0.90)
    min_reproduction = float(policy.get("minimum_reproduction_rate") or 0.90)

    technique_rows: list[dict[str, Any]] = []
    for technique in resolved_registry["techniques"]:
        technique_id = str(technique["id"])
        fixtures = technique.get("fixtures") or {}
        grouped: dict[str, dict[str, int]] = defaultdict(lambda: {"secure": 0, "vulnerable": 0})
        for mode in ("secure", "vulnerable"):
            for fixture in fixtures.get(mode) or []:
                family_id = str(fixture.get("target_family") or "")
                if family_id:
                    grouped[family_id][mode] += 1
        paired = sorted(family_id for family_id, counts in grouped.items() if counts["secure"] and counts["vulnerable"])
        field_paired = sorted(
            family_id for family_id in paired if (families.get(family_id) or {}).get("independent_for_field_gate") is True
        )
        metrics = technique.get("metrics") or {}
        gaps: list[str] = []
        claimed = technique_id in claims
        if claimed and technique.get("qualification_status") != "qualified":
            gaps.append("mechanism qualification is below qualified")
        if claimed and len(paired) < min_family_pairs:
            gaps.append(f"requires {min_family_pairs} secure/vulnerable implementation families")
        if claimed and len(field_paired) < min_field_pairs:
            gaps.append(f"requires {min_field_pairs} non-framework secure/vulnerable target family")
        if claimed and float(metrics.get("precision") or 0.0) < min_precision:
            gaps.append(f"precision is below {min_precision:.2f}")
        if claimed and float(metrics.get("supported_recall") or 0.0) < min_recall:
            gaps.append(f"supported recall is below {min_recall:.2f}")
        if claimed and float(metrics.get("reproduction_rate") or 0.0) < min_reproduction:
            gaps.append(f"reproduction is below {min_reproduction:.2f}")
        if not claimed:
            support_status = "experimental"
        elif gaps:
            support_status = "mechanism-qualified"
        else:
            support_status = "field-qualified"
        technique_rows.append({
            "id": technique_id,
            "risk_id": technique["risk_id"],
            "title": technique["title"],
            "implementation_path": (technique.get("implementation") or {}).get("path"),
            "registry_status": technique.get("qualification_status"),
            "professional_claim_candidate": claimed,
            "secure_vulnerable_family_pairs": paired,
            "non_framework_family_pairs": field_paired,
            "metrics": {
                "precision": metrics.get("precision"),
                "supported_recall": metrics.get("supported_recall"),
                "reproduction_rate": metrics.get("reproduction_rate"),
                "execution_error_rate": metrics.get("execution_error_rate"),
            },
            "field_support_status": support_status,
            "gaps": gaps,
        })

    style_rows: list[dict[str, Any]] = []
    for style in resolved_corpus["required_target_styles"]:
        matching = sorted(family_id for family_id, family in families.items() if style in (family.get("target_styles") or []))
        independent = sorted(family_id for family_id in matching if families[family_id].get("independent_for_field_gate") is True)
        status = "field-covered" if len(independent) >= 2 else "field-sampled" if independent else "mechanism-only"
        style_rows.append({
            "id": style,
            "implementation_families": matching,
            "non_framework_families": independent,
            "status": status,
        })

    capability_style = {
        "multimodal": "multimodal",
        "agents": "agentic-multi-agent",
        "mcp": "current-mcp",
        "rag": "rag-external-content",
        "training_pipeline": "model-training-pipeline",
        "privacy_testing": "privacy-inference",
        "resource_telemetry": "resource-cost-availability",
        "operational_controls": "cloud-client-operational",
    }
    style_index = {str(item["id"]): item for item in style_rows}
    m4_rows: list[dict[str, Any]] = []
    for package in resolved_m4["work_packages"]:
        style = capability_style[str(package["required_capability"])]
        style_row = style_index[style]
        m4_rows.append({
            "id": package["id"],
            "title": package["title"],
            "controls": len(package["controls"]),
            "mechanism_qualification": "qualified" if all(item.get("qualification_status") == "qualified" for item in package["controls"]) else "incomplete",
            "field_target_style": style,
            "non_framework_families": style_row["non_framework_families"],
            "field_status": style_row["status"],
        })

    claimed_rows = [item for item in technique_rows if item["professional_claim_candidate"]]
    field_rows = [item for item in claimed_rows if item["field_support_status"] == "field-qualified"]
    independent_styles = [item for item in style_rows if item["status"] == "field-covered"]
    gates = [
        {
            "id": "frozen-source-integrity",
            "threshold": len(resolved_corpus["frozen_sources"]),
            "value": len(resolved_corpus["frozen_sources"]),
            "passed": True,
        },
        {
            "id": "non-framework-target-portfolio",
            "threshold": 3,
            "value": len([item for item in families.values() if item.get("independent_for_field_gate") is True]),
            "passed": len([item for item in families.values() if item.get("independent_for_field_gate") is True]) >= 3,
        },
        {
            "id": "required-style-mechanism-coverage",
            "threshold": len(style_rows),
            "value": len([item for item in style_rows if item["implementation_families"]]),
            "passed": all(item["implementation_families"] for item in style_rows),
        },
        {
            "id": "required-style-independent-depth",
            "threshold": len(style_rows),
            "value": len(independent_styles),
            "passed": len(independent_styles) == len(style_rows),
        },
        {
            "id": "professional-technique-field-qualification",
            "threshold": len(claimed_rows),
            "value": len(field_rows),
            "passed": len(field_rows) == len(claimed_rows),
        },
        {
            "id": "m4-domain-field-qualification",
            "threshold": len(m4_rows),
            "value": len([item for item in m4_rows if item["field_status"] == "field-covered"]),
            "passed": all(item["field_status"] == "field-covered" for item in m4_rows),
        },
    ]
    complete = all(item["passed"] for item in gates)
    return {
        "schema_version": FIELD_RESULT_SCHEMA_VERSION,
        "milestone": "M5.1",
        "corpus": {
            "id": resolved_corpus["corpus_id"],
            "version": resolved_corpus["corpus_version"],
            "frozen_at": resolved_corpus["frozen_at"],
            "frozen_sources": len(resolved_corpus["frozen_sources"]),
        },
        "status": "complete" if complete else "in_progress",
        "summary": {
            "registry_techniques": len(technique_rows),
            "professional_claim_candidates": len(claimed_rows),
            "field_qualified_techniques": len(field_rows),
            "mechanism_qualified_pending_field_evidence": len([item for item in claimed_rows if item["field_support_status"] == "mechanism-qualified"]),
            "experimental_techniques": len([item for item in technique_rows if item["field_support_status"] == "experimental"]),
            "target_families": len(families),
            "non_framework_target_families": len([item for item in families.values() if item.get("independent_for_field_gate") is True]),
            "required_target_styles": len(style_rows),
            "field_covered_target_styles": len(independent_styles),
            "m4_work_packages": len(m4_rows),
            "field_covered_m4_work_packages": len([item for item in m4_rows if item["field_status"] == "field-covered"]),
        },
        "gates": gates,
        "techniques": technique_rows,
        "target_styles": style_rows,
        "m4_work_packages": m4_rows,
        "limitations": list(resolved_corpus.get("limitations") or []),
    }


def render_field_qualification_report(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# AdverScope M5.1 field qualification and support matrix",
        "",
        "<!-- Generated by scripts/qualify_milestone5.py; edit the frozen corpus or qualification registries, not this file. -->",
        "",
        f"Corpus `{result['corpus']['id']}` version `{result['corpus']['version']}` was frozen at `{result['corpus']['frozen_at']}`. Current M5.1 status: **{result['status'].replace('_', ' ')}**.",
        "",
        "This report separates mechanism qualification from field qualification. A technique may work reliably against controlled fixtures without yet having enough non-framework target evidence for a professional field-support claim.",
        "",
        "## Current support statement",
        "",
        f"- {summary['field_qualified_techniques']} of {summary['professional_claim_candidates']} professional claim candidates currently satisfy the M5.1 field-evidence gate.",
        f"- {summary['mechanism_qualified_pending_field_evidence']} remain mechanism-qualified but require another non-framework secure/vulnerable target family.",
        f"- {summary['experimental_techniques']} techniques remain experimental and are not represented as professionally field-qualified.",
        f"- {summary['field_covered_target_styles']} of {summary['required_target_styles']} required target styles currently have two non-framework implementation families.",
        "",
        "## M5.1 gates",
        "",
        "| Gate | Result | Value | Threshold |",
        "|---|---|---:|---:|",
    ]
    for gate in result["gates"]:
        lines.append(f"| {gate['id']} | {'PASS' if gate['passed'] else 'OPEN'} | {gate['value']} | {gate['threshold']} |")
    lines.extend([
        "",
        "## Professional technique claim candidates",
        "",
        "| Technique | Registry | Field status | Secure/vulnerable families | Non-framework families | Remaining gap |",
        "|---|---|---|---:|---:|---|",
    ])
    for item in result["techniques"]:
        if not item["professional_claim_candidate"]:
            continue
        gap = "; ".join(item["gaps"]) or "none"
        lines.append(
            f"| {item['id']} {item['title']} | {item['registry_status']} | {item['field_support_status']} | "
            f"{len(item['secure_vulnerable_family_pairs'])} | {len(item['non_framework_family_pairs'])} | {gap} |"
        )
    lines.extend([
        "",
        "Only `field-qualified` rows are current M5.1 professional field-support candidates. `Mechanism-qualified` means the execution and evaluator lane has passed controlled qualification but the independent target requirement remains open.",
        "",
        "## Target-style portfolio",
        "",
        "| Target style | Status | All implementation families | Non-framework families |",
        "|---|---|---:|---:|",
    ])
    for item in result["target_styles"]:
        lines.append(
            f"| {item['id']} | {item['status']} | {len(item['implementation_families'])} | {len(item['non_framework_families'])} |"
        )
    lines.extend([
        "",
        "## Milestone 4 domain transition",
        "",
        "| Domain | Controls | Mechanism qualification | Field status | Non-framework families |",
        "|---|---:|---|---|---:|",
    ])
    for item in result["m4_work_packages"]:
        lines.append(
            f"| {item['id']} {item['title']} | {item['controls']} | {item['mechanism_qualification']} | "
            f"{item['field_status']} | {len(item['non_framework_families'])} |"
        )
    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
    ])
    lines.extend(f"- {item}" for item in result.get("limitations") or [])
    lines.extend([
        "- A missing field-qualification cell is a support limitation, not evidence that the target is secure or that the technique cannot work.",
        "- Historical benchmark results remain frozen. New evidence is added as a new corpus version rather than rewriting this baseline.",
        "",
    ])
    return "\n".join(lines)
