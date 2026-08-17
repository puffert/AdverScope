from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable

from .config import AppConfig
from .evaluator_corpus import score_evaluator_corpus, validate_evaluator_corpus
from .model_gateway import ModelGateway


MODEL_QUALIFICATION_SCHEMA_VERSION = 1
DEFAULT_PRECISION_GATE = 0.95
DEFAULT_RECALL_GATE = 0.95
DEFAULT_PASS_RATE_GATE = 0.95


def validate_model_candidates(document: dict[str, Any]) -> dict[str, Any]:
    if int(document.get("schema_version") or 0) != MODEL_QUALIFICATION_SCHEMA_VERSION:
        raise ValueError("unsupported model-candidate manifest schema")
    candidates = document.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("model-candidate manifest must contain candidates")
    candidate_ids: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("every model candidate must be an object")
        candidate_id = str(candidate.get("id") or "").strip()
        model = str(candidate.get("model") or "").strip()
        base_url = str(candidate.get("base_url") or "").strip()
        if not candidate_id or candidate_id in candidate_ids:
            raise ValueError("model candidate IDs must be non-empty and unique")
        if not model or not base_url:
            raise ValueError(f"{candidate_id} must define model and base_url")
        if any(key in candidate for key in ("api_key", "password", "private_key", "ssh_user", "ssh_host")):
            raise ValueError(f"{candidate_id} contains a forbidden credential or host field")
        candidate_ids.add(candidate_id)
    return document


def _candidate_config(base: AppConfig, candidate: dict[str, Any]) -> AppConfig:
    return replace(
        base,
        llm_model=str(candidate["model"]),
        llm_base_url=str(candidate["base_url"]),
        ssh_tunnel=bool(candidate.get("ssh_tunnel", base.ssh_tunnel)),
        ssh_local_port=int(candidate.get("ssh_local_port") or base.ssh_local_port),
        ssh_remote_port=int(candidate.get("ssh_remote_port") or base.ssh_remote_port),
    )


def _run_passed(summary: dict[str, Any], gates: dict[str, float]) -> bool:
    return bool(
        int(summary.get("errors") or 0) == 0
        and float(summary.get("precision") or 0.0) >= gates["precision"]
        and float(summary.get("recall") or 0.0) >= gates["recall"]
        and float(summary.get("pass_rate") or 0.0) >= gates["pass_rate"]
    )


def summarize_candidate_runs(
    reports: list[dict[str, Any]],
    *,
    gates: dict[str, float] | None = None,
) -> dict[str, Any]:
    if not reports:
        raise ValueError("at least one model qualification report is required")
    thresholds = gates or {
        "precision": DEFAULT_PRECISION_GATE,
        "recall": DEFAULT_RECALL_GATE,
        "pass_rate": DEFAULT_PASS_RATE_GATE,
    }
    case_outcomes: dict[str, list[str]] = {}
    run_summaries = []
    for index, report in enumerate(reports, start=1):
        summary = dict(report["summary"])
        run_summaries.append({
            "run": index,
            "precision": float(summary["precision"]),
            "recall": float(summary["recall"]),
            "pass_rate": float(summary["pass_rate"]),
            "errors": int(summary["errors"]),
            "passed": _run_passed(summary, thresholds),
        })
        for result in report.get("results") or []:
            case_outcomes.setdefault(str(result["case_id"]), []).append(str(result["classification"]))
        for error in report.get("errors") or []:
            case_outcomes.setdefault(str(error["case_id"]), []).append("error")
    disagreements = [
        {"case_id": case_id, "outcomes": outcomes}
        for case_id, outcomes in sorted(case_outcomes.items())
        if len(outcomes) != len(reports) or len(set(outcomes)) > 1
    ]
    return {
        "repetitions": len(reports),
        "gates": thresholds,
        "minimum_precision": min(item["precision"] for item in run_summaries),
        "minimum_recall": min(item["recall"] for item in run_summaries),
        "minimum_pass_rate": min(item["pass_rate"] for item in run_summaries),
        "total_errors": sum(item["errors"] for item in run_summaries),
        "disagreement_count": len(disagreements),
        "disagreements": disagreements,
        "runs": run_summaries,
        "qualified": all(item["passed"] for item in run_summaries) and not disagreements,
    }


def qualify_model_candidates(
    corpus: dict[str, Any],
    manifest: dict[str, Any],
    *,
    base_config: AppConfig,
    repetitions: int | None = None,
    gateway_factory: Callable[[AppConfig], Any] = ModelGateway,
) -> dict[str, Any]:
    validate_evaluator_corpus(corpus)
    validate_model_candidates(manifest)
    count = int(repetitions or manifest.get("repetitions") or 3)
    if count < 2:
        raise ValueError("multi-model qualification requires at least two repetitions")
    gates = {
        "precision": float((manifest.get("gates") or {}).get("precision") or DEFAULT_PRECISION_GATE),
        "recall": float((manifest.get("gates") or {}).get("recall") or DEFAULT_RECALL_GATE),
        "pass_rate": float((manifest.get("gates") or {}).get("pass_rate") or DEFAULT_PASS_RATE_GATE),
    }
    candidates = []
    for candidate in manifest["candidates"]:
        gateway = gateway_factory(_candidate_config(base_config, candidate))
        reports = []
        try:
            for _index in range(count):
                reports.append(score_evaluator_corpus(corpus, model_mode="asus", model_gateway=gateway))
        finally:
            tunnel = getattr(gateway, "tunnel", None)
            if tunnel:
                tunnel.stop()
        candidates.append({
            "id": str(candidate["id"]),
            "model": str(candidate["model"]),
            "role": str(candidate.get("role") or "evaluator-candidate"),
            "required": bool(candidate.get("required", False)),
            "summary": summarize_candidate_runs(reports, gates=gates),
            "runs": reports,
        })
    required_candidates = [item for item in candidates if item["required"]]
    return {
        "schema_version": MODEL_QUALIFICATION_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_id": str(corpus["corpus_id"]),
        "corpus_version": str(corpus.get("corpus_version") or ""),
        "repetitions": count,
        "gates": gates,
        "candidates": candidates,
        "all_candidates_qualified": all(item["summary"]["qualified"] for item in candidates),
        "required_candidate_count": len(required_candidates),
        "all_required_candidates_qualified": bool(required_candidates) and all(
            item["summary"]["qualified"] for item in required_candidates
        ),
    }
