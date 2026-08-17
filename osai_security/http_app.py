from __future__ import annotations

import json
import hmac
import mimetypes
import os
import shutil
import ssl
import tempfile
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import USER_AGENT, build_identity
from .artifact_security import ARTIFACT_KINDS, MAX_ARTIFACT_BYTES, validate_artifact_profile
from .browser_targets import BrowserTargetClient
from .assessment_contracts import normalize_assessment_contracts
from .config import AppConfig
from .conversations import has_conversation_continuity
from .db import NotFoundError, Repository, new_id
from .engine import reevaluate_stored_run, resolve_attack_settings, run_assessment
from .guardrails import derive_guardrail
from .guided_assessment import (
    GUIDED_PLAN_TTL_SECONDS,
    finalize_guided_plan,
    guided_minimum_request_budget,
    guided_policy_document,
    guided_request_allocation,
    guided_scope_document,
    guided_setup_readiness,
    guided_support_catalog,
    guided_target_values,
    normalize_guided_request,
    planner_catalog,
)
from .evidence_store import EvidenceStore
from .faults import public_fault_taxonomy
from .evidence_bundles import build_evidence_bundle
from .importers import import_api, import_burp, import_inventory, import_nmap
from .model_gateway import ModelGateway
from .methodology import methodology_card_is_trusted, public_methodology_library
from .motor_lab import MotorLabService
from .modules import module_summaries
from .owasp import build_assessment_plan, public_taxonomy
from .m4_security import public_m4_coverage
from .recon import ActiveReconClient
from .qualification_registry import public_qualification_registry
from .reports import build_markdown_report, build_retest_report
from .recovery import (
    MAX_ARCHIVE_BYTES,
    create_local_backup,
    export_project,
    import_project,
    recover_interrupted_restore,
)
from .run_insights import build_run_result_summary, compare_runs
from .preflight import execute_target_preflight, target_preflight_signature
from .security import safe_error
from .evaluation_profiles import evaluation_readiness, validate_evaluation_config
from .targets import TargetClient, assert_target_runtime_ready, parse_headers, parse_template, route_is_authorized, target_runtime_readiness, target_url, validate_analysis_config, validate_browser_profile, validate_conversation_config
from .targets import parse_authorized_routes, validate_authorized_routes
from .tool_engine import execute_tool_run, normalize_tool_definition
from .tool_packs import instantiate_tool_pack, normalize_pack_configuration, pack_readiness, public_target_pack_readiness, public_tool_packs
from .telemetry import telemetry_export
from .transport_reliability import normalize_transport_profile
from .runtime_lifecycle import API_CONTRACT_VERSION, RuntimeLock, runtime_lock_path
from .release import PRODUCT_VERSION
from .target_profiles import (
    export_target_profile,
    public_target_profiles,
    target_profile_readiness,
    validate_target_profile_document,
)


STATIC_DIR = Path(__file__).resolve().parent / "static"


def assessment_target_capabilities(target_snapshot: dict[str, Any]) -> dict[str, Any]:
    """Resolve planner capabilities while preserving explicit adapter opt-outs."""
    capabilities = dict(target_snapshot.get("capabilities") or {})
    default_chat_adapter = target_snapshot.get("kind") in {"chatbot", "browser-chatbot"} and not capabilities.get("retrieval_only")
    capabilities["chat_prompt_adapter"] = bool(
        capabilities.get("chat_prompt_adapter", default_chat_adapter)
    )
    capabilities["token_context"] = bool((target_snapshot.get("analysis_config") or {}).get("enabled"))
    capabilities["structured_history"] = bool((target_snapshot.get("conversation_config") or {}).get("enabled"))
    if capabilities["structured_history"]:
        capabilities["multi_turn"] = True
    capabilities.update(evaluation_readiness(target_snapshot.get("evaluation_config") or {}))
    capabilities["assessment_contract_technique_ids"] = sorted({
        technique
        for contract in target_snapshot.get("assessment_contracts") or []
        if contract.get("enabled")
        for technique in contract.get("technique_ids") or []
    })
    return capabilities


class Application:
    def __init__(
        self,
        repo: Repository,
        *,
        config: AppConfig | None = None,
        model_gateway: ModelGateway | None = None,
        target_client: TargetClient | None = None,
        browser_target_client: BrowserTargetClient | None = None,
        evidence_store: EvidenceStore | None = None,
        recon_client: ActiveReconClient | None = None,
        motor_lab: MotorLabService | None = None,
    ):
        self.repo = repo
        self.config = config or AppConfig.from_env()
        self.model_gateway = model_gateway or ModelGateway(self.config)
        self.target_client = target_client or TargetClient(timeout_seconds=self.config.target_timeout_seconds)
        self.browser_target_client = browser_target_client or BrowserTargetClient(self.config)
        self.evidence_store = evidence_store or EvidenceStore(self.config.evidence_root)
        self.recon_client = recon_client or ActiveReconClient(timeout_seconds=min(self.config.target_timeout_seconds, 5.0))
        self.motor_lab = motor_lab or MotorLabService(self.config.training_root)
        self._background_runs: dict[str, threading.Thread] = {}
        self._background_cancel: dict[str, threading.Event] = {}
        self._background_lock = threading.RLock()
        self._guided_plans: dict[str, dict[str, Any]] = {}
        self._guided_plan_lock = threading.RLock()
        self._startup_recovery = self.repo.reconcile_stale_executions()

    def close(self) -> None:
        with self._background_lock:
            events = list(self._background_cancel.values())
            threads = list(self._background_runs.values())
        for event in events:
            event.set()
        deadline = time.monotonic() + 10.0
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if hasattr(self.model_gateway, "close"):
            self.model_gateway.close()

    def _model_configuration_guard(self) -> None:
        with self._background_lock:
            if self._background_runs:
                raise ValueError("model provider cannot be changed while an assessment or testing-tool run is active")

    def _safe_restart_eligibility(self, project_id: str, run: dict[str, Any]) -> dict[str, Any]:
        status = str(run.get("status") or "")
        if status not in {"interrupted", "cancelled", "completed_with_errors"}:
            return {"eligible": False, "reason": "Only interrupted, cancelled, or error-completed runs can be safely restarted."}
        detail = run if "events" in run else self.repo.get_run_detail(project_id, str(run["id"]))
        request_count = len([event for event in detail.get("events") or [] if event.get("event_type") == "request.sent"])
        plan = detail.get("assessment_plan") or {}
        transport = (
            (plan.get("target_adapter_snapshot") or {}).get("transport_config")
            or self.repo.get_target(project_id, str(detail["target_id"])).get("transport_config")
            or {}
        )
        replay_safe = bool(transport.get("replay_safe"))
        if request_count and not replay_safe:
            return {
                "eligible": False,
                "request_count": request_count,
                "replay_safe": False,
                "reason": "Target traffic was already sent and the saved target is not explicitly attested replay-safe.",
            }
        return {
            "eligible": True,
            "request_count": request_count,
            "replay_safe": replay_safe,
            "mode": "new-run-from-recorded-plan",
            "reason": "A new isolated run can restart the recorded plan without rewriting the historical run.",
        }

    def _restart_recorded_run(self, project_id: str, run_id: str) -> tuple[int, dict[str, Any]]:
        self._model_configuration_guard()
        source = self.repo.get_run_detail(project_id, run_id)
        eligibility = self._safe_restart_eligibility(project_id, source)
        if not eligibility.get("eligible"):
            raise ValueError(str(eligibility.get("reason") or "run is not safe to restart"))
        plan = dict(source.get("assessment_plan") or {})
        plan["restart"] = {
            "source_run_id": run_id,
            "mode": "new-run-from-recorded-plan",
            "source_status": source.get("status"),
            "source_request_count": eligibility.get("request_count", 0),
            "replay_safe_attested": eligibility.get("replay_safe", False),
        }
        run = self.repo.create_run(
            project_id,
            str(source["target_id"]),
            list(source.get("module_ids") or []),
            str(source.get("model_mode") or "offline"),
            attack_profile=str(source.get("attack_profile") or "standard"),
            attack_budget=int(source.get("attack_budget") or 3),
            assessment_plan=plan,
        )
        self.repo.add_run_event(
            project_id,
            run["id"],
            event_type="assessment.restart.created",
            title="Safe restart created from an immutable prior run",
            details={**plan["restart"], "target_traffic_sent": False},
        )
        cancel_event = threading.Event()
        thread = threading.Thread(
            target=self._execute_background_run,
            kwargs={
                "project_id": project_id,
                "target_id": str(source["target_id"]),
                "module_ids": list(source.get("module_ids") or []),
                "model_mode": str(source.get("model_mode") or "offline"),
                "attack_profile": str(source.get("attack_profile") or "standard"),
                "attack_budget": int(source.get("attack_budget") or 3),
                "assessment_plan": plan,
                "run": run,
                "cancel_event": cancel_event,
            },
            daemon=True,
            name=f"assessment-{run['id']}",
        )
        with self._background_lock:
            self._background_runs[run["id"]] = thread
            self._background_cancel[run["id"]] = cancel_event
        thread.start()
        return 202, {**run, "restart": plan["restart"]}

    def _target_profile_readiness(self, project_id: str, profile_id: str, target_id: str) -> dict[str, Any]:
        project = self.repo.get_project(project_id)
        target = self.repo.get_target(project_id, target_id) if target_id else None
        documents = project.get("documents") or []
        guardrail = self.repo.get_guardrail(project_id, target_id) if target_id else {}
        artifact_count = len([
            item for item in project.get("artifacts") or []
            if item.get("status") == "active" and (not target_id or item.get("target_id") == target_id)
        ])
        return target_profile_readiness(
            profile_id,
            target,
            has_scope=any(item.get("kind") == "scope" for item in documents),
            has_policy=any(item.get("kind") == "policy" for item in documents),
            guardrail=guardrail,
            artifact_count=artifact_count,
        )

    def _create_retest_run(self, project_id: str, source_run_id: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._model_configuration_guard()
        source = self.repo.get_run_detail(project_id, source_run_id)
        if source.get("status") == "running":
            raise ValueError("a running assessment cannot be used as a retest baseline")
        if payload.get("approved") not in {True, "true", "on", "1", 1}:
            raise ValueError("retest creation requires explicit approval of the recorded plan and listed changes")
        change_note = str(payload.get("change_note") or "").strip()
        if len(change_note) < 8:
            raise ValueError("retest approval requires a short reason describing the intended comparison")
        target_id = str(payload.get("target_id") or source.get("target_id") or "")
        target_snapshot = self.repo.get_target(project_id, target_id)
        assert_target_runtime_ready(target_snapshot)
        guardrail_snapshot = self.repo.get_guardrail(project_id, target_id)
        if guardrail_snapshot.get("status") != "approved":
            raise ValueError("the selected retest target requires an approved execution guardrail")
        source_plan = deepcopy(source.get("assessment_plan") or {})
        target_capabilities = assessment_target_capabilities(target_snapshot)
        objectives = deepcopy(source_plan.get("objectives") or [])
        browser_outcome_rule = (target_snapshot.get("browser_profile") or {}).get("outcome_rule") or {}
        target_proof_technique_ids = (
            list(browser_outcome_rule.get("technique_ids") or [])
            if browser_outcome_rule.get("enabled") and browser_outcome_rule.get("finding_evidence")
            else []
        )
        requested_turns = max(1, int(source_plan.get("adaptive_turns") or 1))
        approved_turns = min(requested_turns, int(guardrail_snapshot.get("max_turns_per_objective") or 1))
        if approved_turns > 1 and (not has_conversation_continuity(target_capabilities) or not guardrail_snapshot.get("allow_multi_turn")):
            raise ValueError("the recorded adaptive plan requires an explicit continuity transport and current guardrail permission")
        assessment_plan = build_assessment_plan(
            whole_risk_ids=list(source_plan.get("selected_risk_ids") or []),
            technique_ids=list(source_plan.get("selected_technique_ids") or []),
            objectives=objectives,
            legacy_module_ids=list(source.get("module_ids") or []),
            target_capabilities=target_capabilities,
            evaluation_config=target_snapshot.get("evaluation_config") or {},
            assessment_contracts=target_snapshot.get("assessment_contracts") or [],
            target_proof_technique_ids=target_proof_technique_ids,
            adaptive_turns=approved_turns,
        )
        self.snapshot_artifacts_for_plan(project_id, target_id, assessment_plan)
        if any(item.get("reproduce") for item in assessment_plan.get("assessment_contracts") or []) and not guardrail_snapshot.get("allow_reproduction"):
            raise ValueError("the retest plan contains evidence contracts that require current reproduction permission")
        model_mode = str(payload.get("model_mode") or source.get("model_mode") or "offline")
        if model_mode not in {"asus", "asus-evaluator", "offline"}:
            raise ValueError("retest model mode must be asus, asus-evaluator, or offline")
        attack_profile, attack_budget = resolve_attack_settings(
            str(payload.get("attack_profile") or source.get("attack_profile") or "standard"),
            payload.get("attack_budget") if "attack_budget" in payload else source.get("attack_budget"),
        )
        assessment_plan.update({
            "run_mode": "advanced-retest",
            "target_capabilities": target_capabilities,
            "target_adapter_snapshot": {
                "target_id": target_snapshot["id"],
                "name": target_snapshot.get("name"),
                "kind": target_snapshot["kind"],
                "base_url": target_snapshot.get("base_url"),
                "path": target_snapshot.get("path"),
                "method": target_snapshot.get("method"),
                "request_template": target_snapshot.get("request_template") or {},
                "response_path": target_snapshot.get("response_path"),
                "capabilities": target_snapshot.get("capabilities") or {},
                "analysis_config": target_snapshot.get("analysis_config") or {},
                "conversation_config": target_snapshot.get("conversation_config") or {},
                "transport_config": target_snapshot.get("transport_config") or {},
                "evaluation_config": target_snapshot.get("evaluation_config") or {},
                "technique_adapters": target_snapshot.get("technique_adapters") or {},
                "assessment_contracts": target_snapshot.get("assessment_contracts") or [],
                "authorized_routes": target_snapshot.get("authorized_routes") or [],
            },
            "guardrail": guardrail_snapshot,
            "adaptive_turns": approved_turns,
            "recon": deepcopy(source_plan.get("recon") or {"mode": "none", "profile": "configured"}),
            "confirmation_policy": {
                "mode": "minimum-proof",
                "reproduction_attempts": int(guardrail_snapshot.get("reproduction_max_attempts") or 1) if guardrail_snapshot.get("allow_reproduction") else 0,
                "reproduction_mode": str(guardrail_snapshot.get("reproduction_mode") or "exact-one"),
                "minimum_successes": int(guardrail_snapshot.get("reproduction_min_successes") or 1),
                "minimum_success_rate": float(guardrail_snapshot.get("reproduction_min_success_rate") or 1.0),
                "stop_after_confirmed_technique": True,
                "handoff": "human-manual-testing",
            },
        })
        current_reasoning_snapshot = self.repo.reasoning_snapshot(project_id, target_id=target_id)
        assessment_plan["reasoning_snapshot"] = current_reasoning_snapshot
        changes: list[dict[str, Any]] = []
        for field, before, after in (
            ("target_id", source.get("target_id"), target_id),
            ("model_mode", source.get("model_mode"), model_mode),
            ("attack_profile", source.get("attack_profile"), attack_profile),
            ("attack_budget", source.get("attack_budget"), attack_budget),
        ):
            if before != after:
                changes.append({"field": field, "before": before, "after": after})
        source_adapter = source_plan.get("target_adapter_snapshot") or {}
        if json.dumps(source_adapter, sort_keys=True, default=str) != json.dumps(assessment_plan["target_adapter_snapshot"], sort_keys=True, default=str):
            changes.append({"field": "target_configuration", "before": "source run snapshot", "after": "current saved target configuration"})
        def methodology_identity(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
            return sorted(
                [
                    {
                        "id": str(card.get("id") or card.get("card_id") or ""),
                        "version": str(card.get("version") or ""),
                        "sha256": str(card.get("sha256") or ""),
                        "trusted_for_model": methodology_card_is_trusted(card),
                    }
                    for card in snapshot.get("methodology_cards") or []
                ],
                key=lambda item: (item["id"], item["version"], item["sha256"]),
            )
        source_methodology = methodology_identity(source_plan.get("reasoning_snapshot") or {})
        current_methodology = methodology_identity(current_reasoning_snapshot)
        if source_methodology != current_methodology:
            changes.append({
                "field": "assessment_methodology",
                "before": source_methodology,
                "after": current_methodology,
            })
        assessment_plan["retest"] = {
            "source_run_id": source_run_id,
            "approval_note": change_note,
            "approved_changes": changes,
            "source_status": source.get("status"),
            "immutable_source": True,
        }
        module_ids = list(assessment_plan.get("module_ids") or [])
        if not module_ids and not assessment_plan.get("assessment_contracts"):
            raise ValueError("the retest plan has no currently executable techniques or evidence contracts")
        self.repo.assert_run_ready(project_id, target_id)
        run = self.repo.create_run(
            project_id,
            target_id,
            module_ids,
            model_mode,
            attack_profile=attack_profile,
            attack_budget=attack_budget,
            assessment_plan=assessment_plan,
        )
        self.repo.add_run_event(
            project_id,
            run["id"],
            event_type="retest.created",
            title="Retest created from an immutable prior plan",
            details={**assessment_plan["retest"], "target_traffic_sent": False},
        )
        cancel_event = threading.Event()
        thread = threading.Thread(
            target=self._execute_background_run,
            kwargs={
                "project_id": project_id,
                "target_id": target_id,
                "module_ids": module_ids,
                "model_mode": model_mode,
                "attack_profile": attack_profile,
                "attack_budget": attack_budget,
                "assessment_plan": assessment_plan,
                "run": run,
                "cancel_event": cancel_event,
            },
            daemon=True,
            name=f"retest-{run['id']}",
        )
        with self._background_lock:
            self._background_runs[run["id"]] = thread
            self._background_cancel[run["id"]] = cancel_event
        thread.start()
        return 202, {**run, "retest": assessment_plan["retest"]}

    def upload_artifact_stream(
        self,
        *,
        project_id: str,
        target_id: str,
        filename: str,
        kind: str,
        mime_type: str,
        stream: Any,
        content_length: int,
    ) -> dict[str, Any]:
        target = self.repo.get_target(project_id, target_id)
        if kind not in ARTIFACT_KINDS:
            raise ValueError("artifact kind is not supported")
        clean_filename = Path(filename.replace("\\", "/")).name.strip()[:240]
        if not clean_filename or clean_filename in {".", ".."}:
            raise ValueError("artifact filename is required")
        artifact_id = new_id("art")
        stored = self.evidence_store.store_artifact_stream(
            project_id,
            artifact_id,
            stream,
            content_length=content_length,
            maximum_bytes=MAX_ARTIFACT_BYTES,
        )
        try:
            artifact = self.repo.add_artifact(
                project_id,
                artifact_id=artifact_id,
                target_id=target_id,
                filename=clean_filename,
                kind=kind,
                relative_path=str(stored["relative_path"]),
                mime_type=mime_type or "application/octet-stream",
                size_bytes=int(stored["size_bytes"]),
                sha256=str(stored["sha256"]),
            )
            capabilities = dict(target.get("capabilities") or {})
            if not capabilities.get("artifact_inventory"):
                capabilities["artifact_inventory"] = True
                self.repo.update_target_capabilities(project_id, target_id, capabilities)
            return artifact
        except Exception:
            path = self.evidence_store.resolve(str(stored["relative_path"]))
            path.unlink(missing_ok=True)
            try:
                path.parent.rmdir()
            except OSError:
                pass
            raise

    def save_artifact_profile(self, project_id: str, target_id: str, raw_profile: dict[str, Any]) -> dict[str, Any]:
        target = self.repo.get_target(project_id, target_id)
        profile = validate_artifact_profile(raw_profile)
        project_objective_ids = {str(item["id"]) for item in self.repo.get_project(project_id).get("objectives") or []}
        for case in profile.get("cases") or []:
            artifact = self.repo.get_artifact(project_id, str(case["artifact_id"]), include_path=False)
            if artifact["target_id"] != target_id:
                raise ValueError(f"artifact {artifact['id']} belongs to a different target")
            if artifact["status"] != "active":
                raise ValueError(f"artifact {artifact['id']} is archived")
            unknown_objective_ids = sorted(set(case.get("objective_ids") or []) - project_objective_ids)
            if unknown_objective_ids:
                raise ValueError(f"artifact case references objectives outside this project: {', '.join(unknown_objective_ids)}")
        config = dict(target.get("evaluation_config") or {})
        config["artifact"] = profile
        return self.repo.update_target_evaluation_config(project_id, target_id, validate_evaluation_config(config))

    def archive_artifact(self, project_id: str, artifact_id: str) -> dict[str, Any]:
        artifact = self.repo.get_artifact(project_id, artifact_id)
        result = self.repo.archive_artifact(project_id, artifact_id)
        target = self.repo.get_target(project_id, str(artifact["target_id"]))
        config = dict(target.get("evaluation_config") or {})
        profile = dict(config.get("artifact") or {})
        remaining = [case for case in profile.get("cases") or [] if case.get("artifact_id") != artifact_id]
        config["artifact"] = {"enabled": True, "cases": remaining} if remaining else {}
        self.repo.update_target_evaluation_config(project_id, str(artifact["target_id"]), validate_evaluation_config(config))
        return result

    def snapshot_artifacts_for_plan(self, project_id: str, target_id: str, assessment_plan: dict[str, Any]) -> None:
        if "artifact-security" not in (assessment_plan.get("module_ids") or []):
            assessment_plan["artifact_inventory"] = []
            return
        profile = (assessment_plan.get("evaluation_config") or {}).get("artifact") or {}
        selected = set((assessment_plan.get("strategy_filters") or {}).get("artifact-security") or [])
        inventory = []
        for case in profile.get("cases") or []:
            if selected and str(case.get("technique_id") or "") not in selected:
                continue
            artifact = self.repo.get_artifact(project_id, str(case.get("artifact_id") or ""), include_path=True)
            if artifact["target_id"] != target_id or artifact["status"] != "active":
                raise ValueError(f"artifact {artifact['id']} is not an active artifact for the selected target")
            inventory.append({**artifact, "policy_case_id": case["id"]})
        if not inventory:
            raise ValueError("artifact security is selected but no active uploaded artifact matches the selected LLM03 techniques")
        assessment_plan["artifact_inventory"] = inventory

    @staticmethod
    def _project_payload(project: dict[str, Any]) -> dict[str, Any]:
        """Attach computed adapter readiness without persisting derived state."""
        latest_preflights: dict[str, dict[str, Any]] = {}
        for item in project.get("target_preflights") or []:
            latest_preflights.setdefault(str(item.get("target_id") or ""), item)
        guardrails = {str(item.get("target_id") or ""): item for item in project.get("guardrails") or []}
        for target in project.get("targets") or []:
            target["technique_adapter_readiness"] = public_target_pack_readiness(target)
            target["runtime_readiness"] = target_runtime_readiness(target)
            latest = latest_preflights.get(str(target.get("id") or ""))
            if latest:
                current_signature = target_preflight_signature(
                    target,
                    guardrails.get(str(target.get("id") or "")) or {},
                )
                latest = {**latest, "current": latest.get("configuration_sha256") == current_signature}
            target["latest_preflight"] = latest
        return project

    def preflight_target(self, project_id: str, target_id: str) -> dict[str, Any]:
        target = self.repo.get_target(project_id, target_id)
        guardrail = self.repo.get_guardrail(project_id, target_id)
        signature = target_preflight_signature(target, guardrail)
        preflight = self.repo.create_target_preflight(
            project_id,
            target_id,
            target_snapshot=target,
            guardrail_snapshot=guardrail,
            configuration_sha256=signature,
        )
        output_directory = self.evidence_store.attempt_directory(project_id, "_preflights", preflight["id"])
        result = execute_target_preflight(
            target,
            guardrail,
            target_client=self.target_client,
            browser_target_client=self.browser_target_client,
            browser_output_directory=output_directory,
        )
        return self.repo.complete_target_preflight(project_id, preflight["id"], result)

    def prepare_guided_plan(self, project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.repo.require_project(project_id)
        config = normalize_guided_request(payload)
        setup_readiness = guided_setup_readiness(config)
        if not setup_readiness["ready"]:
            message = "; ".join(str(item.get("message") or "Guided setup is not ready.") for item in setup_readiness["issues"])
            raise ValueError(message or "guided setup is not ready")
        minimum_requests = guided_minimum_request_budget(config)
        if config["max_requests"] < minimum_requests:
            raise ValueError(
                "maximum requests must be at least "
                f"{minimum_requests} to complete request-schema discovery and every reviewed "
                "Guided baseline"
            )
        catalog = planner_catalog(config)
        if not hasattr(self.model_gateway, "plan_guided_assessment_with_trace"):
            raise ValueError("the configured local model gateway does not support guided planning")
        proposal, trace = self.model_gateway.plan_guided_assessment_with_trace(
            endpoint=config["endpoint_url"],
            authorized_boundary=config["authorized_boundary"],
            prohibited_behavior=config["prohibited_behavior"],
            security_goal=config["security_goal"],
            allowed_techniques=catalog,
        )
        plan = finalize_guided_plan(config, proposal)
        selected_minimum_requests = guided_minimum_request_budget(
            config,
            plan["selected_technique_ids"],
        )
        request_allocation = guided_request_allocation(config, plan["selected_technique_ids"])
        if config["max_requests"] < selected_minimum_requests:
            raise ValueError(
                "maximum requests must be at least "
                f"{selected_minimum_requests} to execute one reviewed catalog baseline for every "
                "selected Guided technique"
            )
        token = new_id("gplan")
        now = time.monotonic()
        with self._guided_plan_lock:
            self._guided_plans = {
                key: value
                for key, value in self._guided_plans.items()
                if now - float(value.get("created_monotonic") or 0.0) <= GUIDED_PLAN_TTL_SECONDS
            }
            self._guided_plans[token] = {
                "project_id": project_id,
                "created_monotonic": now,
                "config": config,
                "plan": plan,
                "planner_trace": trace,
            }
        self.repo.record_audit(
            project_id,
            action="guided.plan.prepared",
            object_type="guided_plan",
            object_id=token,
            metadata={
                "target": config["target_name"],
                "selected_techniques": ",".join(plan["selected_technique_ids"]),
                "expires_seconds": GUIDED_PLAN_TTL_SECONDS,
            },
        )
        selected = {item["id"]: item for item in plan["available_catalog"]}
        return {
            "plan_token": token,
            "expires_in_seconds": GUIDED_PLAN_TTL_SECONDS,
            "run_mode": "guided",
            "target": {
                "name": config["target_name"],
                "endpoint_url": config["endpoint_url"],
                "method": "POST",
                "maximum_requests": config["max_requests"],
                "maximum_runtime_seconds": config["max_runtime_seconds"],
                "adaptive_turns": config["adaptive_turns"],
                "controlled_reproduction": config["allow_reproduction"],
                "reviewed_baseline_request_reserve": selected_minimum_requests,
            },
            "objective": plan["objective"],
            "selected_techniques": [selected[item] for item in plan["selected_technique_ids"]],
            "model_selected_technique_ids": plan["model_selected_technique_ids"],
            "mandatory_baseline_technique_ids": plan["mandatory_baseline_technique_ids"],
            "planner_rationale": plan["planner_rationale"],
            "requires_advanced_configuration": plan["requires_advanced_configuration"],
            "advanced_handoff": plan["advanced_handoff"],
            "goal_template_id": plan["goal_template_id"],
            "request_allocation": request_allocation,
            "connection_discovery": [
                {"id": item["id"], "title": item["title"]}
                for item in config["request_schema_candidates"]
            ],
        }

    def validate_guided_setup(self, project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.repo.require_project(project_id)
        config = normalize_guided_request(payload)
        result = guided_setup_readiness(config)
        _status, health = self._health_payload()
        model_ready = bool(health.get("model_ready"))
        model_detail = health.get("dependencies", {}).get("model", {})
        model_check = {
            "id": "model",
            "field": "model_provider",
            "ready": model_ready,
            "title": "Planning model",
            "detail": (
                f"{model_detail.get('provider') or 'Configured provider'} · {model_detail.get('configured_model') or 'configured model'} is ready for planning."
                if model_ready
                else str(model_detail.get("error") or "Choose a configured model provider and make its credential reference available.")
            ),
        }
        result["checks"].append(model_check)
        result["ready"] = bool(result["ready"] and model_ready)
        if not model_ready:
            result["issues"].append({"code": "model_not_ready", "location": "model_provider", "message": model_check["detail"]})
        result.update({
            "schema_version": config["schema_version"],
            "target": {
                "name": config["target_name"],
                "method": config["method"],
                "endpoint_url": config["endpoint_url"],
                "environment_header_references": [
                    {"header": key, "environment": value[4:]}
                    for key, value in config["headers"].items()
                    if isinstance(value, str) and value.startswith("env:")
                ],
            },
            "recovery": guided_support_catalog()["recovery"],
        })
        return result

    def _consume_guided_plan(self, project_id: str, token: str) -> dict[str, Any]:
        with self._guided_plan_lock:
            record = self._guided_plans.get(token)
            if not record or record.get("project_id") != project_id:
                raise NotFoundError("guided plan was not found in this project; generate a new plan")
            if time.monotonic() - float(record.get("created_monotonic") or 0.0) > GUIDED_PLAN_TTL_SECONDS:
                self._guided_plans.pop(token, None)
                raise ValueError("guided plan expired; generate and review a new plan")
            self._guided_plans.pop(token, None)
        return record

    def start_guided_run(self, project_id: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        token = str(payload.get("plan_token") or "")
        if not token:
            raise ValueError("guided run requires a reviewed plan token")
        record = self._consume_guided_plan(project_id, token)
        config, guided_plan = record["config"], record["plan"]
        target_values = guided_target_values(config)
        preview_objective = {"id": "guided-preview", **guided_plan["objective"]}
        # Validate executable coverage before creating any durable project records.
        build_assessment_plan(
            technique_ids=guided_plan["selected_technique_ids"],
            objectives=[preview_objective],
            target_capabilities=target_values["capabilities"],
            adaptive_turns=config["adaptive_turns"],
        )
        assert_target_runtime_ready(target_values)
        suffix = token.rsplit("_", 1)[-1]
        target = self.repo.add_target(project_id, **target_values)
        scope_document = self.repo.add_document(
            project_id,
            kind="scope",
            filename=f"guided-scope-{suffix}.md",
            content=guided_scope_document(config),
        )
        self.repo.add_document(
            project_id,
            kind="policy",
            filename=f"guided-policy-{suffix}.md",
            content=guided_policy_document(config),
        )
        guardrail = self.repo.save_guardrail(
            project_id,
            target["id"],
            source_document_id=scope_document["id"],
            status="approved",
            max_requests=config["max_requests"],
            max_runtime_seconds=config["max_runtime_seconds"],
            max_consecutive_errors=config["max_consecutive_errors"],
            allow_active_recon=False,
            allow_multi_turn=config["allow_multi_turn"],
            max_turns_per_objective=config["adaptive_turns"],
            allow_reproduction=config["allow_reproduction"],
            allow_screenshots=False,
            stop_on_http_5xx=True,
            notes="Approved from the reviewed Guided Autonomous Assessment boundary. Exact endpoint only; no route expansion or target-proposed tool execution.",
        )
        objective = self.repo.add_objective(project_id, **guided_plan["objective"])
        target_snapshot = self.repo.get_target(project_id, target["id"])
        target_capabilities = assessment_target_capabilities(target_snapshot)
        assessment_plan = build_assessment_plan(
            technique_ids=guided_plan["selected_technique_ids"],
            objectives=[objective],
            target_capabilities=target_capabilities,
            evaluation_config=target_snapshot.get("evaluation_config") or {},
            adaptive_turns=config["adaptive_turns"],
        )
        planner_attempts = record["planner_trace"].get("attempts") if isinstance(record["planner_trace"], dict) else []
        planner_attempt = planner_attempts[0] if isinstance(planner_attempts, list) and planner_attempts and isinstance(planner_attempts[0], dict) else {}
        guided_allocation = guided_request_allocation(config, guided_plan["selected_technique_ids"])
        assessment_plan.update({
            "run_mode": "guided",
            "target_capabilities": target_capabilities,
            "target_adapter_snapshot": {
                "target_id": target_snapshot["id"],
                "name": target_snapshot.get("name"),
                "kind": target_snapshot["kind"],
                "base_url": target_snapshot.get("base_url"),
                "path": target_snapshot.get("path"),
                "method": target_snapshot.get("method"),
                "request_template": target_snapshot.get("request_template") or {},
                "response_path": target_snapshot.get("response_path"),
                "capabilities": target_snapshot.get("capabilities") or {},
                "transport_config": target_snapshot.get("transport_config") or {},
                "analysis_config": target_snapshot.get("analysis_config") or {},
                "conversation_config": target_snapshot.get("conversation_config") or {},
                "evaluation_config": target_snapshot.get("evaluation_config") or {},
                "technique_adapters": target_snapshot.get("technique_adapters") or {},
                "assessment_contracts": [],
                "authorized_routes": target_snapshot.get("authorized_routes") or [],
            },
            "confirmation_policy": {
                "mode": "minimum-proof",
                "reproduction_attempts": 1 if config["allow_reproduction"] else 0,
                "stop_after_confirmed_technique": True,
                "handoff": "human-manual-testing",
            },
            "guardrail": guardrail,
            "adaptive_turns": config["adaptive_turns"],
            "recon": {"mode": "none", "profile": "guided-connection-discovery"},
            "guided": {
                "enabled": True,
                "schema_version": guided_plan["schema_version"],
                "endpoint_url": config["endpoint_url"],
                "request_schema_candidates": config["request_schema_candidates"],
                "planner_rationale": guided_plan["planner_rationale"],
                "model_selected_technique_ids": guided_plan["model_selected_technique_ids"],
                "mandatory_baseline_technique_ids": guided_plan["mandatory_baseline_technique_ids"],
                "requires_advanced_configuration": guided_plan["requires_advanced_configuration"],
                "advanced_handoff": guided_plan["advanced_handoff"],
                "goal_template_id": guided_plan["goal_template_id"],
                "request_allocation": guided_allocation,
                "planner": {
                    "provider": str(planner_attempt.get("provider") or "configured-model-provider"),
                    "model": str(planner_attempt.get("model") or getattr(self.config, "llm_model", "")),
                    "trace": record["planner_trace"],
                },
            },
        })
        assessment_plan["reasoning_snapshot"] = self.repo.reasoning_snapshot(project_id, target_id=target["id"])
        attack_profile, attack_budget = resolve_attack_settings("focused", None)
        module_ids = assessment_plan["module_ids"]
        self.repo.assert_run_ready(project_id, target["id"])
        run = self.repo.create_run(project_id, target["id"], module_ids, "asus", attack_profile=attack_profile, attack_budget=attack_budget, assessment_plan=assessment_plan)
        background = payload.get("background") not in {False, "false", "off", "0", 0}
        if not background:
            return 201, run_assessment(
                self.repo,
                project_id=project_id,
                target_id=target["id"],
                module_ids=module_ids,
                model_mode="asus",
                attack_profile=attack_profile,
                attack_budget=attack_budget,
                assessment_plan=assessment_plan,
                model_gateway=self.model_gateway,
                target_client=self.target_client,
                browser_target_client=self.browser_target_client,
                evidence_store=self.evidence_store,
                recon_client=self.recon_client,
                existing_run=run,
            )
        cancel_event = threading.Event()
        thread = threading.Thread(
            target=self._execute_background_run,
            kwargs={"project_id": project_id, "target_id": target["id"], "module_ids": module_ids, "model_mode": "asus", "attack_profile": attack_profile, "attack_budget": attack_budget, "assessment_plan": assessment_plan, "run": run, "cancel_event": cancel_event},
            daemon=True,
            name=f"guided-assessment-{run['id']}",
        )
        with self._background_lock:
            self._background_runs[run["id"]] = thread
            self._background_cancel[run["id"]] = cancel_event
        thread.start()
        return 202, run

    def _execute_background_tool(self, *, project_id: str, tool_run_id: str, cancel_event: threading.Event) -> None:
        try:
            execute_tool_run(self.repo, project_id=project_id, tool_run_id=tool_run_id, target_client=self.target_client, cancel_event=cancel_event)
        except Exception as exc:
            try:
                current = self.repo.get_tool_run(project_id, tool_run_id, include_events=False)
                if current["status"] == "running":
                    message = f"background testing tool failed: {safe_error(exc)}"
                    self.repo.add_tool_event(project_id, tool_run_id, step_id="", event_type="error", title="Background testing tool failed", details={"message": message})
                    self.repo.complete_tool_run(project_id, tool_run_id, status="completed_with_errors", error=message)
            except Exception:
                pass
        finally:
            with self._background_lock:
                self._background_runs.pop(tool_run_id, None)
                self._background_cancel.pop(tool_run_id, None)

    def _execute_background_run(self, *, project_id: str, target_id: str, module_ids: list[str], model_mode: str, attack_profile: str, attack_budget: int, assessment_plan: dict[str, Any], run: dict[str, Any], cancel_event: threading.Event) -> None:
        try:
            run_assessment(
                self.repo,
                project_id=project_id,
                target_id=target_id,
                module_ids=module_ids,
                model_mode=model_mode,
                attack_profile=attack_profile,
                attack_budget=attack_budget,
                assessment_plan=assessment_plan,
                model_gateway=self.model_gateway,
                target_client=self.target_client,
                browser_target_client=self.browser_target_client,
                evidence_store=self.evidence_store,
                recon_client=self.recon_client,
                existing_run=run,
                cancel_event=cancel_event,
            )
        except Exception as exc:
            current = self.repo.require_run(project_id, run["id"])
            if current["status"] == "running":
                message = f"background assessment failed: {safe_error(exc)}"
                self.repo.add_run_event(project_id, run["id"], event_type="error", title="Background assessment failed", details={"message": message})
                self.repo.complete_run(project_id, run["id"], status="completed_with_errors", error=message)
        finally:
            with self._background_lock:
                self._background_runs.pop(run["id"], None)
                self._background_cancel.pop(run["id"], None)

    def _health_payload(self) -> tuple[int, dict[str, Any]]:
        dependencies: dict[str, Any] = {}
        try:
            dependencies["database"] = self.repo.healthcheck()
        except Exception as exc:
            dependencies["database"] = {"ok": False, "error": safe_error(exc)}
        try:
            dependencies["evidence_store"] = self.evidence_store.healthcheck()
        except Exception as exc:
            dependencies["evidence_store"] = {"ok": False, "error": safe_error(exc)}
        dependencies["model"] = self.model_gateway.healthcheck(timeout_seconds=min(3.0, self.config.llm_timeout_seconds)) if hasattr(self.model_gateway, "healthcheck") else {"ok": False, "error": "model health probe is unavailable"}
        browser_helper = getattr(self.browser_target_client, "helper_path", None)
        helper_ready = bool(browser_helper and Path(browser_helper).is_file())
        dependencies["browser"] = {
            "ok": bool(shutil.which("node") and helper_ready),
            "node": bool(shutil.which("node")),
            "capture_helper": helper_ready,
        }
        core_ok = bool(dependencies["database"].get("ok") and dependencies["evidence_store"].get("ok"))
        payload = {
            "ok": core_ok,
            "assessment_ready": core_ok,
            "asus_ready": bool(dependencies["model"].get("ok") and dependencies["model"].get("model_available")),
            "model_ready": bool(dependencies["model"].get("ok") and dependencies["model"].get("model_available")),
            "browser_ready": bool(dependencies["browser"].get("ok")),
            "dependencies": dependencies,
            "startup_recovery": self._startup_recovery,
            "active_background_executions": len(self._background_runs),
        }
        return (200 if core_ok else 503), payload

    def _request_background_cancel(self, *, project_id: str, execution_id: str, kind: str) -> tuple[int, dict[str, Any]]:
        current = self.repo.require_run(project_id, execution_id) if kind == "assessment" else self.repo.get_tool_run(project_id, execution_id, include_events=False)
        if current["status"] != "running":
            return 200, {"id": execution_id, "status": current["status"], "cancellation_requested": False}
        with self._background_lock:
            cancel_event = self._background_cancel.get(execution_id)
            if cancel_event is not None:
                cancel_event.set()
        if kind == "assessment":
            self.repo.add_run_event(project_id, execution_id, event_type="cancellation.requested", title="Operator requested assessment cancellation", details={"cooperative": cancel_event is not None})
        else:
            self.repo.add_tool_event(project_id, execution_id, step_id="", event_type="cancellation.requested", title="Operator requested testing-tool cancellation", details={"cooperative": cancel_event is not None})
        if cancel_event is None:
            reason = "execution had no live worker in this application process"
            if kind == "assessment":
                self.repo.complete_run(project_id, execution_id, status="cancelled", error=reason)
            else:
                self.repo.complete_tool_run(project_id, execution_id, status="cancelled", error=reason)
            return 200, {"id": execution_id, "status": "cancelled", "cancellation_requested": True}
        return 202, {"id": execution_id, "status": "cancelling", "cancellation_requested": True}

    def evidence_asset_path(self, project_id: str, asset_id: str) -> Path:
        asset = self.repo.get_evidence_asset(project_id, asset_id)
        path = self.evidence_store.resolve(asset["relative_path"])
        if not path.is_file():
            raise NotFoundError("evidence asset file is missing")
        return path

    def professional_evidence_bundle(
        self,
        project_id: str,
        *,
        run_id: str | None = None,
        mode: str = "redacted",
        acknowledge_sensitive: bool = False,
    ) -> dict[str, Any]:
        if mode == "full" and not acknowledge_sensitive:
            raise ValueError("full internal evidence export requires explicit sensitive-data acknowledgement")
        self.repo.record_audit(
            project_id,
            action="evidence_bundle.requested",
            object_type="assessment_run" if run_id else "project",
            object_id=run_id or project_id,
            metadata={"mode": mode, "scope": "run" if run_id else "project"},
        )
        result = build_evidence_bundle(
            self.repo,
            self.evidence_store,
            project_id=project_id,
            run_id=run_id,
            mode=mode,
        )
        self.repo.record_audit(
            project_id,
            action="evidence_bundle.exported",
            object_type="assessment_run" if run_id else "project",
            object_id=run_id or project_id,
            outcome="success",
            metadata={
                "mode": mode,
                "scope": "run" if run_id else "project",
                "bundle_sha256": result["sha256"],
                "manifest_sha256": result["manifest"]["manifest_sha256"],
                "size_bytes": result["size_bytes"],
            },
        )
        return result

    def professional_project_transfer(
        self,
        project_id: str,
        destination: Path,
        *,
        acknowledge_sensitive: bool,
        include_browser_sessions: bool = False,
    ) -> dict[str, Any]:
        self.repo.record_audit(
            project_id,
            action="project.transfer.requested",
            object_type="project",
            object_id=project_id,
            metadata={"browser_sessions_included": bool(include_browser_sessions)},
        )
        result = export_project(
            self.repo,
            self.config.evidence_root,
            project_id,
            destination,
            acknowledge_sensitive=acknowledge_sensitive,
            include_browser_sessions=include_browser_sessions,
        )
        self.repo.record_audit(
            project_id,
            action="project.transfer.exported",
            object_type="project",
            object_id=project_id,
            outcome="success",
            metadata={"archive_sha256": result["archive_sha256"], "browser_sessions_included": bool(include_browser_sessions)},
        )
        return result

    def import_project_transfer(self, archive: Path, *, acknowledge_sensitive: bool) -> dict[str, Any]:
        result = import_project(
            self.repo,
            self.config.evidence_root,
            archive,
            acknowledge_sensitive=acknowledge_sensitive,
        )
        project_id = str(result["project"]["id"])
        self.repo.record_audit(
            project_id,
            action="project.transfer.imported",
            object_type="project",
            object_id=project_id,
            outcome="success",
            metadata={"archive_sha256": result["archive_sha256"]},
        )
        return result

    def professional_local_backup(
        self,
        destination: Path,
        *,
        acknowledge_sensitive: bool,
        include_browser_sessions: bool = False,
    ) -> dict[str, Any]:
        return create_local_backup(
            self.repo,
            self.config,
            destination,
            acknowledge_sensitive=acknowledge_sensitive,
            include_browser_sessions=include_browser_sessions,
        )

    def dispatch(self, method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
        payload = payload or {}
        parsed_path = urlparse(path)
        query = parse_qs(parsed_path.query, keep_blank_values=True)
        parts = [part for part in parsed_path.path.split("/") if part]
        if parts == ["api", "health"] and method == "GET":
            return self._health_payload()
        if parts == ["api", "runtime"] and method == "GET":
            return 200, {"api_contract_version": API_CONTRACT_VERSION, "build": build_identity()}
        if parts == ["api", "fault-taxonomy"] and method == "GET":
            return 200, public_fault_taxonomy()
        if parts == ["api", "model-providers"] and method == "GET":
            if not hasattr(self.model_gateway, "public_provider_profiles"):
                return 200, {"selected_provider": "test", "providers": [], "credential_policy": "Test gateway does not expose provider profiles."}
            return 200, self.model_gateway.public_provider_profiles()
        if parts == ["api", "model-providers", "selection"] and method == "PATCH":
            self._model_configuration_guard()
            if not hasattr(self.model_gateway, "configure_provider"):
                raise ValueError("configured model gateway does not support provider switching")
            return 200, self.model_gateway.configure_provider(
                str(payload.get("provider_id") or ""),
                model=str(payload.get("model") or ""),
                api_key_env=str(payload.get("api_key_env") or ""),
            )
        if parts == ["api", "model-providers", "roles"] and method == "PATCH":
            self._model_configuration_guard()
            if not hasattr(self.model_gateway, "configure_model_roles"):
                raise ValueError("configured model gateway does not support model-role assignments")
            assignments = payload.get("role_profiles") if isinstance(payload.get("role_profiles"), dict) else payload
            return 200, self.model_gateway.configure_model_roles({
                role: (str(assignments.get(role) or "") or None)
                for role in ("planner", "generator", "evaluator", "adjudicator")
                if role in assignments
            })
        if len(parts) == 4 and parts[:3] == ["api", "model-providers", "profiles"]:
            profile_id = parts[3]
            self._model_configuration_guard()
            if method == "PUT":
                if not hasattr(self.model_gateway, "upsert_provider_profile"):
                    raise ValueError("configured model gateway does not support named profiles")
                boolean_fields = ("use_ssh_tunnel", "supports_disable_thinking")
                for field in boolean_fields:
                    if field in payload and not isinstance(payload[field], bool):
                        raise ValueError(f"{field} must be a JSON boolean")
                return 200, self.model_gateway.upsert_provider_profile(
                    profile_id,
                    label=str(payload.get("label") or ""),
                    kind=str(payload.get("kind") or ""),
                    base_url=str(payload.get("base_url") or ""),
                    model=str(payload.get("model") or ""),
                    api_key_env=str(payload.get("api_key_env") or ""),
                    use_ssh_tunnel=payload.get("use_ssh_tunnel", False),
                    supports_disable_thinking=payload.get("supports_disable_thinking", False),
                )
            if method == "DELETE":
                if not hasattr(self.model_gateway, "delete_provider_profile"):
                    raise ValueError("configured model gateway does not support named profiles")
                return 200, self.model_gateway.delete_provider_profile(profile_id)
        if len(parts) == 4 and parts[:2] == ["api", "model-providers"] and parts[3] == "session-key":
            self._model_configuration_guard()
            if method == "POST":
                return 200, self.model_gateway.set_session_api_key(parts[2], str(payload.get("api_key") or ""))
            if method == "DELETE":
                return 200, self.model_gateway.clear_session_api_key(parts[2])
        if len(parts) == 4 and parts[:2] == ["api", "model-providers"] and parts[3] == "qualification" and method == "POST":
            if not hasattr(self.model_gateway, "qualify_provider_profile"):
                raise ValueError("configured model gateway does not support provider connection qualification")
            return 200, self.model_gateway.qualify_provider_profile(parts[2])
        if parts == ["api", "modules"] and method == "GET":
            return 200, {"modules": module_summaries()}
        if parts == ["api", "taxonomies", "owasp-llm-2025"] and method == "GET":
            return 200, public_taxonomy()
        if parts == ["api", "qualification-registry"] and method == "GET":
            return 200, public_qualification_registry()
        if parts == ["api", "milestone-4", "coverage"] and method == "GET":
            return 200, public_m4_coverage()
        if parts == ["api", "testing-tool-packs"] and method == "GET":
            return 200, public_tool_packs()
        if parts == ["api", "methodology-cards"] and method == "GET":
            capabilities = [
                value.strip()
                for raw in query.get("capability", [])
                for value in str(raw).split(",")
                if value.strip()
            ]
            return 200, public_methodology_library(
                query=str((query.get("q") or [""])[0]),
                capabilities=capabilities,
            )
        if parts == ["api", "guided-support"] and method == "GET":
            return 200, guided_support_catalog()
        if parts == ["api", "target-profiles"] and method == "GET":
            return 200, public_target_profiles()
        if parts == ["api", "target-profiles", "validate"] and method == "POST":
            document = payload.get("document") if "document" in payload else payload
            return 200, validate_target_profile_document(document)
        if parts == ["api", "motor-lab"] and method == "GET":
            return 200, self.motor_lab.datasets()
        if parts == ["api", "motor-lab", "operator-traces"]:
            if method == "GET":
                return 200, self.motor_lab.operator_traces()
            if method == "POST":
                return 201, self.motor_lab.add_operator_trace(payload)
        if parts == ["api", "motor-lab", "experiments"]:
            if method == "GET":
                return 200, self.motor_lab.list_experiments()
            if method == "POST":
                return 201, self.motor_lab.create_experiment(payload)
        if len(parts) == 4 and parts[:3] == ["api", "motor-lab", "experiments"] and method == "GET":
            return 200, self.motor_lab.experiment(parts[3])
        if len(parts) == 5 and parts[:3] == ["api", "motor-lab", "experiments"] and parts[4] == "audit" and method == "POST":
            return 200, self.motor_lab.audit_experiment(parts[3])
        if len(parts) == 5 and parts[:3] == ["api", "motor-lab", "datasets"]:
            dataset_id = parts[3]
            if parts[4] == "reviews" and method == "GET":
                return 200, self.motor_lab.review_records(
                    dataset_id,
                    status=str((query.get("status") or [""])[0]),
                    task=str((query.get("task") or [""])[0]),
                    source_id=str((query.get("source_id") or [""])[0]),
                    query=str((query.get("query") or [""])[0]),
                    offset=int((query.get("offset") or ["0"])[0]),
                    limit=int((query.get("limit") or ["20"])[0]),
                )
            if parts[4] == "review-overlay" and method == "GET":
                return 200, self.motor_lab.review_overlay(dataset_id)
        if len(parts) == 6 and parts[:3] == ["api", "motor-lab", "datasets"] and parts[4] == "reviews" and method == "PATCH":
            return 200, self.motor_lab.save_review(parts[3], parts[5], payload)
        if parts == ["api", "projects"] and method == "GET":
            include_archived = str((query.get("include_archived") or [""])[0]).casefold() in {"1", "true", "yes"}
            return 200, {"projects": self.repo.list_projects(include_archived=include_archived)}
        if parts == ["api", "projects"] and method == "POST":
            return 201, self.repo.create_project(name=str(payload.get("name", "")), client=str(payload.get("client", "")), environment=str(payload.get("environment", "test")), data_classification=str(payload.get("data_classification", "confidential")))
        if len(parts) >= 3 and parts[:2] == ["api", "projects"]:
            project_id = parts[2]
            if len(parts) == 3 and method == "GET":
                return 200, self._project_payload(self.repo.get_project(project_id))
            if len(parts) == 4 and parts[3] == "organization" and method == "PATCH":
                tags = payload.get("tags") if "tags" in payload else None
                return 200, self.repo.update_project_organization(
                    project_id,
                    folder=str(payload.get("folder") or "") if "folder" in payload else None,
                    tags=tags,
                    pinned=payload.get("pinned") if "pinned" in payload else None,
                )
            if len(parts) == 4 and parts[3] == "opened" and method == "POST":
                return 200, self.repo.mark_project_opened(project_id)
            if len(parts) == 4 and parts[3] == "archive" and method == "POST":
                return 200, self.repo.archive_project(project_id)
            if len(parts) == 4 and parts[3] == "restore" and method == "POST":
                return 200, self.repo.restore_project(project_id)
            if method in {"POST", "PATCH", "DELETE"} and self.repo.require_project(project_id).get("status") == "archived":
                raise ValueError("archived projects are read-only; restore this project before making changes")
            if len(parts) == 4 and parts[3] == "report" and method == "GET":
                project = self.repo.get_project_for_report(project_id)
                safe_name = "-".join(project["name"].casefold().split())[:80] or project_id
                return 200, {"filename": f"{safe_name}-assessment-report.md", "content": build_markdown_report(project)}
            if len(parts) == 4 and parts[3] == "report-review" and method == "POST":
                return 200, self.repo.set_report_review(
                    project_id,
                    status=str(payload.get("status") or "draft"),
                    reviewer=str(payload.get("reviewer") or ""),
                    notes=str(payload.get("notes") or ""),
                )
            if len(parts) == 4 and parts[3] == "validation-analysis" and method == "GET":
                project = self.repo.get_project(project_id)
                return 200, project.get("validation_analysis") or {}
            if len(parts) == 4 and parts[3] == "target-profile-readiness" and method == "GET":
                profile_id = str((query.get("profile_id") or [""])[0])
                target_id = str((query.get("target_id") or [""])[0])
                return 200, self._target_profile_readiness(project_id, profile_id, target_id)
            if len(parts) == 4 and parts[3] == "run-comparison" and method == "GET":
                baseline_id = str((query.get("baseline") or [""])[0])
                current_id = str((query.get("current") or [""])[0])
                return 200, compare_runs(
                    self.repo.get_run_detail(project_id, baseline_id),
                    self.repo.get_run_detail(project_id, current_id),
                )
            if len(parts) == 4 and parts[3] == "retest-report" and method == "GET":
                baseline_id = str((query.get("baseline") or [""])[0])
                current_id = str((query.get("current") or [""])[0])
                comparison = compare_runs(
                    self.repo.get_run_detail(project_id, baseline_id),
                    self.repo.get_run_detail(project_id, current_id),
                )
                project = self.repo.get_project(project_id)
                safe_name = "-".join(project["name"].casefold().split())[:64] or project_id
                return 200, {
                    "filename": f"{safe_name}-{baseline_id}-to-{current_id}-retest-report.md",
                    "content": build_retest_report(project, comparison),
                    "comparison": comparison,
                }
            if len(parts) == 4 and parts[3] == "guided-plans" and method == "POST":
                return 201, self.prepare_guided_plan(project_id, payload)
            if len(parts) == 4 and parts[3] == "guided-validation" and method == "POST":
                return 200, self.validate_guided_setup(project_id, payload)
            if len(parts) == 4 and parts[3] == "guided-runs" and method == "POST":
                return self.start_guided_run(project_id, payload)
            if len(parts) == 4 and parts[3] == "reasoning" and method == "GET":
                target_id = str((query.get("target_id") or [""])[0]).strip() or None
                return 200, self.repo.reasoning_workspace(project_id, target_id=target_id)
            if len(parts) == 4 and parts[3] == "methodology-cards":
                if method == "GET":
                    return 200, {"methodology_cards": self.repo.list_methodology_pins(project_id)}
                if method == "POST":
                    return 201, self.repo.pin_methodology_card(
                        project_id,
                        str(payload.get("card_id") or ""),
                        notes=str(payload.get("notes") or ""),
                        refresh=payload.get("refresh") in {True, "true", "on", "1", 1},
                    )
            if len(parts) == 5 and parts[3] == "methodology-cards":
                if method == "GET":
                    return 200, self.repo.get_methodology_pin(project_id, parts[4])
                if method == "PATCH":
                    existing = self.repo.get_methodology_pin(project_id, parts[4])
                    return 200, self.repo.pin_methodology_card(
                        project_id,
                        parts[4],
                        notes=str(payload.get("notes", existing.get("notes") or "")),
                        refresh=payload.get("refresh") in {True, "true", "on", "1", 1},
                    )
                if method == "DELETE":
                    return 200, self.repo.unpin_methodology_card(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "reasoning-nodes":
                if method == "GET":
                    target_id = str((query.get("target_id") or [""])[0]).strip() or None
                    return 200, {"nodes": self.repo.list_reasoning_nodes(project_id, target_id=target_id)}
                if method == "POST":
                    return 201, self.repo.create_reasoning_node(
                        project_id,
                        kind=str(payload.get("kind") or ""),
                        label=str(payload.get("label") or ""),
                        description=str(payload.get("description") or ""),
                        confidence=str(payload.get("confidence") or "unknown"),
                        source_ref=str(payload.get("source_ref") or ""),
                        target_id=str(payload.get("target_id") or "") or None,
                    )
            if len(parts) == 5 and parts[3] == "reasoning-nodes":
                if method == "GET":
                    return 200, self.repo.get_reasoning_node(project_id, parts[4])
                if method == "PATCH":
                    existing = self.repo.get_reasoning_node(project_id, parts[4])
                    return 200, self.repo.update_reasoning_node(
                        project_id, parts[4],
                        kind=str(payload.get("kind", existing["kind"])),
                        label=str(payload.get("label", existing["label"])),
                        description=str(payload.get("description", existing["description"])),
                        confidence=str(payload.get("confidence", existing["confidence"])),
                        source_ref=str(payload.get("source_ref", existing["source_ref"])),
                        target_id=(str(payload.get("target_id") or "") or None) if "target_id" in payload else existing.get("target_id"),
                    )
                if method == "DELETE":
                    return 200, self.repo.delete_reasoning_node(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "reasoning-edges":
                if method == "GET":
                    return 200, {"edges": self.repo.list_reasoning_edges(project_id)}
                if method == "POST":
                    return 201, self.repo.create_reasoning_edge(
                        project_id,
                        source_node_id=str(payload.get("source_node_id") or ""),
                        target_node_id=str(payload.get("target_node_id") or ""),
                        kind=str(payload.get("kind") or ""),
                        status=str(payload.get("status") or "unknown"),
                        label=str(payload.get("label") or ""),
                        description=str(payload.get("description") or ""),
                        evidence_refs=payload.get("evidence_refs"),
                    )
            if len(parts) == 5 and parts[3] == "reasoning-edges":
                if method == "GET":
                    return 200, self.repo.get_reasoning_edge(project_id, parts[4])
                if method == "PATCH":
                    existing = self.repo.get_reasoning_edge(project_id, parts[4])
                    return 200, self.repo.update_reasoning_edge(
                        project_id, parts[4],
                        source_node_id=str(payload.get("source_node_id", existing["source_node_id"])),
                        target_node_id=str(payload.get("target_node_id", existing["target_node_id"])),
                        kind=str(payload.get("kind", existing["kind"])),
                        status=str(payload.get("status", existing["status"])),
                        label=str(payload.get("label", existing["label"])),
                        description=str(payload.get("description", existing["description"])),
                        evidence_refs=payload.get("evidence_refs", existing.get("evidence_refs") or []),
                    )
                if method == "DELETE":
                    return 200, self.repo.delete_reasoning_edge(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "hypotheses":
                if method == "GET":
                    target_id = str((query.get("target_id") or [""])[0]).strip() or None
                    return 200, {"hypotheses": self.repo.list_reasoning_hypotheses(project_id, target_id=target_id)}
                if method == "POST":
                    return 201, self.repo.create_reasoning_hypothesis(
                        project_id,
                        classification=str(payload.get("classification") or "hypothesis"),
                        decision=str(payload.get("decision") or "hold"),
                        claim=str(payload.get("claim") or ""),
                        rationale=str(payload.get("rationale") or ""),
                        missing_prerequisite=str(payload.get("missing_prerequisite") or ""),
                        cheapest_test=str(payload.get("cheapest_test") or ""),
                        evidence_refs=payload.get("evidence_refs"),
                        methodology_card_ids=payload.get("methodology_card_ids"),
                        target_id=str(payload.get("target_id") or "") or None,
                    )
            if len(parts) == 5 and parts[3] == "hypotheses":
                if method == "GET":
                    return 200, self.repo.get_reasoning_hypothesis(project_id, parts[4])
                if method == "PATCH":
                    return 200, self.repo.update_reasoning_hypothesis(project_id, parts[4], **payload)
                if method == "DELETE":
                    return 200, self.repo.delete_reasoning_hypothesis(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "evidence-checkpoints":
                if method == "GET":
                    target_id = str((query.get("target_id") or [""])[0]).strip() or None
                    return 200, {"checkpoints": self.repo.list_reasoning_checkpoints(project_id, target_id=target_id)}
                if method == "POST":
                    return 201, self.repo.create_reasoning_checkpoint(
                        project_id,
                        title=str(payload.get("title") or ""),
                        starting_identity=str(payload.get("starting_identity") or ""),
                        prerequisite=str(payload.get("prerequisite") or ""),
                        action=str(payload.get("action") or ""),
                        result=str(payload.get("result") or ""),
                        impact=str(payload.get("impact") or ""),
                        cleanup_status=str(payload.get("cleanup_status") or "not-required"),
                        stages=payload.get("stages"),
                        notes=str(payload.get("notes") or ""),
                        target_id=str(payload.get("target_id") or "") or None,
                        run_id=str(payload.get("run_id") or "") or None,
                        test_case_id=str(payload.get("test_case_id") or "") or None,
                        evidence_id=str(payload.get("evidence_id") or "") or None,
                        correction_of_id=str(payload.get("correction_of_id") or "") or None,
                    )
            if len(parts) == 5 and parts[3] == "evidence-checkpoints" and method == "GET":
                return 200, self.repo.get_reasoning_checkpoint(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "documents" and method == "POST":
                return 201, self.repo.add_document(project_id, kind=str(payload.get("kind", "")), filename=str(payload.get("filename", "")), content=str(payload.get("content", "")))
            if len(parts) == 5 and parts[3] == "documents" and method == "GET":
                return 200, self.repo.get_document(project_id, parts[4])
            if len(parts) == 5 and parts[3] == "documents" and method == "PATCH":
                return 200, self.repo.update_document(project_id, parts[4], kind=str(payload.get("kind", "")), filename=str(payload.get("filename", "")), content=str(payload.get("content", "")))
            if len(parts) == 5 and parts[3] == "documents" and method == "DELETE":
                return 200, self.repo.delete_document(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "artifacts" and method == "GET":
                return 200, {"artifacts": self.repo.list_artifacts(project_id)}
            if len(parts) == 5 and parts[3] == "artifacts" and method == "DELETE":
                return 200, self.archive_artifact(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "objectives" and method == "POST":
                risk_ids, technique_ids = payload.get("risk_ids") or [], payload.get("technique_ids") or []
                proof_rule_ids = payload.get("proof_rule_ids") or []
                if not isinstance(risk_ids, list) or not isinstance(technique_ids, list) or not isinstance(proof_rule_ids, list):
                    raise ValueError("objective OWASP mappings and proof rule ids must be lists")
                return 201, self.repo.add_objective(project_id, title=str(payload.get("title", "")), description=str(payload.get("description", "")), success_criteria=str(payload.get("success_criteria", "")), expected_safe_behavior=str(payload.get("expected_safe_behavior", "")), false_positive_exclusions=str(payload.get("false_positive_exclusions", "")), proof_mode=str(payload.get("proof_mode") or "model-review"), proof_rule_ids=proof_rule_ids, require_reproduction=payload.get("require_reproduction") in {True, "true", "on", "1", 1}, risk_ids=risk_ids, technique_ids=technique_ids)
            if len(parts) == 5 and parts[3] == "objectives" and method == "PATCH":
                risk_ids, technique_ids = payload.get("risk_ids") or [], payload.get("technique_ids") or []
                proof_rule_ids = payload.get("proof_rule_ids") or []
                if not isinstance(risk_ids, list) or not isinstance(technique_ids, list) or not isinstance(proof_rule_ids, list):
                    raise ValueError("objective OWASP mappings and proof rule ids must be lists")
                return 200, self.repo.update_objective(project_id, parts[4], title=str(payload.get("title", "")), description=str(payload.get("description", "")), success_criteria=str(payload.get("success_criteria", "")), expected_safe_behavior=str(payload.get("expected_safe_behavior", "")), false_positive_exclusions=str(payload.get("false_positive_exclusions", "")), proof_mode=str(payload.get("proof_mode") or "model-review"), proof_rule_ids=proof_rule_ids, require_reproduction=payload.get("require_reproduction") in {True, "true", "on", "1", 1}, risk_ids=risk_ids, technique_ids=technique_ids)
            if len(parts) == 5 and parts[3] == "objectives" and method == "DELETE":
                return 200, self.repo.delete_objective(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "targets" and method == "POST":
                kind = str(payload.get("kind", "chatbot"))
                browser_profile = None
                if kind == "browser-chatbot":
                    browser_profile = validate_browser_profile({
                        "input_selector": payload.get("input_selector", ""),
                        "submit_selector": payload.get("submit_selector", ""),
                        "response_selector": payload.get("response_selector", ""),
                        "streaming_selector": payload.get("streaming_selector", ""),
                        "completion_selector": payload.get("completion_selector", ""),
                        "transient_response_patterns": payload.get("transient_response_patterns", ""),
                        "response_stability_ms": payload.get("response_stability_ms"),
                        "persistent_session": payload.get("persistent_session", True) in {True, "true", "on", "1", 1},
                        "full_page": payload.get("full_page") in {True, "true", "on", "1", 1},
                        "navigation_transport": payload.get("navigation_transport", "auto"),
                        "outcome_rule": {
                            "enabled": payload.get("outcome_enabled") in {True, "true", "on", "1", 1},
                            "id": payload.get("outcome_rule_id", ""),
                            "label": payload.get("outcome_label", ""),
                            "path": payload.get("outcome_path", ""),
                            "selector": payload.get("outcome_selector", ""),
                            "expected_text": payload.get("outcome_expected_text", ""),
                            "verification_timeout_ms": payload.get("outcome_verification_timeout_ms", 5000),
                            "case_sensitive": payload.get("outcome_case_sensitive") in {True, "true", "on", "1", 1},
                            "finding_evidence": payload.get("outcome_finding_evidence") in {True, "true", "on", "1", 1},
                            "stop_after_match": payload.get("outcome_stop_after_match", True) in {True, "true", "on", "1", 1},
                            "severity": payload.get("outcome_severity", "high"),
                            "technique_ids": [str(payload.get("outcome_technique_id") or "")] if payload.get("outcome_technique_id") else [],
                        },
                    })
                candidate = {
                    "base_url": str(payload.get("base_url", "")),
                    "path": str(payload.get("path", "")),
                }
                if not candidate["path"].strip():
                    raise ValueError("primary target path must be configured explicitly in Attack Surface")
                if kind in {"chatbot", "browser-chatbot"}:
                    target_url(candidate)
                capabilities = payload.get("capabilities") or {}
                if not isinstance(capabilities, dict):
                    raise ValueError("target capabilities must be an object")
                analysis_config = validate_analysis_config({
                    "enabled": payload.get("token_context_enabled") in {True, "true", "on", "1", 1},
                    "tokenizer_path": payload.get("tokenizer_path", ""),
                    "tokenizer_method": payload.get("tokenizer_method", ""),
                    "context_info_path": payload.get("context_info_path", ""),
                    "context_info_method": payload.get("context_info_method", ""),
                    "context_padding_field": payload.get("context_padding_field", ""),
                    "history_field": payload.get("history_field", ""),
                    "tokenizer_text_field": payload.get("tokenizer_text_field", ""),
                    "max_context_padding_chars": payload.get("max_context_padding_chars"),
                })
                primary_method = "GET" if kind == "browser-chatbot" else str(payload.get("method", ""))
                authorized_routes = validate_authorized_routes(
                    parse_authorized_routes(payload.get("authorized_routes")),
                    primary_path=candidate["path"],
                    primary_method=primary_method,
                    analysis_config=analysis_config,
                )
                request_template = {} if kind == "browser-chatbot" else parse_template(
                    str(payload.get("request_template", "")),
                    require_prompt=kind == "chatbot",
                )
                conversation_config = validate_conversation_config(
                    payload.get("conversation_config") if isinstance(payload.get("conversation_config"), dict) else {},
                    request_template=request_template,
                )
                transport_config = normalize_transport_profile({
                    "enabled": payload.get("transport_retries_enabled") in {True, "true", "on", "1", 1},
                    "max_retries": payload.get("transport_max_retries", 0),
                    "replay_safe": payload.get("transport_replay_safe") in {True, "true", "on", "1", 1},
                    "retry_statuses": [408, 425, 429, 500, 502, 503, 504],
                    "base_delay_ms": payload.get("transport_base_delay_ms", 250),
                    "honor_retry_after": payload.get("transport_honor_retry_after") in {True, "true", "on", "1", 1},
                    "max_retry_after_ms": payload.get("transport_max_retry_after_ms", 10000),
                    "min_request_interval_ms": payload.get("transport_min_request_interval_ms", 0),
                    "request_timeout_seconds": payload.get("transport_request_timeout_seconds", 0),
                    "require_sse_done": payload.get("transport_require_sse_done") in {True, "true", "on", "1", 1},
                })
                return 201, self.repo.add_target(project_id, name=str(payload.get("name", "")), kind=kind, base_url=candidate["base_url"], path=candidate["path"], method=primary_method, headers=parse_headers(str(payload.get("headers", "{}"))), request_template=request_template, response_path=str(payload.get("response_path", "")), description=str(payload.get("description", "")), browser_profile=browser_profile, capabilities=capabilities, analysis_config=analysis_config, conversation_config=conversation_config, transport_config=transport_config, authorized_routes=authorized_routes, scope_confirmed=payload.get("scope_confirmed") in {True, "true", "on", "1", 1})
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "transport-reliability" and method == "PATCH":
                return 200, self.repo.update_target_transport_config(project_id, parts[4], payload)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "browser-transport" and method == "PATCH":
                target = self.repo.get_target(project_id, parts[4])
                if target["kind"] != "browser-chatbot":
                    raise ValueError("browser transport requires a browser chatbot target")
                browser_profile = validate_browser_profile({
                    **(target.get("browser_profile") or {}),
                    "navigation_transport": payload.get("navigation_transport", "auto"),
                })
                return 200, self.repo.update_target_browser_profile(project_id, parts[4], browser_profile)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "origin" and method == "PATCH":
                target = self.repo.get_target(project_id, parts[4])
                candidate = {**target, "base_url": str(payload.get("base_url") or "")}
                if target["kind"] in {"chatbot", "browser-chatbot"}:
                    target_url(candidate)
                return 200, self.repo.update_target_origin(project_id, parts[4], candidate["base_url"])
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "preflights" and method == "POST":
                return 201, self.preflight_target(project_id, parts[4])
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "preflights" and method == "GET":
                return 200, {"preflights": self.repo.list_target_preflights(project_id, target_id=parts[4])}
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "profile" and method == "GET":
                profile_id = str((query.get("profile_id") or ["generic-json-chatbot"])[0])
                return 200, export_target_profile(self.repo.get_target(project_id, parts[4]), profile_id=profile_id)
            if len(parts) == 7 and parts[3] == "targets" and parts[5] == "preflights" and method == "GET":
                item = self.repo.get_target_preflight(project_id, parts[6])
                if item["target_id"] != parts[4]:
                    raise NotFoundError("target preflight not found for this target")
                return 200, item
            if len(parts) == 5 and parts[3] == "targets" and method == "DELETE":
                return 200, self.repo.delete_target(project_id, parts[4])
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "authorized-routes" and method == "PATCH":
                target = self.repo.get_target(project_id, parts[4])
                routes = validate_authorized_routes(
                    parse_authorized_routes(payload.get("authorized_routes")),
                    primary_path=target["path"], primary_method=target["method"], analysis_config=target.get("analysis_config") or {},
                )
                return 200, self.repo.update_target_authorized_routes(project_id, parts[4], routes)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "capabilities" and method == "PATCH":
                capabilities = payload.get("capabilities") or {}
                if not isinstance(capabilities, dict):
                    raise ValueError("target capabilities must be an object")
                return 200, self.repo.update_target_capabilities(project_id, parts[4], capabilities)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "analysis-config" and method == "PATCH":
                analysis_config = validate_analysis_config({
                    "enabled": payload.get("enabled") in {True, "true", "on", "1", 1},
                    "tokenizer_path": payload.get("tokenizer_path", ""),
                    "tokenizer_method": payload.get("tokenizer_method", ""),
                    "context_info_path": payload.get("context_info_path", ""),
                    "context_info_method": payload.get("context_info_method", ""),
                    "context_padding_field": payload.get("context_padding_field", ""),
                    "history_field": payload.get("history_field", ""),
                    "tokenizer_text_field": payload.get("tokenizer_text_field", ""),
                    "max_context_padding_chars": payload.get("max_context_padding_chars"),
                })
                return 200, self.repo.update_target_analysis_config(project_id, parts[4], analysis_config)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "conversation-config" and method == "PATCH":
                target = self.repo.get_target(project_id, parts[4])
                if target.get("kind") == "browser-chatbot":
                    raise ValueError("structured request history applies only to JSON API targets")
                conversation_config = validate_conversation_config(
                    payload,
                    request_template=target.get("request_template") or {},
                )
                return 200, self.repo.update_target_conversation_config(project_id, parts[4], conversation_config)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "evaluation-config" and method == "PATCH":
                target = self.repo.get_target(project_id, parts[4])
                config_payload = dict(payload)
                if "artifact" not in config_payload:
                    config_payload["artifact"] = (target.get("evaluation_config") or {}).get("artifact") or {}
                evaluation_config = validate_evaluation_config(config_payload)
                for case in (evaluation_config.get("agency") or {}).get("cases") or []:
                    if case.get("evidence_source") == "verifier":
                        verification_method = str(case.get("verification_method") or "")
                        verification_path = str(case.get("verification_path") or "")
                        if not route_is_authorized(target, verification_path, verification_method):
                            raise ValueError(f"agency verifier route {verification_method} {verification_path} must first be added to this target's authorized routes")
                    if case.get("impact") == "reversible-change":
                        cleanup_method = str(case.get("cleanup_method") or "")
                        cleanup_path = str(case.get("cleanup_path") or "")
                        if not route_is_authorized(target, cleanup_path, cleanup_method):
                            raise ValueError(f"agency cleanup route {cleanup_method} {cleanup_path} must first be added to this target's authorized routes")
                for case in (evaluation_config.get("tool_agent") or {}).get("cases") or []:
                    if case.get("confirmation") == "verifier":
                        verification_method = str(case.get("verification_method") or "")
                        verification_path = str(case.get("verification_path") or "")
                        if not route_is_authorized(target, verification_path, verification_method):
                            raise ValueError(f"tool-agent verifier route {verification_method} {verification_path} must first be added to this target's authorized routes")
                    if case.get("impact") == "reversible-change":
                        cleanup_method = str(case.get("cleanup_method") or "")
                        cleanup_path = str(case.get("cleanup_path") or "")
                        if not route_is_authorized(target, cleanup_path, cleanup_method):
                            raise ValueError(f"tool-agent cleanup route {cleanup_method} {cleanup_path} must first be added to this target's authorized routes")
                for case in (evaluation_config.get("agentic_trace") or {}).get("cases") or []:
                    if case.get("confirmation") == "verifier":
                        verification_method = str(case.get("verification_method") or "")
                        verification_path = str(case.get("verification_path") or "")
                        if not route_is_authorized(target, verification_path, verification_method):
                            raise ValueError(f"agentic trace verifier route {verification_method} {verification_path} must first be added to this target's authorized routes")
                    if case.get("impact") == "reversible-change":
                        cleanup_method = str(case.get("cleanup_method") or "")
                        cleanup_path = str(case.get("cleanup_path") or "")
                        if not route_is_authorized(target, cleanup_path, cleanup_method):
                            raise ValueError(f"agentic trace cleanup route {cleanup_method} {cleanup_path} must first be added to this target's authorized routes")
                mcp_profile = evaluation_config.get("mcp") or {}
                if mcp_profile.get("enabled"):
                    if str(mcp_profile.get("transport") or "auto") != "stdio":
                        endpoint_path = str(mcp_profile.get("endpoint_path") or "")
                        if not route_is_authorized(target, endpoint_path, "POST"):
                            raise ValueError(f"MCP endpoint route POST {endpoint_path} must first be added to this target's authorized routes")
                        retained_streamable_notifications = (
                            mcp_profile.get("open_streamable_event_channel") is True
                            and
                            str(mcp_profile.get("transport") or "auto") != "stateless-http"
                            and str(mcp_profile.get("transport") or "auto") != "legacy-http-sse"
                            and any(
                                case.get("inventory_change_policy") == "require-notification"
                                and int(case.get("inventory_recheck_count") or 0) > 0
                                for case in mcp_profile.get("cases") or []
                            )
                        )
                        if retained_streamable_notifications and not route_is_authorized(target, endpoint_path, "GET"):
                            raise ValueError(
                                f"MCP Streamable HTTP notification route GET {endpoint_path} must first be added to this target's authorized routes"
                            )
                        legacy_sse_path = str(mcp_profile.get("legacy_sse_path") or "")
                        if legacy_sse_path and not route_is_authorized(target, legacy_sse_path, "GET"):
                            raise ValueError(f"legacy MCP SSE route GET {legacy_sse_path} must first be added to this target's authorized routes")
                rag_profile = evaluation_config.get("rag") or {}
                if rag_profile.get("enabled"):
                    for operation_name, operation in (rag_profile.get("operations") or {}).items():
                        operation_path = str(operation.get("path") or "")
                        concrete_path = operation_path
                        for placeholder in ("document_id", "canary", "case_id", "owner_identity_id", "query_identity_id"):
                            concrete_path = concrete_path.replace("{{" + placeholder + "}}", "adverscope-probe")
                        operation_method = str(operation.get("method") or "")
                        if not route_is_authorized(target, concrete_path, operation_method):
                            raise ValueError(f"RAG {operation_name} route {operation_method} {operation_path} must first be added to this target's authorized routes")
                return 200, self.repo.update_target_evaluation_config(project_id, parts[4], evaluation_config)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "artifact-profile" and method == "PATCH":
                return 200, self.save_artifact_profile(project_id, parts[4], payload)
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "assessment-contracts" and method == "PATCH":
                target = self.repo.get_target(project_id, parts[4])
                contracts = normalize_assessment_contracts(
                    payload.get("contracts") or [],
                    target,
                    objectives=self.repo.get_project(project_id).get("objectives") or [],
                )
                guardrail = self.repo.get_guardrail(project_id, parts[4])
                if any(item.get("enabled") and item.get("reproduce") for item in contracts) and not guardrail.get("allow_reproduction"):
                    raise ValueError("enabled security assessment contracts require reproduction permission in the approved target guardrail")
                maximum_requests = sum(int(item.get("maximum_requests") or 0) for item in contracts if item.get("enabled"))
                if maximum_requests > int(guardrail.get("max_requests") or 0):
                    raise ValueError(f"enabled assessment contracts can send up to {maximum_requests} requests, exceeding the approved target limit of {guardrail.get('max_requests')}")
                return 200, self.repo.update_target_assessment_contracts(project_id, parts[4], contracts)
            if len(parts) == 7 and parts[3] == "targets" and parts[5] == "technique-adapters" and method == "PATCH":
                pack_id = parts[6]
                configuration = normalize_pack_configuration(pack_id, payload.get("configuration") or {})
                target = self.repo.update_target_technique_adapter(project_id, parts[4], pack_id, configuration)
                return 200, {"target": target, "readiness": pack_readiness(pack_id, target)}
            if len(parts) == 7 and parts[3] == "targets" and parts[5] == "technique-adapters" and method == "DELETE":
                target = self.repo.update_target_technique_adapter(project_id, parts[4], parts[6], None)
                return 200, {"target": target, "readiness": pack_readiness(parts[6], target)}
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "guardrail" and method == "GET":
                return 200, self.repo.get_guardrail(project_id, parts[4])
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "guardrail" and method in {"POST", "PATCH"}:
                values = dict(payload)
                if values.pop("derive_from_scope", False):
                    source_id = str(values.get("source_document_id") or "")
                    if not source_id:
                        scope_docs = [item for item in self.repo.list_documents(project_id) if item["kind"] == "scope"]
                        if not scope_docs:
                            raise ValueError("a scope document is required before deriving guardrails")
                        source_id = scope_docs[0]["id"]
                    document = self.repo.get_document(project_id, source_id)
                    values = {**derive_guardrail(document["content"]), "source_document_id": source_id, "status": "draft"}
                return 200, self.repo.save_guardrail(project_id, parts[4], **{key: values[key] for key in ("source_document_id", "status", "max_requests", "max_runtime_seconds", "max_consecutive_errors", "allow_active_recon", "allow_multi_turn", "max_turns_per_objective", "allow_reproduction", "reproduction_mode", "reproduction_max_attempts", "reproduction_min_successes", "reproduction_min_success_rate", "reproduction_delay_ms", "allow_screenshots", "stop_on_http_5xx", "blocked_prompt_patterns", "notes") if key in values})
            if len(parts) == 6 and parts[3] == "targets" and parts[5] == "browser-session" and method == "POST":
                target = self.repo.get_target(project_id, parts[4])
                result = self.browser_target_client.open_session(target)
                self.repo.record_audit(project_id, action="browser.session.opened", object_type="target", object_id=target["id"], outcome=result["status"], metadata={"process_id": result["process_id"]})
                return 202, result
            if len(parts) == 4 and parts[3] == "imports" and method == "POST":
                kind = str(payload.get("kind", ""))
                args = {"filename": str(payload.get("filename", "")), "content": str(payload.get("content", ""))}
                if kind == "api":
                    return 201, import_api(self.repo, project_id, **args)
                if kind == "burp":
                    return 201, import_burp(self.repo, project_id, **args)
                if kind == "nmap":
                    return 201, import_nmap(self.repo, project_id, **args)
                if kind == "inventory":
                    return 201, import_inventory(self.repo, project_id, **args)
                raise ValueError("import kind must be api, burp, nmap, or inventory")
            if len(parts) == 5 and parts[3] == "imports" and method == "GET":
                return 200, self.repo.get_import(project_id, parts[4])
            if len(parts) == 5 and parts[3] == "imports" and method == "DELETE":
                return 200, self.repo.delete_import(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "testing-tools" and method == "GET":
                return 200, {"testing_tools": self.repo.list_tool_definitions(project_id)}
            if len(parts) == 4 and parts[3] == "testing-tools" and method == "POST":
                pack_id = str(payload.get("pack_id") or "")
                target_id = str(payload.get("target_id") or "")
                pack = instantiate_tool_pack(pack_id, self.repo.get_target(project_id, target_id)) if pack_id else None
                kind = str((pack or {}).get("kind") or payload.get("kind") or "")
                definition = normalize_tool_definition(kind, (pack or {}).get("definition") or payload.get("definition"))
                return 201, self.repo.create_tool_definition(
                    project_id, target_id=target_id, kind=kind,
                    name=str(payload.get("name") or (pack or {}).get("name") or ""),
                    description=str(payload.get("description") or (pack or {}).get("description") or ""),
                    definition=definition,
                )
            if len(parts) == 5 and parts[3] == "testing-tools" and method == "GET":
                return 200, self.repo.get_tool_definition(project_id, parts[4])
            if len(parts) == 5 and parts[3] == "testing-tools" and method == "PATCH":
                existing = self.repo.get_tool_definition(project_id, parts[4])
                definition = normalize_tool_definition(existing["kind"], payload.get("definition"))
                return 200, self.repo.update_tool_definition(
                    project_id, parts[4], target_id=str(payload.get("target_id") or existing["target_id"]),
                    name=str(payload.get("name") or existing["name"]), description=str(payload.get("description") or existing["description"]), definition=definition,
                )
            if len(parts) == 5 and parts[3] == "testing-tools" and method == "DELETE":
                return 200, self.repo.delete_tool_definition(project_id, parts[4])
            if len(parts) == 6 and parts[3] == "testing-tools" and parts[5] == "runs" and method == "POST":
                saved = self.repo.get_tool_definition(project_id, parts[4])
                assert_target_runtime_ready(self.repo.get_target(project_id, saved["target_id"]))
                input_values = payload.get("input") or {}
                if not isinstance(input_values, dict):
                    raise ValueError("testing tool input must be an object")
                run = self.repo.create_tool_run(project_id, target_id=saved["target_id"], kind=saved["kind"], name=saved["name"], definition=saved["definition"], input_values=input_values, definition_id=saved["id"])
                if payload.get("background") in {True, "true", "on", "1", 1}:
                    cancel_event = threading.Event()
                    thread = threading.Thread(target=self._execute_background_tool, kwargs={"project_id": project_id, "tool_run_id": run["id"], "cancel_event": cancel_event}, daemon=True, name=f"testing-tool-{run['id']}")
                    with self._background_lock:
                        self._background_runs[run["id"]] = thread
                        self._background_cancel[run["id"]] = cancel_event
                    thread.start()
                    return 202, run
                return 201, execute_tool_run(self.repo, project_id=project_id, tool_run_id=run["id"], target_client=self.target_client)
            if len(parts) == 4 and parts[3] == "tool-runs" and method == "POST":
                kind = str(payload.get("kind") or "replay")
                if kind != "replay":
                    raise ValueError("direct testing tool runs currently accept replay definitions only")
                replay_target_id = str(payload.get("target_id") or "")
                assert_target_runtime_ready(self.repo.get_target(project_id, replay_target_id))
                definition = normalize_tool_definition(kind, payload.get("definition"))
                input_values = payload.get("input") or {}
                if not isinstance(input_values, dict):
                    raise ValueError("replay input must be an object")
                run = self.repo.create_tool_run(project_id, target_id=replay_target_id, kind=kind, name=str(payload.get("name") or "Request replay"), definition=definition, input_values=input_values)
                return 201, execute_tool_run(self.repo, project_id=project_id, tool_run_id=run["id"], target_client=self.target_client)
            if len(parts) == 5 and parts[3] == "tool-runs" and method == "GET":
                return 200, self.repo.get_tool_run(project_id, parts[4])
            if len(parts) == 6 and parts[3] == "tool-runs" and parts[5] == "cancel" and method == "POST":
                return self._request_background_cancel(project_id=project_id, execution_id=parts[4], kind="tool")
            if len(parts) == 6 and parts[3] == "tool-runs" and parts[5] == "telemetry" and method == "GET":
                detail = self.repo.get_tool_run(project_id, parts[4])
                return 200, telemetry_export(detail, execution_kind="tool")
            if len(parts) == 6 and parts[3] == "tool-runs" and parts[5] == "adjudications" and method == "GET":
                return 200, {"adjudications": self.repo.list_adjudications(project_id, execution_kind="tool", execution_id=parts[4])}
            if len(parts) == 6 and parts[3] == "tool-runs" and parts[5] == "adjudications" and method == "POST":
                return 200, self.repo.upsert_adjudication(project_id, execution_kind="tool", execution_id=parts[4], source=str(payload.get("source") or "human"), expectation_id=str(payload.get("expectation_id") or ""), expected_outcome=str(payload.get("expected_outcome") or "unknown"), observed_outcome=str(payload.get("observed_outcome") or "unknown"), classification=str(payload.get("classification") or "inconclusive"), root_cause=str(payload.get("root_cause") or "unclassified"), notes=str(payload.get("notes") or ""), metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {})
            if len(parts) == 5 and parts[3] == "tool-findings" and method == "PATCH":
                return 200, self.repo.update_tool_finding_status(project_id, parts[4], str(payload.get("status") or ""))
            if len(parts) == 4 and parts[3] == "interactions" and method == "GET":
                return 200, {"interaction_tokens": self.repo.list_interaction_tokens(project_id)}
            if len(parts) == 4 and parts[3] == "interactions" and method == "POST":
                target_id = str(payload.get("target_id") or "") or None
                return 201, self.repo.create_interaction_token(project_id, name=str(payload.get("name") or ""), target_id=target_id)
            if len(parts) == 5 and parts[3] == "interactions" and method == "GET":
                return 200, self.repo.get_interaction_token(project_id, parts[4])
            if len(parts) == 5 and parts[3] == "interactions" and method == "DELETE":
                return 200, self.repo.disable_interaction_token(project_id, parts[4])
            if len(parts) == 4 and parts[3] == "runs" and method == "POST":
                module_ids = payload.get("modules") or []
                if not isinstance(module_ids, list) or not all(isinstance(item, str) for item in module_ids):
                    raise ValueError("modules must be a list of module ids")
                whole_risk_ids = payload.get("whole_risk_ids") or []
                technique_ids = payload.get("technique_ids") or []
                objective_ids = payload.get("objective_ids") or []
                for label, value in (("whole_risk_ids", whole_risk_ids), ("technique_ids", technique_ids), ("objective_ids", objective_ids)):
                    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                        raise ValueError(f"{label} must be a list of ids")
                target_id = str(payload.get("target_id", ""))
                target_snapshot = self.repo.get_target(project_id, target_id)
                assert_target_runtime_ready(target_snapshot)
                target_capabilities = assessment_target_capabilities(target_snapshot)
                guardrail_snapshot = self.repo.get_guardrail(project_id, target_id)
                target_request_timeout = int((target_snapshot.get("transport_config") or {}).get("request_timeout_seconds") or 0)
                if target_request_timeout > int(guardrail_snapshot.get("max_runtime_seconds") or 0):
                    raise ValueError(
                        "the target per-request timeout cannot exceed the approved run maximum runtime"
                    )
                requested_turns = max(1, min(10, int(payload.get("adaptive_turns") or 1)))
                if requested_turns > 1 and (not has_conversation_continuity(target_capabilities) or not guardrail_snapshot.get("allow_multi_turn")):
                    raise ValueError("adaptive multi-turn requires guardrail permission and an explicit target-managed session, client transcript replay, or structured request-history transport")
                approved_turns = min(requested_turns, int(guardrail_snapshot.get("max_turns_per_objective") or 1))
                objectives = self.repo.get_objectives(project_id, objective_ids)
                target_proof_rule_ids = {
                    str(rule.get("id") or "")
                    for rule in (target_snapshot.get("evaluation_config") or {}).get("canaries") or []
                    if str(rule.get("id") or "")
                }
                browser_outcome_rule = (target_snapshot.get("browser_profile") or {}).get("outcome_rule") or {}
                if browser_outcome_rule.get("enabled") and str(browser_outcome_rule.get("id") or ""):
                    target_proof_rule_ids.add(str(browser_outcome_rule["id"]))
                target_proof_technique_ids = (
                    list(browser_outcome_rule.get("technique_ids") or [])
                    if browser_outcome_rule.get("enabled") and browser_outcome_rule.get("finding_evidence")
                    else []
                )
                for objective in objectives:
                    required_rule_ids = set(objective.get("proof_rule_ids") or [])
                    missing_rule_ids = sorted(required_rule_ids - target_proof_rule_ids)
                    if missing_rule_ids:
                        raise ValueError(
                            f"objective {objective['id']} requires proof rules not configured on the selected target: "
                            + ", ".join(missing_rule_ids)
                        )
                    if objective.get("require_reproduction") and not guardrail_snapshot.get("allow_reproduction"):
                        raise ValueError(f"objective {objective['id']} requires reproduction permission in the approved target guardrail")
                execution_mode = str(payload.get("execution_mode") or "combined")
                if execution_mode not in {"combined", "contracts-only"}:
                    raise ValueError("execution mode must be combined or contracts-only")
                assessment_plan = build_assessment_plan(whole_risk_ids=whole_risk_ids, technique_ids=technique_ids, objectives=objectives, legacy_module_ids=module_ids, target_capabilities=target_capabilities, evaluation_config=target_snapshot.get("evaluation_config") or {}, assessment_contracts=target_snapshot.get("assessment_contracts") or [], target_proof_technique_ids=target_proof_technique_ids, adaptive_turns=approved_turns, include_modules=execution_mode == "combined")
                self.snapshot_artifacts_for_plan(project_id, target_id, assessment_plan)
                if any(item.get("reproduce") for item in assessment_plan.get("assessment_contracts") or []) and not guardrail_snapshot.get("allow_reproduction"):
                    raise ValueError("selected Attack Surface evidence contracts require reproduction permission in the approved target guardrail")
                module_ids = assessment_plan["module_ids"]
                if not module_ids and not assessment_plan.get("assessment_contracts"):
                    raise ValueError("select at least one automated OWASP technique or configure an enabled Attack Surface evidence contract")
                recon_mode = str(payload.get("recon_mode") or "none")
                recon_profile = str(payload.get("recon_profile") or "configured")
                if recon_mode not in {"none", "bounded"}:
                    raise ValueError("recon mode must be none or bounded")
                if recon_profile not in {"configured", "attack-surface"}:
                    raise ValueError("recon profile must be configured or attack-surface")
                if recon_mode == "bounded" and not guardrail_snapshot.get("allow_active_recon"):
                    raise ValueError("bounded pre-run reconnaissance requires guardrail permission")
                assessment_plan["target_capabilities"] = target_capabilities
                assessment_plan["target_adapter_snapshot"] = {
                    "target_id": target_snapshot["id"],
                    "name": target_snapshot.get("name"),
                    "kind": target_snapshot["kind"],
                    "base_url": target_snapshot.get("base_url"),
                    "path": target_snapshot.get("path"),
                    "method": target_snapshot.get("method"),
                    "request_template": target_snapshot.get("request_template") or {},
                    "response_path": target_snapshot.get("response_path"),
                    "capabilities": target_snapshot.get("capabilities") or {},
                    "analysis_config": target_snapshot.get("analysis_config") or {},
                    "conversation_config": target_snapshot.get("conversation_config") or {},
                    "transport_config": target_snapshot.get("transport_config") or {},
                    "evaluation_config": target_snapshot.get("evaluation_config") or {},
                    "technique_adapters": target_snapshot.get("technique_adapters") or {},
                    "assessment_contracts": target_snapshot.get("assessment_contracts") or [],
                    "authorized_routes": target_snapshot.get("authorized_routes") or [],
                }
                assessment_plan["confirmation_policy"] = {
                    "mode": "minimum-proof",
                    "reproduction_attempts": int(guardrail_snapshot.get("reproduction_max_attempts") or 1) if guardrail_snapshot.get("allow_reproduction") else 0,
                    "reproduction_mode": str(guardrail_snapshot.get("reproduction_mode") or "exact-one"),
                    "minimum_successes": int(guardrail_snapshot.get("reproduction_min_successes") or 1),
                    "minimum_success_rate": float(guardrail_snapshot.get("reproduction_min_success_rate") or 1.0),
                    "stop_after_confirmed_technique": True,
                    "handoff": "human-manual-testing",
                }
                assessment_plan["guardrail"] = guardrail_snapshot
                assessment_plan["adaptive_turns"] = approved_turns
                assessment_plan["recon"] = {"mode": recon_mode, "profile": recon_profile}
                assessment_plan["reasoning_snapshot"] = self.repo.reasoning_snapshot(project_id, target_id=target_id)
                model_mode = str(payload.get("model_mode", "asus"))
                attack_profile, attack_budget = resolve_attack_settings(str(payload.get("attack_profile", "standard")), payload.get("attack_budget"))
                if payload.get("background") in {True, "true", "on", "1", 1}:
                    if model_mode not in {"asus", "asus-evaluator", "offline"}:
                        raise ValueError("model mode must be asus, asus-evaluator, or offline")
                    known_modules = {module["id"] for module in module_summaries()}
                    unknown_modules = [module_id for module_id in module_ids if module_id not in known_modules]
                    if unknown_modules:
                        raise ValueError("unknown test module: " + ", ".join(unknown_modules))
                    self.repo.assert_run_ready(project_id, target_id)
                    run = self.repo.create_run(project_id, target_id, module_ids, model_mode, attack_profile=attack_profile, attack_budget=attack_budget, assessment_plan=assessment_plan)
                    cancel_event = threading.Event()
                    thread = threading.Thread(
                        target=self._execute_background_run,
                        kwargs={"project_id": project_id, "target_id": target_id, "module_ids": module_ids, "model_mode": model_mode, "attack_profile": attack_profile, "attack_budget": attack_budget, "assessment_plan": assessment_plan, "run": run, "cancel_event": cancel_event},
                        daemon=True,
                        name=f"assessment-{run['id']}",
                    )
                    with self._background_lock:
                        self._background_runs[run["id"]] = thread
                        self._background_cancel[run["id"]] = cancel_event
                    thread.start()
                    return 202, run
                run = run_assessment(self.repo, project_id=project_id, target_id=target_id, module_ids=module_ids, model_mode=model_mode, attack_profile=attack_profile, attack_budget=attack_budget, assessment_plan=assessment_plan, model_gateway=self.model_gateway, target_client=self.target_client, browser_target_client=self.browser_target_client, evidence_store=self.evidence_store, recon_client=self.recon_client)
                return 201, run
            if len(parts) == 5 and parts[3] == "runs" and method == "GET":
                detail = self.repo.get_run_detail(project_id, parts[4])
                detail["safe_restart"] = self._safe_restart_eligibility(project_id, detail)
                detail["result_summary"] = build_run_result_summary(detail)
                return 200, detail
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "restart" and method == "POST":
                return self._restart_recorded_run(project_id, parts[4])
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "retest" and method == "POST":
                return self._create_retest_run(project_id, parts[4], payload)
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "cancel" and method == "POST":
                return self._request_background_cancel(project_id=project_id, execution_id=parts[4], kind="assessment")
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "telemetry" and method == "GET":
                detail = self.repo.get_run_detail(project_id, parts[4])
                return 200, telemetry_export(detail, execution_kind="assessment")
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "adjudications" and method == "GET":
                return 200, {"adjudications": self.repo.list_adjudications(project_id, execution_kind="assessment", execution_id=parts[4])}
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "adjudications" and method == "POST":
                return 200, self.repo.upsert_adjudication(project_id, execution_kind="assessment", execution_id=parts[4], test_case_id=str(payload.get("test_case_id") or ""), source=str(payload.get("source") or "human"), expectation_id=str(payload.get("expectation_id") or ""), expected_outcome=str(payload.get("expected_outcome") or "unknown"), observed_outcome=str(payload.get("observed_outcome") or "unknown"), classification=str(payload.get("classification") or "inconclusive"), root_cause=str(payload.get("root_cause") or "unclassified"), notes=str(payload.get("notes") or ""), metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {})
            if len(parts) == 6 and parts[3] == "runs" and parts[5] == "reevaluate" and method == "POST":
                return 200, reevaluate_stored_run(self.repo, project_id=project_id, run_id=parts[4], model_mode=str(payload.get("model_mode", "offline")), model_gateway=self.model_gateway)
            if len(parts) == 5 and parts[3] == "findings" and method == "PATCH":
                return 200, self.repo.update_finding_status(project_id, parts[4], str(payload.get("status", "")))
        raise NotFoundError("route not found")


class RequestHandler(BaseHTTPRequestHandler):
    server_version = USER_AGENT

    @property
    def application(self) -> Application:
        return self.server.application  # type: ignore[attr-defined]

    def _send_release_headers(self) -> None:
        self.send_header("X-AdverScope-Version", PRODUCT_VERSION)
        self.send_header("X-AdverScope-API-Contract", API_CONTRACT_VERSION)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if bool(getattr(self.server, "tls_enabled", False)):
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _authorized(self) -> bool:
        required = str(getattr(self.server, "access_token", "") or "")
        if not required:
            return True
        supplied = str(self.headers.get("Authorization") or "")
        prefix = "Bearer "
        candidate = supplied[len(prefix):] if supplied.startswith(prefix) else ""
        if candidate and hmac.compare_digest(candidate, required):
            return True
        body = b'{"error":"authentication required"}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("WWW-Authenticate", 'Bearer realm="AdverScope"')
        self._send_release_headers()
        self.end_headers()
        self.wfile.write(body)
        return False

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_release_headers()
        self.end_headers()
        self.wfile.write(body)

    def _payload(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("request body must be a JSON object")
        return parsed

    def _record_interaction(self) -> bool:
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2 or parts[0] != "interactions":
            return False
        token = parts[1]
        length = int(self.headers.get("Content-Length", "0"))
        if length > 200_000:
            self._send_json(413, {"error": "interaction body is too large"})
            return True
        raw = self.rfile.read(length) if length else b""
        body = raw.decode("utf-8", errors="replace")
        event = self.application.repo.record_interaction(
            token,
            method=self.command,
            path=self.path,
            source=str(self.client_address[0] if self.client_address else ""),
            headers={str(key): str(value) for key, value in self.headers.items()},
            body=body,
        )
        if event is None:
            self._send_json(404, {"error": "interaction token not found or disabled"})
        else:
            self._send_json(200, {"ok": True, "recorded_at": event["created_at"]})
        return True

    def _upload_artifact(self) -> bool:
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 4 or parts[:2] != ["api", "projects"] or parts[3] != "artifacts":
            return False
        try:
            values = parse_qs(parsed.query, keep_blank_values=True)
            target_id = str((values.get("target_id") or [""])[0])
            kind = str((values.get("kind") or [""])[0])
            filename = str((values.get("filename") or [""])[0])
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_ARTIFACT_BYTES:
                self.close_connection = True
                self._send_json(413, {"error": f"artifact upload exceeds the {MAX_ARTIFACT_BYTES} byte limit"})
                return True
            artifact = self.application.upload_artifact_stream(
                project_id=parts[2],
                target_id=target_id,
                filename=filename,
                kind=kind,
                mime_type=str(self.headers.get("Content-Type") or "application/octet-stream").split(";", 1)[0],
                stream=self.rfile,
                content_length=length,
            )
            self._send_json(201, artifact)
        except NotFoundError as exc:
            self._send_json(404, {"error": str(exc)})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._send_json(500, {"error": safe_error(exc)})
        return True

    def _upload_project_transfer(self) -> bool:
        parsed = urlparse(self.path)
        if parsed.path != "/api/project-transfers":
            return False
        temporary: Path | None = None
        try:
            values = parse_qs(parsed.query, keep_blank_values=True)
            acknowledge = str((values.get("acknowledge_sensitive") or [""])[0]).casefold() in {"1", "true", "yes"}
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                raise ValueError("project transfer upload is empty")
            if length > MAX_ARCHIVE_BYTES:
                self.close_connection = True
                self._send_json(413, {"error": "project transfer exceeds the supported archive size"})
                return True
            upload_root = Path(self.application.config.database_path).parent / "tmp"
            upload_root.mkdir(parents=True, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(prefix="project-transfer-", suffix=".zip", dir=upload_root, delete=False)
            temporary = Path(handle.name)
            remaining = length
            try:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("project transfer upload ended before Content-Length bytes were received")
                    handle.write(chunk)
                    remaining -= len(chunk)
            finally:
                handle.close()
            result = self.application.import_project_transfer(temporary, acknowledge_sensitive=acknowledge)
            self._send_json(201, result)
        except NotFoundError as exc:
            self._send_json(404, {"error": str(exc)})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._send_json(500, {"error": safe_error(exc)})
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return True

    def do_GET(self) -> None:
        if not self._authorized():
            return
        parsed = urlparse(self.path)
        if parsed.path.startswith("/interactions/") and self._record_interaction():
            return
        if parsed.path == "/" or parsed.path == "/index.html":
            self._send_file(STATIC_DIR / "index.html")
            return
        if parsed.path.startswith("/static/"):
            requested = (STATIC_DIR / parsed.path.removeprefix("/static/")).resolve()
            if STATIC_DIR.resolve() not in requested.parents:
                self._send_json(404, {"error": "not found"})
            else:
                self._send_file(requested)
            return
        parts = [part for part in parsed.path.split("/") if part]
        if parsed.path == "/api/local-backup":
            temporary: Path | None = None
            try:
                query = parse_qs(parsed.query)
                acknowledge = str((query.get("acknowledge_sensitive") or [""])[0]).casefold() in {"1", "true", "yes"}
                include_sessions = str((query.get("include_browser_sessions") or [""])[0]).casefold() in {"1", "true", "yes"}
                output_root = Path(self.application.config.database_path).parent / "tmp"
                output_root.mkdir(parents=True, exist_ok=True)
                temporary = output_root / f"adverscope-local-backup-{int(time.time())}-{uuid.uuid4().hex[:8]}.zip"
                result = self.application.professional_local_backup(
                    temporary,
                    acknowledge_sensitive=acknowledge,
                    include_browser_sessions=include_sessions,
                )
                self._send_download_file(
                    temporary,
                    filename=f"adverscope-local-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip",
                )
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"error": safe_error(exc)})
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            return
        if len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "transfer":
            temporary = None
            try:
                query = parse_qs(parsed.query)
                acknowledge = str((query.get("acknowledge_sensitive") or [""])[0]).casefold() in {"1", "true", "yes"}
                include_sessions = str((query.get("include_browser_sessions") or [""])[0]).casefold() in {"1", "true", "yes"}
                output_root = Path(self.application.config.database_path).parent / "tmp"
                output_root.mkdir(parents=True, exist_ok=True)
                temporary = output_root / f"{parts[2]}-{uuid.uuid4().hex[:8]}.zip"
                self.application.professional_project_transfer(
                    parts[2],
                    temporary,
                    acknowledge_sensitive=acknowledge,
                    include_browser_sessions=include_sessions,
                )
                self._send_download_file(temporary, filename=f"{parts[2]}.advscope-project.zip")
            except NotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"error": safe_error(exc)})
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            return
        if len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "evidence-bundle":
            try:
                query = parse_qs(parsed.query)
                mode = str((query.get("mode") or ["redacted"])[0])
                run_id = str((query.get("run_id") or [""])[0]).strip() or None
                acknowledge = str((query.get("acknowledge_sensitive") or [""])[0]).casefold() in {"1", "true", "yes"}
                result = self.application.professional_evidence_bundle(
                    parts[2],
                    run_id=run_id,
                    mode=mode,
                    acknowledge_sensitive=acknowledge,
                )
                self._send_download_bytes(
                    result["content"],
                    filename=str(result["filename"]),
                    content_type="application/zip",
                )
            except NotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"error": safe_error(exc)})
            return
        if len(parts) == 6 and parts[:2] == ["api", "projects"] and parts[3] == "evidence-assets" and parts[5] == "content":
            try:
                self._send_file(self.application.evidence_asset_path(parts[2], parts[4]), cache_control="private, no-store")
            except NotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
            except ValueError:
                self._send_json(404, {"error": "not found"})
            return
        self._dispatch("GET")

    def do_POST(self) -> None:
        if not self._authorized():
            return
        if urlparse(self.path).path.startswith("/interactions/") and self._record_interaction():
            return
        if self._upload_artifact():
            return
        if self._upload_project_transfer():
            return
        self._dispatch("POST")

    def do_PATCH(self) -> None:
        if not self._authorized():
            return
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        if not self._authorized():
            return
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        try:
            payload = self._payload() if method in {"POST", "PATCH"} else None
            status, result = self.application.dispatch(method, self.path, payload)
            self._send_json(status, result)
        except NotFoundError as exc:
            self._send_json(404, {"error": str(exc)})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # keep internal details redacted from the client
            self._send_json(500, {"error": safe_error(exc)})

    def _send_file(self, path: Path, *, cache_control: str = "no-cache") -> None:
        if not path.is_file():
            self._send_json(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Cache-Control", cache_control)
        self._send_release_headers()
        self.end_headers()
        with path.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile, length=1024 * 1024)

    def _send_download_file(self, path: Path, *, filename: str, content_type: str = "application/zip") -> None:
        if not path.is_file():
            self._send_json(404, {"error": "not found"})
            return
        safe_filename = Path(filename.replace("\\", "/")).name.replace('"', "")[:180] or "adverscope-export.bin"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Cache-Control", "private, no-store")
        self._send_release_headers()
        self.end_headers()
        with path.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile, length=1024 * 1024)

    def _send_download_bytes(self, body: bytes, *, filename: str, content_type: str) -> None:
        safe_filename = Path(filename.replace("\\", "/")).name.replace('"', "")[:180] or "adverscope-export.bin"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self._send_release_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep request logs useful without echoing request bodies or headers.
        try:
            print(f"{self.command} {self.path} - {format % args}")
        except (OSError, ValueError):
            # A detached Windows launcher can leave stdout without a valid
            # console handle. Access logging must never turn a valid API
            # response into HTTP 500 merely because that optional sink closed.
            pass


def create_server(
    application: Application,
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    access_token: str = "",
    tls_cert_path: str = "",
    tls_key_path: str = "",
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), RequestHandler)
    server.application = application  # type: ignore[attr-defined]
    server.access_token = access_token  # type: ignore[attr-defined]
    server.tls_enabled = bool(tls_cert_path and tls_key_path)  # type: ignore[attr-defined]
    if bool(tls_cert_path) != bool(tls_key_path):
        server.server_close()
        raise ValueError("both TLS certificate and private key are required")
    if tls_cert_path and tls_key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=tls_cert_path, keyfile=tls_key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def run_server(config: AppConfig | None = None) -> None:
    config = config or AppConfig.from_env()
    runtime_lock = RuntimeLock(runtime_lock_path(config.database_path, config.port), port=config.port)
    runtime_lock.acquire()
    application: Application | None = None
    server: ThreadingHTTPServer | None = None
    try:
        from .deployment_security import validate_serve_security

        deployment = validate_serve_security(config)
        access_token = os.environ.get(config.remote_access_token_env, "") if deployment["authentication"] else ""
        recover_interrupted_restore(config)
        application = Application(Repository(config.database_path), config=config)
        server = create_server(
            application,
            config.host,
            config.port,
            access_token=access_token,
            tls_cert_path=config.tls_cert_path if deployment["tls"] else "",
            tls_key_path=config.tls_key_path if deployment["tls"] else "",
        )
        scheme = "https" if deployment["tls"] else "http"
        print(f"AdverScope listening on {scheme}://{config.host}:{config.port} ({deployment['mode']})")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.server_close()
        if application is not None:
            application.close()
            application.repo.close()
        runtime_lock.release()
