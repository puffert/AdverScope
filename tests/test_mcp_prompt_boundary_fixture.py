from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from osai_security.db import Repository
from osai_security.engine import run_assessment
from osai_security.evaluation_profiles import evaluation_readiness, validate_evaluation_config
from osai_security.evidence_store import EvidenceStore
from osai_security.mcp_prompt_boundary_fixture import (
    MCPPromptBoundaryFixtureServer,
    PROTECTED_PROMPT,
    PUBLIC_PROMPT,
)
from osai_security.owasp import build_assessment_plan
from osai_security.targets import TargetClient


TECHNIQUES = ["LLM03-MCP-INVENTORY", "LLM02-MCP-PROMPT"]


def prompt_profile(transport: str) -> dict:
    return validate_evaluation_config({
        "mcp": {
            "enabled": True,
            "transport": transport,
            "endpoint_path": "/mcp",
            "legacy_sse_path": "/sse" if transport == "legacy-http-sse" else "",
            "protocol_versions": ["2024-11-05"] if transport == "legacy-http-sse" else ["2025-11-25"],
            "max_pages": 5,
            "identities": [{"id": "restricted-reader", "headers": {"X-MCP-Identity": "restricted-reader"}}],
            "cases": [
                {
                    "id": "prompt-inventory",
                    "title": "Approved MCP prompt inventory",
                    "scenario": "inventory-integrity",
                    "identity_id": "restricted-reader",
                    "technique_id": "LLM03-MCP-INVENTORY",
                    "required_prompts": [PUBLIC_PROMPT],
                    "forbidden_prompts": [PROTECTED_PROMPT],
                    "impact": "read-only",
                    "emission_is_violation": True,
                    "severity": "high",
                },
                {
                    "id": "protected-prompt",
                    "title": "Protected MCP prompt retrieval",
                    "scenario": "unauthorized-prompt-get",
                    "identity_id": "restricted-reader",
                    "technique_id": "LLM02-MCP-PROMPT",
                    "prompt_name": PROTECTED_PROMPT,
                    "prompt_arguments": {"case_id": "synthetic-qualification-case"},
                    "action_assertions": [
                        {"path": "result._meta.authorization.outcome", "operator": "equals", "expected": "allowed"},
                        {"path": "result._meta.caller_identity", "operator": "equals", "expected": "restricted-reader"},
                        {"path": "result._meta.classification", "operator": "equals", "expected": "confidential"},
                        {"path": "result._meta.prompt_name", "operator": "equals", "expected": PROTECTED_PROMPT},
                    ],
                    "approved_execution": True,
                    "impact": "read-only",
                    "emission_is_violation": True,
                    "severity": "high",
                },
            ],
        }
    })


def run_fixture(root: Path, server: MCPPromptBoundaryFixtureServer, transport: str) -> tuple[Repository, dict]:
    repo = Repository(root / "assessment.sqlite3")
    project = repo.create_project(name="MCP prompt boundary", client="AdverScope Qualification")
    repo.add_document(project["id"], kind="scope", filename="scope.md", content="Authorized local prompt fixture; read-only list/get and one reproduction are allowed.")
    repo.add_document(project["id"], kind="policy", filename="policy.md", content="The restricted identity must not discover or retrieve the protected prompt.")
    config = prompt_profile(transport)
    routes = [{"path": "/mcp", "methods": ["POST"], "role": "mcp-endpoint"}]
    if transport == "legacy-http-sse":
        routes.extend([
            {"path": "/sse", "methods": ["GET"], "role": "legacy-mcp-sse"},
            {"path": "/messages", "methods": ["POST"], "role": "legacy-mcp-messages"},
        ])
    target = repo.add_target(
        project["id"],
        name="Prompt fixture",
        kind="chatbot",
        base_url=server.base_url,
        path="/mcp",
        method="POST",
        request_template={"message": "{{prompt}}"},
        response_path="",
        capabilities={"mcp": True, "chat_prompt_adapter": False},
        evaluation_config=config,
        authorized_routes=routes,
        scope_confirmed=True,
    )
    guardrail = repo.save_guardrail(
        project["id"], target["id"], status="approved", max_requests=120, max_runtime_seconds=120,
        max_consecutive_errors=3, allow_active_recon=False, allow_multi_turn=False,
        max_turns_per_objective=1, allow_reproduction=True, allow_screenshots=False, stop_on_http_5xx=True,
    )
    capabilities = {**target["capabilities"], **evaluation_readiness(config)}
    plan = build_assessment_plan(technique_ids=TECHNIQUES, target_capabilities=capabilities, evaluation_config=config)
    plan.update({"guardrail": guardrail, "target_capabilities": capabilities, "adaptive_turns": 1, "recon": {"mode": "none", "profile": "configured"}})
    run = run_assessment(
        repo,
        project_id=project["id"],
        target_id=target["id"],
        module_ids=plan["module_ids"],
        model_mode="offline",
        model_gateway=object(),
        target_client=TargetClient(timeout_seconds=5),
        browser_target_client=object(),
        evidence_store=EvidenceStore(root / "projects"),
        attack_budget=2,
        assessment_plan=plan,
    )
    return repo, repo.get_run_detail(project["id"], run["id"])


class MCPPromptBoundaryFixtureTests(unittest.TestCase):
    def test_current_and_legacy_secure_vulnerable_controls(self) -> None:
        for transport in ("streamable-http", "legacy-http-sse"):
            for mode in ("secure", "vulnerable"):
                with self.subTest(transport=transport, mode=mode), MCPPromptBoundaryFixtureServer(mode, transport) as server, tempfile.TemporaryDirectory() as directory:
                    repo, detail = run_fixture(Path(directory), server, transport)
                    try:
                        statuses = {case["evaluation"]["owasp_technique_ids"][0]: case["status"] for case in detail["test_cases"]}
                        expected = "safe" if mode == "secure" else "vulnerable"
                        self.assertEqual(statuses, {technique: expected for technique in TECHNIQUES})
                        self.assertEqual(len(detail["findings"]), 0 if mode == "secure" else 1)
                        if mode == "vulnerable":
                            prompt_case = next(case for case in detail["test_cases"] if case["evaluation"]["owasp_technique_ids"] == ["LLM02-MCP-PROMPT"])
                            self.assertEqual(prompt_case["evaluation"]["mcp_execution"]["action_method"], "prompts/get")
                            self.assertTrue(prompt_case["evaluation"]["automation_validation"]["policy"]["action_assertions_satisfied"])
                            self.assertEqual(detail["metrics"]["reproduction_rate"], 1.0)
                    finally:
                        repo.close()

    def test_prompt_get_requires_exact_assertions_and_approval(self) -> None:
        profile = {
            "mcp": {
                "enabled": True,
                "endpoint_path": "/mcp",
                "protocol_versions": ["2025-11-25"],
                "identities": [{"id": "reader", "headers": {}}],
                "cases": [{
                    "id": "prompt",
                    "title": "Prompt",
                    "scenario": "unauthorized-prompt-get",
                    "identity_id": "reader",
                    "prompt_name": PROTECTED_PROMPT,
                    "approved_execution": True,
                    "impact": "read-only",
                    "emission_is_violation": True,
                }],
            }
        }
        with self.assertRaisesRegex(ValueError, "requires target-owned action_assertions"):
            validate_evaluation_config(profile)


if __name__ == "__main__":
    unittest.main()
