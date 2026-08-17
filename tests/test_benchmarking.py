from __future__ import annotations

import json
from pathlib import Path
import unittest

from osai_security.benchmarking import BenchmarkConfigurationError, score_benchmark, score_expectation, validate_benchmark_definition


def configured_project() -> dict:
    return {
        "id": "proj_fixture",
        "name": "Independent benchmark fixture",
        "objectives": [{"id": "obj_boundary", "title": "Confirm protected boundary failure", "require_reproduction": True}],
    }


def assessment_run(*, achieved: bool = True, reproduced: bool = True, status: str = "vulnerable") -> dict:
    return {
        "id": "run_fixture",
        "project_id": "proj_fixture",
        "status": "completed",
        "test_cases": [{
            "id": "case_fixture",
            "status": status,
            "evaluation": {
                "attack_variant_id": "module:secure-control",
                "objective_results": [{"objective_id": "obj_boundary", "achieved": achieved}],
            },
            "trace": {
                "transport": {"request_sent": True, "response_received": True},
                "extraction": {"completed": True},
                "evaluation": {"completed": status != "error"},
                "reproduction": {"status": "confirmed" if reproduced else "not-reproduced"},
            },
            "diagnostic": {"root_cause": "none"},
        }],
        "findings": [],
    }


def tool_run() -> dict:
    return {
        "id": "toolrun_fixture",
        "project_id": "proj_fixture",
        "status": "completed",
        "context": {"all_required_assertions_passed": True},
        "security_findings": [{"outcome_id": "verified-effect", "status": "accepted", "confirmation": "reproduction"}],
    }


def assessment_finding_run(*, finding_status: str = "accepted", reproduced: bool = True, case_status: str = "vulnerable", technique_id: str = "LLM01-INDIRECT") -> dict:
    run = assessment_run(achieved=False, reproduced=reproduced, status=case_status)
    case = run["test_cases"][0]
    case["evaluation"]["owasp_technique_ids"] = [technique_id]
    run["findings"] = [] if case_status != "vulnerable" else [{
        "id": "find_fixture",
        "run_id": run["id"],
        "test_case_id": case["id"],
        "status": finding_status,
        "occurrences": [{"run_id": run["id"], "test_case_id": case["id"]}],
        "validations": [{
            "run_id": run["id"],
            "test_case_id": case["id"],
            "status": "confirmed" if reproduced else "not-reproduced",
        }],
    }]
    return run


class BenchmarkingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.campaign = {
            "schema_version": 1,
            "suite_id": "independent-suite",
            "campaign_id": "campaign-1",
            "projects": {"fixture": {"project_id": "proj_fixture", "project_name": "Independent benchmark fixture", "assessment_run_ids": ["run_fixture"], "tool_run_ids": ["toolrun_fixture"]}},
        }
        self.oracle = {
            "schema_version": 1,
            "suite_id": "independent-suite",
            "projects": {"fixture": {"title": "Fixture", "expectations": [
                {"id": "boundary", "title": "Boundary", "expected_outcome": "vulnerable", "observations": [{"kind": "objective", "objective_title": "Confirm protected boundary failure", "require_reproduction": True}]},
                {"id": "effect", "title": "Verified effect", "expected_outcome": "vulnerable", "observations": [{"kind": "tool_finding", "outcome_id": "verified-effect", "accepted_statuses": ["accepted"]}]},
                {"id": "control", "title": "Secure control", "expected_outcome": "secure", "observations": [{"kind": "case", "variant_id": "module:secure-control", "require_reproduction": True}]},
            ]}},
        }

    def test_definition_enforces_oracle_campaign_separation(self) -> None:
        self.assertEqual(validate_benchmark_definition(self.campaign, self.oracle), [])
        self.campaign["projects"]["fixture"]["expected_outcome"] = "vulnerable"
        self.oracle["projects"]["fixture"]["expectations"][0]["observations"][0]["payload"] = "not allowed"
        errors = validate_benchmark_definition(self.campaign, self.oracle)
        self.assertTrue(any("oracle fields" in item for item in errors))
        self.assertTrue(any("unsupported fields" in item for item in errors))

    def test_definition_accepts_technique_mapped_assessment_finding(self) -> None:
        oracle = json.loads(json.dumps(self.oracle))
        oracle["projects"]["fixture"]["expectations"] = [{
            "id": "native-finding",
            "title": "Native finding",
            "expected_outcome": "vulnerable",
            "observations": [{
                "kind": "assessment_finding",
                "technique_id": "LLM01-INDIRECT",
                "accepted_statuses": ["accepted", "fixed"],
                "require_reproduction": True,
            }],
        }]
        self.assertEqual([], validate_benchmark_definition(self.campaign, oracle))

    def test_portswigger_target_campaign_preserves_oracle_separation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        campaign = json.loads((root / "validation" / "portswigger" / "campaign-target-apps-2026-08-08.json").read_text(encoding="utf-8"))
        oracle = json.loads((root / "validation" / "portswigger" / "oracle-target-apps.json").read_text(encoding="utf-8"))
        self.assertEqual([], validate_benchmark_definition(campaign, oracle))
        self.assertEqual(4, len(campaign["projects"]))
        self.assertEqual(4, len(oracle["projects"]))

    def test_score_combines_objective_tool_proof_and_secure_control(self) -> None:
        run = assessment_run(achieved=True, reproduced=True, status="safe")
        result = score_benchmark(
            self.campaign,
            self.oracle,
            project_loader=lambda _project_id: configured_project(),
            assessment_loader=lambda _project_id, _run_id: run,
            tool_loader=lambda _project_id, _run_id: tool_run(),
        )
        self.assertEqual(result["summary"]["classifications"], {"true_negative": 1, "true_positive": 2})
        self.assertEqual(result["summary"]["precision"], 1.0)
        self.assertEqual(result["summary"]["recall"], 1.0)
        self.assertEqual(result["summary"]["reproduction_required"], 2)
        self.assertEqual(result["summary"]["reproduction_confirmed"], 2)
        self.assertEqual(result["summary"]["reproduction_rate"], 1.0)
        control = next(item for item in result["rows"][0]["expectations"] if item["id"] == "control")
        self.assertEqual(control["classification"], "true_negative")
        self.assertEqual(control["root_cause"], "none")

    def test_secure_observation_retains_failure_stage_only_when_it_is_a_false_negative(self) -> None:
        expectation = self.oracle["projects"]["fixture"]["expectations"][0]
        result = score_expectation(
            configured_project(),
            [assessment_run(achieved=False, reproduced=False, status="safe")],
            [],
            expectation,
        )
        self.assertEqual(result["classification"], "false_negative")
        self.assertEqual(result["root_cause"], "payload_generation")

    def test_unreproduced_objective_is_inconclusive_not_confirmed(self) -> None:
        expectation = self.oracle["projects"]["fixture"]["expectations"][0]
        result = score_expectation(configured_project(), [assessment_run(achieved=True, reproduced=False)], [], expectation)
        self.assertEqual(result["classification"], "inconclusive")
        self.assertEqual(result["root_cause"], "reproduction")

        one_expectation_oracle = {
            "schema_version": 1,
            "suite_id": "independent-suite",
            "projects": {"fixture": {"expectations": [expectation]}},
        }
        one_run_campaign = {
            "schema_version": 1,
            "suite_id": "independent-suite",
            "campaign_id": "campaign-inconclusive",
            "projects": {"fixture": {"project_id": "proj_fixture", "assessment_run_ids": ["run_fixture"], "tool_run_ids": []}},
        }
        score = score_benchmark(
            one_run_campaign,
            one_expectation_oracle,
            project_loader=lambda _project_id: configured_project(),
            assessment_loader=lambda _project_id, _run_id: assessment_run(achieved=True, reproduced=False),
            tool_loader=lambda _project_id, _run_id: {},
        )
        self.assertEqual(score["summary"]["recall"], 0.0)
        self.assertEqual(score["summary"]["reproduction_required"], 1)
        self.assertEqual(score["summary"]["reproduction_confirmed"], 0)
        self.assertEqual(score["summary"]["reproduction_rate"], 0.0)

    def test_accepted_reproduced_assessment_finding_is_confirmed_by_technique(self) -> None:
        expectation = {
            "id": "native-finding",
            "title": "Native finding",
            "expected_outcome": "vulnerable",
            "observations": [{
                "kind": "assessment_finding",
                "technique_id": "LLM01-INDIRECT",
                "accepted_statuses": ["accepted"],
                "require_reproduction": True,
            }],
        }
        result = score_expectation(configured_project(), [assessment_finding_run()], [], expectation)
        self.assertEqual("true_positive", result["classification"])
        self.assertTrue(result["reproduction_confirmed"])

    def test_unreproduced_assessment_finding_is_inconclusive(self) -> None:
        expectation = {
            "id": "native-finding",
            "title": "Native finding",
            "expected_outcome": "vulnerable",
            "observations": [{
                "kind": "assessment_finding",
                "technique_id": "LLM01-INDIRECT",
                "accepted_statuses": ["accepted"],
                "require_reproduction": True,
            }],
        }
        result = score_expectation(
            configured_project(),
            [assessment_finding_run(reproduced=False)],
            [],
            expectation,
        )
        self.assertEqual("inconclusive", result["classification"])
        self.assertEqual("reproduction", result["root_cause"])

    def test_assessment_finding_observation_requires_the_expected_technique_mapping(self) -> None:
        expectation = {
            "id": "native-control",
            "title": "Native control",
            "expected_outcome": "secure",
            "observations": [{
                "kind": "assessment_finding",
                "technique_id": "LLM01-INDIRECT",
                "accepted_statuses": ["accepted"],
                "require_reproduction": True,
            }],
        }
        secure = assessment_finding_run(case_status="safe")
        result = score_expectation(configured_project(), [secure], [], expectation)
        self.assertEqual("true_negative", result["classification"])

        differently_mapped = assessment_finding_run(technique_id="LLM01-DIRECT")
        result = score_expectation(configured_project(), [differently_mapped], [], expectation)
        self.assertEqual("inconclusive", result["classification"])
        self.assertEqual("planner_coverage", result["root_cause"])

    def test_case_level_confirmation_does_not_confirm_an_unreproduced_sibling_objective(self) -> None:
        project = configured_project()
        project["objectives"].append({
            "id": "obj_sibling",
            "title": "Confirm sibling boundary failure",
            "require_reproduction": True,
        })
        run = assessment_run(achieved=True, reproduced=True)
        test_case = run["test_cases"][0]
        test_case["evaluation"]["objective_results"].append({
            "objective_id": "obj_sibling",
            "achieved": True,
        })
        test_case["evaluation"]["objective_reproductions"] = [{
            "status": "partial",
            "required_objective_ids": ["obj_boundary", "obj_sibling"],
            "reproduced_objective_ids": ["obj_boundary"],
        }]
        test_case["trace"]["reproduction"].update({
            "objective_ids": ["obj_boundary", "obj_sibling"],
            "reproduced_objective_ids": ["obj_boundary"],
        })
        sibling_expectation = {
            "id": "sibling",
            "title": "Sibling boundary",
            "expected_outcome": "vulnerable",
            "observations": [{
                "kind": "objective",
                "objective_title": "Confirm sibling boundary failure",
                "require_reproduction": True,
            }],
        }
        result = score_expectation(project, [run], [], sibling_expectation)
        self.assertEqual("inconclusive", result["classification"])
        self.assertEqual("reproduction", result["root_cause"])

        primary_expectation = self.oracle["projects"]["fixture"]["expectations"][0]
        primary = score_expectation(project, [run], [], primary_expectation)
        self.assertEqual("true_positive", primary["classification"])

    def test_extraction_failure_is_an_infrastructure_error_with_stage(self) -> None:
        run = assessment_run(achieved=False, reproduced=False, status="error")
        run["test_cases"][0]["trace"]["extraction"]["completed"] = False
        expectation = self.oracle["projects"]["fixture"]["expectations"][0]
        result = score_expectation(configured_project(), [run], [], expectation)
        self.assertEqual(result["classification"], "infrastructure_error")
        self.assertEqual(result["root_cause"], "response_parser")

    def test_cross_project_execution_is_rejected(self) -> None:
        run = assessment_run()
        run["project_id"] = "proj_other"
        with self.assertRaises(BenchmarkConfigurationError):
            score_benchmark(
                self.campaign,
                self.oracle,
                project_loader=lambda _project_id: configured_project(),
                assessment_loader=lambda _project_id, _run_id: run,
                tool_loader=lambda _project_id, _run_id: tool_run(),
            )


if __name__ == "__main__":
    unittest.main()
