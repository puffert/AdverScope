from __future__ import annotations

import unittest

from osai_security.modules import ATTACK_CATALOG_VERSION, get_module
from osai_security.owasp import build_assessment_plan, build_coverage, public_taxonomy
from osai_security.tool_engine import normalize_tool_definition


class OwaspMappingTests(unittest.TestCase):
    def test_whole_risk_expands_executable_and_visible_coverage_gaps(self) -> None:
        plan = build_assessment_plan(whole_risk_ids=["LLM01"])
        self.assertEqual(plan["taxonomy_version"], "2025")
        self.assertEqual(plan["module_ids"], ["prompt-injection"])
        self.assertIn("LLM01-DIRECT", plan["executable_technique_ids"])
        self.assertIn("LLM01-PERSONA", plan["executable_technique_ids"])
        self.assertIn("LLM01-SUFFIX", plan["executable_technique_ids"])
        self.assertIn("LLM01-INDIRECT", plan["unsupported_technique_ids"])
        self.assertIn("LLM01-MULTIMODAL", plan["unsupported_technique_ids"])

    def test_fine_grained_selection_limits_module_strategies(self) -> None:
        plan = build_assessment_plan(technique_ids=["LLM02-PII"])
        self.assertEqual(plan["module_ids"], ["sensitive-disclosure"])
        self.assertEqual(plan["selected_risk_ids"], ["LLM02"])
        self.assertEqual(plan["selected_technique_ids"], ["LLM02-PII"])
        self.assertEqual(plan["strategy_filters"]["sensitive-disclosure"], ["personal data extraction", "multi-record aggregation", "memory recall", "trusted colleague impersonation"])
        aggregate = next(
            item for item in get_module("sensitive-disclosure").offline_attacks
            if item["strategy"] == "multi-record aggregation"
        )
        self.assertIn("at least three distinct", aggregate["prompt"].lower())
        self.assertNotIn("aigoat", aggregate["prompt"].lower())

    def test_direct_injection_includes_a_canonical_previous_instruction_baseline(self) -> None:
        plan = build_assessment_plan(technique_ids=["LLM01-DIRECT"])
        self.assertIn("canonical hierarchy override", plan["strategy_filters"]["prompt-injection"])
        self.assertIn("explicit context replacement", plan["strategy_filters"]["prompt-injection"])
        attack = next(
            item for item in get_module("prompt-injection").offline_attacks
            if item["strategy"] == "canonical hierarchy override"
        )
        self.assertIn("ignore previous instructions", attack["prompt"].lower())
        context_attack = next(
            item for item in get_module("prompt-injection").offline_attacks
            if item["strategy"] == "explicit context replacement"
        )
        self.assertIn("ignore the context above", context_attack["prompt"].lower())
        self.assertIn("replace the context", context_attack["prompt"].lower())
        self.assertNotIn("aigoat", context_attack["prompt"].lower())
        self.assertEqual("2026.08.15", ATTACK_CATALOG_VERSION)

    def test_persona_hijacking_is_fine_grained_generic_and_provenance_safe(self) -> None:
        plan = build_assessment_plan(technique_ids=["LLM01-PERSONA"])
        self.assertEqual(["prompt-injection"], plan["module_ids"])
        self.assertEqual(["LLM01-PERSONA"], plan["executable_technique_ids"])
        self.assertEqual(
            ["persona replacement", "developer-mode adoption", "dan-mode substitution", "unrestricted-role simulation"],
            plan["strategy_filters"]["prompt-injection"],
        )
        attacks = [
            attack for attack in get_module("prompt-injection").offline_attacks
            if attack["strategy"] in plan["strategy_filters"]["prompt-injection"]
        ]
        self.assertEqual(4, len(attacks))
        combined = " ".join(attack["prompt"] for attack in attacks).casefold()
        self.assertNotIn("cracky", combined)
        self.assertNotIn("aigoat", combined)
        self.assertNotIn("developer mode enabled", combined)
        self.assertNotIn("dan mode activated", combined)

    def test_split_payload_requires_capability_and_two_approved_turns(self) -> None:
        unavailable = build_assessment_plan(whole_risk_ids=["LLM01"], target_capabilities={"multi_turn": True})
        self.assertIn("LLM01-SPLIT", unavailable["unsupported_technique_ids"])
        with self.assertRaisesRegex(ValueError, "no executable techniques"):
            build_assessment_plan(technique_ids=["LLM01-SPLIT"], target_capabilities={"multi_turn": True}, adaptive_turns=2)
        available = build_assessment_plan(technique_ids=["LLM01-SPLIT"], target_capabilities={"multi_turn": True, "transcript_replay": True}, adaptive_turns=2)
        self.assertEqual(["prompt-injection"], available["module_ids"])
        self.assertEqual(["LLM01-SPLIT"], available["executable_technique_ids"])
        self.assertEqual(["payload split priming"], available["strategy_filters"]["prompt-injection"])

    def test_crescendo_requires_five_approved_turns(self) -> None:
        unavailable = build_assessment_plan(whole_risk_ids=["LLM01"], target_capabilities={"multi_turn": True}, adaptive_turns=4)
        self.assertIn("LLM01-CRESCENDO", unavailable["unsupported_technique_ids"])
        available = build_assessment_plan(technique_ids=["LLM01-CRESCENDO"], target_capabilities={"multi_turn": True, "memory": True}, adaptive_turns=5)
        self.assertEqual(["prompt-injection"], available["module_ids"])
        self.assertEqual(["LLM01-CRESCENDO"], available["executable_technique_ids"])
        self.assertEqual(["crescendo priming"], available["strategy_filters"]["prompt-injection"])

    def test_objectives_define_success_without_silently_selecting_coverage(self) -> None:
        objective = {"id": "obj_key", "title": "Extract key", "success_criteria": "Exact key is returned", "risk_ids": ["LLM02"], "technique_ids": ["LLM02-SECRETS"]}
        plan = build_assessment_plan(objectives=[objective])
        self.assertEqual(plan["module_ids"], [])
        self.assertEqual(plan["selected_technique_ids"], [])
        self.assertEqual(plan["objectives"][0]["success_criteria"], "Exact key is returned")

    def test_unexecuted_and_unsupported_techniques_are_not_passes(self) -> None:
        coverage = build_coverage([])
        prompt_injection = next(item for item in coverage["risks"] if item["id"] == "LLM01")
        excessive_agency = next(item for item in coverage["risks"] if item["id"] == "LLM06")
        self.assertEqual(prompt_injection["status"], "not_tested")
        self.assertEqual(excessive_agency["status"], "needs_configuration")
        self.assertNotIn("pass", {item["status"] for item in coverage["risks"]})

    def test_remaining_owasp_controls_are_conditionally_automatable_by_target_contract(self) -> None:
        technique_capabilities = {
            "LLM01-MULTIMODAL": "multimodal",
            "LLM03-MODEL": "artifact_inventory",
            "LLM03-DEPS": "artifact_inventory",
            "LLM04-DATA": "training_pipeline",
            "LLM04-BACKDOOR": "model_evaluation",
            "LLM10-TOKEN": "resource_telemetry",
            "LLM10-COST": "resource_telemetry",
        }
        taxonomy = public_taxonomy()
        public_techniques = {
            technique["id"]: technique
            for risk in taxonomy["risks"]
            for technique in risk["techniques"]
        }
        for technique_id in technique_capabilities:
            self.assertTrue(public_techniques[technique_id]["automated"])
            self.assertTrue(public_techniques[technique_id]["contract_automatable"])
            self.assertEqual(
                public_techniques[technique_id]["required_configuration"],
                "artifact_adapter" if technique_id.startswith("LLM03-") else "assessment_contract",
            )
            if technique_id.startswith("LLM03-"):
                self.assertTrue(public_techniques[technique_id]["native_automated"])

        outcomes = [
            {
                "id": f"outcome-{index}",
                "title": technique_id,
                "technique_ids": [technique_id],
            }
            for index, technique_id in enumerate(technique_capabilities, start=1)
        ]
        contract = {
            "id": "remaining-owasp-controls",
            "enabled": True,
            "technique_ids": list(technique_capabilities),
            "definition": {"security_outcomes": outcomes},
        }
        capabilities = {capability: True for capability in technique_capabilities.values()}
        plan = build_assessment_plan(
            technique_ids=list(technique_capabilities),
            target_capabilities=capabilities,
            assessment_contracts=[contract],
            include_modules=False,
        )
        self.assertEqual(plan["module_ids"], [])
        self.assertEqual(plan["executable_technique_ids"], sorted(technique_capabilities))
        self.assertEqual(plan["contract_technique_ids"], sorted(technique_capabilities))
        self.assertEqual(len(plan["assessment_contracts"][0]["definition"]["security_outcomes"]), 7)

    def test_contract_automation_requires_both_capability_and_matching_contract(self) -> None:
        with self.assertRaisesRegex(ValueError, "need target-specific validation cases"):
            build_assessment_plan(
                technique_ids=["LLM04-BACKDOOR"],
                target_capabilities={"model_evaluation": True},
            )
        contract = {
            "id": "backdoor-oracle",
            "enabled": True,
            "technique_ids": ["LLM04-BACKDOOR"],
            "definition": {"security_outcomes": [{
                "id": "triggered",
                "title": "Trigger behavior",
                "technique_ids": ["LLM04-BACKDOOR"],
            }]},
        }
        with self.assertRaisesRegex(ValueError, "no executable techniques"):
            build_assessment_plan(
                technique_ids=["LLM04-BACKDOOR"],
                target_capabilities={},
                assessment_contracts=[contract],
            )

        missing = build_coverage([], target_capabilities=[{"model_evaluation": True}])
        missing_case = next(
            item for risk in missing["risks"] for item in risk["techniques"]
            if item["id"] == "LLM04-BACKDOOR"
        )
        self.assertEqual(missing_case["status"], "needs_configuration")
        ready = build_coverage([], target_capabilities=[{
            "model_evaluation": True,
            "assessment_contract_technique_ids": ["LLM04-BACKDOOR"],
        }])
        ready_case = next(
            item for risk in ready["risks"] for item in risk["techniques"]
            if item["id"] == "LLM04-BACKDOOR"
        )
        self.assertEqual(ready_case["status"], "not_tested")

    def test_published_owasp_contract_recipes_are_executable_workflow_definitions(self) -> None:
        taxonomy = public_taxonomy()
        self.assertEqual(taxonomy["contract_recipe_version"], "2026.08.3")
        mapped = set()
        contracts_by_id = {}
        for recipe in taxonomy["contract_recipes"]:
            self.assertTrue(recipe["operator_note"])
            self.assertTrue(recipe["required_capabilities"])
            for contract in recipe["contracts"]:
                self.assertEqual(contract["recipe_provenance"]["recipe_id"], recipe["id"])
                self.assertEqual(contract["recipe_provenance"]["recipe_version"], "2026.08.3")
                self.assertFalse(contract["recipe_provenance"]["reviewed"])
                definition = normalize_tool_definition("workflow", contract["definition"])
                self.assertTrue(definition["steps"])
                self.assertTrue(definition["security_outcomes"])
                self.assertTrue(contract["reproduce"])
                self.assertIn("TARGET_APPROVED_", str(contract["definition"]))
                contracts_by_id[contract["id"]] = definition
                mapped.update(
                    technique_id
                    for outcome in definition["security_outcomes"]
                    for technique_id in outcome["technique_ids"]
                )
        self.assertTrue({
            "LLM01-MULTIMODAL",
            "LLM03-MODEL",
            "LLM03-DEPS",
            "LLM04-DATA",
            "LLM04-BACKDOOR",
            "LLM10-TOKEN",
            "LLM10-COST",
            "LLM06-PRIVILEGE",
            "LLM08-TENANT",
            "LLM02-PII",
            "LLM05-ACTIVE",
        }.issubset(mapped))
        self.assertEqual(len(contracts_by_id["multimodal-instruction-boundary"]["steps"]), 2)
        self.assertEqual(len(contracts_by_id["bounded-quota-cost-control"]["steps"]), 3)
        self.assertTrue(any(
            assertion["role"] == "precondition"
            for definition in contracts_by_id.values()
            for step in definition["steps"]
            for assertion in step["assertions"]
        ))
        self.assertTrue(any(
            assertion["role"] == "evidence"
            for definition in contracts_by_id.values()
            for step in definition["steps"]
            for assertion in step["assertions"]
        ))


if __name__ == "__main__":
    unittest.main()
