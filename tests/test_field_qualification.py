from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from osai_security.field_qualification import (
    evaluate_field_qualification,
    load_field_corpus,
    render_field_qualification_report,
    validate_field_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "validation" / "milestone5" / "corpus-v1.json"


class FieldQualificationTests(unittest.TestCase):
    def test_frozen_corpus_reports_mechanism_and_field_support_separately(self) -> None:
        result = evaluate_field_qualification(load_field_corpus(CORPUS), root=ROOT)
        self.assertEqual(result["status"], "in_progress")
        self.assertEqual(result["summary"]["registry_techniques"], 47)
        self.assertEqual(result["summary"]["professional_claim_candidates"], 10)
        self.assertEqual(result["summary"]["field_qualified_techniques"], 2)
        self.assertEqual(result["summary"]["mechanism_qualified_pending_field_evidence"], 8)
        field_qualified = {
            item["id"] for item in result["techniques"]
            if item["field_support_status"] == "field-qualified"
        }
        self.assertEqual(field_qualified, {"LLM01-INDIRECT-WEB", "LLM06-TOOLS"})
        self.assertTrue(next(item for item in result["gates"] if item["id"] == "frozen-source-integrity")["passed"])
        self.assertFalse(next(item for item in result["gates"] if item["id"] == "professional-technique-field-qualification")["passed"])

    def test_framework_fixture_cannot_be_relabelled_as_field_independent(self) -> None:
        corpus = load_field_corpus(CORPUS)
        altered = deepcopy(corpus)
        family = next(item for item in altered["target_families"] if item["id"].startswith("adverscope-"))
        family["independent_for_field_gate"] = True
        with self.assertRaisesRegex(ValueError, "cannot count for the field gate"):
            validate_field_corpus(altered, root=ROOT)

    def test_unclassified_registry_family_blocks_the_corpus(self) -> None:
        corpus = load_field_corpus(CORPUS)
        altered = deepcopy(corpus)
        altered["target_families"] = [
            item for item in altered["target_families"]
            if item["id"] != "adverscope-independent-semantic-fixture"
        ]
        with self.assertRaisesRegex(ValueError, "unclassified target families"):
            validate_field_corpus(altered, root=ROOT)

    def test_frozen_source_hash_drift_blocks_qualification(self) -> None:
        corpus = load_field_corpus(CORPUS)
        altered = deepcopy(corpus)
        altered["frozen_sources"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
            validate_field_corpus(altered, root=ROOT)

    def test_generated_baseline_and_public_report_are_current(self) -> None:
        result = evaluate_field_qualification(load_field_corpus(CORPUS), root=ROOT)
        expected_json = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        expected_markdown = render_field_qualification_report(result)
        self.assertEqual(
            (ROOT / "validation/milestone5/m5.1-baseline-2026-08-14.json").read_text(encoding="utf-8"),
            expected_json,
        )
        self.assertEqual(
            (ROOT / "docs/M5_FIELD_QUALIFICATION.md").read_text(encoding="utf-8"),
            expected_markdown,
        )


if __name__ == "__main__":
    unittest.main()
