from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from osai_security.model_role_qualification import (
    evaluate_model_role_corpus,
    load_model_role_corpus,
    render_model_role_report,
    validate_model_role_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "validation/milestone5/model-role-corpus-v1.json"


class ModelRoleQualificationTests(unittest.TestCase):
    def test_retained_evidence_is_reported_without_remote_overclaim(self) -> None:
        result = evaluate_model_role_corpus(load_model_role_corpus(CORPUS_PATH), root=ROOT)
        self.assertEqual("in_progress", result["status"])
        self.assertEqual(3, result["summary"]["qualified_roles"])
        self.assertEqual(1, result["summary"]["qualified_provider_families"])
        self.assertEqual(1, result["summary"]["qualified_model_families"])
        self.assertGreater(result["summary"]["latency_samples"], 0)
        self.assertEqual(0, result["summary"]["usage_samples"])
        self.assertEqual(["adjudicator"], result["missing_roles"])
        self.assertEqual(["openai", "zai"], result["missing_provider_families"])

    def test_frozen_source_hash_drift_is_rejected(self) -> None:
        corpus = deepcopy(load_model_role_corpus(CORPUS_PATH))
        corpus["sources"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash drifted"):
            validate_model_role_corpus(corpus, root=ROOT)

    def test_provider_without_retained_candidate_cannot_be_promoted(self) -> None:
        corpus = deepcopy(load_model_role_corpus(CORPUS_PATH))
        corpus["candidates"][0]["provider_family"] = "openai"
        with self.assertRaisesRegex(ValueError, "another provider family"):
            validate_model_role_corpus(corpus, root=ROOT)

    def test_checked_in_baseline_and_public_report_are_current(self) -> None:
        result = evaluate_model_role_corpus(load_model_role_corpus(CORPUS_PATH), root=ROOT)
        self.assertEqual(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            (ROOT / "validation/milestone5/m5.2-model-role-baseline-2026-08-14.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            render_model_role_report(result),
            (ROOT / "docs/M5_MODEL_ROLE_QUALIFICATION.md").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
