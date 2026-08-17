from __future__ import annotations

from pathlib import Path
import unittest

from osai_security.config import AppConfig
from osai_security.evaluator_corpus import load_evaluator_corpus
from osai_security.model_qualification import (
    qualify_model_candidates,
    summarize_candidate_runs,
    validate_model_candidates,
)


class DeterministicSafeGateway:
    def __init__(self, config: AppConfig):
        self.config = config
        self.tunnel = None

    def evaluate_response_with_trace(self, **_kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        return ({
            "vulnerable": False,
            "severity": "info",
            "confidence": 0.9,
            "title": "No target-backed evidence",
            "summary": "No direct target-backed proof was present.",
            "reasoning": "Synthetic qualification gateway.",
            "evaluator": "test-model",
        }, {"provider": "test", "model": self.config.llm_model})


class ModelQualificationTests(unittest.TestCase):
    def test_manifest_forbids_connection_secrets(self) -> None:
        with self.assertRaisesRegex(ValueError, "forbidden"):
            validate_model_candidates({
                "schema_version": 1,
                "candidates": [{
                    "id": "unsafe",
                    "model": "fixture-model",
                    "base_url": "http://127.0.0.1:18001/v1",
                    "api_key": "must-not-be-stored",
                }],
            })

    def test_summary_rejects_cross_run_disagreement(self) -> None:
        reports = [
            {"summary": {"errors": 0, "precision": 1.0, "recall": 1.0, "pass_rate": 1.0}, "results": [{"case_id": "case-1", "classification": "true_negative"}], "errors": []},
            {"summary": {"errors": 0, "precision": 1.0, "recall": 1.0, "pass_rate": 1.0}, "results": [{"case_id": "case-1", "classification": "false_positive"}], "errors": []},
        ]
        summary = summarize_candidate_runs(reports)
        self.assertFalse(summary["qualified"])
        self.assertEqual(1, summary["disagreement_count"])

    def test_repeated_qualification_uses_real_corpus_and_records_role(self) -> None:
        corpus = load_evaluator_corpus(Path("validation/evaluator-corpus/corpus-v1.json"))
        manifest = {
            "schema_version": 1,
            "repetitions": 2,
            "candidates": [{
                "id": "fixture",
                "model": "fixture-model",
                "role": "evaluator-candidate",
                "required": True,
                "base_url": "http://127.0.0.1:18001/v1",
                "ssh_tunnel": False,
            }],
        }
        report = qualify_model_candidates(
            corpus,
            manifest,
            base_config=AppConfig(),
            gateway_factory=DeterministicSafeGateway,
        )
        self.assertEqual("evaluator-candidate", report["candidates"][0]["role"])
        self.assertTrue(report["all_required_candidates_qualified"])
        self.assertEqual(2, report["candidates"][0]["summary"]["repetitions"])
        self.assertEqual(25, report["candidates"][0]["runs"][0]["summary"]["cases"])


if __name__ == "__main__":
    unittest.main()
