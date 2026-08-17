from __future__ import annotations

import unittest
from pathlib import Path

from osai_security.evaluator_corpus import load_evaluator_corpus, score_evaluator_corpus


CORPUS_PATH = Path(__file__).resolve().parents[1] / "validation" / "evaluator-corpus" / "corpus-v1.json"


class EvaluatorCorpusTests(unittest.TestCase):
    def test_offline_corpus_passes_precision_recall_and_field_gates(self) -> None:
        report = score_evaluator_corpus(load_evaluator_corpus(CORPUS_PATH))
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(report["summary"]["precision"], 1.0)
        self.assertEqual(report["summary"]["recall"], 1.0)
        self.assertEqual(report["summary"]["pass_rate"], 1.0)

    def test_corpus_covers_false_positive_and_transformation_families(self) -> None:
        corpus = load_evaluator_corpus(CORPUS_PATH)
        categories = {case["category"] for case in corpus["cases"]}
        self.assertTrue({
            "refusal",
            "partial-refusal",
            "policy-explanation",
            "prompt-repetition",
            "hypothetical-content",
            "hallucinated-canary",
            "request-origin-provenance",
            "spaced-transformation",
            "zero-width-transformation",
            "structured-character-array",
            "decimal-transformation",
            "hex-transformation",
            "encoded-transformation",
            "delimiter-transformation",
            "structured-output",
            "multilingual-refusal",
            "unsafe-output-observation",
            "verified-downstream-effect",
        }.issubset(categories))


if __name__ == "__main__":
    unittest.main()
