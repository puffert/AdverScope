from __future__ import annotations

import json
from pathlib import Path
import unittest

from osai_security.reliability_qualification import (
    evaluate_reliability_corpus,
    load_reliability_corpus,
    render_reliability_report,
    validate_reliability_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "validation" / "milestone5" / "reliability-corpus-v1.json"


class ReliabilityQualificationTests(unittest.TestCase):
    def test_frozen_manifest_is_complete_and_explicit_about_open_gates(self) -> None:
        corpus = validate_reliability_corpus(load_reliability_corpus(CORPUS_PATH), root=ROOT)
        self.assertEqual(7, len(corpus["workstreams"]))
        self.assertGreaterEqual(sum(len(item["controls"]) for item in corpus["workstreams"]), 40)
        self.assertEqual(
            {"long-run-soak", "independent-product-security-review", "supported-platform-release-matrix"},
            {item["id"] for item in corpus["open_gates"]},
        )

    def test_manifest_rejects_duplicate_executable_selector(self) -> None:
        corpus = load_reliability_corpus(CORPUS_PATH)
        corpus["workstreams"][1]["controls"][0]["test"] = corpus["workstreams"][0]["controls"][0]["test"]
        with self.assertRaisesRegex(ValueError, "duplicate unittest selector"):
            validate_reliability_corpus(corpus, root=ROOT)

    def test_checked_in_baseline_and_public_report_are_current(self) -> None:
        result = evaluate_reliability_corpus(load_reliability_corpus(CORPUS_PATH), root=ROOT)
        expected_json = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.assertEqual(
            expected_json,
            (ROOT / "validation/milestone5/m5.4-reliability-baseline-2026-08-14.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            render_reliability_report(result),
            (ROOT / "docs/M5_RELIABILITY_QUALIFICATION.md").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
