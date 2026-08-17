from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from osai_security.motor_dataset import build_motor_dataset, validate_build_config, validate_source_registry
from osai_security.motor_training import (
    MotorTrainingError,
    audit_dataset_tokens,
    compare_motor_qualification,
    default_experiment_config,
    validate_experiment_config,
)
from tests.test_motor_dataset import ROOT, _fixture_config, _fixture_registry, _write_raw_fixtures


class FakeTokenizer:
    chat_template = "{{ messages }}"
    special_tokens_map = {"eos_token": "<eos>", "pad_token": "<eos>"}

    def __init__(self, fixed_length: int | None = None) -> None:
        self.fixed_length = fixed_length

    def apply_chat_template(self, messages, *, tokenize, add_generation_prompt):
        if self.fixed_length is not None:
            return list(range(self.fixed_length))
        words = sum(len(str(message["content"]).split()) for message in messages)
        return list(range(words + 12))

    def get_vocab(self):
        return {"<eos>": 0, "authorized": 1, "assessment": 2}


def _qualification_report(candidate_id: str, summary: dict, duration_ms: int) -> dict:
    return {
        "candidates": [{
            "id": candidate_id,
            "summary": summary,
            "runs": [{"duration_ms": duration_ms}, {"duration_ms": duration_ms + 2}],
        }],
    }


class MotorTrainingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        cache = root / "cache"
        _write_raw_fixtures(cache)
        registry = validate_source_registry(_fixture_registry())
        config = validate_build_config(_fixture_config(), registry)
        self.release = root / "release"
        build_motor_dataset(registry, config, cache_root=cache, output_directory=self.release, repository_root=ROOT)
        self.experiment = default_experiment_config(
            experiment_id="fixture-8b-v1",
            dataset_directory=self.release,
            dataset_id=config["dataset_id"],
            dataset_version=config["dataset_version"],
            base_model="example/instruct-8b",
            model_revision="b" * 40,
            max_sequence_tokens=512,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_experiment_rejects_secrets_unpinned_models_and_remote_code(self) -> None:
        secret = deepcopy(self.experiment)
        secret["api_key"] = "not-allowed"
        with self.assertRaisesRegex(MotorTrainingError, "must not contain credentials"):
            validate_experiment_config(secret)
        unpinned = deepcopy(self.experiment)
        unpinned["model"]["revision"] = "main"
        with self.assertRaisesRegex(MotorTrainingError, "immutable 40-character"):
            validate_experiment_config(unpinned)
        remote_code = deepcopy(self.experiment)
        remote_code["model"]["trust_remote_code"] = True
        with self.assertRaisesRegex(MotorTrainingError, "do not execute remote model code"):
            validate_experiment_config(remote_code)

    def test_exact_tokenizer_audit_records_distribution_and_fails_overflow(self) -> None:
        passed = audit_dataset_tokens(self.experiment, tokenizer_loader=lambda _config: FakeTokenizer())
        self.assertEqual("passed", passed["status"])
        self.assertEqual(passed["counts"]["records"], passed["distribution"]["records"])
        self.assertEqual(set(_fixture_config()["quality"]["required_tasks"]), set(passed["by_task"]))
        self.assertEqual(64, len(passed["model"]["tokenizer_fingerprint_sha256"]))

        failed = audit_dataset_tokens(self.experiment, tokenizer_loader=lambda _config: FakeTokenizer(513))
        self.assertEqual("failed", failed["status"])
        self.assertEqual(failed["counts"]["records"], failed["counts"]["overflow_records"])
        self.assertFalse(failed["gates"][0]["passed"])

    def test_repeated_qualification_requires_quality_latency_and_no_regression(self) -> None:
        baseline_attack = _qualification_report("27b", {
            "qualified": True,
            "minimum_pass_rate": 0.96,
            "total_errors": 0,
            "safety_violations": 0,
        }, 200)
        candidate_attack = _qualification_report("8b", {
            "qualified": True,
            "minimum_pass_rate": 0.98,
            "total_errors": 0,
            "safety_violations": 0,
        }, 100)
        baseline_evaluator = _qualification_report("27b", {
            "qualified": True,
            "minimum_precision": 0.97,
            "minimum_recall": 0.96,
            "minimum_pass_rate": 0.96,
            "total_errors": 0,
        }, 200)
        candidate_evaluator = _qualification_report("8b", {
            "qualified": True,
            "minimum_precision": 0.98,
            "minimum_recall": 0.97,
            "minimum_pass_rate": 0.98,
            "total_errors": 0,
        }, 100)
        result = compare_motor_qualification(
            experiment=self.experiment,
            baseline_attack=baseline_attack,
            candidate_attack=candidate_attack,
            baseline_evaluator=baseline_evaluator,
            candidate_evaluator=candidate_evaluator,
            baseline_candidate_id="27b",
            candidate_candidate_id="8b",
        )
        self.assertEqual("qualified", result["status"])
        self.assertTrue(all(gate["passed"] for gate in result["gates"]))

        regressed = deepcopy(candidate_evaluator)
        regressed["candidates"][0]["summary"]["minimum_recall"] = 0.80
        failed = compare_motor_qualification(
            experiment=self.experiment,
            baseline_attack=baseline_attack,
            candidate_attack=candidate_attack,
            baseline_evaluator=baseline_evaluator,
            candidate_evaluator=regressed,
            baseline_candidate_id="27b",
            candidate_candidate_id="8b",
        )
        self.assertEqual("not-qualified", failed["status"])
        self.assertFalse(next(gate for gate in failed["gates"] if gate["id"] == "evaluator-recall")["passed"])


if __name__ == "__main__":
    unittest.main()
