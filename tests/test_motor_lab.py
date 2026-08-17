from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.http_app import Application
from osai_security.motor_dataset import (
    MotorDatasetError,
    build_from_paths,
    build_motor_dataset,
    effective_review_decisions,
    validate_build_config,
    validate_dataset_release,
    validate_source_registry,
)
from osai_security.motor_lab import MotorLabError, MotorLabService, OPERATOR_SOURCE_ID
from tests.test_motor_dataset import ROOT, _fixture_config, _fixture_registry, _source, _write_raw_fixtures


def _review_payload(reviewer: str, *, expected_version: int = 0, status: str = "accepted") -> dict:
    return {
        "status": status,
        "reviewer_id": reviewer,
        "expected_version": expected_version,
        "scope_correct": True,
        "output_contract_correct": True,
        "label_correct": True,
        "safe_for_training": True,
        "notes": "Reviewed against the exact role contract.",
    }


class MotorLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.training = self.root / "training"
        self.cache = self.training / "sources"
        _write_raw_fixtures(self.cache)
        registry = deepcopy(_fixture_registry())
        registry["sources"].append(_source(OPERATOR_SOURCE_ID, "operator-reviewed-jsonl", "gold"))
        config = deepcopy(_fixture_config())
        config["sources"].append({
            "id": OPERATOR_SOURCE_ID,
            "max_records": 0,
            "options": {"filename": "reviewed-records.jsonl", "optional_if_missing": True},
        })
        self.registry = validate_source_registry(registry)
        self.config = validate_build_config(config, self.registry)
        self.release = self.training / "motor-release"
        build_motor_dataset(
            self.registry,
            self.config,
            cache_root=self.cache,
            output_directory=self.release,
            repository_root=ROOT,
        )
        self.service = MotorLabService(self.training)
        self.dataset_id = self.config["dataset_id"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _records(self) -> list[dict]:
        return self.service.review_records(self.dataset_id, limit=100)["records"]

    def _complete_review(self, *, reject_first: bool = False) -> dict:
        rejected = False
        for record in self._records():
            payload = _review_payload("primary-reviewer")
            if reject_first and not rejected and record["task"] != "response-evaluation":
                payload.update({
                    "status": "rejected",
                    "scope_correct": False,
                    "notes": "Fixture record intentionally excluded from the reviewed training corpus.",
                })
                rejected = True
            result = self.service.save_review(
                self.dataset_id,
                record["record_id"],
                payload,
            )
            if record["task"] == "response-evaluation":
                self.assertEqual("second-review", result["current_status"])
                result = self.service.save_review(
                    self.dataset_id,
                    record["record_id"],
                    _review_payload("independent-reviewer", expected_version=1),
                )
                self.assertTrue(result["gold_ready"])
        overlay = self.service.review_overlay(self.dataset_id)
        self.assertTrue(overlay["complete"])
        return overlay

    def _add_trace(self) -> dict:
        source = next(record for record in self._records() if record["task"] == "attack-generation")
        return self.service.add_operator_trace({
            "source_record_id": "independent-trace-001",
            "task": source["task"],
            "target_family": "independent-synthetic-chat-001",
            "benchmark_only": False,
            "technique_ids": source["labels"]["technique_ids"],
            "hard_negative": bool(source["labels"].get("hard_negative")),
            "messages": source["messages"],
            "reviewer_id": "trace-reviewer",
            "scope_correct": True,
            "output_contract_correct": True,
            "label_correct": True,
            "safe_for_training": True,
            "notes": "Independent authorized synthetic target trajectory.",
        })

    def test_review_journal_is_versioned_and_evaluator_gold_requires_two_reviewers(self) -> None:
        records = self._records()
        ordinary = next(record for record in records if record["task"] != "response-evaluation")
        accepted = self.service.save_review(self.dataset_id, ordinary["record_id"], _review_payload("reviewer-one"))
        self.assertTrue(accepted["gold_ready"])
        self.assertEqual("single", accepted["review_stage"])
        with self.assertRaisesRegex(MotorLabError, "changed since it was opened"):
            self.service.save_review(self.dataset_id, ordinary["record_id"], _review_payload("reviewer-one"))

        evaluator = next(record for record in records if record["task"] == "response-evaluation")
        primary = self.service.save_review(self.dataset_id, evaluator["record_id"], _review_payload("reviewer-one"))
        self.assertEqual("second-review", primary["current_status"])
        self.assertFalse(primary["gold_ready"])
        repeated = self.service.save_review(
            self.dataset_id,
            evaluator["record_id"],
            _review_payload("reviewer-one", expected_version=1),
        )
        self.assertEqual("second-review", repeated["current_status"])
        secondary = self.service.save_review(
            self.dataset_id,
            evaluator["record_id"],
            _review_payload("reviewer-two", expected_version=2),
        )
        self.assertEqual("secondary", secondary["review_stage"])
        self.assertNotEqual(secondary["primary_reviewer_id"], secondary["secondary_reviewer_id"])

    def test_secondary_acceptance_preserves_primary_evaluator_correction(self) -> None:
        evaluator = next(record for record in self._records() if record["task"] == "response-evaluation")
        corrected = json.loads(evaluator["messages"][2]["content"])
        corrected.update({
            "vulnerable": False,
            "severity": "info",
            "confidence": 0.99,
            "title": "Not demonstrated",
            "summary": "The response does not demonstrate the objective.",
            "reasoning": "Only target-originated evidence can satisfy the objective.",
        })
        corrected["objective_results"] = [{
            "objective_id": corrected["objective_results"][0]["objective_id"],
            "achieved": False,
            "confidence": 0.99,
            "reason": "The target response does not satisfy the configured objective.",
        }]
        primary_payload = _review_payload("reviewer-one", status="corrected")
        primary_payload.update({"corrected_assistant": corrected, "corrected_hard_negative": True})
        primary = self.service.save_review(self.dataset_id, evaluator["record_id"], primary_payload)
        self.assertEqual("second-review", primary["current_status"])

        secondary = self.service.save_review(
            self.dataset_id,
            evaluator["record_id"],
            _review_payload("reviewer-two", expected_version=1),
        )
        self.assertEqual("corrected", secondary["status"])
        self.assertEqual("accepted", secondary["review_action"])
        self.assertEqual(corrected, secondary["corrected_assistant"])
        self.assertTrue(secondary["corrected_labels"]["hard_negative"])
        self.assertEqual(primary["event_id"], secondary["inherited_correction_event_id"])

        decision = self.service.review_overlay(self.dataset_id)["decisions"][0]
        self.assertEqual("corrected", decision["status"])
        self.assertEqual(corrected, decision["corrected_assistant"])

    def test_legacy_secondary_acceptance_projects_the_primary_correction(self) -> None:
        record_id = "motor_" + "a" * 24
        correction = {"vulnerable": False}
        labels = {"technique_ids": [], "hard_negative": True}
        primary = {
            "record_id": record_id,
            "task": "response-evaluation",
            "status": "corrected",
            "review_stage": "primary",
            "corrected_assistant": correction,
            "corrected_labels": labels,
            "redactions": {"email": 1},
            "event_id": "primary-event",
            "event_sha256": "1" * 64,
        }
        secondary = {
            "record_id": record_id,
            "task": "response-evaluation",
            "status": "accepted",
            "review_stage": "secondary",
            "corrected_assistant": None,
            "corrected_labels": None,
            "redactions": {},
            "event_id": "secondary-event",
            "event_sha256": "2" * 64,
        }
        decision = effective_review_decisions([primary, secondary])[record_id]
        self.assertEqual("corrected", decision["status"])
        self.assertEqual(correction, decision["corrected_assistant"])
        self.assertEqual(labels, decision["corrected_labels"])
        self.assertTrue(decision["accepted_primary_correction"])
        self.assertEqual("primary-event", decision["correction_source_event_id"])

    def test_rejection_requires_a_failed_quality_check(self) -> None:
        record = next(record for record in self._records() if record["task"] != "response-evaluation")
        payload = _review_payload("reviewer-one", status="rejected")
        payload["notes"] = "Reject this record."
        with self.assertRaisesRegex(MotorLabError, "at least one failed review check"):
            self.service.save_review(self.dataset_id, record["record_id"], payload)

    def test_review_journal_tampering_is_detected(self) -> None:
        record = self._records()[0]
        self.service.save_review(self.dataset_id, record["record_id"], _review_payload("reviewer-one"))
        path = self.service._review_path(self.dataset_id)  # intentional white-box integrity test
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[0]["notes"] = "tampered"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        with self.assertRaisesRegex(MotorLabError, "integrity failed"):
            self.service.review_records(self.dataset_id)

    def test_operator_trace_blocks_reserved_benchmarks_and_is_build_connected(self) -> None:
        source = next(record for record in self._records() if record["task"] == "attack-generation")
        invalid = {
            "source_record_id": "bad-trace",
            "task": source["task"],
            "target_family": "portswigger-lab-001",
            "benchmark_only": False,
            "technique_ids": source["labels"]["technique_ids"],
            "messages": source["messages"],
            "reviewer_id": "reviewer-one",
            "scope_correct": True,
            "output_contract_correct": True,
            "label_correct": True,
            "safe_for_training": True,
        }
        with self.assertRaisesRegex(MotorLabError, "reserved qualification"):
            self.service.add_operator_trace(invalid)
        retained = self._add_trace()
        self.assertEqual("independent-trace-001", retained["source_record_id"])
        self.assertTrue((self.cache / OPERATOR_SOURCE_ID / "source-manifest.json").is_file())

    def test_complete_review_rebuild_and_experiment_gate(self) -> None:
        with self.assertRaisesRegex(MotorLabError, "reviewed dataset release"):
            self.service.create_experiment({
                "experiment_id": "motor-test-v1",
                "dataset_id": self.dataset_id,
                "base_model": "example/instruct-8b",
                "model_revision": "a" * 40,
            })
        overlay = self._complete_review()
        self._add_trace()
        build_motor_dataset(
            self.registry,
            self.config,
            cache_root=self.cache,
            output_directory=self.release,
            repository_root=ROOT,
            review_overlay=overlay,
        )
        overview = self.service.datasets()["datasets"][0]
        self.assertTrue(overview["reviewed_release"])
        self.assertTrue(overview["review"]["complete"])
        experiment = self.service.create_experiment({
            "experiment_id": "motor-test-v1",
            "dataset_id": self.dataset_id,
            "base_model": "example/instruct-8b",
            "model_revision": "a" * 40,
            "max_sequence_tokens": 4096,
        })
        self.assertEqual("motor-test-v1", experiment["config"]["experiment_id"])
        self.assertIn("run_motor_experiment.py audit", experiment["commands"]["audit"])
        with self.assertRaisesRegex(MotorLabError, "immutable reviewed release"):
            self.service.save_review(self.dataset_id, self._records()[0]["record_id"], _review_payload("reviewer-three"))

    def test_reviewed_release_can_add_operator_traces_without_reopening_source_review(self) -> None:
        overlay = self._complete_review(reject_first=True)
        overlay_path = self.root / "review-overlay.json"
        registry_path = self.root / "source-registry.json"
        config_path = self.root / "build-config.json"
        overlay_path.write_text(json.dumps(overlay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        registry_path.write_text(json.dumps(self.registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        config_path.write_text(json.dumps(self.config, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        build_from_paths(
            registry_path=registry_path,
            config_path=config_path,
            cache_root=self.cache,
            output_directory=self.release,
            repository_root=ROOT,
            review_overlay_path=overlay_path,
        )
        reviewed_before = json.loads((self.release / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(0, reviewed_before["counts"]["sources"].get(OPERATOR_SOURCE_ID, 0))
        before_trace = self.service.datasets()["datasets"][0]
        self.assertFalse(before_trace["experiment_ready"])
        self.assertTrue(before_trace["review"]["overlay_path"].endswith("provenance\\review-overlay.json") or before_trace["review"]["overlay_path"].endswith("provenance/review-overlay.json"))
        rejected_audit = self.service.review_records(self.dataset_id, status="rejected", limit=100)
        self.assertEqual(1, rejected_audit["pagination"]["total"])
        self.assertTrue(all(item["current_status"] == "rejected" for item in rejected_audit["records"]))

        self._add_trace()
        pending_extension = self.service.datasets()["datasets"][0]
        self.assertTrue(pending_extension["review"]["operator_update_available"])

        # Releases created before pipeline 2026.08.14.3 omitted rejected rows
        # from the read-only audit queue. Preserve that exact legacy shape and
        # prove the guarded extension can repair it without weakening any
        # other release-integrity error.
        queue_path = self.release / "review" / "review-queue.jsonl"
        queue_rows = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines()]
        queue_rows = [item for item in queue_rows if (item.get("review") or {}).get("status") != "rejected"]
        queue_path.write_text(
            "".join(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for item in queue_rows),
            encoding="utf-8",
        )
        legacy_manifest_path = self.release / "manifest.json"
        legacy_manifest = json.loads(legacy_manifest_path.read_text(encoding="utf-8"))
        queue_entry = next(item for item in legacy_manifest["files"] if item["path"] == "review/review-queue.jsonl")
        queue_entry.update({
            "records": len(queue_rows),
            "bytes": queue_path.stat().st_size,
            "sha256": hashlib.sha256(queue_path.read_bytes()).hexdigest(),
        })
        legacy_manifest_path.write_text(json.dumps(legacy_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        legacy_validation = validate_dataset_release(self.release)
        self.assertEqual("failed", legacy_validation["status"])
        self.assertIn("reviewed queue does not retain every review disposition", legacy_validation["errors"])

        extended = build_from_paths(
            registry_path=registry_path,
            config_path=config_path,
            cache_root=self.cache,
            output_directory=self.release,
            repository_root=ROOT,
            review_overlay_path=overlay_path,
        )

        self.assertEqual(1, extended["reviewed_extension"]["operator_records_added"])
        self.assertEqual(1, extended["manifest"]["counts"]["sources"][OPERATOR_SOURCE_ID])
        self.assertEqual("passed", extended["validation"]["status"])
        extended_overview = self.service.datasets()["datasets"][0]
        self.assertTrue(extended_overview["experiment_ready"])
        self.assertFalse(extended_overview["review"]["operator_update_available"])
        self.assertEqual(
            reviewed_before["review_overlay"]["overlay_sha256"],
            extended["manifest"]["review_overlay"]["overlay_sha256"],
        )
        experiment = self.service.create_experiment({
            "experiment_id": "motor-post-review-extension",
            "dataset_id": self.dataset_id,
            "base_model": "example/instruct-8b",
            "model_revision": "b" * 40,
        })
        self.assertEqual("motor-post-review-extension", experiment["config"]["experiment_id"])

        manifest_before_drift_attempt = (self.release / "manifest.json").read_bytes()
        deepset_path = self.cache / "deepset-fixture" / "rows.jsonl"
        deepset_path.write_text(
            deepset_path.read_text(encoding="utf-8").replace(" number ", " materially-changed-number "),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MotorDatasetError, "review overlay does not match|changed the non-operator corpus"):
            build_from_paths(
                registry_path=registry_path,
                config_path=config_path,
                cache_root=self.cache,
                output_directory=self.release,
                repository_root=ROOT,
                review_overlay_path=overlay_path,
            )
        self.assertEqual(manifest_before_drift_attempt, (self.release / "manifest.json").read_bytes())

    def test_http_routes_keep_model_work_outside_project_storage(self) -> None:
        database = self.root / "app" / "adverscope.sqlite3"
        config = AppConfig(database_path=database, evidence_root=self.root / "app" / "projects")
        repository = Repository(database)
        app = Application(repository, config=config, motor_lab=self.service)
        try:
            status, overview = app.dispatch("GET", "/api/motor-lab")
            self.assertEqual(200, status)
            self.assertEqual(self.dataset_id, overview["datasets"][0]["dataset_id"])
            status, page = app.dispatch("GET", f"/api/motor-lab/datasets/{self.dataset_id}/reviews?limit=2")
            self.assertEqual(200, status)
            self.assertEqual(2, len(page["records"]))
            record = page["records"][0]
            status, decision = app.dispatch(
                "PATCH",
                f"/api/motor-lab/datasets/{self.dataset_id}/reviews/{record['record_id']}",
                _review_payload("api-reviewer"),
            )
            self.assertEqual(200, status)
            self.assertEqual(record["record_id"], decision["record_id"])
            self.assertEqual([], repository.list_projects(include_archived=True))
        finally:
            app.close()
            repository.close()

    def test_application_uses_explicit_installation_training_root(self) -> None:
        database = self.root / "separate-project-state" / "adverscope.sqlite3"
        config = AppConfig(
            database_path=database,
            evidence_root=self.root / "separate-project-state" / "projects",
            training_root=self.training,
        )
        repository = Repository(database)
        app = Application(repository, config=config)
        try:
            self.assertEqual(self.training.resolve(), app.motor_lab.training_root)
            status, overview = app.dispatch("GET", "/api/motor-lab")
            self.assertEqual(200, status)
            self.assertEqual(self.dataset_id, overview["datasets"][0]["dataset_id"])
        finally:
            app.close()
            repository.close()

    def test_unreadable_optional_release_does_not_disable_model_lab(self) -> None:
        blocked = self.training / "blocked-release"
        blocked.mkdir()
        original_is_file = Path.is_file

        def guarded_is_file(path: Path) -> bool:
            if path.name == "manifest.json" and path.parent.name == blocked.name:
                raise PermissionError("fixture access denied")
            return original_is_file(path)

        with patch.object(Path, "is_file", guarded_is_file):
            overview = self.service.datasets()

        self.assertIn(self.dataset_id, {item["dataset_id"] for item in overview["datasets"]})
        self.assertEqual(
            [{
                "dataset_id": blocked.name,
                "error": "dataset release is not readable by the AdverScope process",
            }],
            overview["discovery_errors"],
        )


if __name__ == "__main__":
    unittest.main()
