from __future__ import annotations

import hashlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from osai_security.artifact_security import artifact_evaluation, scan_artifact, validate_artifact_profile
from osai_security.config import AppConfig
from osai_security.db import NotFoundError, Repository, new_id
from osai_security.engine import run_assessment
from osai_security.evidence_store import EvidenceStore
from osai_security.http_app import Application, assessment_target_capabilities
from osai_security.owasp import build_assessment_plan


class NoNetworkClient:
    def close_sessions_for_run(self, *_args: object) -> None:
        return None

    def __getattr__(self, name: str):
        raise AssertionError(f"artifact assessment attempted target/network operation: {name}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_record(path: Path, *, kind: str = "other") -> dict[str, object]:
    return {
        "id": "art_123456789abc",
        "filename": path.name,
        "kind": kind,
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def policy_case(artifact_id: str = "art_123456789abc", **values: object) -> dict[str, object]:
    result: dict[str, object] = {
        "id": "artifact-case",
        "artifact_id": artifact_id,
        "title": "Artifact security policy",
        "technique_id": "LLM03-DEPS",
    }
    result.update(values)
    return result


class ArtifactScannerTests(unittest.TestCase):
    def test_dependency_manifest_proves_unpinned_and_unhashed_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("safe==1.2.3 --hash=sha256:" + "a" * 64 + "\nunsafe>=2\n", encoding="utf-8")
            report = scan_artifact(
                path,
                artifact_record(path, kind="dependency-manifest"),
                policy_case(require_dependency_pinning=True, require_component_hashes=True),
            )
            self.assertEqual(report["format"], "python-requirements")
            self.assertEqual(
                {item["rule_id"] for item in report["violations"]},
                {"ART-DEPENDENCY-UNPINNED", "ART-COMPONENT-HASH-MISSING"},
            )
            self.assertTrue(artifact_evaluation(report)["vulnerable"])

    def test_clean_cyclonedx_manifest_holds_configured_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            path.write_text(json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"supplier": {"name": "Approved supplier"}},
                "signature": {"algorithm": "RS256", "value": "metadata-only-fixture"},
                "components": [{"type": "library", "name": "safe-lib", "version": "1.2.3", "hashes": [{"alg": "SHA-256", "content": "a" * 64}]}],
            }), encoding="utf-8")
            report = scan_artifact(
                path,
                artifact_record(path, kind="sbom"),
                policy_case(require_dependency_pinning=True, require_component_hashes=True, require_provenance_metadata=True, require_signature_metadata=True),
            )
            evaluation = artifact_evaluation(report)
            self.assertEqual(report["format"], "cyclonedx-json")
            self.assertEqual(report["violations"], [])
            self.assertEqual(evaluation["automation_validation"]["classification"], "control-held")
            self.assertFalse(evaluation["vulnerable"])

    def test_archive_traversal_and_pickle_are_detected_without_extraction_or_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", "must-not-be-written")
            report = scan_artifact(archive_path, artifact_record(archive_path, kind="model"), policy_case(technique_id="LLM03-MODEL"))
            self.assertIn("ART-ARCHIVE-PATH-TRAVERSAL", {item["rule_id"] for item in report["violations"]})
            self.assertFalse((root.parent / "escape.txt").exists())

            pickle_path = root / "model.pkl"
            pickle_path.write_bytes(b"cos\nsystem\n(S'never-executed'\ntR.")
            pickle_report = scan_artifact(pickle_path, artifact_record(pickle_path, kind="model"), policy_case(technique_id="LLM03-MODEL"))
            self.assertIn("ART-EXECUTABLE-SERIALIZATION", {item["rule_id"] for item in pickle_report["violations"]})
            self.assertGreater(pickle_report["format_details"]["executable_opcode_counts"].get("GLOBAL", 0), 0)

    def test_safetensors_and_digest_mismatch_are_bounded_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.safetensors"
            header = json.dumps({"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode("utf-8")
            path.write_bytes(struct.pack("<Q", len(header)) + header + b"\0\0\0\0")
            case = policy_case(technique_id="LLM03-MODEL", expected_sha256="0" * 64)
            first = scan_artifact(path, artifact_record(path, kind="model"), case)
            second = scan_artifact(path, artifact_record(path, kind="model"), case)
            self.assertEqual(first["format"], "safetensors")
            self.assertEqual(first["report_sha256"], second["report_sha256"])
            self.assertIn("ART-DIGEST-MISMATCH", {item["rule_id"] for item in first["violations"]})

    def test_profile_rejects_duplicate_artifacts_and_invalid_digests(self) -> None:
        with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
            validate_artifact_profile({"enabled": True, "cases": [policy_case(expected_sha256="bad")]})
        with self.assertRaisesRegex(ValueError, "valid objective ids"):
            validate_artifact_profile({"enabled": True, "cases": [policy_case(objective_ids=["outside-project"])]})
        with self.assertRaisesRegex(ValueError, "only once"):
            validate_artifact_profile({"enabled": True, "cases": [policy_case(), {**policy_case(), "id": "second"}]})


class ArtifactVerticalSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = Repository(self.root / "assessment.sqlite3")
        self.store = EvidenceStore(self.root / "projects")
        self.config = AppConfig(database_path=self.root / "assessment.sqlite3", evidence_root=self.root / "projects")
        self.app = Application(self.repo, config=self.config, evidence_store=self.store)
        self.project = self.repo.create_project(name="Artifact Assessment", client="Test")
        self.repo.add_document(self.project["id"], kind="scope", filename="scope.md", content="Authorized local artifact assessment for the configured target.")
        self.repo.add_document(self.project["id"], kind="policy", filename="policy.md", content="Dependencies must be pinned and integrity hashed.")
        self.target = self.repo.add_target(
            self.project["id"],
            name="Documented AI deployment",
            kind="api",
            base_url="https://authorized.invalid",
            path="/inventory",
            method="GET",
            request_template={},
            scope_confirmed=True,
        )
        self.repo.save_guardrail(
            self.project["id"], self.target["id"], status="approved",
            max_requests=20, max_runtime_seconds=900, max_consecutive_errors=3,
            allow_active_recon=False, allow_multi_turn=False, max_turns_per_objective=1,
            allow_reproduction=True, allow_screenshots=False, stop_on_http_5xx=True,
            notes="Approved local artifact-assessment fixture boundary.",
        )

    def tearDown(self) -> None:
        self.repo.close()
        self.temp.cleanup()

    def upload(self, content: bytes, filename: str = "requirements.txt", kind: str = "dependency-manifest") -> dict[str, object]:
        return self.app.upload_artifact_stream(
            project_id=self.project["id"],
            target_id=self.target["id"],
            filename=filename,
            kind=kind,
            mime_type="text/plain",
            stream=io.BytesIO(content),
            content_length=len(content),
        )

    def test_project_isolation_profile_validation_and_forensic_archive(self) -> None:
        artifact = self.upload(b"library==1.0\n")
        other = self.repo.create_project(name="Other")
        with self.assertRaises(NotFoundError):
            self.repo.get_artifact(other["id"], str(artifact["id"]))
        with self.assertRaisesRegex(ValueError, "outside this project"):
            self.app.save_artifact_profile(self.project["id"], self.target["id"], {
                "enabled": True,
                "cases": [policy_case(str(artifact["id"]), objective_ids=["obj_000000000000"])],
            })

        configured = self.app.save_artifact_profile(self.project["id"], self.target["id"], {
            "enabled": True,
            "cases": [policy_case(str(artifact["id"]), require_dependency_pinning=True)],
        })
        self.assertEqual(configured["evaluation_config"]["artifact"]["cases"][0]["artifact_id"], artifact["id"])
        archived = self.app.archive_artifact(self.project["id"], str(artifact["id"]))
        self.assertTrue(archived["retained_for_evidence"])
        self.assertEqual(self.repo.get_artifact(self.project["id"], str(artifact["id"]))["status"], "archived")
        self.assertEqual(self.repo.get_target(self.project["id"], self.target["id"])["evaluation_config"]["artifact"], {})

    def test_native_llm03_run_creates_exact_evidence_finding_reproduction_and_coverage(self) -> None:
        artifact = self.upload(b"safe==1.0 --hash=sha256:" + b"a" * 64 + b"\nunsafe>=2\n")
        objective = self.repo.add_objective(
            self.project["id"],
            title="Demonstrate dependency policy failure",
            description="Assess the configured artifact policy.",
            success_criteria="A linked static policy case deterministically records a violation.",
            risk_ids=[],
            technique_ids=[],
            require_reproduction=True,
        )
        self.app.save_artifact_profile(self.project["id"], self.target["id"], {
            "enabled": True,
            "cases": [policy_case(str(artifact["id"]), objective_ids=[objective["id"]], require_dependency_pinning=True, require_component_hashes=True)],
        })
        target = self.repo.get_target(self.project["id"], self.target["id"])
        plan = build_assessment_plan(
            technique_ids=["LLM03-DEPS"],
            objectives=[objective],
            target_capabilities=assessment_target_capabilities(target),
            evaluation_config=target["evaluation_config"],
        )
        self.app.snapshot_artifacts_for_plan(self.project["id"], self.target["id"], plan)
        plan["guardrail"] = self.repo.get_guardrail(self.project["id"], self.target["id"])
        plan["target_capabilities"] = assessment_target_capabilities(target)
        plan["confirmation_policy"] = {"mode": "minimum-proof", "reproduction_attempts": 1}
        run = run_assessment(
            self.repo,
            project_id=self.project["id"],
            target_id=self.target["id"],
            module_ids=plan["module_ids"],
            model_mode="offline",
            model_gateway=object(),
            target_client=NoNetworkClient(),
            browser_target_client=NoNetworkClient(),
            evidence_store=self.store,
            attack_budget=1,
            assessment_plan=plan,
        )
        detail = self.repo.get_run_detail(self.project["id"], run["id"])
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(len(detail["test_cases"]), 1)
        case = detail["test_cases"][0]
        self.assertEqual(case["module_id"], "artifact-security")
        self.assertEqual(case["status"], "vulnerable")
        static_report = json.loads(case["response"])
        self.assertEqual(static_report["format"], "python-requirements")
        self.assertEqual(
            {item["rule_id"] for item in static_report["violations"]},
            {"ART-DEPENDENCY-UNPINNED", "ART-COMPONENT-HASH-MISSING"},
        )
        self.assertEqual(case["evaluation"]["execution_source"], "native-artifact-static-analysis")
        self.assertEqual(case["evaluation"]["objective_results"][0]["objective_id"], objective["id"])
        self.assertTrue(case["evaluation"]["objective_results"][0]["achieved"])
        self.assertEqual(case["evaluation"]["objective_results"][0]["proof_source"], "deterministic-artifact-policy")
        self.assertEqual(len(case["evidence"]), 2)
        self.assertIn("never imported, deserialized, extracted, or executed", case["evidence"][0]["content"])
        self.assertEqual(len(detail["findings"]), 1)
        self.assertEqual(detail["findings"][0]["validation_status"], "confirmed")
        reproduction_results = detail["findings"][0]["validations"][0]["evaluation"]["objective_results"]
        self.assertEqual(reproduction_results[0]["objective_id"], objective["id"])
        self.assertTrue(reproduction_results[0]["achieved"])
        technique = next(item for risk in detail["owasp_coverage"]["risks"] for item in risk["techniques"] if item["id"] == "LLM03-DEPS")
        self.assertEqual(technique["status"], "confirmed")
        self.assertFalse(any(event["event_type"] == "request.sent" for event in detail["events"]))
        self.assertTrue(all(event.get("details", {}).get("target_traffic_sent") is not True for event in detail["events"] if event["event_type"].startswith("artifact.")))
        self.assertEqual(detail["metrics"]["local_static_case_count"], 1)
        self.assertEqual(detail["metrics"]["target_transport_case_count"], 0)
        self.assertEqual(detail["metrics"]["pipeline"]["local_analysis"], 1)
        self.assertEqual(detail["metrics"]["evidence_completeness_rate"], 1.0)

    def test_running_assessment_prevents_archiving_its_artifact_snapshot(self) -> None:
        artifact = self.upload(b"library==1.0\n")
        plan = {"artifact_inventory": [{"id": artifact["id"]}]}
        self.repo.create_run(self.project["id"], self.target["id"], ["artifact-security"], "offline", assessment_plan=plan)
        with self.assertRaisesRegex(ValueError, "in use by running assessment"):
            self.repo.archive_artifact(self.project["id"], str(artifact["id"]))


if __name__ == "__main__":
    unittest.main()
