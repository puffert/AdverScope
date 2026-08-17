from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from osai_security.db import Repository
from osai_security.evidence_bundles import EvidenceBundleError, build_evidence_bundle, verify_evidence_bundle
from osai_security.evidence_store import EvidenceStore
from osai_security.config import AppConfig
from osai_security.http_app import Application


class EvidenceBundleTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Repository, EvidenceStore, dict, dict, dict]:
        repo = Repository(root / "assessment.sqlite3")
        store = EvidenceStore(root / "projects")
        project = repo.create_project(name="Evidence custody fixture", client="Authorized client")
        repo.add_document(project["id"], kind="scope", filename="scope.md", content="Authorized local target only.")
        repo.add_document(project["id"], kind="policy", filename="policy.md", content="Protected data must not be disclosed.")
        target = repo.add_target(
            project["id"], name="Fixture chatbot", kind="chatbot", base_url="http://127.0.0.1:9",
            path="/chat", method="POST", request_template={"message": "{{prompt}}"},
            response_path="response", scope_confirmed=True,
        )
        repo.save_guardrail(
            project["id"], target["id"], status="approved", max_requests=10,
            max_runtime_seconds=120, max_consecutive_errors=2, allow_active_recon=False,
            allow_multi_turn=False, max_turns_per_objective=1, allow_reproduction=True,
            allow_screenshots=True, stop_on_http_5xx=True,
        )
        run = repo.create_run(project["id"], target["id"], ["prompt-injection"], "offline")
        evaluation = {
            "vulnerable": True, "severity": "high", "confidence": 0.99,
            "title": "Verified boundary failure", "summary": "Synthetic proof was returned.",
            "evaluator": "deterministic", "direct_evidence": True,
            "evidence_assurance": {"level": "exact-protected-value", "finding_eligible": True, "confirmation_state": "confirmed", "basis": "Exact synthetic proof."},
            "owasp_risk_ids": ["LLM01"], "owasp_technique_ids": ["LLM01-DIRECT"],
        }
        case = repo.add_test_case(
            project["id"], run_id=run["id"], target_id=target["id"], module_id="prompt-injection",
            title="Verified boundary failure", prompt="Exercise the authorized synthetic boundary.",
            rationale="Qualification fixture", response="Synthetic target proof returned.",
            evaluation=evaluation, generation_source="offline", status="vulnerable",
        )
        evidence = repo.add_evidence(
            project["id"], run_id=run["id"], test_case_id=case["id"], kind="chatbot-interaction",
            title="Exact retained exchange", content="Authorization: local-fixture-secret\nSynthetic target proof returned.",
            metadata={"request": {"headers": {"Authorization": "local-fixture-secret"}}, "status_code": 200},
        )
        capture = store.attempt_directory(project["id"], run["id"], "capture_fixture") / "initial.png"
        capture.write_bytes(b"synthetic-png-evidence")
        import hashlib
        repo.add_evidence_asset(
            project["id"], run_id=run["id"], test_case_id=case["id"], evidence_id=evidence["id"],
            kind="screenshot", attempt="initial", relative_path=store.relative_path(capture),
            mime_type="image/png", size_bytes=capture.stat().st_size,
            sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
        )
        repo.add_finding(
            project["id"], run_id=run["id"], test_case_id=case["id"], evidence_id=evidence["id"],
            module_id="prompt-injection", title="Verified boundary failure", severity="high",
            confidence=0.99, summary="Synthetic proof was returned.",
        )
        repo.complete_run(project["id"], run["id"], status="completed")
        return repo, store, project, run, {"case": case, "evidence": evidence, "capture": capture}

    def test_redacted_and_full_bundles_are_scoped_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, store, project, run, fixture = self._fixture(root)
            other = repo.create_project(name="Other project")
            repo.add_document(other["id"], kind="scope", filename="other.md", content="SECOND_PROJECT_MARKER")
            repo.set_report_review(project["id"], status="accepted", reviewer="Qualified reviewer", notes="Evidence and reproduction reviewed.")

            redacted = build_evidence_bundle(repo, store, project_id=project["id"], run_id=run["id"], mode="redacted")
            redacted_check = verify_evidence_bundle(redacted["content"], expected_project_id=project["id"], expected_run_id=run["id"])
            self.assertTrue(redacted_check["ok"])
            self.assertEqual("accepted", redacted_check["report_status"])
            with zipfile.ZipFile(io.BytesIO(redacted["content"])) as archive:
                names = archive.namelist()
                self.assertNotIn("evidence/assets", "\n".join(names))
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(1, len(manifest["omitted_assets"]))
                text_records = "\n".join(
                    archive.read(name).decode("utf-8")
                    for name in names
                    if name.endswith((".json", ".md"))
                )
                self.assertNotIn("local-fixture-secret", text_records)
                self.assertNotIn("SECOND_PROJECT_MARKER", text_records)
                self.assertNotIn(other["id"], text_records)

            full = build_evidence_bundle(repo, store, project_id=project["id"], run_id=run["id"], mode="full")
            self.assertTrue(verify_evidence_bundle(full["content"])["ok"])
            with zipfile.ZipFile(io.BytesIO(full["content"])) as archive:
                asset_names = [name for name in archive.namelist() if name.startswith("evidence/assets/")]
                self.assertEqual(1, len(asset_names))
                self.assertEqual(fixture["capture"].read_bytes(), archive.read(asset_names[0]))
            repo.close()

    def test_tampering_and_broken_assets_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, store, project, run, fixture = self._fixture(root)
            bundle = build_evidence_bundle(repo, store, project_id=project["id"], mode="full")
            with zipfile.ZipFile(io.BytesIO(bundle["content"])) as source:
                changed = io.BytesIO()
                with zipfile.ZipFile(changed, "w") as destination:
                    for name in source.namelist():
                        content = source.read(name)
                        if name == "README.md":
                            content += b"tampered"
                        destination.writestr(name, content)
            with self.assertRaisesRegex(EvidenceBundleError, "integrity check failed"):
                verify_evidence_bundle(changed.getvalue())

            fixture["capture"].unlink()
            with self.assertRaisesRegex(EvidenceBundleError, "is missing"):
                build_evidence_bundle(repo, store, project_id=project["id"], run_id=run["id"], mode="full")
            repo.close()

    def test_report_acceptance_becomes_stale_after_project_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _store, project, _run, _fixture = self._fixture(root)
            accepted = repo.set_report_review(project["id"], status="accepted", reviewer="Reviewer")
            self.assertTrue(accepted["is_current"])
            repo.add_document(project["id"], kind="policy", filename="updated-policy.md", content="Additional reviewed policy boundary.")
            stale = repo.get_report_review(project["id"])
            self.assertFalse(stale["is_current"])
            self.assertEqual("draft", stale["effective_status"])
            repo.close()

    def test_application_requires_full_export_acknowledgement_and_enforces_run_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, store, project, run, _fixture = self._fixture(root)
            other_repo_project = repo.create_project(name="Other boundary")
            app = Application(
                repo,
                config=AppConfig(database_path=repo.path, evidence_root=store.root),
                evidence_store=store,
            )
            status, review = app.dispatch("POST", f"/api/projects/{project['id']}/report-review", {
                "status": "accepted", "reviewer": "Professional reviewer", "notes": "Current evidence accepted.",
            })
            self.assertEqual(200, status)
            self.assertTrue(review["is_current"])
            with self.assertRaisesRegex(ValueError, "acknowledgement"):
                app.professional_evidence_bundle(project["id"], mode="full")
            exported = app.professional_evidence_bundle(
                project["id"], run_id=run["id"], mode="full", acknowledge_sensitive=True,
            )
            self.assertTrue(verify_evidence_bundle(exported["content"], expected_project_id=project["id"])["ok"])
            with self.assertRaisesRegex(Exception, "not found"):
                app.professional_evidence_bundle(other_repo_project["id"], run_id=run["id"], mode="redacted")
            repo.close()


if __name__ == "__main__":
    unittest.main()
