from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from osai_security.release import PRODUCT_VERSION
from scripts.platform_qualification import qualify
from scripts.release_integrity import build_sbom, unsafe_archive_entries, verify_distribution_archive


ROOT = Path(__file__).resolve().parents[1]


class ReleaseIntegrityTests(unittest.TestCase):
    def test_release_archive_denylist_covers_evidence_sessions_secrets_and_keys(self) -> None:
        protected = [
            "adverscope/data/project.sqlite3",
            "adverscope/project/_browser_sessions/target/Cookies",
            "adverscope/output/report.zip",
            "adverscope/.env.production",
            "adverscope/local-config.private.json",
            "adverscope/server.key",
            "adverscope/client.pem",
            "adverscope/validation/runtime/evidence.json",
        ]
        self.assertEqual(set(unsafe_archive_entries(protected)), set(protected))
        self.assertEqual(unsafe_archive_entries(["adverscope/osai_security/db.py", "adverscope/docs/INSTALLATION.md", "adverscope/local-config.example.json"]), [])

    def test_distribution_verifier_requires_license_version_and_clean_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / f"adverscope-{PRODUCT_VERSION}-py3-none-any.whl"
            with zipfile.ZipFile(safe, "w") as archive:
                archive.writestr("adverscope/__init__.py", "")
                archive.writestr(f"adverscope-{PRODUCT_VERSION}.dist-info/licenses/LICENSE", "Apache-2.0")
            self.assertTrue(verify_distribution_archive(safe, PRODUCT_VERSION)["verified"])
            unsafe = root / f"adverscope-{PRODUCT_VERSION}-unsafe.whl"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("adverscope/LICENSE", "Apache-2.0")
                archive.writestr("adverscope/_browser_sessions/Default/Cookies", "credential state")
            with self.assertRaisesRegex(ValueError, "protected local material"):
                verify_distribution_archive(unsafe, PRODUCT_VERSION)

    def test_source_distribution_requires_complete_m5_preview_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / f"adverscope-{PRODUCT_VERSION}.tar.gz"
            license_path = root / "LICENSE"
            license_path.write_text("Apache-2.0", encoding="utf-8")
            with tarfile.open(source, "w:gz") as archive:
                archive.add(license_path, arcname=f"adverscope-{PRODUCT_VERSION}/LICENSE")
            with self.assertRaisesRegex(ValueError, "missing M5.0 preview assets"):
                verify_distribution_archive(source, PRODUCT_VERSION)

    def test_sbom_is_cyclonedx_and_contains_locked_python_and_browser_components(self) -> None:
        sbom = build_sbom(PRODUCT_VERSION)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.7")
        self.assertEqual(sbom["metadata"]["component"]["version"], PRODUCT_VERSION)
        references = {component["bom-ref"] for component in sbom["components"]}
        self.assertTrue(any(reference.startswith("pkg:npm/playwright-core@") for reference in references))
        self.assertTrue(any(reference.startswith("pkg:pypi/mcp@") for reference in references))

    def test_container_is_api_focused_and_published_only_to_host_loopback(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('"127.0.0.1:8091:8091"', compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("cap_drop", compose)
        self.assertNotIn("node", dockerfile.casefold())
        self.assertNotIn("playwright", dockerfile.casefold())

    def test_workflows_pin_third_party_actions_to_full_commits(self) -> None:
        for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            for line in workflow.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line:
                    continue
                reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                if reference.startswith("./"):
                    continue
                self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$", workflow.name)

    def test_issue_templates_prohibit_sensitive_assessment_material(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml")
        ).casefold()
        for phrase in ("secrets", "client evidence", "credentials", "browser profiles"):
            self.assertIn(phrase, text)

    def test_platform_qualification_keeps_browser_profile_out_of_artifacts(self) -> None:
        retained_profile: list[Path] = []
        original_run = subprocess.run

        def fake_browser_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "input" not in kwargs:
                return original_run(*args, **kwargs)
            config = json.loads(str(kwargs["input"]))
            output = Path(config["output_directory"]).resolve()
            profile = Path(config["profile_directory"]).resolve()
            retained_profile.append(profile)
            self.assertTrue(profile.is_dir())
            self.assertFalse(profile.is_relative_to(output))
            screenshots = []
            for name in ("login-before.png", "login-after.png", "chat-request.png", "chat-response.png"):
                (output / name).write_bytes(b"synthetic-image")
                screenshots.append({"name": name, "bytes": len(b"synthetic-image")})
            browser = {
                "login_completed": True,
                "persistent_session": True,
                "screenshots": screenshots,
            }
            (output / "browser-platform-result.json").write_text(json.dumps(browser), encoding="utf-8")
            return subprocess.CompletedProcess([], 0, stdout=json.dumps(browser), stderr="")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "platform-result"
            with patch("scripts.platform_qualification.subprocess.run", side_effect=fake_browser_run):
                result = qualify(output)
            self.assertTrue(result["ok"])
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "platform-qualification.json",
                    "browser-platform-result.json",
                    "login-before.png",
                    "login-after.png",
                    "chat-request.png",
                    "chat-response.png",
                },
            )
            self.assertFalse((output / "persistent-profile").exists())
        self.assertEqual(len(retained_profile), 1)
        self.assertFalse(retained_profile[0].exists())

    def test_platform_ci_upload_uses_an_explicit_artifact_allowlist(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("path: platform-result\n", workflow)
        for name in (
            "platform-qualification.json",
            "browser-platform-result.json",
            "login-before.png",
            "login-after.png",
            "chat-request.png",
            "chat-response.png",
        ):
            self.assertIn(f"platform-result/{name}", workflow)


if __name__ == "__main__":
    unittest.main()
