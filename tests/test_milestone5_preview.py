from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_tester_preview import MANIFEST_PATH, ROOT, check_preview


class Milestone5PreviewTests(unittest.TestCase):
    def _copy_preview_fixture(self, destination: Path) -> None:
        manifest = json.loads((ROOT / MANIFEST_PATH).read_text(encoding="utf-8"))
        paths = set(manifest["required_assets"])
        paths.update(manifest["manual_screenshots"])
        paths.update(
            {
                MANIFEST_PATH.as_posix(),
                ".github/workflows/ci.yml",
            }
        )
        for relative in paths:
            source = ROOT / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def test_repository_preview_package_is_ready(self) -> None:
        result = check_preview(ROOT)
        self.assertEqual(result["status"], "ready", result["errors"])
        self.assertGreaterEqual(result["validated_manual_screenshots"], 14)

    def test_missing_manual_screenshot_blocks_preview(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._copy_preview_fixture(root)
            (root / "docs/images/manual/01-projects-dashboard.jpg").unlink()
            result = check_preview(root)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any("01-projects-dashboard.jpg" in error for error in result["errors"]))

    def test_feedback_form_requires_all_sanitized_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._copy_preview_fixture(root)
            form = root / ".github/ISSUE_TEMPLATE/m5-tester-feedback.yml"
            form.write_text(form.read_text(encoding="utf-8").replace("    id: execution_ids\n", "    id: removed_execution_ids\n"), encoding="utf-8")
            result = check_preview(root)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("M5 feedback issue form is missing field: 'execution_ids'", result["errors"])


if __name__ == "__main__":
    unittest.main()
