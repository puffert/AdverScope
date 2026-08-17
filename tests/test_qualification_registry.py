from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.http_app import Application
from osai_security.owasp import TECHNIQUE_INDEX
from osai_security.qualification_registry import (
    REGISTRY_SCHEMA_VERSION,
    build_qualification_registry,
    render_automation_matrix,
    validate_qualification_registry,
)


class QualificationRegistryTests(unittest.TestCase):
    def test_registry_covers_the_exact_taxonomy_without_inflating_qualification(self) -> None:
        registry = build_qualification_registry()
        self.assertEqual(registry["schema_version"], REGISTRY_SCHEMA_VERSION)
        rows = {item["id"]: item for item in registry["techniques"]}
        self.assertEqual(set(rows), set(TECHNIQUE_INDEX))
        self.assertEqual(len(rows), 47)
        self.assertEqual(rows["LLM01-DIRECT"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM01-INDIRECT-WEB"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM06-TOOLS"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM06-MCP-TOOLS"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM06-MCP-DEPUTY"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM01-MCP-CONTENT"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM02-MCP-PROMPT"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM02-MCP-RESOURCE"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM03-MCP-INVENTORY"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM08-MCP-BOUNDARY"]["qualification_status"], "qualified")
        self.assertEqual(rows["LLM05-ACTIVE"]["qualification_status"], "experimental")
        self.assertEqual(
            [item["id"] for item in rows.values() if item["qualification_status"] == "qualified"],
            [
                "LLM01-DIRECT",
                "LLM01-INDIRECT-WEB",
                "LLM01-MCP-CONTENT",
                "LLM02-MCP-RESOURCE",
                "LLM02-MCP-PROMPT",
                "LLM03-MCP-INVENTORY",
                "LLM06-TOOLS",
                "LLM06-MCP-TOOLS",
                "LLM06-MCP-DEPUTY",
                "LLM08-MCP-BOUNDARY",
            ],
        )

    def test_registry_rejects_unsubstantiated_qualified_claims(self) -> None:
        registry = build_qualification_registry()
        invalid = deepcopy(registry)
        entry = next(item for item in invalid["techniques"] if item["id"] == "LLM01-DIRECT")
        first_family = entry["fixtures"]["secure"][0]["target_family"]
        entry["fixtures"]["secure"] = [
            fixture for fixture in entry["fixtures"]["secure"]
            if fixture["target_family"] == first_family
        ]
        entry["fixtures"]["vulnerable"] = [
            fixture for fixture in entry["fixtures"]["vulnerable"]
            if fixture["target_family"] == first_family
        ]
        with self.assertRaisesRegex(ValueError, "two independent target families"):
            validate_qualification_registry(invalid)

    def test_registry_is_available_through_the_local_api(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects")
            repo = Repository(config.database_path)
            try:
                app = Application(repo, config=config)
                status, registry = app.dispatch("GET", "/api/qualification-registry")
                self.assertEqual(status, 200)
                self.assertEqual(
                    {item["id"] for item in registry["techniques"]},
                    set(TECHNIQUE_INDEX),
                )
            finally:
                repo.close()

    def test_generated_matrix_and_gui_use_the_registry_labels(self) -> None:
        registry = build_qualification_registry()
        matrix = render_automation_matrix(registry)
        script = (Path(__file__).resolve().parents[1] / "osai_security" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn(f"maps {len(registry['techniques'])} techniques", matrix)
        for technique in registry["techniques"]:
            self.assertIn(f"| {technique['id']} · {technique['title']} |", matrix)
        self.assertIn('api("/api/qualification-registry")', script)
        self.assertIn("techniqueQualificationMarkup(technique)", script)
        self.assertIn("qualificationRegistry", script)


if __name__ == "__main__":
    unittest.main()
