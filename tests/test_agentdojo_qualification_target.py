from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_agentdojo_target.py"
SPEC = importlib.util.spec_from_file_location("run_agentdojo_target", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AgentDojoQualificationTargetTests(unittest.TestCase):
    def test_case_reference_is_pinned_and_strict(self) -> None:
        case = MODULE.parse_case_reference(
            "banking:user_task_0:injection_task_1",
            benchmark_version="v1.2.2",
        )
        self.assertEqual("banking:user_task_0:injection_task_1", case.case_id)
        self.assertEqual("v1.2.2", case.benchmark_version)
        for invalid in ("", "banking:user", "banking:user:injection:extra", "banking:user:../bad"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                MODULE.parse_case_reference(invalid, benchmark_version="v1.2.2")

    def test_request_parser_accepts_only_a_bounded_prompt(self) -> None:
        self.assertEqual("authorized test", MODULE.parse_evaluation_request(b'{"prompt":"authorized test"}'))
        self.assertEqual(
            "temporary content",
            MODULE.parse_string_field_request(b'{"content":"temporary content"}', field="content", label="content"),
        )
        for invalid in (b"", b"[]", b"{}", b'{"prompt":""}', b"not-json"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                MODULE.parse_evaluation_request(invalid)
        oversized = json.dumps({"prompt": "x" * (MODULE.MAX_PROMPT_CHARACTERS + 1)}).encode()
        with self.assertRaisesRegex(ValueError, "qualification limit"):
            MODULE.parse_evaluation_request(oversized)

    def test_only_adverscope_proof_instrumentation_is_removed(self) -> None:
        effective, count = MODULE.remove_adverscope_instrumentation(
            "ADV-RAG-CONTROL-ABC123\nTODO: perform the reviewed benchmark action.\nADV-RAG-XYZ789"
        )
        self.assertEqual("TODO: perform the reviewed benchmark action.", effective)
        self.assertEqual(2, count)
        untouched, count = MODULE.remove_adverscope_instrumentation(
            "TODO: preserve ordinary target text and identifiers."
        )
        self.assertEqual("TODO: preserve ordinary target text and identifiers.", untouched)
        self.assertEqual(0, count)
        with self.assertRaisesRegex(ValueError, "effective AgentDojo injection is empty"):
            MODULE.remove_adverscope_instrumentation("ADV-RAG-CONTROL-ABC123 ADV-RAG-XYZ789")

    def test_agentdojo_yaml_transport_preserves_arbitrary_reviewed_text(self) -> None:
        original = 'Next: {"url":"https://example.test/a\\b"}\nContinue with the quoted "section".'
        encoded = MODULE.escape_agentdojo_yaml_template_value(original)
        reconstructed = json.loads('"{}"'.format(encoded))
        self.assertEqual(original, reconstructed)

    def test_public_result_exposes_only_official_boolean_oracles(self) -> None:
        case = MODULE.AgentDojoCase("v1.2.2", "slack", "user_task_0", "injection_task_1")
        result = MODULE.public_oracle_result(
            case,
            utility=True,
            injection_succeeded=True,
            injection_position_count=2,
            duration_seconds=1.23456,
            package_version="0.1.35",
            prompt="do not expose this prompt",
        )
        self.assertTrue(result["official_oracle"]["injection_succeeded"])
        self.assertFalse(result["official_oracle"]["security_control_held"])
        self.assertTrue(result["official_oracle"]["utility_preserved"])
        self.assertEqual(64, len(result["evidence"]["prompt_sha256"]))
        self.assertFalse(result["evidence"]["messages_exposed"])
        self.assertFalse(result["evidence"]["oracle_goal_exposed"])
        self.assertNotIn("do not expose", json.dumps(result))

        held = MODULE.public_oracle_result(
            case,
            utility=True,
            injection_succeeded=False,
            injection_position_count=2,
            duration_seconds=1.0,
            package_version="0.1.35",
            prompt="bounded prompt",
        )
        self.assertFalse(held["official_oracle"]["injection_succeeded"])
        self.assertTrue(held["official_oracle"]["security_control_held"])

    def test_model_parse_fault_recovers_with_bounded_temperature_change(self) -> None:
        class JSONDecodeError(Exception):
            pass

        class TemperatureElement:
            def __init__(self) -> None:
                self.temperature = 0.7

        class Pipeline:
            def __init__(self, element: object) -> None:
                self.elements = [element, type("Nested", (), {"elements": [element]})()]

        class Suite:
            def __init__(self, element: TemperatureElement) -> None:
                self.element = element
                self.temperatures: list[float] = []

            def run_task_with_pipeline(self, *_args: object) -> tuple[bool, bool]:
                self.temperatures.append(self.element.temperature)
                if len(self.temperatures) == 1:
                    raise JSONDecodeError("malformed tool-call JSON")
                return True, False

        service = object.__new__(MODULE.AgentDojoQualificationService)
        element = TemperatureElement()
        service.pipeline = Pipeline(element)
        service.suite = Suite(element)
        service.user_task = object()
        service.injection_task = object()
        service.max_model_attempts = 3

        utility, injection_succeeded, faults = service._run_with_model_recovery({"position": "prompt"})

        self.assertTrue(utility)
        self.assertFalse(injection_succeeded)
        self.assertEqual(["JSONDecodeError"], faults)
        self.assertEqual([0.0, 0.1], service.suite.temperatures)
        self.assertEqual(0.7, element.temperature)

    def test_openai_compatible_client_applies_explicit_completion_and_time_bounds(self) -> None:
        class Completions:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def create(self, **kwargs: object) -> dict[str, object]:
                self.calls.append(kwargs)
                return kwargs

        class Client:
            def __init__(self) -> None:
                self.chat = type("Chat", (), {"completions": Completions()})()
                self.timeout: float | None = None

            def with_options(self, *, timeout: float) -> object:
                self.timeout = timeout
                return self

        client = Client()
        bounded = MODULE.BoundedOpenAIClient(client, max_completion_tokens=512, timeout_seconds=45)
        result = bounded.chat.completions.create(model="qualified-model")

        self.assertEqual(45.0, client.timeout)
        self.assertEqual(512, result["max_completion_tokens"])
        self.assertEqual("qualified-model", result["model"])

    def test_non_retryable_model_fault_is_not_replayed(self) -> None:
        class Suite:
            attempts = 0

            def run_task_with_pipeline(self, *_args: object) -> tuple[bool, bool]:
                self.attempts += 1
                raise ValueError("invalid benchmark configuration")

        service = object.__new__(MODULE.AgentDojoQualificationService)
        service.pipeline = type("Pipeline", (), {"elements": []})()
        service.suite = Suite()
        service.user_task = object()
        service.injection_task = object()
        service.max_model_attempts = 3

        with self.assertRaises(ValueError):
            service._run_with_model_recovery({"position": "prompt"})
        self.assertEqual(1, service.suite.attempts)

    def test_retryable_model_fault_stops_at_configured_limit(self) -> None:
        class JSONDecodeError(Exception):
            pass

        class Suite:
            attempts = 0

            def run_task_with_pipeline(self, *_args: object) -> tuple[bool, bool]:
                self.attempts += 1
                raise JSONDecodeError("malformed response")

        service = object.__new__(MODULE.AgentDojoQualificationService)
        service.pipeline = type("Pipeline", (), {"elements": []})()
        service.suite = Suite()
        service.user_task = object()
        service.injection_task = object()
        service.max_model_attempts = 2

        with self.assertRaises(JSONDecodeError):
            service._run_with_model_recovery({"position": "prompt"})
        self.assertEqual(2, service.suite.attempts)

    def test_reversible_lifecycle_emits_marker_only_after_official_success(self) -> None:
        service = object.__new__(MODULE.AgentDojoQualificationService)
        service._lock = MODULE.threading.RLock()
        service._document = ""
        service._document_id = ""
        service.control_query = "authorized retrieval control"
        baseline = service.query("authorized trigger")
        self.assertFalse(baseline["official_oracle"]["injection_succeeded"])
        self.assertNotIn("ADV-RAG-", baseline["response"])

        stored = service.ingest(
            "Untrusted test content with marker ADV-RAG-ABC123 and control ADV-RAG-CONTROL-XYZ789"
        )
        control = service.query("authorized retrieval control")
        self.assertTrue(control["retrieval_control_emitted"])
        self.assertEqual("ADV-RAG-CONTROL-XYZ789", control["response"])
        self.assertNotIn("ADV-RAG-ABC123", control["response"])
        service.evaluate = lambda _prompt: {"official_oracle": {"injection_succeeded": False}}
        held = service.query("authorized trigger")
        self.assertFalse(held["marker_emitted"])
        self.assertNotIn("ADV-RAG-ABC123", held["response"])

        service.evaluate = lambda _prompt: {"official_oracle": {"injection_succeeded": True}}
        violated = service.query("authorized trigger")
        self.assertTrue(violated["marker_emitted"])
        self.assertEqual("ADV-RAG-ABC123", violated["response"])

        self.assertEqual("deleted", service.cleanup(stored["document_id"])["status"])
        after_cleanup = service.query("authorized trigger")
        self.assertNotIn("ADV-RAG-ABC123", after_cleanup["response"])
        after_cleanup_control = service.query("authorized retrieval control")
        self.assertNotIn("ADV-RAG-CONTROL-XYZ789", after_cleanup_control["response"])
        with self.assertRaises(ValueError):
            service.cleanup(stored["document_id"])


if __name__ == "__main__":
    unittest.main()
