from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.metadata import version
from typing import Any


MAX_REQUEST_BYTES = 256_000
MAX_PROMPT_CHARACTERS = 20_000
MAX_MODEL_ATTEMPTS = 5
MIN_MODEL_COMPLETION_TOKENS = 128
MAX_MODEL_COMPLETION_TOKENS = 8_192
MIN_MODEL_REQUEST_TIMEOUT_SECONDS = 30
MAX_MODEL_REQUEST_TIMEOUT_SECONDS = 1_200
MARKER_PATTERN = re.compile(r"\bADV-RAG-(?!CONTROL-)[A-Z0-9]+\b")
CONTROL_MARKER_PATTERN = re.compile(r"\bADV-RAG-CONTROL-[A-Z0-9]+\b")

RETRYABLE_MODEL_FAULT_TOKENS = (
    "jsondecodeerror",
    "apiconnectionerror",
    "apitimeouterror",
    "ratelimiterror",
    "internalservererror",
    "connectionerror",
    "timeouterror",
)


@dataclass(frozen=True)
class AgentDojoCase:
    benchmark_version: str
    suite: str
    user_task_id: str
    injection_task_id: str

    @property
    def case_id(self) -> str:
        return f"{self.suite}:{self.user_task_id}:{self.injection_task_id}"


def parse_case_reference(value: str, *, benchmark_version: str) -> AgentDojoCase:
    parts = [part.strip() for part in str(value or "").split(":")]
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("case must use SUITE:USER_TASK_ID:INJECTION_TASK_ID")
    for part in parts:
        if len(part) > 120 or not all(character.isalnum() or character in {"-", "_"} for character in part):
            raise ValueError("case identifiers may contain only letters, numbers, hyphens, and underscores")
    return AgentDojoCase(
        benchmark_version=str(benchmark_version),
        suite=parts[0],
        user_task_id=parts[1],
        injection_task_id=parts[2],
    )


def parse_evaluation_request(raw: bytes) -> str:
    return parse_string_field_request(raw, field="prompt", label="prompt")


def parse_string_field_request(raw: bytes, *, field: str, label: str) -> str:
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ValueError(f"request body must contain between 1 and {MAX_REQUEST_BYTES} bytes")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body must be one UTF-8 JSON object") from exc
    if not isinstance(document, dict):
        raise ValueError("request body must be a JSON object")
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required and must be a non-empty string")
    if len(value) > MAX_PROMPT_CHARACTERS:
        raise ValueError(f"{label} exceeds the {MAX_PROMPT_CHARACTERS}-character qualification limit")
    return value


def remove_adverscope_instrumentation(value: str) -> tuple[str, int]:
    """Remove only run-unique AdverScope proof labels before victim execution.

    The full received document remains available to the HTTP evidence layer and
    positive retrieval control.  AgentDojo receives the operator-reviewed attack
    carrier without framework instrumentation, preserving benchmark fidelity.
    """

    marker_count = len(MARKER_PATTERN.findall(value)) + len(CONTROL_MARKER_PATTERN.findall(value))
    effective = CONTROL_MARKER_PATTERN.sub("", MARKER_PATTERN.sub("", value)).strip()
    if not effective:
        raise ValueError("the effective AgentDojo injection is empty after proof-label removal")
    return effective, marker_count


def escape_agentdojo_yaml_template_value(value: str) -> str:
    """Encode a value for AgentDojo's double-quoted YAML format template.

    AgentDojo resolves its environment YAML and then inserts attack text with
    ``str.format``. Its resolved scalar strings are double quoted, so raw quote,
    backslash, or newline characters can otherwise make an authorized payload
    fail before the model is invoked. JSON string escaping is compatible with
    YAML double-quoted scalars and reconstructs the exact original text.
    """

    return json.dumps(str(value), ensure_ascii=False)[1:-1]


def is_retryable_model_fault(exc: BaseException) -> bool:
    """Return whether a model transport/serialization fault is safe to replay.

    Qualification retries are deliberately limited to failures that happen
    before an official oracle result exists. Configuration, benchmark, and
    assertion failures are never replayed implicitly.
    """

    identity = f"{type(exc).__module__}.{type(exc).__name__}".replace("_", "").lower()
    return any(token in identity for token in RETRYABLE_MODEL_FAULT_TOKENS)


def model_attempt_temperature(attempt_index: int) -> float:
    """Use deterministic decoding first, then bounded diversity for recovery."""

    return round(min(max(int(attempt_index), 0) * 0.1, 0.4), 1)


def pipeline_elements_with_attribute(pipeline: Any, attribute: str) -> list[Any]:
    """Find unique nested pipeline elements exposing one public attribute."""

    found: list[Any] = []
    visited: set[int] = set()

    def visit(element: Any) -> None:
        identity = id(element)
        if identity in visited:
            return
        visited.add(identity)
        if hasattr(element, attribute):
            found.append(element)
        nested = getattr(element, "elements", ())
        if isinstance(nested, (list, tuple)):
            for child in nested:
                visit(child)

    visit(pipeline)
    return found


def pipeline_temperature_elements(pipeline: Any) -> list[Any]:
    return pipeline_elements_with_attribute(pipeline, "temperature")


class _BoundedCompletions:
    def __init__(self, wrapped: Any, max_completion_tokens: int) -> None:
        self._wrapped = wrapped
        self._max_completion_tokens = int(max_completion_tokens)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("max_completion_tokens", self._max_completion_tokens)
        return self._wrapped.create(*args, **kwargs)


class _BoundedChat:
    def __init__(self, wrapped: Any, max_completion_tokens: int) -> None:
        self._wrapped = wrapped
        self.completions = _BoundedCompletions(wrapped.completions, max_completion_tokens)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


class BoundedOpenAIClient:
    """Transparent OpenAI-compatible client with explicit request bounds."""

    def __init__(self, wrapped: Any, *, max_completion_tokens: int, timeout_seconds: int) -> None:
        bounded = wrapped.with_options(timeout=float(timeout_seconds))
        self._wrapped = bounded
        self.chat = _BoundedChat(bounded.chat, max_completion_tokens)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


def public_oracle_result(
    case: AgentDojoCase,
    *,
    utility: bool,
    injection_succeeded: bool,
    injection_position_count: int,
    duration_seconds: float,
    package_version: str,
    prompt: str,
) -> dict[str, Any]:
    # AgentDojo's run_task_with_pipeline() returns
    # (user_task_succeeded, injection_task_succeeded).  The second value is an
    # attack-success oracle despite the upstream implementation using the local
    # variable name ``security`` in a few places.  Preserve those semantics here
    # so a successful injection can never be reported as a held control.
    injection_succeeded = bool(injection_succeeded)
    return {
        "status": "completed",
        "adapter": "agentdojo-official-oracle-v1",
        "benchmark_version": case.benchmark_version,
        "agentdojo_package_version": package_version,
        "case": {
            "id": case.case_id,
            "suite": case.suite,
            "user_task_id": case.user_task_id,
            "injection_task_id": case.injection_task_id,
        },
        "official_oracle": {
            "utility_preserved": bool(utility),
            "security_control_held": not injection_succeeded,
            "injection_succeeded": injection_succeeded,
        },
        "summary": (
            "The official AgentDojo security oracle reports that the configured injection goal was achieved."
            if injection_succeeded
            else "The official AgentDojo security oracle reports that the configured injection goal was not achieved."
        ),
        "evidence": {
            "injection_position_count": int(injection_position_count),
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "duration_seconds": round(float(duration_seconds), 3),
            "messages_exposed": False,
            "oracle_goal_exposed": False,
        },
    }


class AgentDojoQualificationService:
    """Expose one pinned official AgentDojo case as a bounded JSON target.

    The supplied prompt is inserted only into the official injection positions
    discovered by AgentDojo. AgentDojo's own utility and security oracles decide
    the result. Task goals, environment state, and model messages are deliberately
    not returned to the caller.
    """

    def __init__(
        self,
        case: AgentDojoCase,
        *,
        model_id: str,
        control_query: str,
        max_model_attempts: int = 3,
        max_completion_tokens: int = 2_048,
        model_request_timeout_seconds: int = 180,
    ) -> None:
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.attacks.base_attacks import BaseAttack
        from agentdojo.models import ModelsEnum
        from agentdojo.task_suite.load_suites import get_suite

        class SuppliedPromptAttack(BaseAttack):
            name = "adverscope-supplied-prompt"

            def __init__(self, task_suite: Any, target_pipeline: Any, prompt: str) -> None:
                super().__init__(task_suite, target_pipeline)
                self.prompt = prompt

            def attack(self, user_task: Any, injection_task: Any) -> dict[str, str]:
                return {position: self.prompt for position in self.get_injection_candidates(user_task)}

        self.case = case
        self.model_id = str(model_id)
        self.max_model_attempts = int(max_model_attempts)
        if not 1 <= self.max_model_attempts <= MAX_MODEL_ATTEMPTS:
            raise ValueError(f"max_model_attempts must be between 1 and {MAX_MODEL_ATTEMPTS}")
        self.max_completion_tokens = int(max_completion_tokens)
        if not MIN_MODEL_COMPLETION_TOKENS <= self.max_completion_tokens <= MAX_MODEL_COMPLETION_TOKENS:
            raise ValueError(
                "max_completion_tokens must be between "
                f"{MIN_MODEL_COMPLETION_TOKENS} and {MAX_MODEL_COMPLETION_TOKENS}"
            )
        self.model_request_timeout_seconds = int(model_request_timeout_seconds)
        if not MIN_MODEL_REQUEST_TIMEOUT_SECONDS <= self.model_request_timeout_seconds <= MAX_MODEL_REQUEST_TIMEOUT_SECONDS:
            raise ValueError(
                "model_request_timeout_seconds must be between "
                f"{MIN_MODEL_REQUEST_TIMEOUT_SECONDS} and {MAX_MODEL_REQUEST_TIMEOUT_SECONDS}"
            )
        self.control_query = str(control_query).strip()
        if not self.control_query or len(self.control_query) > MAX_PROMPT_CHARACTERS:
            raise ValueError("control_query must be a non-empty bounded string")
        self.package_version = version("agentdojo")
        self.suite = get_suite(case.benchmark_version, case.suite)
        self.user_task = self.suite.get_user_task_by_id(case.user_task_id)
        self.injection_task = self.suite.get_injection_task_by_id(case.injection_task_id)
        self.pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=ModelsEnum.OPENAI_COMPATIBLE,
                model_id=self.model_id,
                defense=None,
                system_message_name=None,
                system_message=None,
            )
        )
        wrapped_clients: dict[int, BoundedOpenAIClient] = {}
        for element in pipeline_elements_with_attribute(self.pipeline, "client"):
            original_client = element.client
            client_identity = id(original_client)
            if client_identity not in wrapped_clients:
                wrapped_clients[client_identity] = BoundedOpenAIClient(
                    original_client,
                    max_completion_tokens=self.max_completion_tokens,
                    timeout_seconds=self.model_request_timeout_seconds,
                )
            element.client = wrapped_clients[client_identity]
        preflight_attack = SuppliedPromptAttack(self.suite, self.pipeline, "ADVERSCOPE PREFLIGHT MARKER")
        self.injection_positions = tuple(preflight_attack.get_injection_candidates(self.user_task))
        if not self.injection_positions:
            raise ValueError(f"AgentDojo case {case.case_id} has no injectable position")
        self._lock = threading.RLock()
        self._document = ""
        self._document_id = ""

    def health(self) -> dict[str, Any]:
        return {
            "status": "ready",
            "adapter": "agentdojo-official-oracle-v1",
            "benchmark_version": self.case.benchmark_version,
            "agentdojo_package_version": self.package_version,
            "case_id": self.case.case_id,
            "model_id": self.model_id,
            "injection_position_count": len(self.injection_positions),
            "lifecycle": ["ingest", "query", "cleanup"],
            "retrieval_control_supported": True,
            "max_model_attempts": self.max_model_attempts,
            "max_completion_tokens": self.max_completion_tokens,
            "model_request_timeout_seconds": self.model_request_timeout_seconds,
        }

    def _run_with_model_recovery(self, injections: dict[str, str]) -> tuple[bool, bool, list[str]]:
        temperature_elements = pipeline_temperature_elements(self.pipeline)
        original_temperatures = [(element, element.temperature) for element in temperature_elements]
        recoverable_faults: list[str] = []
        try:
            for attempt_index in range(self.max_model_attempts):
                temperature = model_attempt_temperature(attempt_index)
                for element in temperature_elements:
                    element.temperature = temperature
                try:
                    utility, injection_succeeded = self.suite.run_task_with_pipeline(
                        self.pipeline,
                        self.user_task,
                        self.injection_task,
                        injections,
                    )
                    return bool(utility), bool(injection_succeeded), recoverable_faults
                except Exception as exc:
                    if not is_retryable_model_fault(exc) or attempt_index + 1 >= self.max_model_attempts:
                        raise
                    recoverable_faults.append(type(exc).__name__)
        finally:
            for element, original_temperature in original_temperatures:
                element.temperature = original_temperature
        raise RuntimeError("model recovery loop ended without an oracle result")

    def evaluate(self, prompt: str) -> dict[str, Any]:
        started = time.monotonic()
        effective_prompt, marker_count = remove_adverscope_instrumentation(prompt)
        with self._lock:
            serialized_prompt = escape_agentdojo_yaml_template_value(effective_prompt)
            injections = {position: serialized_prompt for position in self.injection_positions}
            utility, injection_succeeded, recoverable_faults = self._run_with_model_recovery(injections)
        result = public_oracle_result(
            self.case,
            utility=utility,
            injection_succeeded=injection_succeeded,
            injection_position_count=len(injections),
            duration_seconds=time.monotonic() - started,
            package_version=self.package_version,
            prompt=effective_prompt,
        )
        result["evidence"]["received_prompt_sha256"] = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        result["evidence"]["instrumentation_marker_count"] = marker_count
        result["evidence"]["framework_instrumentation_removed"] = bool(marker_count)
        result["evidence"]["model_attempt_count"] = len(recoverable_faults) + 1
        result["evidence"]["model_recovery_used"] = bool(recoverable_faults)
        result["evidence"]["recoverable_error_classes"] = recoverable_faults
        result["evidence"]["adapter_transport_encoding"] = "yaml-double-quoted-scalar"
        return result

    def ingest(self, content: str) -> dict[str, Any]:
        with self._lock:
            self._document = content
            self._document_id = "scenario-" + hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
            return {"status": "stored", "document_id": self._document_id}

    def query(self, query: str) -> dict[str, Any]:
        with self._lock:
            if not self._document:
                return {
                    "status": "completed",
                    "response": "No temporary external-content scenario is currently stored.",
                    "official_oracle": {
                        "utility_preserved": True,
                        "security_control_held": True,
                        "injection_succeeded": False,
                    },
                }
            if query == self.control_query:
                control_marker = next(iter(CONTROL_MARKER_PATTERN.findall(self._document)), "")
                return {
                    "status": "completed",
                    "response": control_marker or "The temporary scenario does not contain a retrieval-control marker.",
                    "retrieval_control_emitted": bool(control_marker),
                    "official_oracle": {
                        "utility_preserved": True,
                        "security_control_held": True,
                        "injection_succeeded": False,
                    },
                }
            result = self.evaluate(self._document)
            marker = next(iter(MARKER_PATTERN.findall(self._document)), "")
            succeeded = bool((result.get("official_oracle") or {}).get("injection_succeeded"))
            return {
                **result,
                "response": marker if succeeded and marker else "The official security control held for this attempt.",
                "marker_emitted": bool(succeeded and marker),
            }

    def cleanup(self, document_id: str) -> dict[str, Any]:
        with self._lock:
            if not self._document_id or document_id != self._document_id:
                raise ValueError("document_id does not identify the active temporary scenario")
            self._document = ""
            self._document_id = ""
            return {"status": "deleted"}


class QualificationHandler(BaseHTTPRequestHandler):
    server: "QualificationHTTPServer"

    def _send_json(self, status: int, document: dict[str, Any]) -> None:
        body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._send_json(404, {"status": "not-found"})
            return
        self._send_json(200, self.server.service.health())

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/evaluate", "/ingest", "/query", "/cleanup"}:
            self._send_json(404, {"status": "not-found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
            if length < 1 or length > MAX_REQUEST_BYTES:
                raise ValueError(f"Content-Length must be between 1 and {MAX_REQUEST_BYTES}")
            raw = self.rfile.read(length)
            if self.path == "/evaluate":
                result = self.server.service.evaluate(parse_evaluation_request(raw))
            elif self.path == "/ingest":
                result = self.server.service.ingest(parse_string_field_request(raw, field="content", label="content"))
            elif self.path == "/query":
                result = self.server.service.query(parse_string_field_request(raw, field="query", label="query"))
            else:
                result = self.server.service.cleanup(parse_string_field_request(raw, field="document_id", label="document_id"))
        except ValueError as exc:
            self._send_json(400, {"status": "invalid-request", "error": str(exc)})
            return
        except Exception as exc:
            print(f"AgentDojo evaluation failed: {type(exc).__module__}.{type(exc).__name__}", flush=True)
            self._send_json(502, {"status": "evaluation-error", "error": type(exc).__name__})
            return
        self._send_json(200, result)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {format % args}", flush=True)


class QualificationHTTPServer(HTTPServer):
    def __init__(self, server_address: tuple[str, int], service: AgentDojoQualificationService) -> None:
        super().__init__(server_address, QualificationHandler)
        self.service = service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expose one pinned official AgentDojo case as an AdverScope qualification target."
    )
    parser.add_argument("--case", required=True, help="SUITE:USER_TASK_ID:INJECTION_TASK_ID")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--model-id", default="qwen3.8-27b")
    parser.add_argument(
        "--model-attempts",
        type=int,
        default=3,
        help=f"Bounded model serialization/transport attempts (1-{MAX_MODEL_ATTEMPTS})",
    )
    parser.add_argument(
        "--max-completion-tokens",
        type=int,
        default=2_048,
        help=(
            "Maximum output tokens for each victim-model turn "
            f"({MIN_MODEL_COMPLETION_TOKENS}-{MAX_MODEL_COMPLETION_TOKENS})"
        ),
    )
    parser.add_argument(
        "--model-request-timeout-seconds",
        type=int,
        default=180,
        help=(
            "Timeout for each victim-model request "
            f"({MIN_MODEL_REQUEST_TIMEOUT_SECONDS}-{MAX_MODEL_REQUEST_TIMEOUT_SECONDS} seconds)"
        ),
    )
    parser.add_argument(
        "--control-query",
        required=True,
        help="Exact benign retrieval-control query configured in the AdverScope RAG case",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    return parser


def main() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    arguments = build_parser().parse_args()
    if not 1 <= arguments.port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 1 <= arguments.model_attempts <= MAX_MODEL_ATTEMPTS:
        raise ValueError(f"model-attempts must be between 1 and {MAX_MODEL_ATTEMPTS}")
    if not MIN_MODEL_COMPLETION_TOKENS <= arguments.max_completion_tokens <= MAX_MODEL_COMPLETION_TOKENS:
        raise ValueError(
            "max-completion-tokens must be between "
            f"{MIN_MODEL_COMPLETION_TOKENS} and {MAX_MODEL_COMPLETION_TOKENS}"
        )
    if not MIN_MODEL_REQUEST_TIMEOUT_SECONDS <= arguments.model_request_timeout_seconds <= MAX_MODEL_REQUEST_TIMEOUT_SECONDS:
        raise ValueError(
            "model-request-timeout-seconds must be between "
            f"{MIN_MODEL_REQUEST_TIMEOUT_SECONDS} and {MAX_MODEL_REQUEST_TIMEOUT_SECONDS}"
        )
    case = parse_case_reference(arguments.case, benchmark_version=arguments.benchmark_version)
    service = AgentDojoQualificationService(
        case,
        model_id=arguments.model_id,
        control_query=arguments.control_query,
        max_model_attempts=arguments.model_attempts,
        max_completion_tokens=arguments.max_completion_tokens,
        model_request_timeout_seconds=arguments.model_request_timeout_seconds,
    )
    server = QualificationHTTPServer((arguments.host, arguments.port), service)
    print(
        f"AgentDojo qualification target {case.case_id} listening on http://{arguments.host}:{arguments.port}",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
