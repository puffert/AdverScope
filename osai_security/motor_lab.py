"""Local, installation-scoped human review and motor experiment workspace."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Iterable

from .motor_dataset import (
    MotorDatasetError,
    effective_review_decisions,
    sanitize_text,
    validate_dataset_release,
    validate_sft_messages,
)
from .motor_training import (
    MotorTrainingError,
    audit_dataset_tokens,
    default_experiment_config,
    dependency_status,
    validate_experiment_config,
)
from .owasp import TECHNIQUE_INDEX
from .release import MOTOR_REVIEW_SCHEMA_VERSION


DATASET_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{2,79}")
RECORD_ID_PATTERN = re.compile(r"motor_[0-9a-f]{24}")
REVIEWER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,79}")
TRACE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,119}")
REVIEW_STATUSES = {"accepted", "corrected", "rejected"}
REVIEW_CHECKS = ("scope_correct", "output_contract_correct", "label_correct", "safe_for_training")
OPERATOR_SOURCE_ID = "adverscope-operator-reviewed"
RESERVED_TARGET_FAMILY_MARKERS = (
    "agentdojo", "ai-goat", "aigoat", "bipia", "cyberseceval", "jailbreakbench",
    "private-internal", "portswigger", "tensor-trust", "tensortrust", "web-security-academy",
)


class MotorLabError(ValueError):
    """Raised when review state or experiment configuration fails closed."""


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    _atomic_text(path, "".join(_stable_json(record) + "\n" for record in records))


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MotorLabError(f"could not read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise MotorLabError(f"{path.name} must contain a JSON object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise MotorLabError(f"{path.name} line {line_number} is invalid JSON") from exc
            if not isinstance(value, dict):
                raise MotorLabError(f"{path.name} line {line_number} must contain an object")
            records.append(value)
    return records


def _sanitize_value(value: Any) -> tuple[Any, Counter[str]]:
    if isinstance(value, str):
        clean, counts = sanitize_text(value)
        return clean, Counter(counts)
    if isinstance(value, list):
        result = []
        counts: Counter[str] = Counter()
        for item in value:
            clean, item_counts = _sanitize_value(item)
            result.append(clean)
            counts.update(item_counts)
        return result, counts
    if isinstance(value, dict):
        result_dict: dict[str, Any] = {}
        counts = Counter()
        for key, item in value.items():
            clean, item_counts = _sanitize_value(item)
            result_dict[str(key)] = clean
            counts.update(item_counts)
        return result_dict, counts
    return value, Counter()


class MotorLabService:
    """File-backed, tamper-evident review state outside client projects."""

    def __init__(self, training_root: Path):
        self.training_root = training_root.expanduser().resolve()
        self.state_root = self.training_root / "motor-lab"
        self.review_root = self.state_root / "reviews"
        self.trace_root = self.training_root / "sources" / OPERATOR_SOURCE_ID
        self.experiment_root = self.state_root / "experiments"
        for path in (self.training_root, self.review_root, self.trace_root, self.experiment_root):
            path.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _dataset_directories(self) -> list[Path]:
        directories: list[Path] = []
        self._dataset_discovery_errors: list[dict[str, str]] = []
        try:
            candidates = list(self.training_root.iterdir())
        except OSError:
            self._dataset_discovery_errors.append({
                "dataset_id": "training-root",
                "error": "training dataset directory is not readable",
            })
            return directories
        for path in candidates:
            try:
                if path.is_dir() and not path.is_symlink() and (path / "manifest.json").is_file():
                    directories.append(path.resolve())
            except OSError:
                self._dataset_discovery_errors.append({
                    "dataset_id": path.name,
                    "error": "dataset release is not readable by the AdverScope process",
                })
        return sorted(directories)

    def _dataset(self, dataset_id: str) -> tuple[Path, dict[str, Any]]:
        if not DATASET_ID_PATTERN.fullmatch(dataset_id):
            raise MotorLabError("invalid dataset ID")
        matches: list[tuple[Path, dict[str, Any]]] = []
        for path in self._dataset_directories():
            manifest = _load_json(path / "manifest.json")
            if str(manifest.get("dataset_id") or "") == dataset_id:
                matches.append((path, manifest))
        if not matches:
            raise MotorLabError("dataset release not found")
        if len(matches) > 1:
            raise MotorLabError("multiple dataset releases share this dataset ID; retain unique dataset IDs")
        return matches[0]

    @staticmethod
    def _review_queue_path(directory: Path, manifest: dict[str, Any]) -> Path:
        relative = next(
            (str(item.get("path") or "") for item in manifest.get("files") or [] if str(item.get("path") or "").endswith("review/review-queue.jsonl")),
            "",
        )
        if not relative:
            raise MotorLabError("dataset manifest does not declare a review queue")
        candidate = (directory / relative).resolve()
        try:
            candidate.relative_to(directory.resolve())
        except ValueError as exc:
            raise MotorLabError("dataset review path escapes its release") from exc
        if not candidate.is_file() or candidate.is_symlink():
            raise MotorLabError("dataset review queue is unavailable")
        return candidate

    def _queue(self, dataset_id: str) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
        directory, manifest = self._dataset(dataset_id)
        validation = validate_dataset_release(directory, expected_dataset_id=dataset_id, verify_manifest_hashes=True)
        if validation["status"] != "passed":
            raise MotorLabError("dataset release failed integrity validation")
        records = _load_jsonl(self._review_queue_path(directory, manifest))
        ids = [str(item.get("record_id") or "") for item in records]
        if not ids or len(ids) != len(set(ids)) or any(not RECORD_ID_PATTERN.fullmatch(item) for item in ids):
            raise MotorLabError("dataset review queue has invalid record identities")
        return directory, manifest, records

    def _release_sha256(self, dataset_id: str) -> str:
        directory, _manifest = self._dataset(dataset_id)
        return _sha256_file(directory / "manifest.json")

    def _review_path(self, dataset_id: str, release_sha256: str | None = None) -> Path:
        release_hash = release_sha256 or self._release_sha256(dataset_id)
        return self.review_root / dataset_id / release_hash / "review-events.jsonl"

    def _review_overlay_path(self, dataset_id: str, release_sha256: str | None = None) -> Path:
        release_hash = release_sha256 or self._release_sha256(dataset_id)
        return self.review_root / dataset_id / release_hash / "review-overlay.json"

    def _review_events(self, dataset_id: str, release_sha256: str | None = None) -> list[dict[str, Any]]:
        events = _load_jsonl(self._review_path(dataset_id, release_sha256))
        previous = ""
        for index, event in enumerate(events, start=1):
            if int(event.get("schema_version") or 0) != MOTOR_REVIEW_SCHEMA_VERSION:
                raise MotorLabError(f"review journal event {index} has an unsupported schema")
            if event.get("dataset_id") != dataset_id or event.get("previous_event_sha256") != previous:
                raise MotorLabError(f"review journal chain failed at event {index}")
            expected = str(event.get("event_sha256") or "")
            unsigned = {key: value for key, value in event.items() if key != "event_sha256"}
            observed = _sha256_bytes(_stable_json(unsigned).encode("utf-8"))
            if expected != observed:
                raise MotorLabError(f"review journal integrity failed at event {index}")
            previous = expected
        return events

    @staticmethod
    def _current_decisions(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return effective_review_decisions(events)

    @staticmethod
    def _decision_status(decision: dict[str, Any] | None, task: str) -> str:
        if decision is None:
            return "pending"
        status = str(decision.get("status") or "pending")
        if status == "rejected" and all(decision.get(name) is True for name in REVIEW_CHECKS):
            return "review-conflict"
        if task == "response-evaluation" and status in {"accepted", "corrected"} and decision.get("gold_ready") is not True:
            return "second-review"
        return status

    def datasets(self) -> dict[str, Any]:
        datasets = []
        trace_summary = self.operator_trace_summary()
        directories = self._dataset_directories()
        for directory in directories:
            try:
                manifest = _load_json(directory / "manifest.json")
                dataset_id = str(manifest.get("dataset_id") or "")
                if not DATASET_ID_PATTERN.fullmatch(dataset_id):
                    continue
                _directory, _manifest, queue = self._queue(dataset_id)
                release_sha256 = _sha256_file(directory / "manifest.json")
                reviewed_release = isinstance(manifest.get("review_overlay"), dict)
                operator_records = int(
                    (((manifest.get("counts") or {}).get("sources") or {}).get(OPERATOR_SOURCE_ID) or 0)
                )
                if reviewed_release:
                    review_summary = manifest["review_overlay"]
                    counts = Counter({
                        "accepted": int((review_summary.get("counts") or {}).get("accepted") or 0),
                        "corrected": int((review_summary.get("counts") or {}).get("corrected") or 0),
                        "rejected": int((review_summary.get("counts") or {}).get("rejected") or 0),
                    })
                    pending = 0
                    complete = True
                    total = int(review_summary.get("decisions") or sum(counts.values()))
                else:
                    events = self._review_events(dataset_id, release_sha256)
                    decisions = self._current_decisions(events)
                    statuses = [self._decision_status(decisions.get(str(item["record_id"])), str(item.get("task") or "")) for item in queue]
                    counts = Counter(statuses)
                    pending = counts["pending"] + counts["second-review"] + counts["review-conflict"]
                    complete = len(queue) > 0 and pending == 0
                    total = len(queue)
                overlay_path = (
                    directory / "provenance" / "review-overlay.json"
                    if reviewed_release
                    else self._review_overlay_path(dataset_id, release_sha256)
                )
                datasets.append({
                    "dataset_id": dataset_id,
                    "dataset_version": str(manifest.get("dataset_version") or ""),
                    "status": str(manifest.get("status") or ""),
                    "records": sum(int(item) for item in (manifest.get("counts") or {}).get("splits", {}).values()),
                    "reviewed_release": reviewed_release,
                    "experiment_ready": reviewed_release and operator_records > 0,
                    "review": {
                        "total": total,
                        "pending": pending,
                        "second_review": counts["second-review"],
                        "conflicts": counts["review-conflict"],
                        "accepted": counts["accepted"],
                        "corrected": counts["corrected"],
                        "rejected": counts["rejected"],
                        "complete": complete,
                        "overlay_path": str(overlay_path) if overlay_path.is_file() else "",
                        "operator_records": operator_records,
                        "operator_update_available": reviewed_release and int(trace_summary["records"]) > operator_records,
                    },
                })
            except (MotorLabError, MotorDatasetError) as exc:
                datasets.append({"dataset_id": directory.name, "dataset_version": "", "status": "invalid", "error": str(exc)})
        return {
            "datasets": datasets,
            "discovery_errors": list(getattr(self, "_dataset_discovery_errors", [])),
            "dependencies": dependency_status(),
            "operator_traces": trace_summary,
            "experiments": self.list_experiments()["experiments"],
        }

    def review_records(
        self,
        dataset_id: str,
        *,
        status: str = "",
        task: str = "",
        source_id: str = "",
        query: str = "",
        offset: int = 0,
        limit: int = 20,
    ) -> dict[str, Any]:
        _directory, manifest, queue = self._queue(dataset_id)
        reviewed_release = isinstance(manifest.get("review_overlay"), dict)
        events = [] if reviewed_release else self._review_events(dataset_id)
        decisions = self._current_decisions(events)
        rows = []
        needle = query.strip().casefold()
        for record in queue:
            record_id = str(record["record_id"])
            embedded_review = record.get("review") if reviewed_release and isinstance(record.get("review"), dict) else None
            decision = embedded_review or decisions.get(record_id)
            current_status = str(decision.get("status") or "accepted") if reviewed_release and decision else self._decision_status(decision, str(record.get("task") or ""))
            if status and current_status != status:
                continue
            if task and str(record.get("task") or "") != task:
                continue
            if source_id and str(record.get("source_id") or "") != source_id:
                continue
            if needle and needle not in _stable_json(record).casefold() and needle not in _stable_json(decision or {}).casefold():
                continue
            rows.append({**record, "current_status": current_status, "decision": decision})
        bounded_limit = max(1, min(100, int(limit)))
        bounded_offset = max(0, int(offset))
        task_counts = Counter(str(item.get("task") or "") for item in queue)
        source_counts = Counter(str(item.get("source_id") or "") for item in queue)
        status_counts = Counter(
            str((item.get("review") or {}).get("status") or "accepted")
            if reviewed_release
            else self._decision_status(decisions.get(str(item["record_id"])), str(item.get("task") or ""))
            for item in queue
        )
        return {
            "dataset": {
                "dataset_id": dataset_id,
                "dataset_version": str(manifest.get("dataset_version") or ""),
                "manifest_sha256": _sha256_file(self._dataset(dataset_id)[0] / "manifest.json"),
            },
            "records": rows[bounded_offset:bounded_offset + bounded_limit],
            "pagination": {"offset": bounded_offset, "limit": bounded_limit, "total": len(rows)},
            "read_only": reviewed_release,
            "counts": {
                "statuses": dict(sorted(status_counts.items())),
                "tasks": dict(sorted(task_counts.items())),
                "sources": dict(sorted(source_counts.items())),
            },
        }

    def save_review(self, dataset_id: str, record_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not RECORD_ID_PATTERN.fullmatch(record_id):
            raise MotorLabError("invalid review record ID")
        _directory, manifest, queue = self._queue(dataset_id)
        if isinstance(manifest.get("review_overlay"), dict):
            raise MotorLabError("this dataset is an immutable reviewed release; review its next version instead")
        original = next((item for item in queue if str(item["record_id"]) == record_id), None)
        if original is None:
            raise MotorLabError("review record not found")
        status = str(payload.get("status") or "")
        reviewer_id = str(payload.get("reviewer_id") or "").strip()
        if status not in REVIEW_STATUSES:
            raise MotorLabError("review status must be accepted, corrected, or rejected")
        if not REVIEWER_ID_PATTERN.fullmatch(reviewer_id):
            raise MotorLabError("reviewer ID must be a non-secret identifier of at least three characters")
        checks = {name: payload.get(name) for name in REVIEW_CHECKS}
        if any(value not in {True, False} for value in checks.values()):
            raise MotorLabError("every review check requires an explicit yes or no decision")
        if status in {"accepted", "corrected"} and not all(checks.values()):
            raise MotorLabError("accepted and corrected records require all four review checks to pass")
        notes, note_redactions = sanitize_text(str(payload.get("notes") or ""), maximum_characters=4000)
        if status == "rejected" and len(notes.strip()) < 4:
            raise MotorLabError("rejected records require a short explanation")
        if status == "rejected" and all(checks.values()):
            raise MotorLabError("rejected records require at least one failed review check")
        corrected_assistant: dict[str, Any] | None = None
        corrected_labels: dict[str, Any] | None = None
        redactions: Counter[str] = Counter(note_redactions)
        if status == "corrected":
            raw_assistant = payload.get("corrected_assistant")
            if isinstance(raw_assistant, str):
                try:
                    raw_assistant = json.loads(raw_assistant)
                except json.JSONDecodeError as exc:
                    raise MotorLabError("corrected assistant output must be valid JSON") from exc
            if not isinstance(raw_assistant, dict):
                raise MotorLabError("corrected assistant output must be a JSON object")
            corrected_assistant, assistant_redactions = _sanitize_value(raw_assistant)
            redactions.update(assistant_redactions)
            corrected_messages = [*original["messages"][:2], {"role": "assistant", "content": _stable_json(corrected_assistant)}]
            try:
                validate_sft_messages(str(original["task"]), corrected_messages)
            except MotorDatasetError as exc:
                raise MotorLabError(f"corrected assistant output violates the {original['task']} contract: {exc}") from exc
            supplied_techniques = payload.get("corrected_technique_ids")
            if supplied_techniques is None and str(original["task"]) == "guided-planning":
                supplied_techniques = corrected_assistant.get("selected_technique_ids")
            if supplied_techniques is None and str(original["task"]) == "content-triage":
                supplied_techniques = corrected_assistant.get("technique_ids")
            if supplied_techniques is None:
                supplied_techniques = (original.get("labels") or {}).get("technique_ids") or []
            if not isinstance(supplied_techniques, list):
                raise MotorLabError("corrected technique labels must be an array")
            technique_ids = sorted({str(item) for item in supplied_techniques if str(item)})
            unknown = [item for item in technique_ids if item not in TECHNIQUE_INDEX]
            if unknown:
                raise MotorLabError("corrected labels contain unknown technique IDs: " + ", ".join(unknown))
            hard_negative = payload.get("corrected_hard_negative")
            if hard_negative is None:
                hard_negative = bool((original.get("labels") or {}).get("hard_negative"))
            if hard_negative not in {True, False}:
                raise MotorLabError("corrected records require an explicit hard-negative label")
            corrected_labels = {"technique_ids": technique_ids, "hard_negative": hard_negative}
        with self._lock:
            events = self._review_events(dataset_id)
            current = self._current_decisions(events).get(record_id)
            expected_version = int(payload.get("expected_version") or 0)
            observed_version = int((current or {}).get("version") or 0)
            if expected_version != observed_version:
                raise MotorLabError("review changed since it was opened; reload before saving")
            task = str(original.get("task") or "")
            if status == "rejected":
                review_stage = "rejected"
                gold_ready = True
                primary_reviewer_id = reviewer_id
                secondary_reviewer_id = ""
            elif task != "response-evaluation":
                review_stage = "single"
                gold_ready = True
                primary_reviewer_id = reviewer_id
                secondary_reviewer_id = ""
            elif current and current.get("gold_ready") is not True and str(current.get("status") or "") in {"accepted", "corrected"} and str(current.get("reviewer_id") or "") != reviewer_id:
                review_stage = "secondary"
                gold_ready = True
                primary_reviewer_id = str(current.get("primary_reviewer_id") or current.get("reviewer_id") or "")
                secondary_reviewer_id = reviewer_id
            else:
                review_stage = "primary"
                gold_ready = False
                primary_reviewer_id = reviewer_id
                secondary_reviewer_id = ""
            recorded_status = status
            inherited_correction_event_id = ""
            inherited_correction_event_sha256 = ""
            if status == "accepted" and current and str(current.get("status") or "") == "corrected":
                inherited_assistant = current.get("corrected_assistant")
                inherited_labels = current.get("corrected_labels")
                if not isinstance(inherited_assistant, dict) or not isinstance(inherited_labels, dict):
                    raise MotorLabError("the correction being accepted is incomplete; reload and save an explicit correction")
                recorded_status = "corrected"
                corrected_assistant = inherited_assistant
                corrected_labels = inherited_labels
                redactions.update(current.get("redactions") or {})
                inherited_correction_event_id = str(current.get("event_id") or "")
                inherited_correction_event_sha256 = str(current.get("event_sha256") or "")
            unsigned = {
                "schema_version": MOTOR_REVIEW_SCHEMA_VERSION,
                "event_id": "rev_" + os.urandom(12).hex(),
                "dataset_id": dataset_id,
                "dataset_version": str(manifest.get("dataset_version") or ""),
                "dataset_manifest_sha256": _sha256_file(self._dataset(dataset_id)[0] / "manifest.json"),
                "record_id": record_id,
                "task": task,
                "original_record_sha256": _sha256_bytes(_stable_json(original).encode("utf-8")),
                "version": observed_version + 1,
                "status": recorded_status,
                "review_action": status,
                "reviewer_id": reviewer_id,
                "review_stage": review_stage,
                "gold_ready": gold_ready,
                "primary_reviewer_id": primary_reviewer_id,
                "secondary_reviewer_id": secondary_reviewer_id,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                **checks,
                "notes": notes,
                "corrected_assistant": corrected_assistant,
                "corrected_labels": corrected_labels,
                "inherited_correction_event_id": inherited_correction_event_id,
                "inherited_correction_event_sha256": inherited_correction_event_sha256,
                "redactions": dict(sorted(redactions.items())),
                "previous_event_sha256": str(events[-1]["event_sha256"]) if events else "",
            }
            event = {**unsigned, "event_sha256": _sha256_bytes(_stable_json(unsigned).encode("utf-8"))}
            events.append(event)
            _write_jsonl(self._review_path(dataset_id), events)
            overlay = self.review_overlay(dataset_id)
            _atomic_json(self._review_overlay_path(dataset_id), overlay)
        return {**event, "current_status": self._decision_status(event, task), "review_complete": bool(overlay["complete"])}

    def review_overlay(self, dataset_id: str) -> dict[str, Any]:
        directory, manifest, queue = self._queue(dataset_id)
        events = self._review_events(dataset_id)
        decisions = self._current_decisions(events)
        ordered = [decisions[str(item["record_id"])] for item in queue if str(item["record_id"]) in decisions]
        queue_by_id = {str(item["record_id"]): item for item in queue}
        counts = Counter(self._decision_status(item, str(queue_by_id[str(item["record_id"])].get("task") or "")) for item in ordered)
        complete = len(ordered) == len(queue) and all(
            item.get("gold_ready") is True
            and self._decision_status(item, str(queue_by_id[str(item["record_id"])].get("task") or "")) != "review-conflict"
            for item in ordered
        )
        return {
            "schema_version": MOTOR_REVIEW_SCHEMA_VERSION,
            "dataset_id": dataset_id,
            "dataset_version": str(manifest.get("dataset_version") or ""),
            "dataset_manifest_sha256": _sha256_file(directory / "manifest.json"),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "queue_records": len(queue),
            "decided_records": len(ordered),
            "complete": complete,
            "counts": dict(sorted(counts.items())),
            "events": events,
            "decisions": ordered,
        }

    def _trace_path(self) -> Path:
        return self.trace_root / "reviewed-records.jsonl"

    def _write_operator_source_manifest(self, records: list[dict[str, Any]]) -> None:
        trace_path = self._trace_path()
        manifest = {
            "schema_version": 1,
            "source_id": OPERATOR_SOURCE_ID,
            "source_kind": "operator-reviewed-jsonl",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "records": len(records),
            "reviewed_records_sha256": _sha256_file(trace_path) if trace_path.is_file() else "",
            "tasks": dict(sorted(Counter(str(item.get("task") or "") for item in records).items())),
            "target_families": sorted({str(item.get("target_family") or "") for item in records}),
            "benchmark_policy": "explicitly excluded",
        }
        _atomic_json(self.trace_root / "source-manifest.json", manifest)

    def operator_trace_summary(self) -> dict[str, Any]:
        records = _load_jsonl(self._trace_path())
        return {
            "records": len(records),
            "tasks": dict(sorted(Counter(str(item.get("task") or "") for item in records).items())),
            "target_families": len({str(item.get("target_family") or "") for item in records}),
            "path": str(self._trace_path()),
        }

    def operator_traces(self) -> dict[str, Any]:
        records = _load_jsonl(self._trace_path())
        return {"records": records, "summary": self.operator_trace_summary()}

    def add_operator_trace(self, payload: dict[str, Any]) -> dict[str, Any]:
        source_record_id = str(payload.get("source_record_id") or "trace-" + os.urandom(8).hex())
        if not TRACE_ID_PATTERN.fullmatch(source_record_id):
            raise MotorLabError("trace source_record_id contains unsupported characters")
        target_family = str(payload.get("target_family") or "").strip()
        if not TRACE_ID_PATTERN.fullmatch(target_family):
            raise MotorLabError("target_family must identify a non-benchmark synthetic target family")
        normalized_family = target_family.casefold().replace("_", "-")
        if any(marker in normalized_family for marker in RESERVED_TARGET_FAMILY_MARKERS):
            raise MotorLabError("reserved qualification and benchmark target families cannot enter motor training")
        if payload.get("benchmark_only") is not False:
            raise MotorLabError("training traces require an explicit non-benchmark declaration")
        reviewer_id = str(payload.get("reviewer_id") or "")
        if not REVIEWER_ID_PATTERN.fullmatch(reviewer_id):
            raise MotorLabError("trace reviewer ID is invalid")
        if any(payload.get(name) is not True for name in REVIEW_CHECKS):
            raise MotorLabError("operator traces require all review checks to pass")
        task = str(payload.get("task") or "")
        messages = payload.get("messages")
        if not isinstance(messages, list):
            raise MotorLabError("operator trace requires system, user, and assistant messages")
        clean_messages, redactions = _sanitize_value(messages)
        try:
            validate_sft_messages(task, clean_messages)
        except MotorDatasetError as exc:
            raise MotorLabError(f"operator trace violates the {task or 'unknown'} contract: {exc}") from exc
        technique_ids = sorted({str(item) for item in payload.get("technique_ids") or [] if str(item)})
        unknown = [item for item in technique_ids if item not in TECHNIQUE_INDEX]
        if unknown:
            raise MotorLabError("operator trace contains unknown technique IDs: " + ", ".join(unknown))
        notes, note_redactions = sanitize_text(str(payload.get("notes") or ""), maximum_characters=4000)
        redactions.update(note_redactions)
        record = {
            "source_record_id": source_record_id,
            "task": task,
            "target_family": target_family,
            "benchmark_only": False,
            "technique_ids": technique_ids,
            "dedup_text": str(clean_messages[1]["content"]),
            "hard_negative": payload.get("hard_negative") is True,
            "messages": clean_messages,
            "review": {
                "status": "accepted",
                "reviewer_id": reviewer_id,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                **{name: True for name in REVIEW_CHECKS},
                "notes": notes,
                "redactions": dict(sorted(redactions.items())),
            },
        }
        with self._lock:
            records = _load_jsonl(self._trace_path())
            if any(str(item.get("source_record_id") or "") == source_record_id for item in records):
                raise MotorLabError("operator trace source_record_id already exists")
            records.append(record)
            _write_jsonl(self._trace_path(), records)
            self._write_operator_source_manifest(records)
        return record

    def list_experiments(self) -> dict[str, Any]:
        experiments = []
        for path in sorted(self.experiment_root.iterdir()) if self.experiment_root.is_dir() else []:
            config_path = path / "experiment.json"
            if not path.is_dir() or path.is_symlink() or not config_path.is_file():
                continue
            try:
                config = validate_experiment_config(_load_json(config_path))
                audit = _load_json(path / "tokenizer-audit.json") if (path / "tokenizer-audit.json").is_file() else None
                training = _load_json(path / "training-result.json") if (path / "training-result.json").is_file() else None
                comparison = _load_json(path / "comparison.json") if (path / "comparison.json").is_file() else None
                status = (
                    "qualified" if comparison and comparison.get("status") == "qualified"
                    else "not-qualified" if comparison
                    else "trained-unqualified" if training
                    else "audit-passed" if audit and audit.get("status") == "passed"
                    else "audit-failed" if audit
                    else "draft"
                )
                experiments.append({
                    "experiment_id": config["experiment_id"],
                    "dataset_id": config["dataset"]["dataset_id"],
                    "base_model": config["model"]["base_model"],
                    "model_revision": config["model"]["revision"],
                    "max_sequence_tokens": config["tokenizer"]["max_sequence_tokens"],
                    "status": status,
                    "audit": audit,
                    "training": training,
                    "comparison": comparison,
                })
            except (MotorTrainingError, MotorLabError) as exc:
                experiments.append({"experiment_id": path.name, "status": "invalid", "error": str(exc)})
        return {"experiments": experiments}

    def create_experiment(self, payload: dict[str, Any]) -> dict[str, Any]:
        experiment_id = str(payload.get("experiment_id") or "")
        dataset_id = str(payload.get("dataset_id") or "")
        directory, manifest = self._dataset(dataset_id)
        if str(manifest.get("status") or "") != "review-sample-complete" or not isinstance(manifest.get("review_overlay"), dict):
            raise MotorLabError("create a reviewed dataset release before starting a motor experiment")
        operator_source = next(
            (item for item in manifest.get("sources") or [] if str(item.get("source_id") or "") == OPERATOR_SOURCE_ID),
            None,
        )
        retained_operator_records = int(
            (((manifest.get("counts") or {}).get("sources") or {}).get(OPERATOR_SOURCE_ID) or 0)
        )
        if (
            not operator_source
            or int(operator_source.get("retained_after_cap") or 0) < 1
            or retained_operator_records < 1
        ):
            raise MotorLabError("the reviewed release must contain accepted non-benchmark operator trajectories")
        config = default_experiment_config(
            experiment_id=experiment_id,
            dataset_directory=directory,
            dataset_id=dataset_id,
            dataset_version=str(manifest.get("dataset_version") or ""),
            base_model=str(payload.get("base_model") or ""),
            model_revision=str(payload.get("model_revision") or ""),
            max_sequence_tokens=int(payload.get("max_sequence_tokens") or 4096),
        )
        for section in ("qlora", "training", "qualification"):
            overrides = payload.get(section)
            if overrides is not None:
                if not isinstance(overrides, dict):
                    raise MotorLabError(f"{section} overrides must be an object")
                unknown = set(overrides) - set(config[section])
                if unknown:
                    raise MotorLabError(f"{section} contains unsupported settings: {', '.join(sorted(unknown))}")
                config[section].update(overrides)
        validate_experiment_config(config)
        target = self.experiment_root / experiment_id
        with self._lock:
            if target.exists():
                raise MotorLabError("experiment ID already exists")
            target.mkdir(parents=True)
            _atomic_json(target / "experiment.json", config)
        return self.experiment(experiment_id)

    def _experiment_directory(self, experiment_id: str) -> Path:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,79}", experiment_id):
            raise MotorLabError("invalid experiment ID")
        path = (self.experiment_root / experiment_id).resolve()
        try:
            path.relative_to(self.experiment_root.resolve())
        except ValueError as exc:
            raise MotorLabError("experiment path escapes the motor lab") from exc
        if not path.is_dir() or path.is_symlink():
            raise MotorLabError("experiment not found")
        return path

    def experiment(self, experiment_id: str) -> dict[str, Any]:
        path = self._experiment_directory(experiment_id)
        config = validate_experiment_config(_load_json(path / "experiment.json"))
        audit = _load_json(path / "tokenizer-audit.json") if (path / "tokenizer-audit.json").is_file() else None
        training = _load_json(path / "training-result.json") if (path / "training-result.json").is_file() else None
        comparison = _load_json(path / "comparison.json") if (path / "comparison.json").is_file() else None
        quoted = '"' + str(path / "experiment.json") + '"'
        return {
            "config": config,
            "audit": audit,
            "training": training,
            "comparison": comparison,
            "commands": {
                "install": 'uv sync --extra training',
                "audit": f"uv run --extra training python scripts/run_motor_experiment.py audit --experiment {quoted}",
                "train": f"uv run --extra training python scripts/run_motor_experiment.py train --experiment {quoted}",
                "qualification": "Serve the saved adapter as a separate AdverScope model profile, run the frozen attack and evaluator corpora at least three times, then use the compare command documented in training/README.md.",
            },
        }

    def audit_experiment(self, experiment_id: str) -> dict[str, Any]:
        path = self._experiment_directory(experiment_id)
        config = validate_experiment_config(_load_json(path / "experiment.json"))
        report = audit_dataset_tokens(config)
        _atomic_json(path / "tokenizer-audit.json", report)
        return report
