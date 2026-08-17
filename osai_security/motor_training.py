"""Tokenizer audit, QLoRA training, and qualification comparison for the motor.

Heavy training dependencies are imported lazily so the normal AdverScope
application remains lightweight.  Training is always tied to a validated
dataset release, a pinned model revision, and a passing tokenizer audit.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import tempfile
from typing import Any, Callable, Iterable

from .motor_dataset import MotorDatasetError, validate_dataset_release
from .release import (
    MOTOR_EXPERIMENT_SCHEMA_VERSION,
    MODEL_COMPARISON_SCHEMA_VERSION,
    TOKENIZER_AUDIT_SCHEMA_VERSION,
)


TRAINING_PACKAGES = ("accelerate", "bitsandbytes", "datasets", "peft", "torch", "transformers", "trl")
EXPERIMENT_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{2,79}")
REMOTE_MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
PINNED_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")


class MotorTrainingError(ValueError):
    """Raised when a model-development action cannot proceed safely."""


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


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _contains_secret_field(value: Any) -> bool:
    forbidden = {"api_key", "password", "token", "private_key", "cookie", "authorization", "access_key"}
    if isinstance(value, dict):
        return any(str(key).casefold() in forbidden or _contains_secret_field(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret_field(item) for item in value)
    return False


def dependency_status() -> dict[str, Any]:
    packages: dict[str, dict[str, Any]] = {}
    for name in TRAINING_PACKAGES:
        installed = importlib.util.find_spec(name) is not None
        version = ""
        if installed:
            try:
                version = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                version = "unknown"
        packages[name] = {"installed": installed, "version": version}
    cuda = {"available": False, "device_count": 0, "bf16_supported": False, "devices": []}
    if packages["torch"]["installed"]:
        try:
            import torch

            cuda["available"] = bool(torch.cuda.is_available())
            cuda["device_count"] = int(torch.cuda.device_count()) if cuda["available"] else 0
            cuda["bf16_supported"] = bool(torch.cuda.is_bf16_supported()) if cuda["available"] else False
            cuda["devices"] = [str(torch.cuda.get_device_name(index)) for index in range(cuda["device_count"])]
        except Exception as exc:  # dependency diagnostics must remain usable after a broken install
            cuda["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"
    return {
        "ready_for_tokenizer_audit": packages["transformers"]["installed"],
        "ready_for_qlora": all(item["installed"] for item in packages.values()) and cuda["available"],
        "packages": packages,
        "cuda": cuda,
        "platform": platform.platform(),
    }

def default_experiment_config(
    *,
    experiment_id: str,
    dataset_directory: Path,
    dataset_id: str,
    dataset_version: str,
    base_model: str,
    model_revision: str,
    max_sequence_tokens: int = 4096,
) -> dict[str, Any]:
    return validate_experiment_config({
        "schema_version": MOTOR_EXPERIMENT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "dataset": {
            "directory": str(dataset_directory.resolve()),
            "dataset_id": dataset_id,
            "dataset_version": dataset_version,
        },
        "model": {
            "base_model": base_model,
            "revision": model_revision,
            "trust_remote_code": False,
        },
        "tokenizer": {
            "max_sequence_tokens": max_sequence_tokens,
            "maximum_overflow_fraction": 0.0,
        },
        "qlora": {
            "load_in_4bit": True,
            "quant_type": "nf4",
            "double_quant": True,
            "compute_dtype": "bfloat16",
            "target_modules": "all-linear",
            "rank": 32,
            "alpha": 64,
            "dropout": 0.05,
        },
        "training": {
            "epochs": 2.0,
            "learning_rate": 0.0002,
            "per_device_train_batch_size": 1,
            "per_device_eval_batch_size": 1,
            "gradient_accumulation_steps": 16,
            "warmup_ratio": 0.03,
            "weight_decay": 0.0,
            "logging_steps": 10,
            "eval_steps": 100,
            "save_steps": 100,
            "save_total_limit": 2,
            "seed": 2501,
            "gradient_checkpointing": True,
            "packing": False,
            "completion_only_loss": True,
        },
        "qualification": {
            "repetitions": 3,
            "minimum_attack_pass_rate": 0.95,
            "minimum_evaluator_precision": 0.95,
            "minimum_evaluator_recall": 0.95,
            "minimum_evaluator_pass_rate": 0.95,
            "maximum_latency_ratio": 1.0,
        },
    })


def validate_experiment_config(document: dict[str, Any]) -> dict[str, Any]:
    if int(document.get("schema_version") or 0) != MOTOR_EXPERIMENT_SCHEMA_VERSION:
        raise MotorTrainingError("unsupported motor experiment schema")
    experiment_id = str(document.get("experiment_id") or "")
    if not EXPERIMENT_ID_PATTERN.fullmatch(experiment_id):
        raise MotorTrainingError("experiment_id must be a lowercase slug")
    if _contains_secret_field(document):
        raise MotorTrainingError("experiment configuration must not contain credentials or secret fields")
    dataset = document.get("dataset")
    model = document.get("model")
    tokenizer = document.get("tokenizer")
    qlora = document.get("qlora")
    training = document.get("training")
    qualification = document.get("qualification")
    if not all(isinstance(item, dict) for item in (dataset, model, tokenizer, qlora, training, qualification)):
        raise MotorTrainingError("experiment requires dataset, model, tokenizer, qlora, training, and qualification objects")
    assert isinstance(dataset, dict) and isinstance(model, dict) and isinstance(tokenizer, dict)
    assert isinstance(qlora, dict) and isinstance(training, dict) and isinstance(qualification, dict)
    if not all(str(dataset.get(key) or "").strip() for key in ("directory", "dataset_id", "dataset_version")):
        raise MotorTrainingError("experiment dataset identity is incomplete")
    base_model = str(model.get("base_model") or "").strip()
    revision = str(model.get("revision") or "").strip().casefold()
    local_model = Path(base_model).expanduser().is_dir()
    if not local_model and not REMOTE_MODEL_PATTERN.fullmatch(base_model):
        raise MotorTrainingError("base_model must be a local model directory or a Hugging Face owner/model identifier")
    if not local_model and not PINNED_REVISION_PATTERN.fullmatch(revision):
        raise MotorTrainingError("remote base models require an immutable 40-character revision")
    if model.get("trust_remote_code") is not False:
        raise MotorTrainingError("motor experiments do not execute remote model code")
    max_tokens = int(tokenizer.get("max_sequence_tokens") or 0)
    if not 512 <= max_tokens <= 131072:
        raise MotorTrainingError("max_sequence_tokens must be between 512 and 131072")
    overflow_fraction = float(tokenizer.get("maximum_overflow_fraction") or 0.0)
    if not 0.0 <= overflow_fraction <= 0.05:
        raise MotorTrainingError("maximum_overflow_fraction must be between zero and 0.05")
    if qlora.get("load_in_4bit") is not True or str(qlora.get("quant_type") or "") != "nf4":
        raise MotorTrainingError("the first motor experiment requires four-bit NF4 QLoRA")
    if str(qlora.get("compute_dtype") or "") not in {"bfloat16", "float16"}:
        raise MotorTrainingError("QLoRA compute_dtype must be bfloat16 or float16")
    if str(qlora.get("target_modules") or "") != "all-linear":
        raise MotorTrainingError("QLoRA must explicitly target all linear layers")
    if not 4 <= int(qlora.get("rank") or 0) <= 256:
        raise MotorTrainingError("QLoRA rank must be between 4 and 256")
    if not 4 <= int(qlora.get("alpha") or 0) <= 1024:
        raise MotorTrainingError("QLoRA alpha must be between 4 and 1024")
    if not 0.0 <= float(qlora.get("dropout") or 0.0) <= 0.5:
        raise MotorTrainingError("QLoRA dropout must be between zero and 0.5")
    numeric_boundaries = {
        "epochs": (0.1, 20.0),
        "learning_rate": (1e-7, 0.01),
        "per_device_train_batch_size": (1, 128),
        "per_device_eval_batch_size": (1, 128),
        "gradient_accumulation_steps": (1, 1024),
        "warmup_ratio": (0.0, 0.5),
        "weight_decay": (0.0, 1.0),
        "logging_steps": (1, 100000),
        "eval_steps": (1, 100000),
        "save_steps": (1, 100000),
        "save_total_limit": (1, 100),
        "seed": (0, 2**31 - 1),
    }
    for key, (minimum, maximum) in numeric_boundaries.items():
        value = float(training.get(key))
        if not minimum <= value <= maximum:
            raise MotorTrainingError(f"training.{key} is outside the supported range")
    if training.get("completion_only_loss") is not True:
        raise MotorTrainingError("motor training must compute loss on the assistant completion only")
    if training.get("packing") not in {True, False} or training.get("gradient_checkpointing") not in {True, False}:
        raise MotorTrainingError("training packing and gradient_checkpointing must be booleans")
    repetitions = int(qualification.get("repetitions") or 0)
    if not 2 <= repetitions <= 10:
        raise MotorTrainingError("qualification repetitions must be between 2 and 10")
    for key in (
        "minimum_attack_pass_rate", "minimum_evaluator_precision", "minimum_evaluator_recall",
        "minimum_evaluator_pass_rate", "maximum_latency_ratio",
    ):
        value = float(qualification.get(key) or 0.0)
        if not 0.0 < value <= 2.0:
            raise MotorTrainingError(f"qualification.{key} must be above zero and at most two")
    return document


def _load_tokenizer(config: dict[str, Any]) -> Any:
    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise MotorTrainingError("tokenizer audit requires the AdverScope training dependencies") from exc
    model = config["model"]
    base_model = str(model["base_model"])
    local = Path(base_model).expanduser().is_dir()
    kwargs: dict[str, Any] = {"trust_remote_code": False, "use_fast": True}
    if not local:
        kwargs["revision"] = str(model["revision"])
    try:
        tokenizer = AutoTokenizer.from_pretrained(base_model, **kwargs)
    except Exception as exc:
        raise MotorTrainingError(f"could not load the pinned tokenizer: {type(exc).__name__}: {str(exc)[:300]}") from exc
    if not getattr(tokenizer, "chat_template", None):
        raise MotorTrainingError("selected tokenizer has no chat template; choose an instruction model with an explicit template")
    if getattr(tokenizer, "pad_token", None) is None:
        tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


def _tokenizer_fingerprint(tokenizer: Any) -> str:
    try:
        vocabulary = tokenizer.get_vocab()
    except Exception as exc:
        raise MotorTrainingError(f"selected tokenizer vocabulary cannot be fingerprinted: {exc}") from exc
    value = {
        "class": type(tokenizer).__name__,
        "vocabulary": vocabulary,
        "chat_template": str(getattr(tokenizer, "chat_template", "") or ""),
        "special_tokens": getattr(tokenizer, "special_tokens_map", {}),
    }
    return _sha256_bytes(_stable_json(value).encode("utf-8"))


def _record_token_count(tokenizer: Any, messages: list[dict[str, str]]) -> int:
    try:
        encoded = tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=False)
    except Exception as exc:
        raise MotorTrainingError(f"chat template could not encode a dataset record: {type(exc).__name__}: {str(exc)[:240]}") from exc
    if isinstance(encoded, dict):
        encoded = encoded.get("input_ids")
    if hasattr(encoded, "shape"):
        shape = list(encoded.shape)
        return int(shape[-1]) if shape else 0
    return len(encoded)


def _percentile(values: list[int], quantile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return int(ordered[index])


def _distribution(values: list[int]) -> dict[str, int | float]:
    return {
        "records": len(values),
        "minimum": min(values, default=0),
        "p50": _percentile(values, 0.50),
        "p90": _percentile(values, 0.90),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "maximum": max(values, default=0),
        "mean": round(sum(values) / len(values), 2) if values else 0.0,
    }


def audit_dataset_tokens(
    experiment: dict[str, Any],
    *,
    tokenizer_loader: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    validate_experiment_config(experiment)
    dataset_directory = Path(str(experiment["dataset"]["directory"])).expanduser().resolve()
    validation = validate_dataset_release(
        dataset_directory,
        expected_dataset_id=str(experiment["dataset"]["dataset_id"]),
        verify_manifest_hashes=True,
    )
    if validation["status"] != "passed":
        raise MotorTrainingError("tokenizer audit requires a valid, untampered dataset release")
    manifest_path = dataset_directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if str(manifest.get("dataset_version") or "") != str(experiment["dataset"]["dataset_version"]):
        raise MotorTrainingError("experiment dataset version does not match its manifest")
    tokenizer = (tokenizer_loader or _load_tokenizer)(experiment)
    maximum = int(experiment["tokenizer"]["max_sequence_tokens"])
    counts: list[int] = []
    by_task: dict[str, list[int]] = defaultdict(list)
    by_split: dict[str, list[int]] = defaultdict(list)
    overflow_records: list[dict[str, Any]] = []
    record_path = dataset_directory / "corpus" / "records.jsonl"
    with record_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise MotorTrainingError(f"canonical corpus line {line_number} is invalid JSON") from exc
            token_count = _record_token_count(tokenizer, record["messages"])
            counts.append(token_count)
            by_task[str(record["task"])].append(token_count)
            by_split[str(record["split"])].append(token_count)
            if token_count > maximum:
                overflow_records.append({
                    "record_id": str(record["record_id"]),
                    "task": str(record["task"]),
                    "split": str(record["split"]),
                    "tokens": token_count,
                })
    overflow_fraction = len(overflow_records) / max(1, len(counts))
    threshold = float(experiment["tokenizer"]["maximum_overflow_fraction"])
    report = {
        "schema_version": TOKENIZER_AUDIT_SCHEMA_VERSION,
        "experiment_id": experiment["experiment_id"],
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if overflow_fraction <= threshold else "failed",
        "dataset": {
            "dataset_id": manifest["dataset_id"],
            "dataset_version": manifest["dataset_version"],
            "manifest_sha256": _sha256_file(manifest_path),
            "records_sha256": _sha256_file(record_path),
        },
        "model": {
            "base_model": experiment["model"]["base_model"],
            "revision": experiment["model"]["revision"],
            "tokenizer_class": type(tokenizer).__name__,
            "tokenizer_fingerprint_sha256": _tokenizer_fingerprint(tokenizer),
        },
        "maximum_sequence_tokens": maximum,
        "counts": {
            "records": len(counts),
            "overflow_records": len(overflow_records),
            "overflow_fraction": round(overflow_fraction, 8),
        },
        "distribution": _distribution(counts),
        "by_task": {key: _distribution(value) for key, value in sorted(by_task.items())},
        "by_split": {key: _distribution(value) for key, value in sorted(by_split.items())},
        "overflow_records": sorted(overflow_records, key=lambda item: (-int(item["tokens"]), str(item["record_id"]))),
        "gates": [{
            "id": "no-silent-truncation",
            "passed": overflow_fraction <= threshold,
            "value": round(overflow_fraction, 8),
            "threshold": threshold,
        }],
    }
    return report


def write_tokenizer_audit(
    experiment_path: Path,
    *,
    output_path: Path | None = None,
    tokenizer_loader: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    experiment_path = experiment_path.expanduser().resolve()
    experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
    report = audit_dataset_tokens(experiment, tokenizer_loader=tokenizer_loader)
    target = output_path.expanduser().resolve() if output_path else experiment_path.parent / "tokenizer-audit.json"
    _atomic_json(target, report)
    return report


def _require_training_dependencies() -> None:
    status = dependency_status()
    missing = [name for name, item in status["packages"].items() if not item["installed"]]
    if missing:
        raise MotorTrainingError("QLoRA dependencies are missing: " + ", ".join(missing))
    if not status["cuda"]["available"]:
        raise MotorTrainingError("QLoRA training requires an available CUDA device")


def _read_sft_as_prompt_completion(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise MotorTrainingError(f"SFT file {path.name} line {line_number} is invalid JSON") from exc
            messages = item.get("messages") if isinstance(item, dict) else None
            if not isinstance(messages, list) or [message.get("role") for message in messages] != ["system", "user", "assistant"]:
                raise MotorTrainingError(f"SFT file {path.name} line {line_number} has an invalid message contract")
            rows.append({
                "prompt": messages[:2],
                "completion": messages[2:],
                "record_id": str(item.get("record_id") or ""),
                "task": str(item.get("task") or ""),
            })
    return rows


def _dependency_versions() -> dict[str, str]:
    result: dict[str, str] = {}
    for name in TRAINING_PACKAGES:
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = "missing"
    return result


def _artifact_hashes(root: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative.startswith("checkpoint-"):
            continue
        artifacts.append({"path": relative, "bytes": path.stat().st_size, "sha256": _sha256_file(path)})
    return artifacts


def run_qlora_experiment(
    experiment_path: Path,
    *,
    resume_from_checkpoint: str | bool | None = None,
) -> dict[str, Any]:
    """Execute a validated QLoRA experiment using current TRL/PEFT contracts."""

    _require_training_dependencies()
    experiment_path = experiment_path.expanduser().resolve()
    experiment = validate_experiment_config(json.loads(experiment_path.read_text(encoding="utf-8")))
    audit_path = experiment_path.parent / "tokenizer-audit.json"
    if not audit_path.is_file():
        raise MotorTrainingError("run the tokenizer audit before QLoRA training")
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if audit.get("status") != "passed" or audit.get("experiment_id") != experiment["experiment_id"]:
        raise MotorTrainingError("QLoRA training requires a passing audit for this exact experiment")
    dataset_directory = Path(str(experiment["dataset"]["directory"])).expanduser().resolve()
    manifest_path = dataset_directory / "manifest.json"
    if _sha256_file(manifest_path) != str(audit.get("dataset", {}).get("manifest_sha256") or ""):
        raise MotorTrainingError("dataset changed after tokenizer audit")
    validation = validate_dataset_release(dataset_directory, expected_dataset_id=experiment["dataset"]["dataset_id"])
    if validation["status"] != "passed":
        raise MotorTrainingError("QLoRA training requires an untampered dataset release")

    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import BitsAndBytesConfig
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        raise MotorTrainingError("QLoRA training dependencies are incomplete") from exc

    qlora = experiment["qlora"]
    training = experiment["training"]
    if qlora["compute_dtype"] == "bfloat16" and not torch.cuda.is_bf16_supported():
        raise MotorTrainingError("the configured CUDA device does not support bfloat16; explicitly choose float16 and re-audit")
    compute_dtype = torch.bfloat16 if qlora["compute_dtype"] == "bfloat16" else torch.float16
    tokenizer = _load_tokenizer(experiment)
    train_dataset = Dataset.from_list(_read_sft_as_prompt_completion(dataset_directory / "sft" / "train.jsonl"))
    validation_dataset = Dataset.from_list(_read_sft_as_prompt_completion(dataset_directory / "sft" / "validation.jsonl"))
    adapter_directory = experiment_path.parent / "adapter"
    adapter_directory.mkdir(parents=True, exist_ok=True)
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=bool(qlora["double_quant"]),
        bnb_4bit_compute_dtype=compute_dtype,
    )
    peft_config = LoraConfig(
        r=int(qlora["rank"]),
        lora_alpha=int(qlora["alpha"]),
        lora_dropout=float(qlora["dropout"]),
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )
    model_init_kwargs: dict[str, Any] = {"trust_remote_code": False, "dtype": compute_dtype}
    if not Path(str(experiment["model"]["base_model"])).expanduser().is_dir():
        model_init_kwargs["revision"] = str(experiment["model"]["revision"])
    sft_config = SFTConfig(
        output_dir=str(adapter_directory),
        num_train_epochs=float(training["epochs"]),
        learning_rate=float(training["learning_rate"]),
        per_device_train_batch_size=int(training["per_device_train_batch_size"]),
        per_device_eval_batch_size=int(training["per_device_eval_batch_size"]),
        gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
        warmup_ratio=float(training["warmup_ratio"]),
        weight_decay=float(training["weight_decay"]),
        logging_steps=int(training["logging_steps"]),
        eval_strategy="steps",
        eval_steps=int(training["eval_steps"]),
        save_strategy="steps",
        save_steps=int(training["save_steps"]),
        save_total_limit=int(training["save_total_limit"]),
        seed=int(training["seed"]),
        data_seed=int(training["seed"]),
        gradient_checkpointing=bool(training["gradient_checkpointing"]),
        packing=bool(training["packing"]),
        completion_only_loss=True,
        assistant_only_loss=False,
        max_length=int(experiment["tokenizer"]["max_sequence_tokens"]),
        bf16=qlora["compute_dtype"] == "bfloat16",
        fp16=qlora["compute_dtype"] == "float16",
        report_to="none",
        push_to_hub=False,
        model_init_kwargs=model_init_kwargs,
        trust_remote_code=False,
    )
    trainer = SFTTrainer(
        model=str(experiment["model"]["base_model"]),
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=validation_dataset,
        processing_class=tokenizer,
        quantization_config=quantization_config,
        peft_config=peft_config,
    )
    started_at = datetime.now(timezone.utc)
    train_output = trainer.train(resume_from_checkpoint=resume_from_checkpoint)
    evaluation_metrics = trainer.evaluate()
    trainer.save_model(str(adapter_directory))
    tokenizer.save_pretrained(str(adapter_directory))
    completed_at = datetime.now(timezone.utc)
    result = {
        "schema_version": MOTOR_EXPERIMENT_SCHEMA_VERSION,
        "experiment_id": experiment["experiment_id"],
        "status": "completed-unqualified",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": round((completed_at - started_at).total_seconds(), 3),
        "dataset_manifest_sha256": _sha256_file(manifest_path),
        "tokenizer_audit_sha256": _sha256_file(audit_path),
        "model": experiment["model"],
        "qlora": experiment["qlora"],
        "training": experiment["training"],
        "metrics": {
            "train": dict(train_output.metrics),
            "validation": dict(evaluation_metrics),
        },
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "dependencies": _dependency_versions(),
            "cuda_device": torch.cuda.get_device_name(0),
        },
        "artifacts": _artifact_hashes(adapter_directory),
        "next_gate": "Serve the adapter as a separate model profile and complete repeated frozen-corpus qualification.",
    }
    _atomic_json(experiment_path.parent / "training-result.json", result)
    return result


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _latency(document: dict[str, Any]) -> dict[str, Any]:
    samples = [float(item["duration_ms"]) for item in _walk(document) if isinstance(item.get("duration_ms"), (int, float))]
    rounded = [int(round(item)) for item in samples]
    return {"samples": len(samples), **_distribution(rounded)}


def _candidate(document: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    candidates = [item for item in document.get("candidates") or [] if isinstance(item, dict)]
    if candidate_id:
        match = next((item for item in candidates if str(item.get("id") or "") == candidate_id), None)
        if match is None:
            raise MotorTrainingError(f"qualification candidate is missing: {candidate_id}")
        return match
    if len(candidates) != 1:
        raise MotorTrainingError("qualification report requires an explicit candidate ID")
    return candidates[0]


def compare_motor_qualification(
    *,
    experiment: dict[str, Any],
    baseline_attack: dict[str, Any],
    candidate_attack: dict[str, Any],
    baseline_evaluator: dict[str, Any],
    candidate_evaluator: dict[str, Any],
    baseline_candidate_id: str = "",
    candidate_candidate_id: str = "",
) -> dict[str, Any]:
    validate_experiment_config(experiment)
    baseline_attack_row = _candidate(baseline_attack, baseline_candidate_id)
    candidate_attack_row = _candidate(candidate_attack, candidate_candidate_id)
    baseline_eval_row = _candidate(baseline_evaluator, baseline_candidate_id)
    candidate_eval_row = _candidate(candidate_evaluator, candidate_candidate_id)
    base_attack_summary = baseline_attack_row.get("summary") or {}
    new_attack_summary = candidate_attack_row.get("summary") or {}
    base_eval_summary = baseline_eval_row.get("summary") or {}
    new_eval_summary = candidate_eval_row.get("summary") or {}
    qualification = experiment["qualification"]
    base_latency = _latency({"attack": baseline_attack_row, "evaluator": baseline_eval_row})
    new_latency = _latency({"attack": candidate_attack_row, "evaluator": candidate_eval_row})
    latency_ratio = (
        float(new_latency["p50"]) / float(base_latency["p50"])
        if new_latency["samples"] and base_latency["samples"] and base_latency["p50"]
        else None
    )
    metrics = {
        "attack_minimum_pass_rate": float(new_attack_summary.get("minimum_pass_rate") or 0.0),
        "attack_errors": int(new_attack_summary.get("total_errors") or 0),
        "attack_safety_violations": int(new_attack_summary.get("safety_violations") or 0),
        "evaluator_precision": float(new_eval_summary.get("minimum_precision") or 0.0),
        "evaluator_recall": float(new_eval_summary.get("minimum_recall") or 0.0),
        "evaluator_pass_rate": float(new_eval_summary.get("minimum_pass_rate") or 0.0),
        "evaluator_errors": int(new_eval_summary.get("total_errors") or 0),
        "candidate_latency": new_latency,
        "baseline_latency": base_latency,
        "latency_ratio": round(latency_ratio, 6) if latency_ratio is not None else None,
    }
    gates = [
        {"id": "candidate-attack-qualified", "passed": bool(new_attack_summary.get("qualified")), "value": bool(new_attack_summary.get("qualified")), "threshold": True},
        {"id": "candidate-evaluator-qualified", "passed": bool(new_eval_summary.get("qualified")), "value": bool(new_eval_summary.get("qualified")), "threshold": True},
        {"id": "attack-pass-rate", "passed": metrics["attack_minimum_pass_rate"] >= float(qualification["minimum_attack_pass_rate"]), "value": metrics["attack_minimum_pass_rate"], "threshold": qualification["minimum_attack_pass_rate"]},
        {"id": "evaluator-precision", "passed": metrics["evaluator_precision"] >= float(qualification["minimum_evaluator_precision"]), "value": metrics["evaluator_precision"], "threshold": qualification["minimum_evaluator_precision"]},
        {"id": "evaluator-recall", "passed": metrics["evaluator_recall"] >= float(qualification["minimum_evaluator_recall"]), "value": metrics["evaluator_recall"], "threshold": qualification["minimum_evaluator_recall"]},
        {"id": "evaluator-pass-rate", "passed": metrics["evaluator_pass_rate"] >= float(qualification["minimum_evaluator_pass_rate"]), "value": metrics["evaluator_pass_rate"], "threshold": qualification["minimum_evaluator_pass_rate"]},
        {"id": "zero-qualification-errors", "passed": metrics["attack_errors"] + metrics["evaluator_errors"] == 0, "value": metrics["attack_errors"] + metrics["evaluator_errors"], "threshold": 0},
        {"id": "zero-safety-violations", "passed": metrics["attack_safety_violations"] == 0, "value": metrics["attack_safety_violations"], "threshold": 0},
        {
            "id": "latency-not-regressed",
            "passed": latency_ratio is not None and latency_ratio <= float(qualification["maximum_latency_ratio"]),
            "value": round(latency_ratio, 6) if latency_ratio is not None else "unavailable",
            "threshold": qualification["maximum_latency_ratio"],
        },
        {"id": "attack-not-below-baseline", "passed": metrics["attack_minimum_pass_rate"] >= float(base_attack_summary.get("minimum_pass_rate") or 0.0), "value": metrics["attack_minimum_pass_rate"], "threshold": float(base_attack_summary.get("minimum_pass_rate") or 0.0)},
        {"id": "evaluator-recall-not-below-baseline", "passed": metrics["evaluator_recall"] >= float(base_eval_summary.get("minimum_recall") or 0.0), "value": metrics["evaluator_recall"], "threshold": float(base_eval_summary.get("minimum_recall") or 0.0)},
    ]
    return {
        "schema_version": MODEL_COMPARISON_SCHEMA_VERSION,
        "experiment_id": experiment["experiment_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "qualified" if all(item["passed"] for item in gates) else "not-qualified",
        "baseline": {
            "attack_candidate": baseline_attack_row.get("id"),
            "evaluator_candidate": baseline_eval_row.get("id"),
        },
        "candidate": {
            "attack_candidate": candidate_attack_row.get("id"),
            "evaluator_candidate": candidate_eval_row.get("id"),
        },
        "metrics": metrics,
        "gates": gates,
        "interpretation": (
            "The candidate may be assigned only to roles whose repeated frozen-corpus gates passed."
            if all(item["passed"] for item in gates)
            else "The adapter remains experimental and must not replace the qualified baseline for professional conclusions."
        ),
    }
