from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.motor_training import (  # noqa: E402
    MotorTrainingError,
    compare_motor_qualification,
    dependency_status,
    run_qlora_experiment,
    validate_experiment_config,
    write_tokenizer_audit,
)


def _path(value: str | Path) -> Path:
    source = Path(value).expanduser()
    return source.resolve() if source.is_absolute() else (ROOT / source).resolve()


def _object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MotorTrainingError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MotorTrainingError(f"{path} must contain a JSON object")
    return value


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit, train, and qualify an AdverScope 8B motor experiment")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Show tokenizer and QLoRA dependency readiness")

    audit = commands.add_parser("audit", help="Run the exact selected tokenizer over every dataset record")
    audit.add_argument("--experiment", required=True)
    audit.add_argument("--output", default="")

    train = commands.add_parser("train", help="Run the audited four-bit NF4 QLoRA experiment")
    train.add_argument("--experiment", required=True)
    train.add_argument("--resume", default="", help="Checkpoint path or 'latest'")

    compare = commands.add_parser("compare", help="Compare repeated candidate qualification with the retained baseline")
    compare.add_argument("--experiment", required=True)
    compare.add_argument("--baseline-attack", required=True)
    compare.add_argument("--candidate-attack", required=True)
    compare.add_argument("--baseline-evaluator", required=True)
    compare.add_argument("--candidate-evaluator", required=True)
    compare.add_argument("--baseline-candidate-id", default="")
    compare.add_argument("--candidate-candidate-id", default="")
    compare.add_argument("--output", default="")
    compare.add_argument("--require-gates", action="store_true")

    status = commands.add_parser("status", help="Show retained experiment, audit, training, and comparison state")
    status.add_argument("--experiment", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            status = dependency_status()
            _emit(status)
            return 0 if status["ready_for_qlora"] else 1

        experiment_path = _path(args.experiment)
        experiment = validate_experiment_config(_object(experiment_path))
        if args.command == "audit":
            result = write_tokenizer_audit(
                experiment_path,
                output_path=_path(args.output) if args.output else None,
            )
            _emit(result)
            return 0 if result["status"] == "passed" else 1
        if args.command == "train":
            resume: str | bool | None = None
            if args.resume:
                resume = True if args.resume == "latest" else str(_path(args.resume))
            result = run_qlora_experiment(experiment_path, resume_from_checkpoint=resume)
            _emit(result)
            return 0
        if args.command == "compare":
            result = compare_motor_qualification(
                experiment=experiment,
                baseline_attack=_object(_path(args.baseline_attack)),
                candidate_attack=_object(_path(args.candidate_attack)),
                baseline_evaluator=_object(_path(args.baseline_evaluator)),
                candidate_evaluator=_object(_path(args.candidate_evaluator)),
                baseline_candidate_id=str(args.baseline_candidate_id or ""),
                candidate_candidate_id=str(args.candidate_candidate_id or ""),
            )
            output = _path(args.output) if args.output else experiment_path.parent / "comparison.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            _emit(result)
            return 2 if args.require_gates and result["status"] != "qualified" else 0

        state = {
            "experiment": experiment,
            "dependencies": dependency_status(),
            "tokenizer_audit": _object(experiment_path.parent / "tokenizer-audit.json") if (experiment_path.parent / "tokenizer-audit.json").is_file() else None,
            "training_result": _object(experiment_path.parent / "training-result.json") if (experiment_path.parent / "training-result.json").is_file() else None,
            "comparison": _object(experiment_path.parent / "comparison.json") if (experiment_path.parent / "comparison.json").is_file() else None,
        }
        _emit(state)
        return 0
    except (MotorTrainingError, OSError, ValueError) as exc:
        print(f"Motor experiment stopped safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
