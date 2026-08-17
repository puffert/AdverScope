from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.motor_dataset import (  # noqa: E402
    MotorDatasetError,
    build_from_paths,
    download_training_sources,
    source_registry_summary,
    validate_build_config,
    validate_dataset_release,
    validate_source_registry,
)


DEFAULT_REGISTRY = ROOT / "training" / "public-sources-v1.json"
DEFAULT_CONFIG = ROOT / "training" / "configs" / "motor-v0.1.json"
DEFAULT_CACHE = ROOT / "data" / "training" / "sources"
DEFAULT_OUTPUT = ROOT / "data" / "training" / "adverscope-8b-motor-v0.1"


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MotorDatasetError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MotorDatasetError(f"expected a JSON object in {path}")
    return value


def _path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (ROOT / path).resolve()


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _selected_source_ids(config: dict[str, Any]) -> list[str]:
    return [str(item["id"]) for item in config["sources"]]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and validate leakage-controlled AdverScope 8B motor datasets",
    )
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="Versioned public-source registry")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sources = subparsers.add_parser("sources", help="Show source license and training/benchmark policy")
    sources.add_argument("--config", default=str(DEFAULT_CONFIG), help="Build configuration used to mark selected sources")

    download = subparsers.add_parser("download", help="Download and verify selected training sources")
    download.add_argument("--config", default=str(DEFAULT_CONFIG))
    download.add_argument("--cache", default=str(DEFAULT_CACHE))
    download.add_argument("--source", action="append", default=[], help="Download only this selected source ID; repeat as needed")
    download.add_argument("--refresh", action="store_true", help="Re-fetch pinned remote sources and verify their checksums")

    build = subparsers.add_parser("build", help="Transform selected sources into canonical and chat-SFT JSONL")
    build.add_argument("--config", default=str(DEFAULT_CONFIG))
    build.add_argument("--cache", default=str(DEFAULT_CACHE))
    build.add_argument("--output", default=str(DEFAULT_OUTPUT))
    build.add_argument("--download", action="store_true", help="Download missing selected sources before transforming")
    build.add_argument("--refresh", action="store_true", help="Re-fetch remote sources; requires --download")
    build.add_argument("--review-overlay", default="", help="Complete review overlay exported by the Motor Lab")

    validate = subparsers.add_parser("validate", help="Verify a generated dataset manifest, hashes, schemas, and split isolation")
    validate.add_argument("--directory", default=str(DEFAULT_OUTPUT))
    validate.add_argument("--dataset-id", default="", help="Optional expected dataset ID")
    validate.add_argument("--skip-hashes", action="store_true", help="Skip file hash verification (not suitable for release checks)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    registry_path = _path(args.registry)
    try:
        registry = validate_source_registry(_load_object(registry_path))
        if args.command == "sources":
            config = validate_build_config(_load_object(_path(args.config)), registry)
            selected = set(_selected_source_ids(config))
            summary = source_registry_summary(registry)
            for source in summary["sources"]:
                source["selected_by_config"] = source["id"] in selected
            summary["build_config"] = str(_path(args.config))
            _emit(summary)
            return 0

        if args.command == "download":
            config = validate_build_config(_load_object(_path(args.config)), registry)
            selected = _selected_source_ids(config)
            requested = list(dict.fromkeys(str(item) for item in args.source))
            unknown = sorted(set(requested) - set(selected))
            if unknown:
                raise MotorDatasetError(
                    "--source must be selected by the build config: " + ", ".join(unknown)
                )
            source_ids = requested or selected
            result = download_training_sources(
                registry,
                source_ids,
                cache_root=_path(args.cache),
                repository_root=ROOT,
                refresh=bool(args.refresh),
            )
            _emit(result)
            return 0 if result["ready"] else 2

        if args.command == "build":
            if args.refresh and not args.download:
                raise MotorDatasetError("--refresh requires --download")
            result = build_from_paths(
                registry_path=registry_path,
                config_path=_path(args.config),
                cache_root=_path(args.cache),
                output_directory=_path(args.output),
                repository_root=ROOT,
                download=bool(args.download),
                refresh=bool(args.refresh),
                review_overlay_path=_path(args.review_overlay) if args.review_overlay else None,
            )
            summary = {
                "status": "passed",
                "dataset_id": result["dataset_id"],
                "dataset_version": result["dataset_version"],
                "output_directory": result["output_directory"],
                "records": result["quality"]["records"],
                "counts": result["quality"]["counts"],
                "quality_gates": result["quality"]["gates"],
                "human_review": result["quality"]["human_review"],
            }
            if isinstance(result.get("reviewed_extension"), dict):
                summary["reviewed_extension"] = result["reviewed_extension"]
            _emit(summary)
            return 0

        validation = validate_dataset_release(
            _path(args.directory),
            expected_dataset_id=str(args.dataset_id or "") or None,
            verify_manifest_hashes=not bool(args.skip_hashes),
        )
        _emit(validation)
        return 0 if validation["status"] == "passed" else 1
    except MotorDatasetError as exc:
        print(f"Dataset pipeline stopped safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
