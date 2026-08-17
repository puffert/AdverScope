from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from osai_security.release import PRODUCT_VERSION  # noqa: E402


MANIFEST_PATH = Path("docs/milestone5/m5.0-preview-manifest.json")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _safe_path(root: Path, relative: str) -> Path | None:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _jpeg_dimensions(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    offset = 2
    start_of_frame = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while offset + 4 <= len(data):
        while offset < len(data) and data[offset] != 0xFF:
            offset += 1
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in {0x01, 0xD8, 0xD9}:
            continue
        if offset + 2 > len(data):
            return None
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(data):
            return None
        if marker in start_of_frame:
            if segment_length < 7:
                return None
            height = int.from_bytes(data[offset + 3 : offset + 5], "big")
            width = int.from_bytes(data[offset + 5 : offset + 7], "big")
            return width, height
        offset += segment_length
    return None


def check_preview(root: Path = ROOT) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    manifest_file = root / MANIFEST_PATH
    if not manifest_file.is_file():
        return {
            "milestone": "M5.0",
            "status": "blocked",
            "product_version": PRODUCT_VERSION,
            "errors": [f"missing preview manifest: {MANIFEST_PATH.as_posix()}"],
        }

    try:
        manifest = _read_json(manifest_file)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "milestone": "M5.0",
            "status": "blocked",
            "product_version": PRODUCT_VERSION,
            "errors": [f"invalid preview manifest: {exc}"],
        }

    if manifest.get("schema_version") != "1.0":
        errors.append("preview manifest schema_version must be 1.0")
    if manifest.get("milestone") != "M5.0":
        errors.append("preview manifest must identify M5.0")
    if manifest.get("status") != "complete":
        errors.append("preview manifest is not marked complete")
    if manifest.get("product_version") != PRODUCT_VERSION:
        errors.append("preview manifest product_version does not match AdverScope")
    if manifest.get("release_channel") != "public-beta":
        errors.append("M5.0 must identify the public Beta release channel")

    required_assets = manifest.get("required_assets")
    if not isinstance(required_assets, list) or not required_assets:
        errors.append("preview manifest required_assets must be a non-empty list")
        required_assets = []
    for relative in required_assets:
        if not isinstance(relative, str) or not relative:
            errors.append("preview manifest contains an invalid required asset")
            continue
        path = _safe_path(root, relative)
        if path is None:
            errors.append(f"required asset escapes the repository: {relative}")
        elif not path.is_file() or path.stat().st_size == 0:
            errors.append(f"required preview asset is missing or empty: {relative}")

    guide_path = root / "docs" / "TESTER_PREVIEW_GUIDE.md"
    coordinator_path = root / "docs" / "TESTER_PREVIEW_COORDINATOR.md"
    manual_path = root / "docs" / "USER_MANUAL.md"
    issue_path = root / ".github" / "ISSUE_TEMPLATE" / "m5-tester-feedback.yml"
    ci_path = root / ".github" / "workflows" / "ci.yml"

    texts: dict[str, str] = {}
    for name, path in {
        "guide": guide_path,
        "coordinator": coordinator_path,
        "manual": manual_path,
        "issue": issue_path,
        "ci": ci_path,
    }.items():
        try:
            texts[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot read {path.relative_to(root).as_posix()} as UTF-8: {exc}")
            texts[name] = ""

    required_commands = manifest.get("required_tester_commands")
    if not isinstance(required_commands, list) or not required_commands:
        errors.append("preview manifest required_tester_commands must be a non-empty list")
        required_commands = []
    for command in required_commands:
        if not isinstance(command, str) or command not in texts["guide"]:
            errors.append(f"tester guide is missing required command: {command!r}")

    guide_terms = (
        "explicit written authorization",
        "visible GUI",
        "Do not score an inconclusive result as secure",
        "TESTER_PREVIEW_COORDINATOR.md",
        "m5-tester-feedback.yml",
    )
    for term in guide_terms:
        if term not in texts["guide"]:
            errors.append(f"tester guide is missing required preview language: {term!r}")

    coordinator_terms = (
        "Freeze the preview baseline",
        "Build the authorized target package",
        "Observe without operating for the tester",
        "Levels 3 and 4",
        "Do not hardcode a benchmark",
    )
    for term in coordinator_terms:
        if term not in texts["coordinator"]:
            errors.append(f"coordinator checklist is missing required control: {term!r}")

    feedback_fields = manifest.get("required_feedback_fields")
    if not isinstance(feedback_fields, list) or not feedback_fields:
        errors.append("preview manifest required_feedback_fields must be a non-empty list")
        feedback_fields = []
    for field in feedback_fields:
        if not isinstance(field, str) or not re.search(rf"^\s+id:\s*{re.escape(field)}\s*$", texts["issue"], re.MULTILINE):
            errors.append(f"M5 feedback issue form is missing field: {field!r}")
    for term in ("Do not include customer names", "Data safety confirmation", "inconclusive rather than secure or vulnerable"):
        if term not in texts["issue"]:
            errors.append(f"M5 feedback issue form is missing safety language: {term!r}")

    screenshot_paths = manifest.get("manual_screenshots")
    if not isinstance(screenshot_paths, list) or len(screenshot_paths) < 14:
        errors.append("preview manifest must require at least 14 manual screenshots")
        screenshot_paths = []
    manual_references = set(re.findall(r"\]\((images/manual/[^)#]+\.(?:jpg|jpeg))\)", texts["manual"], re.IGNORECASE))
    validated_screenshots = 0
    for relative in screenshot_paths:
        if not isinstance(relative, str):
            errors.append("preview manifest contains an invalid screenshot path")
            continue
        path = _safe_path(root, relative)
        manual_relative = relative.removeprefix("docs/")
        if manual_relative not in manual_references:
            errors.append(f"user manual does not reference required screenshot: {relative}")
        if path is None or not path.is_file():
            errors.append(f"required manual screenshot is missing: {relative}")
            continue
        dimensions = _jpeg_dimensions(path)
        if dimensions is None:
            errors.append(f"required manual screenshot is not a valid JPEG: {relative}")
            continue
        width, height = dimensions
        if width < 640 or height < 360:
            errors.append(f"required manual screenshot is too small ({width}x{height}): {relative}")
            continue
        validated_screenshots += 1

    if "scripts/check_tester_preview.py" not in texts["ci"]:
        errors.append("release-gate CI does not enforce the M5.0 preview readiness check")

    return {
        "milestone": manifest.get("milestone", "M5.0"),
        "status": "ready" if not errors else "blocked",
        "product_version": PRODUCT_VERSION,
        "release_channel": manifest.get("release_channel"),
        "required_assets": len(required_assets),
        "required_feedback_fields": len(feedback_fields),
        "validated_manual_screenshots": validated_screenshots,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the Milestone 5 controlled tester preview package")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root to inspect")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    result = check_preview(args.root)
    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["status"] == "ready":
        print(
            f"AdverScope {result['product_version']} M5.0 preview is ready: "
            f"{result['required_assets']} assets, {result['required_feedback_fields']} feedback fields, "
            f"and {result['validated_manual_screenshots']} manual screenshots verified"
        )
    else:
        for error in result["errors"]:
            print(f"FAIL: {error}")
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
