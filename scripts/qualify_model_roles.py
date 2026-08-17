from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.model_role_qualification import (  # noqa: E402
    evaluate_model_role_corpus,
    load_model_role_corpus,
    render_model_role_report,
)


DEFAULT_CORPUS = ROOT / "validation/milestone5/model-role-corpus-v1.json"
DEFAULT_JSON = ROOT / "validation/milestone5/m5.2-model-role-baseline-2026-08-14.json"
DEFAULT_MARKDOWN = ROOT / "docs/M5_MODEL_ROLE_QUALIFICATION.md"


def _json_text(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate retained repeated model-role qualification evidence.")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--require-gates", action="store_true")
    args = parser.parse_args()

    result = evaluate_model_role_corpus(load_model_role_corpus(args.corpus), root=ROOT)
    json_text = _json_text(result)
    markdown_text = render_model_role_report(result)
    if args.check:
        stale = []
        if not args.json_output.is_file() or args.json_output.read_text(encoding="utf-8") != json_text:
            stale.append(str(args.json_output.relative_to(ROOT)))
        if not args.markdown_output.is_file() or args.markdown_output.read_text(encoding="utf-8") != markdown_text:
            stale.append(str(args.markdown_output.relative_to(ROOT)))
        if stale:
            print("M5.2 generated qualification output is stale: " + ", ".join(stale))
            return 1
    else:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json_text, encoding="utf-8")
        args.markdown_output.write_text(markdown_text, encoding="utf-8")

    summary = result["summary"]
    print(
        f"M5.2 {result['status']}: {summary['qualified_roles']}/{summary['required_roles']} roles, "
        f"{summary['qualified_provider_families']}/{summary['required_provider_families']} providers, "
        f"{summary['qualified_model_families']}/{summary['minimum_model_families']} model families"
    )
    return 2 if args.require_gates and result["status"] != "complete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
