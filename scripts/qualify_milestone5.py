from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from osai_security.field_qualification import (  # noqa: E402
    evaluate_field_qualification,
    load_field_corpus,
    render_field_qualification_report,
)


DEFAULT_CORPUS = ROOT / "validation" / "milestone5" / "corpus-v1.json"
DEFAULT_JSON = ROOT / "validation" / "milestone5" / "m5.1-baseline-2026-08-14.json"
DEFAULT_MARKDOWN = ROOT / "docs" / "M5_FIELD_QUALIFICATION.md"


def _render_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or verify the frozen Milestone 5 field-qualification matrix")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--check", action="store_true", help="Fail when generated outputs are stale")
    parser.add_argument("--require-gates", action="store_true", help="Fail unless every M5.1 completion gate passes")
    args = parser.parse_args()

    corpus = load_field_corpus(args.corpus.resolve())
    result = evaluate_field_qualification(corpus, root=ROOT)
    rendered_json = _render_json(result)
    rendered_markdown = render_field_qualification_report(result)
    if args.check:
        if not args.json_output.is_file() or args.json_output.read_text(encoding="utf-8") != rendered_json:
            raise SystemExit(f"M5.1 qualification JSON is stale: {args.json_output}")
        if not args.markdown_output.is_file() or args.markdown_output.read_text(encoding="utf-8") != rendered_markdown:
            raise SystemExit(f"M5.1 qualification report is stale: {args.markdown_output}")
    else:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(rendered_json, encoding="utf-8")
        args.markdown_output.write_text(rendered_markdown, encoding="utf-8")
    print(
        f"M5.1 {result['status']}: {result['summary']['field_qualified_techniques']}/"
        f"{result['summary']['professional_claim_candidates']} technique claims and "
        f"{result['summary']['field_covered_target_styles']}/{result['summary']['required_target_styles']} "
        "target styles satisfy field-depth gates"
    )
    return 0 if not args.require_gates or result["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
