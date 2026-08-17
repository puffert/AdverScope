from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.reliability_qualification import (  # noqa: E402
    evaluate_reliability_corpus,
    load_reliability_corpus,
    render_reliability_report,
)


DEFAULT_CORPUS = ROOT / "validation" / "milestone5" / "reliability-corpus-v1.json"
DEFAULT_JSON = ROOT / "validation" / "milestone5" / "m5.4-reliability-baseline-2026-08-14.json"
DEFAULT_MARKDOWN = ROOT / "docs" / "M5_RELIABILITY_QUALIFICATION.md"


def _json_text(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute the frozen M5.4 reliability and evidence-custody qualification matrix.")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--check", action="store_true", help="Fail when checked-in generated results are missing or stale.")
    parser.add_argument("--require-gates", action="store_true", help="Fail unless automated and non-automated M5.4 gates are complete.")
    args = parser.parse_args()

    result = evaluate_reliability_corpus(load_reliability_corpus(args.corpus), root=ROOT)
    json_text = _json_text(result)
    markdown_text = render_reliability_report(result)
    if args.check:
        stale = []
        if not args.json_output.is_file() or args.json_output.read_text(encoding="utf-8") != json_text:
            stale.append(str(args.json_output.relative_to(ROOT)))
        if not args.markdown_output.is_file() or args.markdown_output.read_text(encoding="utf-8") != markdown_text:
            stale.append(str(args.markdown_output.relative_to(ROOT)))
        if stale:
            print("M5.4 generated qualification output is stale: " + ", ".join(stale))
            return 1
    else:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json_text, encoding="utf-8")
        args.markdown_output.write_text(markdown_text, encoding="utf-8")

    summary = result["summary"]
    print(
        f"M5.4 {result['status']}: {summary['controls_passed']}/{summary['controls_total']} "
        f"automated controls passed; {summary['open_gates']} release gates remain open"
    )
    return 2 if args.require_gates and result["status"] != "complete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
