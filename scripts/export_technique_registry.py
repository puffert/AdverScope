from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.qualification_registry import build_qualification_registry, render_automation_matrix


def main() -> int:
    parser = argparse.ArgumentParser(description="Export or verify AdverScope's technique qualification registry.")
    parser.add_argument("--output", type=Path, default=Path("validation/techniques/registry-2026-08-09.json"))
    parser.add_argument("--matrix-output", type=Path, default=Path("docs/OWASP_AUTOMATION_MATRIX.md"))
    parser.add_argument("--check", action="store_true", help="Fail when the output differs from the generated registry.")
    args = parser.parse_args()
    rendered = json.dumps(build_qualification_registry(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    matrix = render_automation_matrix()
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"qualification registry is stale: {args.output}")
        if not args.matrix_output.is_file() or args.matrix_output.read_text(encoding="utf-8") != matrix:
            raise SystemExit(f"OWASP automation matrix is stale: {args.matrix_output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    args.matrix_output.parent.mkdir(parents=True, exist_ok=True)
    args.matrix_output.write_text(matrix, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
