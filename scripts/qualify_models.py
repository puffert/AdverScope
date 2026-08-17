from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.config import AppConfig
from osai_security.evaluator_corpus import load_evaluator_corpus
from osai_security.model_qualification import qualify_model_candidates, validate_model_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Repeatedly qualify configured local models against the AdverScope evaluator corpus.")
    parser.add_argument("--corpus", type=Path, default=Path("validation/evaluator-corpus/corpus-v1.json"))
    parser.add_argument("--candidates", type=Path, default=Path("validation/evaluator-corpus/asus-model-candidates.json"))
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("data/local-config.json"))
    parser.add_argument("--require-gates", action="store_true")
    args = parser.parse_args()
    manifest = validate_model_candidates(json.loads(args.candidates.read_text(encoding="utf-8")))
    report = qualify_model_candidates(
        load_evaluator_corpus(args.corpus),
        manifest,
        base_config=AppConfig.from_sources(args.config),
        repetitions=args.repetitions,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for candidate in report["candidates"]:
        summary = candidate["summary"]
        print(json.dumps({
            "candidate": candidate["id"],
            "model": candidate["model"],
            "required": candidate["required"],
            "qualified": summary["qualified"],
            "minimum_precision": summary["minimum_precision"],
            "minimum_recall": summary["minimum_recall"],
            "minimum_pass_rate": summary["minimum_pass_rate"],
            "errors": summary["total_errors"],
            "disagreements": summary["disagreement_count"],
        }, sort_keys=True))
    if args.require_gates and not report["all_required_candidates_qualified"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
