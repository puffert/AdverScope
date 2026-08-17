from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.attack_qualification import qualify_attack_candidates, validate_attack_corpus
from osai_security.config import AppConfig
from osai_security.model_qualification import validate_model_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Qualify attack generation and Guided planning across repeated local-model runs.")
    parser.add_argument("--corpus", type=Path, default=Path("validation/generation-corpus/corpus-v1.json"))
    parser.add_argument("--candidates", type=Path, default=Path("validation/evaluator-corpus/asus-model-candidates.json"))
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("data/local-config.json"))
    parser.add_argument("--require-gates", action="store_true")
    args = parser.parse_args()
    corpus = validate_attack_corpus(json.loads(args.corpus.read_text(encoding="utf-8")))
    manifest = validate_model_candidates(json.loads(args.candidates.read_text(encoding="utf-8")))
    report = qualify_attack_candidates(corpus, manifest, base_config=AppConfig.from_sources(args.config), repetitions=args.repetitions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for candidate in report["candidates"]:
        print(json.dumps({
            "candidate": candidate["id"], "model": candidate["model"], "status": candidate["status"],
            "qualified": (candidate.get("summary") or {}).get("qualified"),
            "minimum_pass_rate": (candidate.get("summary") or {}).get("minimum_pass_rate"),
            "errors": (candidate.get("summary") or {}).get("total_errors"),
            "safety_violations": (candidate.get("summary") or {}).get("safety_violations"),
        }, sort_keys=True))
    return 2 if args.require_gates and not report["all_required_candidates_qualified"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
