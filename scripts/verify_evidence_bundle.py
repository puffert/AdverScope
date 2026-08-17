from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osai_security.evidence_bundles import EvidenceBundleError, verify_evidence_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify every hash and path in an AdverScope evidence bundle.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--project-id", default="")
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()
    try:
        result = verify_evidence_bundle(
            args.bundle.read_bytes(),
            expected_project_id=args.project_id,
            expected_run_id=args.run_id,
        )
    except (OSError, EvidenceBundleError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
