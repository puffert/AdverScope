from __future__ import annotations

import sys
from pathlib import Path

from osai_security.cli import main


if __name__ == "__main__":
    source_config = Path(__file__).resolve().parent / "data" / "local-config.json"
    raise SystemExit(main(["serve", "--config", str(source_config), *sys.argv[1:]]))
