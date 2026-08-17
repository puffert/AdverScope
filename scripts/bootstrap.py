from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str]) -> None:
    print("Running:", " ".join(command))
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description="Install AdverScope Python and browser dependencies, then initialize local state")
    parser.add_argument("--config")
    parser.add_argument("--data-dir")
    parser.add_argument("--provider", choices=["local", "openai", "zai"], default="local")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--api-key-env", default="")
    parser.add_argument("--skip-browser", action="store_true", help="Install API-only mode without Node browser dependencies")
    parser.add_argument("--skip-init", action="store_true")
    parser.add_argument("--force-init", action="store_true")
    args = parser.parse_args()

    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required")
    uv = shutil.which("uv")
    if not uv:
        parser.error("uv is required; install it from https://docs.astral.sh/uv/")
    _run([uv, "sync", "--extra", "qualification", "--locked"])
    if not args.skip_browser:
        node = shutil.which("node")
        npm = shutil.which("npm")
        if not node or not npm:
            parser.error("Node.js 20 or newer and npm are required for browser capture; use --skip-browser for API-only mode")
        version = subprocess.run([node, "--version"], capture_output=True, text=True, check=False).stdout.strip().lstrip("v")
        try:
            major = int(version.split(".", 1)[0])
        except ValueError:
            major = 0
        if major < 20:
            parser.error("Node.js 20 or newer is required for browser capture; use --skip-browser for API-only mode")
        _run([npm, "ci"])
    if args.skip_init:
        return 0

    python = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    sys.path.insert(0, str(ROOT))
    from osai_security.local_setup import default_config_path

    selected_config = Path(args.config).expanduser().resolve() if args.config else default_config_path()
    if selected_config.exists() and not args.force_init:
        print(f"Existing AdverScope configuration preserved: {selected_config}")
        print(f"Next: {python} -m osai_security.cli doctor --config \"{selected_config}\"")
        return 0
    command = [str(python), "-m", "osai_security.cli", "init", "--provider", args.provider]
    for name, value in (
        ("--config", args.config),
        ("--data-dir", args.data_dir),
        ("--model", args.model),
        ("--base-url", args.base_url),
        ("--api-key-env", args.api_key_env),
    ):
        if value:
            command.extend([name, value])
    if args.force_init:
        command.append("--force")
    _run(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
