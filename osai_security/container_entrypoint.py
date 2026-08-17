from __future__ import annotations

import os

from .cli import main
from .local_setup import default_config_path, initialize_local_state


def run() -> int:
    os.environ["AISEC_CONTAINER_API_ONLY"] = "1"
    config_path = default_config_path()
    if not config_path.is_file():
        provider = os.environ.get("ADVERSCOPE_CONTAINER_PROVIDER", "local")
        initialize_local_state(
            config_path=config_path,
            host="127.0.0.1",
            port=int(os.environ.get("AISEC_PORT", "8091")),
            provider=provider,
            model=os.environ.get("ADVERSCOPE_CONTAINER_MODEL", ""),
            base_url=os.environ.get("ADVERSCOPE_CONTAINER_MODEL_BASE_URL", "") if provider == "local" else "",
            api_key_env=os.environ.get("ADVERSCOPE_CONTAINER_API_KEY_ENV", ""),
        )
    return main(["serve", "--config", str(config_path), "--host", "0.0.0.0"])


if __name__ == "__main__":
    raise SystemExit(run())
