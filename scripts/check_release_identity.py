from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from osai_security.release import (  # noqa: E402
    API_CONTRACT_VERSION,
    PRODUCT_VERSION,
    SCHEMA_VERSIONS,
)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def release_identity_errors() -> list[str]:
    errors: list[str] = []
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dynamic = set((pyproject.get("project") or {}).get("dynamic") or [])
    dynamic_version = (((pyproject.get("tool") or {}).get("setuptools") or {}).get("dynamic") or {}).get("version") or {}
    if "version" not in dynamic or dynamic_version.get("attr") != "osai_security.__version__":
        errors.append("pyproject.toml must obtain its version from osai_security.__version__")

    package = _read_json(ROOT / "package.json")
    package_lock = _read_json(ROOT / "package-lock.json")
    if str(package.get("version") or "") != PRODUCT_VERSION:
        errors.append("package.json version does not match the authoritative product version")
    if str(package_lock.get("version") or "") != PRODUCT_VERSION:
        errors.append("package-lock.json root version does not match the authoritative product version")
    lock_root = (package_lock.get("packages") or {}).get("") or {}
    if str(lock_root.get("version") or "") != PRODUCT_VERSION:
        errors.append("package-lock.json package version does not match the authoritative product version")

    app_source = (ROOT / "osai_security" / "static" / "app.js").read_text(encoding="utf-8")
    contract = re.search(r'^const API_CONTRACT_VERSION = "([^"]+)";', app_source, re.MULTILINE)
    if not contract or contract.group(1) != API_CONTRACT_VERSION:
        errors.append("browser API contract mirror does not match the authoritative API contract")
    index_source = (ROOT / "osai_security" / "static" / "index.html").read_text(encoding="utf-8")
    for asset in ("app.css", "reasoning.js", "app.js"):
        match = re.search(rf'{re.escape(asset)}\?v=([0-9A-Za-z_.-]+)', index_source)
        if not match or match.group(1) != PRODUCT_VERSION:
            errors.append(f"{asset} cache version does not match the authoritative product version")

    manual = (ROOT / "docs" / "USER_MANUAL.md").read_text(encoding="utf-8")
    if not re.search(rf"^Version {re.escape(PRODUCT_VERSION)}\b", manual, re.MULTILINE):
        errors.append("user manual version does not match the authoritative product version")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8") if (ROOT / "CHANGELOG.md").is_file() else ""
    if not re.search(rf"^## \[{re.escape(PRODUCT_VERSION)}\]", changelog, re.MULTILINE):
        errors.append("CHANGELOG.md does not contain the authoritative product version")
    if not (ROOT / "LICENSE").is_file():
        errors.append("LICENSE is missing")
    local_example = _read_json(ROOT / "local-config.example.json")
    if str(local_example.get("schema_version") or "") != str(SCHEMA_VERSIONS["local_configuration"]):
        errors.append("local-config.example.json schema does not match the authoritative configuration schema")

    from osai_security.assessment_contracts import CONTRACT_SCHEMA_VERSION
    from osai_security.evidence_bundles import BUNDLE_SCHEMA_VERSION
    from osai_security.model_providers import PROVIDER_SCHEMA_VERSION
    from osai_security.motor_dataset import MOTOR_DATASET_SCHEMA_VERSION, SOURCE_REGISTRY_SCHEMA_VERSION
    from osai_security.motor_training import (
        MODEL_COMPARISON_SCHEMA_VERSION,
        MOTOR_EXPERIMENT_SCHEMA_VERSION,
        TOKENIZER_AUDIT_SCHEMA_VERSION,
    )
    from osai_security.release import MOTOR_REVIEW_SCHEMA_VERSION
    from osai_security.modules import ATTACK_CATALOG_VERSION
    from osai_security.owasp import CONTRACT_RECIPE_VERSION
    from osai_security.qualification_registry import REGISTRY_SCHEMA_VERSION, REGISTRY_VERSION
    from osai_security.reports import REPORT_SCHEMA_VERSION, RETEST_REPORT_SCHEMA_VERSION
    from osai_security.local_setup import SETUP_SCHEMA_VERSION
    from osai_security.target_profiles import TARGET_PROFILE_SCHEMA_VERSION
    from osai_security.telemetry import TELEMETRY_SCHEMA_VERSION

    observed = {
        "evidence_bundle": BUNDLE_SCHEMA_VERSION,
        "report": REPORT_SCHEMA_VERSION,
        "retest_report": RETEST_REPORT_SCHEMA_VERSION,
        "telemetry": TELEMETRY_SCHEMA_VERSION,
        "attack_catalog": ATTACK_CATALOG_VERSION,
        "assessment_contract": CONTRACT_SCHEMA_VERSION,
        "contract_recipe": CONTRACT_RECIPE_VERSION,
        "target_profile": TARGET_PROFILE_SCHEMA_VERSION,
        "model_provider": PROVIDER_SCHEMA_VERSION,
        "local_configuration": SETUP_SCHEMA_VERSION,
        "qualification_registry_schema": REGISTRY_SCHEMA_VERSION,
        "motor_dataset": MOTOR_DATASET_SCHEMA_VERSION,
        "training_source_registry": SOURCE_REGISTRY_SCHEMA_VERSION,
        "motor_review": MOTOR_REVIEW_SCHEMA_VERSION,
        "motor_experiment": MOTOR_EXPERIMENT_SCHEMA_VERSION,
        "tokenizer_audit": TOKENIZER_AUDIT_SCHEMA_VERSION,
        "model_comparison": MODEL_COMPARISON_SCHEMA_VERSION,
        "qualification_registry": REGISTRY_VERSION,
    }
    for name, value in observed.items():
        if value != SCHEMA_VERSIONS[name]:
            errors.append(f"{name} schema/version drifted from osai_security.release")
    return errors


def main() -> int:
    errors = release_identity_errors()
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print(f"AdverScope {PRODUCT_VERSION}: release identity is consistent across metadata, UI, schemas, and documentation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
