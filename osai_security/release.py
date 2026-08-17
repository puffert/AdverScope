"""Authoritative AdverScope release and persisted-schema identity.

Every user-visible or machine-readable version is sourced from this module.
Metadata files that cannot import Python are verified against it by the
release-identity check.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any


PRODUCT_NAME = "AdverScope"
PRODUCT_VERSION = "0.9.0"
RELEASE_CHANNEL = "beta"
API_CONTRACT_VERSION = "2026.08.14.2"

DATABASE_SCHEMA_VERSION = 4
PROJECT_TRANSFER_SCHEMA_VERSION = "1.0"
LOCAL_BACKUP_SCHEMA_VERSION = "1.0"
EVIDENCE_BUNDLE_SCHEMA_VERSION = "1.0"
REPORT_SCHEMA_VERSION = "1.1"
RETEST_REPORT_SCHEMA_VERSION = "1.0"
TELEMETRY_SCHEMA_VERSION = "1.1"
ATTACK_CATALOG_VERSION = "2026.08.15"
CONTRACT_SCHEMA_VERSION = "2026.08.5"
CONTRACT_RECIPE_VERSION = "2026.08.3"
TARGET_PROFILE_SCHEMA_VERSION = "1.0"
MODEL_PROVIDER_SCHEMA_VERSION = "2.0"
LOCAL_CONFIGURATION_SCHEMA_VERSION = "1.0"
QUALIFICATION_REGISTRY_SCHEMA_VERSION = 1
QUALIFICATION_REGISTRY_VERSION = "2026.08.09.3"
MOTOR_DATASET_SCHEMA_VERSION = 1
TRAINING_SOURCE_REGISTRY_SCHEMA_VERSION = 1
MOTOR_REVIEW_SCHEMA_VERSION = 1
MOTOR_EXPERIMENT_SCHEMA_VERSION = 1
TOKENIZER_AUDIT_SCHEMA_VERSION = 1
MODEL_COMPARISON_SCHEMA_VERSION = 1
ASSESSMENT_REASONING_SCHEMA_VERSION = "1.0"
METHODOLOGY_LIBRARY_VERSION = "2026.08.1"

SCHEMA_VERSIONS = MappingProxyType({
    "api_contract": API_CONTRACT_VERSION,
    "database": DATABASE_SCHEMA_VERSION,
    "project_transfer": PROJECT_TRANSFER_SCHEMA_VERSION,
    "local_backup": LOCAL_BACKUP_SCHEMA_VERSION,
    "evidence_bundle": EVIDENCE_BUNDLE_SCHEMA_VERSION,
    "report": REPORT_SCHEMA_VERSION,
    "retest_report": RETEST_REPORT_SCHEMA_VERSION,
    "telemetry": TELEMETRY_SCHEMA_VERSION,
    "attack_catalog": ATTACK_CATALOG_VERSION,
    "assessment_contract": CONTRACT_SCHEMA_VERSION,
    "contract_recipe": CONTRACT_RECIPE_VERSION,
    "target_profile": TARGET_PROFILE_SCHEMA_VERSION,
    "model_provider": MODEL_PROVIDER_SCHEMA_VERSION,
    "local_configuration": LOCAL_CONFIGURATION_SCHEMA_VERSION,
    "qualification_registry_schema": QUALIFICATION_REGISTRY_SCHEMA_VERSION,
    "qualification_registry": QUALIFICATION_REGISTRY_VERSION,
    "motor_dataset": MOTOR_DATASET_SCHEMA_VERSION,
    "training_source_registry": TRAINING_SOURCE_REGISTRY_SCHEMA_VERSION,
    "motor_review": MOTOR_REVIEW_SCHEMA_VERSION,
    "motor_experiment": MOTOR_EXPERIMENT_SCHEMA_VERSION,
    "tokenizer_audit": TOKENIZER_AUDIT_SCHEMA_VERSION,
    "model_comparison": MODEL_COMPARISON_SCHEMA_VERSION,
    "assessment_reasoning": ASSESSMENT_REASONING_SCHEMA_VERSION,
    "methodology_library": METHODOLOGY_LIBRARY_VERSION,
})


def release_manifest() -> dict[str, Any]:
    """Return a serializable, non-secret release identity."""
    return {
        "name": PRODUCT_NAME,
        "version": PRODUCT_VERSION,
        "channel": RELEASE_CHANNEL,
        "schemas": dict(SCHEMA_VERSIONS),
    }
