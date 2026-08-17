from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any, Iterable

from .release import CONTRACT_SCHEMA_VERSION
from .targets import route_is_authorized
from .tool_engine import normalize_tool_definition


_CONTRACT_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,79}$")
_UNRESOLVED_RECIPE_VALUE = re.compile(r"\bTARGET_(?:APPROVED|OWNED|CONFIGURED|DOCUMENTED)_[A-Z0-9_]+\b")


def _unresolved_recipe_values(value: Any) -> list[str]:
    found: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                visit(key)
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, str):
            found.update(_UNRESOLVED_RECIPE_VALUE.findall(item))

    visit(value)
    return sorted(found)


def _normalize_recipe_provenance(value: Any, contract_id: str) -> dict[str, Any] | None:
    if value in (None, ""):
        return None
    if not isinstance(value, dict):
        raise ValueError(f"assessment contract {contract_id} recipe_provenance must be an object")
    recipe_id = str(value.get("recipe_id") or "").strip()
    recipe_version = str(value.get("recipe_version") or "").strip()
    if not _CONTRACT_ID.fullmatch(recipe_id):
        raise ValueError(f"assessment contract {contract_id} has an invalid recipe id")
    if not recipe_version or len(recipe_version) > 80:
        raise ValueError(f"assessment contract {contract_id} requires a recipe version")
    reviewed = value.get("reviewed") in {True, "true", "1", 1}
    if not reviewed:
        raise ValueError(
            f"assessment contract {contract_id} is an unreviewed recipe; replace every target-specific example and confirm recipe review"
        )
    return {
        "recipe_id": recipe_id,
        "recipe_version": recipe_version,
        "reviewed": True,
        "reviewed_at": str(value.get("reviewed_at") or "")[:80],
    }


def _contract_sha256(
    *,
    contract_id: str,
    title: str,
    description: str,
    enabled: bool,
    reproduce: bool,
    source_definition: dict[str, Any],
    recipe_provenance: dict[str, Any] | None,
) -> str:
    canonical = json.dumps(
        {
            "id": contract_id,
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "title": title,
            "description": description,
            "enabled": enabled,
            "reproduce": reproduce,
            "source_definition": source_definition,
            "recipe_provenance": recipe_provenance or {},
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _request_count(definition: dict[str, Any]) -> int:
    total = 0
    for step in definition.get("steps") or []:
        if step.get("type") == "interaction":
            continue
        total += int(step.get("max_attempts") or 1) if step.get("type") == "poll" else 1
    return total


def _static_routes(definition: dict[str, Any]) -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    for step in definition.get("steps") or []:
        if step.get("type") not in {"http", "poll"}:
            continue
        path = str(step.get("path") or "")
        method = str(step.get("method") or "").upper()
        # Dynamic paths are still checked by TargetClient after rendering. They
        # cannot be proven against the static allowlist during configuration.
        if "{{" not in path:
            routes.append((method, path))
    return routes


def _compile_reproduction(definition: dict[str, Any], enabled: bool) -> dict[str, Any]:
    """Expand one exact reproduction into the immutable workflow definition.

    The testing-tool evidence contract then requires both the initial and
    reproduced proof steps before it can create a finding. This keeps HTTP 200,
    a one-off response, and an unreproduced model judgment from becoming a
    confirmed vulnerability.
    """
    compiled = deepcopy(definition)
    if not enabled:
        compiled["reproduction"] = {"required": False, "attempts": 0}
        return compiled
    steps = compiled.get("steps") or []
    if any(step.get("type") == "interaction" for step in steps):
        raise ValueError("automatic reproduction is not supported for callback/interaction contracts; model the second callback explicitly or disable reproduction")
    original_ids = {str(step["id"]) for step in steps}
    duplicates: list[dict[str, Any]] = []
    id_map: dict[str, str] = {}
    for step in steps:
        original_id = str(step["id"])
        reproduced_id = f"r_{original_id}"
        if len(reproduced_id) > 80 or reproduced_id in original_ids:
            raise ValueError(f"workflow step {original_id} cannot be assigned a unique reproduction id")
        id_map[original_id] = reproduced_id
        duplicates.append({**deepcopy(step), "id": reproduced_id, "name": f"Reproduce: {step['name']}"})
    compiled["steps"] = [*steps, *duplicates]
    for outcome in compiled.get("security_outcomes") or []:
        initial = list(outcome.get("required_step_ids") or [])
        initial_any_groups = [list(group) for group in outcome.get("required_any_step_groups") or []]
        reproduced = [id_map[item] for item in initial]
        reproduced_any_groups = [[id_map[item] for item in group] for group in initial_any_groups]
        outcome["required_step_ids"] = [*initial, *reproduced]
        outcome["required_any_step_groups"] = [*initial_any_groups, *reproduced_any_groups]
        outcome["reproduction_step_ids"] = list(dict.fromkeys([
            *reproduced,
            *(item for group in reproduced_any_groups for item in group),
        ]))
    compiled["reproduction"] = {"required": True, "attempts": 1, "step_id_map": id_map}
    # Validate the expanded definition as well as the operator-authored one.
    return normalize_tool_definition("workflow", compiled)


def _editable_definition(definition: Any) -> Any:
    """Recover the operator-authored workflow from a stored compiled contract.

    Stored contracts contain generated ``r_`` steps so a run is immutable and
    immediately executable. The Attack Surface editor must not submit those
    generated steps as new source steps when an unchanged contract is saved.
    """
    if not isinstance(definition, dict):
        return definition
    editable = deepcopy(definition)
    reproduction = editable.pop("reproduction", None)
    if not isinstance(reproduction, dict) or not reproduction.get("required"):
        return editable
    raw_map = reproduction.get("step_id_map")
    if not isinstance(raw_map, dict) or not raw_map:
        raise ValueError("compiled workflow reproduction metadata requires a step_id_map")
    id_map = {str(original): str(reproduced) for original, reproduced in raw_map.items()}
    if any(reproduced != f"r_{original}" for original, reproduced in id_map.items()):
        raise ValueError("compiled workflow reproduction metadata contains an invalid generated step id")
    steps = editable.get("steps") or []
    by_id = {str(step.get("id") or ""): step for step in steps if isinstance(step, dict)}
    if set(by_id) != set(id_map).union(id_map.values()):
        raise ValueError("compiled workflow reproduction metadata does not match its step set")
    for original_id, reproduced_id in id_map.items():
        original = by_id.get(original_id)
        reproduced = by_id.get(reproduced_id)
        if not original or not reproduced:
            raise ValueError("compiled workflow reproduction metadata references a missing step")
        expected = {**deepcopy(original), "id": reproduced_id, "name": f"Reproduce: {original['name']}"}
        if reproduced != expected:
            raise ValueError(f"compiled workflow reproduction step {reproduced_id} differs from its source step")
    reproduced_ids = set(id_map.values())
    editable["steps"] = [deepcopy(step) for step in steps if str(step.get("id") or "") not in reproduced_ids]
    for outcome in editable.get("security_outcomes") or []:
        outcome["required_step_ids"] = [
            step_id for step_id in outcome.get("required_step_ids") or [] if step_id not in reproduced_ids
        ]
        source_groups = []
        for group in outcome.get("required_any_step_groups") or []:
            group_ids = set(group)
            if group_ids and group_ids.issubset(reproduced_ids):
                continue
            if group_ids.intersection(reproduced_ids):
                raise ValueError("compiled workflow outcome contains a mixed source/reproduction proof group")
            source_groups.append(group)
        outcome["required_any_step_groups"] = source_groups
        outcome.pop("reproduction_step_ids", None)
    return editable


def _validate_objective_links(
    contracts: list[dict[str, Any]],
    objectives: Iterable[dict[str, Any]],
) -> None:
    objective_index = {
        str(objective.get("id") or ""): objective
        for objective in objectives
        if str(objective.get("id") or "")
    }
    for contract in contracts:
        for outcome in (contract.get("source_definition") or {}).get("security_outcomes") or []:
            outcome_risks = set(str(item) for item in outcome.get("risk_ids") or [])
            outcome_techniques = set(str(item) for item in outcome.get("technique_ids") or [])
            for objective_id in outcome.get("objective_ids") or []:
                objective = objective_index.get(str(objective_id))
                if objective is None:
                    raise ValueError(
                        f"assessment contract {contract['id']} outcome {outcome['id']} references an objective outside this project: {objective_id}"
                    )
                objective_techniques = set(str(item) for item in objective.get("technique_ids") or [])
                objective_risks = set(str(item) for item in objective.get("risk_ids") or [])
                if objective_techniques and not objective_techniques.intersection(outcome_techniques):
                    raise ValueError(
                        f"assessment contract {contract['id']} outcome {outcome['id']} does not share an OWASP technique with objective {objective_id}"
                    )
                if not objective_techniques and objective_risks and not objective_risks.intersection(outcome_risks):
                    raise ValueError(
                        f"assessment contract {contract['id']} outcome {outcome['id']} does not share an OWASP risk with objective {objective_id}"
                    )


def normalize_assessment_contracts(
    value: Any,
    target: dict[str, Any],
    *,
    objectives: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Validate target-owned autonomous evidence contracts.

    Contracts contain target-specific routes, schemas, and deterministic proof
    assertions. The framework contains only the generic workflow engine; it
    never assumes a lab route, secret value, or vulnerable result.
    """
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("assessment contracts must be a JSON list containing at most 100 entries")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"assessment contract {index + 1} must be an object")
        contract_id = str(raw.get("id") or f"contract_{index + 1}")
        if not _CONTRACT_ID.fullmatch(contract_id) or contract_id in seen:
            raise ValueError(f"invalid or duplicate assessment contract id: {contract_id}")
        seen.add(contract_id)
        title = str(raw.get("title") or "").strip()
        if not title:
            raise ValueError(f"assessment contract {contract_id} requires a title")
        kind = str(raw.get("kind") or "workflow")
        if kind != "workflow":
            raise ValueError("autonomous assessment contracts currently require workflow definitions")
        source_definition = normalize_tool_definition(
            kind,
            raw.get("source_definition") if isinstance(raw.get("source_definition"), dict)
            else _editable_definition(raw.get("definition")),
        )
        unresolved = _unresolved_recipe_values(source_definition)
        if unresolved:
            raise ValueError(
                f"assessment contract {contract_id} contains unresolved recipe values: " + ", ".join(unresolved)
            )
        recipe_provenance = _normalize_recipe_provenance(raw.get("recipe_provenance"), contract_id)
        definition = source_definition
        if not definition.get("security_outcomes"):
            raise ValueError(
                f"assessment contract {contract_id} requires at least one explicit security, observation, or methodology outcome"
            )
        for method, path in _static_routes(definition):
            if not route_is_authorized(target, path, method):
                raise ValueError(f"assessment contract {contract_id} route {method} {path} is not in the target allowlist")
        reproduce = raw.get("reproduce", True) not in {False, "false", "0", 0}
        enabled = raw.get("enabled", True) not in {False, "false", "0", 0}
        description = str(raw.get("description") or "")[:2000]
        security_outcomes = [item for item in definition.get("security_outcomes") or [] if item.get("kind") == "security"]
        if security_outcomes and not reproduce:
            missing_reproduction = [item["id"] for item in security_outcomes if not item.get("reproduction_step_ids")]
            if missing_reproduction:
                raise ValueError(
                    f"assessment contract {contract_id} security outcomes require automatic reproduction or explicit reproduction_step_ids: "
                    + ", ".join(missing_reproduction)
                )
        compiled = _compile_reproduction(definition, reproduce)
        outcomes = compiled.get("security_outcomes") or []
        technique_ids = sorted({str(item) for outcome in outcomes for item in outcome.get("technique_ids") or []})
        risk_ids = sorted({str(item) for outcome in outcomes for item in outcome.get("risk_ids") or []})
        normalized.append({
            "id": contract_id,
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "title": title[:200],
            "description": description,
            "enabled": enabled,
            "kind": kind,
            "reproduce": reproduce,
            "maximum_requests": _request_count(compiled),
            "risk_ids": risk_ids,
            "technique_ids": technique_ids,
            "recipe_provenance": recipe_provenance,
            "contract_sha256": _contract_sha256(
                contract_id=contract_id,
                title=title,
                description=description,
                enabled=enabled,
                reproduce=reproduce,
                source_definition=source_definition,
                recipe_provenance=recipe_provenance,
            ),
            "source_definition": source_definition,
            "definition": compiled,
        })
    if objectives is not None:
        _validate_objective_links(normalized, objectives)
    return normalized


def contract_technique_ids(contracts: list[dict[str, Any]] | None) -> set[str]:
    return {
        str(technique_id)
        for contract in contracts or []
        if contract.get("enabled")
        for technique_id in contract.get("technique_ids") or []
    }


def contracts_for_techniques(contracts: list[dict[str, Any]] | None, technique_ids: set[str]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for contract in contracts or []:
        mapped = set(str(item) for item in contract.get("technique_ids") or [])
        # Methodology contracts intentionally carry no OWASP technique. They
        # are included whenever explicitly enabled in an otherwise valid run.
        if contract.get("enabled") and (not mapped or mapped.intersection(technique_ids)):
            selected.append(deepcopy(contract))
    return selected
