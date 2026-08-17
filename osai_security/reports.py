from __future__ import annotations

import html
import json
from typing import Any

from . import build_identity
from .methodology import methodology_card_is_trusted
from .release import REPORT_SCHEMA_VERSION, RETEST_REPORT_SCHEMA_VERSION


def _clean(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def _markdown_text(value: Any) -> str:
    text = html.escape(_clean(value), quote=False).replace("\\", "\\\\")
    for marker in ("`", "*", "_", "[", "]"):
        text = text.replace(marker, "\\" + marker)
    return text


def _table_cell(value: Any) -> str:
    return _markdown_text(value).replace("|", "\\|")


def _count_summary(values: dict[str, Any] | None) -> str:
    items = [(str(key), int(value)) for key, value in (values or {}).items() if int(value)]
    return ", ".join(f"{key}: {value}" for key, value in sorted(items)) or "not recorded"


def build_markdown_report(project: dict[str, Any]) -> str:
    report_identity = build_identity()
    report_review = project.get("report_review") or {}
    report_is_accepted = bool(report_review.get("effective_status") == "accepted" and report_review.get("is_current"))
    report_status = "FINAL — professionally reviewed" if report_is_accepted else "DRAFT — professional review required"
    coverage = project.get("owasp_coverage") or {}
    runs = project.get("runs") or []
    tool_runs = project.get("tool_runs") or []
    findings = project.get("findings") or []
    tool_findings = project.get("tool_findings") or []
    targets = project.get("targets") or []
    reasoning = project.get("assessment_reasoning") or {}
    guardrails = {item["target_id"]: item for item in project.get("guardrails") or []}
    lines = [
        f"# {_clean(project.get('name'))} — AI Security Assessment Report",
        "",
        f"- Project ID: `{project.get('id')}`",
        f"- Client: {_clean(project.get('client')) or 'Not specified'}",
        f"- Environment: {_clean(project.get('environment'))}",
        f"- Data classification: {_clean(project.get('data_classification'))}",
        f"- Generated from preserved records: {project.get('updated_at')}",
        f"- Report generator: {report_identity['name']} {report_identity['version']} (build `{_clean(report_identity['build_revision'])}`)",
        f"- Report schema: {REPORT_SCHEMA_VERSION}",
        f"- Report status: **{report_status}**",
        f"- Accepted reviewer: {_clean(report_review.get('reviewer')) or 'Not accepted'}",
        f"- Review recorded: {_clean(report_review.get('updated_at')) or 'Not recorded'}",
        "",
        "## Executive summary",
        "",
        f"The project contains {len(runs)} autonomous assessment run(s), {len(tool_runs)} testing-tool run(s), {len(findings) + len(tool_findings)} finding(s), and {sum(int((run.get('counts') or {}).get('test_cases', 0)) for run in runs)} executed chatbot test case(s). Autonomous findings require target-backed deterministic proof, a deterministic oracle, or a verified downstream effect. Model-only candidates remain inconclusive; untested or non-automated techniques are not represented as passes.",
        "",
        "## Authorized attack surface and execution guardrails",
        "",
    ]
    for target in targets:
        guardrail = guardrails.get(target["id"], {})
        capabilities = ", ".join(key for key, enabled in (target.get("capabilities") or {}).items() if enabled) or "none declared"
        adapters = ", ".join(sorted((target.get("technique_adapters") or {}).keys())) or "none configured"
        tool_agent = ((target.get("evaluation_config") or {}).get("tool_agent") or {})
        agentic_trace = ((target.get("evaluation_config") or {}).get("agentic_trace") or {})
        mcp = ((target.get("evaluation_config") or {}).get("mcp") or {})
        rag = ((target.get("evaluation_config") or {}).get("rag") or {})
        mcp_location = (
            f"local executable SHA-256 {str((mcp.get('stdio') or {}).get('executable_sha256') or '')[:12]}…"
            if mcp.get("transport") == "stdio"
            else f"endpoint `{_clean(mcp.get('endpoint_path')) or '—'}`"
        )
        lines.extend([
            f"### {_clean(target.get('name'))}", "",
            f"- Target reference: `{target.get('id')}`",
            f"- Endpoint: `{target.get('method')} {target.get('base_url')}{target.get('path')}`",
            f"- Capabilities: {capabilities}",
            f"- Attack Surface technique adapters: {adapters}",
            f"- Tool/agent protocol: {_clean(tool_agent.get('protocol')) if tool_agent.get('enabled') else 'not configured'}; {len(tool_agent.get('tools') or [])} function schema(s); {len(tool_agent.get('identities') or [])} identity profile(s); {len(tool_agent.get('cases') or [])} security case(s)",
            f"- Agentic trace protocol: {_clean(agentic_trace.get('protocol')) if agentic_trace.get('enabled') else 'not configured'}; {len(agentic_trace.get('identities') or [])} identity profile(s); {len(agentic_trace.get('cases') or [])} planner/executor boundary case(s)",
            f"- MCP protocol: {_clean(mcp.get('transport')) if mcp.get('enabled') else 'not configured'}; {mcp_location}; {len(mcp.get('identities') or [])} identity profile(s); {len(mcp.get('cases') or [])} security case(s)",
            f"- RAG workflow: {'configured' if rag.get('enabled') else 'not configured'}; {len(rag.get('identities') or [])} identity profile(s); {len(rag.get('cases') or [])} reversible temporary-document case(s); {int(rag.get('query_attempts') or 0)} maximum attack retrieval attempt(s); {int(rag.get('cleanup_verify_attempts') or 0)} maximum post-cleanup verification attempt(s)",
            f"- Guardrail: {_clean(guardrail.get('status')) or 'missing'}; maximum {guardrail.get('max_requests', '—')} requests; maximum runtime {guardrail.get('max_runtime_seconds', '—')} seconds",
            f"- Active recon: {'allowed' if guardrail.get('allow_active_recon') else 'not allowed'}; multi-turn: {'allowed' if guardrail.get('allow_multi_turn') else 'not allowed'}; reproduction: {'allowed' if guardrail.get('allow_reproduction') else 'not allowed'}",
            "",
        ])
    reasoning_summary = reasoning.get("summary") or {}
    methodology_cards = reasoning.get("methodology_cards") or []
    reasoning_nodes = reasoning.get("nodes") or []
    reasoning_edges = reasoning.get("edges") or []
    hypotheses = reasoning.get("hypotheses") or []
    checkpoints = reasoning.get("checkpoints") or []
    node_labels = {str(item.get("id")): _clean(item.get("label")) for item in reasoning_nodes}
    verified_methodology_count = sum(methodology_card_is_trusted(card) for card in methodology_cards)
    lines.extend([
        "## Assessment reasoning record (advisory)", "",
        "These records structure operator reasoning only. They do not add authorization, scope, routes, identities, permissions, evidence, findings, or verdicts. A hypothesis or manual checkpoint is never finding-grade on its own.", "",
        f"- Methodology cards pinned / verified against this framework build: {len(methodology_cards)} / {verified_methodology_count}",
        f"- System-map nodes / relationships: {len(reasoning_nodes)} / {len(reasoning_edges)}",
        f"- Facts / inferences / hypotheses / failed paths: {reasoning_summary.get('facts', 0)} / {reasoning_summary.get('inferences', 0)} / {sum(item.get('classification') == 'hypothesis' for item in hypotheses)} / {reasoning_summary.get('failures', 0)}",
        f"- Evidence checkpoints: {len(checkpoints)}",
        "",
        "### Pinned methodology", "",
        "| Card | Version | Review provenance | Snapshot SHA-256 |",
        "|---|---|---|---|",
    ])
    if methodology_cards:
        for card in methodology_cards:
            provenance = card.get("provenance") or {}
            trusted = methodology_card_is_trusted(card)
            review_status = (
                _table_cell(provenance.get("review_status")) or "not recorded"
                if trusted
                else "UNTRUSTED - excluded from model context"
            )
            lines.append(
                f"| {_table_cell(card.get('card_id') or card.get('id'))} - {_table_cell(card.get('title'))} | "
                f"{_table_cell(card.get('version'))} | {review_status} | "
                f"{_table_cell(card.get('sha256')) or 'not recorded'} |"
            )
    else:
        lines.append("| None pinned | - | - | - |")
    lines.extend([
        "", "### Component and trust relationships", "",
        "| Node | Type | Confidence | Target | Source reference |",
        "|---|---|---|---|---|",
    ])
    if reasoning_nodes:
        for node in reasoning_nodes:
            lines.append(
                f"| {_table_cell(node.get('label'))} | {_table_cell(node.get('kind'))} | {_table_cell(node.get('confidence'))} | "
                f"{_table_cell(node.get('target_id')) or 'project-wide'} | {_table_cell(node.get('source_ref')) or 'not recorded'} |"
            )
    else:
        lines.append("| No nodes recorded | - | - | - | - |")
    lines.extend([
        "", "#### Relationships", "",
        "| Source | Relationship | Destination | Status | Evidence refs |",
        "|---|---|---|---|---|",
    ])
    if reasoning_edges:
        for edge in reasoning_edges:
            lines.append(
                f"| {_table_cell(node_labels.get(str(edge.get('source_node_id'))) or edge.get('source_node_id'))} | "
                f"{_table_cell(edge.get('kind'))} | "
                f"{_table_cell(node_labels.get(str(edge.get('target_node_id'))) or edge.get('target_node_id'))} | "
                f"{_table_cell(edge.get('status'))} | {_table_cell(', '.join(edge.get('evidence_refs') or [])) or 'none'} |"
            )
    else:
        lines.append("| No relationships recorded | - | - | - | - |")
    lines.extend([
        "", "### Facts, inferences, hypotheses, and failed paths", "",
        "| Classification | Decision | Claim | Missing prerequisite / negative evidence | Cheapest discriminating test | Evidence refs |",
        "|---|---|---|---|---|---|",
    ])
    if hypotheses:
        for item in hypotheses:
            lines.append(
                f"| {_table_cell(item.get('classification')).upper()} | {_table_cell(item.get('decision')).upper()} | "
                f"{_table_cell(item.get('claim'))} | {_table_cell(item.get('missing_prerequisite')) or 'none recorded'} | "
                f"{_table_cell(item.get('cheapest_test')) or 'none recorded'} | {_table_cell(', '.join(item.get('evidence_refs') or [])) or 'none'} |"
            )
    else:
        lines.append("| No reasoning claims recorded | - | - | - | - | - |")
    lines.extend([
        "", "### Evidence checkpoints", "",
        "| Checkpoint | Model proposed | App returned | Tool executed | Backend changed | Impact verified | Cleanup | Linked retained evidence |",
        "|---|---|---|---|---|---|---|---|",
    ])
    if checkpoints:
        for item in checkpoints:
            stages = item.get("stages") or {}
            stage_status = lambda key: _table_cell((stages.get(key) or {}).get("status")) or "not-observed"
            evidence_link = _table_cell(item.get("evidence_id")) or "manual / not linked"
            lines.append(
                f"| {_table_cell(item.get('title'))} | {stage_status('model_proposed')} | {stage_status('application_returned')} | "
                f"{stage_status('tool_executed')} | {stage_status('backend_changed')} | {stage_status('impact_verified')} | "
                f"{_table_cell(item.get('cleanup_status'))} | {evidence_link} |"
            )
    else:
        lines.append("| No checkpoints recorded | - | - | - | - | - | - | - |")
    if checkpoints:
        lines.extend(["", "#### Checkpoint detail", ""])
        for item in checkpoints:
            lines.extend([
                f"**{_markdown_text(item.get('title'))}** ({_markdown_text(item.get('id'))})", "",
                f"- Starting identity: {_markdown_text(item.get('starting_identity')) or 'not recorded'}",
                f"- Prerequisite: {_markdown_text(item.get('prerequisite')) or 'not recorded'}",
                f"- Bounded action: {_markdown_text(item.get('action')) or 'not recorded'}",
                f"- Observed result: {_markdown_text(item.get('result')) or 'not recorded'}",
                f"- Independently verified impact: {_markdown_text(item.get('impact')) or 'not recorded'}",
                f"- Correction of: {_markdown_text(item.get('correction_of_id')) or 'none'}",
                "",
            ])
    lines.extend(["", "Checkpoints are append-only. Corrections reference the earlier record; neither record creates or upgrades a finding.", ""])
    lines.extend([
        "## Execution provenance", "",
        "| Execution | Kind | Framework | Build | Manifest SHA-256 |",
        "|---|---|---|---|---|",
    ])
    for execution_kind, execution_runs in (("assessment", runs), ("testing tool", tool_runs)):
        for run in execution_runs:
            manifest = run.get("manifest") or {}
            identity = manifest.get("framework") or {}
            framework_label = f"{_clean(identity.get('name'))} {_clean(identity.get('version'))}".strip() or "legacy/unrecorded"
            lines.append(
                f"| `{run.get('id')}` | {execution_kind} | {framework_label} | "
                f"`{_clean(identity.get('build_revision')) or 'legacy/unrecorded'}` | "
                f"`{_clean(manifest.get('manifest_sha256')) or 'legacy/unrecorded'}` |"
            )
    if not runs and not tool_runs:
        lines.append("| N/A | N/A | No executions recorded | N/A | N/A |")
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.extend(["No findings are currently recorded. This does not imply that untested controls passed.", ""])
    for finding in findings:
        lines.extend([
            f"### {_clean(finding.get('title'))}", "",
            f"- Finding ID: `{finding.get('id')}`",
            f"- Severity: {_clean(finding.get('severity')).upper()}",
            f"- Review status: {_clean(finding.get('status'))}",
            f"- Confidence: {float(finding.get('confidence') or 0):.0%}",
            f"- Occurrences: {finding.get('occurrence_count', 0)}",
            "",
            _clean(finding.get("summary")), "",
            "#### Reproduction evidence", "",
        ])
        for occurrence in finding.get("occurrences") or []:
            evaluation = occurrence.get("evaluation") or {}
            assurance = evaluation.get("evidence_assurance") or {}
            lines.extend([
                f"Run `{occurrence.get('run_id')}`, case `{occurrence.get('test_case_id')}`", "",
                f"- Payload execution source: {_clean(evaluation.get('execution_source')) or 'legacy/unknown'}",
                f"- Evaluator: {_clean(evaluation.get('evaluator')) or 'not recorded'}",
                f"- Evidence assurance: {_clean(assurance.get('level')) or 'legacy/unknown'}; confirmation state: {_clean(assurance.get('confirmation_state')) or 'not recorded'}; finding eligible: {'yes' if assurance.get('finding_eligible') else 'no'}",
                f"- Assurance basis: {_clean(assurance.get('basis')) or 'not recorded'}",
                "",
                "**Payload**", "", "```text", str(occurrence.get("prompt") or ""), "```", "",
                "**Target response**", "", "```text", str(occurrence.get("response") or ""), "```", "",
            ])
            protocol_events = occurrence.get("protocol_events") or []
            if protocol_events:
                normalized = [
                    {
                        "sequence": event.get("sequence"),
                        "protocol": event.get("protocol"),
                        "phase": event.get("phase"),
                        "direction": event.get("direction"),
                        "event_type": event.get("event_type"),
                        "correlation_id": event.get("correlation_id"),
                        "round": event.get("round_number"),
                        "payload": event.get("payload") or {},
                        "recorded_at": event.get("created_at"),
                    }
                    for event in protocol_events
                ]
                lines.extend([
                    f"**Normalized AI protocol trace ({len(normalized)} events)**", "",
                    "AdverScope retained proposed calls and the normalized component trace. Tool-agent cases use configured simulated outputs and never dispatch target tools; MCP and RAG cases retain their explicitly authorized protocol operations and cleanup evidence.", "",
                    "```json", json.dumps(normalized, ensure_ascii=False, indent=2), "```", "",
                ])
    for finding in tool_findings:
        lines.extend([
            f"### {_clean(finding.get('title'))}", "",
            f"- Finding ID: `{finding.get('id')}`",
            f"- Testing-tool run: `{finding.get('tool_run_id')}`",
            f"- Severity: {_clean(finding.get('severity')).upper()}",
            f"- Review status: {_clean(finding.get('status'))}",
            f"- Confidence: {float(finding.get('confidence') or 0):.0%}",
            f"- Confirmation: {_clean(finding.get('confirmation'))}",
            "- Execution source: target-configured evidence contract",
            "- Evidence assurance: deterministic-contract",
            f"- OWASP mapping: {', '.join(finding.get('technique_ids') or finding.get('risk_ids') or [])}",
            "",
            _clean(finding.get("summary")), "",
            "Exact request, response, and assertion evidence remains linked in the immutable testing-tool run.", "",
        ])
    lines.extend(["## Assessment runs", "", "| Run | Status | Started | Recon | Attack catalog | Confirmation policy | Execution sources | Evidence assurance | Tests | Protocol events | Vulnerable observations |", "|---|---|---:|---|---|---|---|---|---:|---:|---:|"])
    for run in runs:
        counts = run.get("counts") or {}
        plan = run.get("assessment_plan") or {}
        recon = plan.get("recon") or {"mode": "none"}
        catalog = plan.get("attack_catalog") or {}
        recon_label = f"{recon.get('mode', 'none')} / {recon.get('profile', '—')}" if recon.get("mode") == "bounded" else "none"
        catalog_label = f"{catalog.get('id')} {catalog.get('version')}" if catalog else "legacy/unspecified"
        confirmation_label = _clean((plan.get("confirmation_policy") or {}).get("mode")) or "legacy/unspecified"
        metrics = run.get("metrics") or {}
        lines.append(f"| `{run.get('id')}` | {_clean(run.get('status'))} | {_clean(run.get('started_at'))} | {_clean(recon_label)} | {_clean(catalog_label)} | {confirmation_label} | {_clean(_count_summary(metrics.get('execution_source_counts')))} | {_clean(_count_summary(metrics.get('evidence_assurance_counts')))} | {counts.get('test_cases', 0)} | {counts.get('protocol_events', 0)} | {counts.get('vulnerable_cases', 0)} |")
    lines.extend(["", "## Testing-tool runs", "", "| Run | Kind | Status | Started | Requests | Passed assertions | Failed assertions | Findings |", "|---|---|---|---|---:|---:|---:|---:|"])
    for run in tool_runs:
        counts = dict(run.get("counts") or {})
        pipeline = ((run.get("metrics") or {}).get("pipeline") or {})
        if not counts:
            counts = {
                "requests": int(pipeline.get("request_sent") or 0),
                "assertions_passed": int(pipeline.get("assertions_passed") or 0),
                "assertions_failed": int(pipeline.get("assertions_failed") or 0),
            }
        lines.append(f"| `{run.get('id')}` | {_clean(run.get('kind'))} | {_clean(run.get('status'))} | {_clean(run.get('started_at'))} | {counts.get('requests', 0)} | {counts.get('assertions_passed', 0)} | {counts.get('assertions_failed', 0)} | {len(run.get('security_findings') or [])} |")
    lines.extend(["", f"## OWASP LLM coverage ({coverage.get('taxonomy_version', '2025')})", "", "| Risk | Status | Attempts | Execution sources |", "|---|---|---:|---|"])
    for risk in coverage.get("risks") or []:
        lines.append(f"| {risk.get('id')} — {_clean(risk.get('title'))} | {_clean(risk.get('status')).replace('_', ' ')} | {risk.get('attempts', 0)} | {_clean(_count_summary(risk.get('execution_sources')))} |")
    lines.extend([
        "", "## Professional review and limitations", "",
        f"Review state: **{report_status}**.", "",
        _clean(report_review.get("notes")) if report_review.get("notes") else "No professional review note is recorded.", "",
        "This report reflects only the saved targets, declared capabilities, approved execution guardrails, selected objectives, versioned attack catalog, executed techniques, run-scoped reconnaissance, and preserved evidence. Optional technical inputs and reconnaissance observations do not expand authorization. Not applicable, not automated, not tested, and inconclusive coverage must not be interpreted as a security pass.", "",
        "The accompanying AdverScope evidence bundle is the technical and evidence appendix. Verify its manifest before relying on linked records or screenshots.", "",
    ])
    return "\n".join(lines)


def build_retest_report(project: dict[str, Any], comparison: dict[str, Any]) -> str:
    """Build a conservative run-to-run retest report from run-scoped evidence."""
    identity = build_identity()
    baseline_id = str(comparison.get("baseline_run_id") or "")
    current_id = str(comparison.get("current_run_id") or "")
    lines = [
        f"# {_clean(project.get('name'))} — AI Security Retest Report",
        "",
        f"- Project ID: `{project.get('id')}`",
        f"- Client: {_clean(project.get('client')) or 'Not specified'}",
        f"- Environment: {_clean(project.get('environment'))}",
        f"- Baseline run: `{baseline_id}` ({_clean(comparison.get('baseline_status'))})",
        f"- Current run: `{current_id}` ({_clean(comparison.get('current_status'))})",
        f"- Generator: {identity['name']} {identity['version']} (build `{_clean(identity['build_revision'])}`)",
        f"- Retest report schema: {RETEST_REPORT_SCHEMA_VERSION}",
        "- Report status: **DRAFT — professional review required**",
        "",
        "## Retest conclusion",
        "",
        _clean(comparison.get("conclusion")),
        "",
        "The comparison uses only evidence, findings, and reproductions scoped to the two named runs. A missing repeat is not automatically a fixed vulnerability.",
        "",
        "## Configuration and methodology changes",
        "",
        "| Section | Changed | Baseline SHA-256 | Current SHA-256 |",
        "|---|---|---|---|",
    ]
    for item in comparison.get("configuration_changes") or []:
        lines.append(
            f"| {_clean(item.get('section'))} | {'yes' if item.get('changed') else 'no'} | "
            f"`{_clean(item.get('baseline_sha256'))}` | `{_clean(item.get('current_sha256'))}` |"
        )
    lines.extend([
        "",
        "Changed configuration snapshots are preserved in the comparison record. Review them before attributing a changed outcome to remediation.",
        "",
        "## Security outcomes",
        "",
        "| Status | Finding | Severity | OWASP techniques | Baseline | Current | Reason |",
        "|---|---|---|---|---|---|---|",
    ])
    outcomes = comparison.get("security_outcomes") or []
    for item in outcomes:
        lines.append(
            f"| {_clean(item.get('status')).replace('_', ' ')} | {_clean(item.get('title'))} | "
            f"{_clean(item.get('severity')).upper()} | {_clean(', '.join(item.get('technique_ids') or [])) or 'not mapped'} | "
            f"`{_clean(item.get('baseline_finding_id')) or '—'}` | `{_clean(item.get('current_finding_id')) or '—'}` | "
            f"{_clean(item.get('reason'))} |"
        )
    if not outcomes:
        lines.append("| No run-scoped findings | — | — | — | — | — | Review coverage gaps before interpreting this as a secure result. |")
    lines.extend([
        "",
        "## Coverage accounting",
        "",
        "| Run | Selected techniques | Planned | Reviewed cases | Model-generated cases | Reproduced techniques | Unsupported | Not tested |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for label, summary in (("Baseline", comparison.get("baseline_summary") or {}), ("Current", comparison.get("current_summary") or {})):
        counts = summary.get("counts") or {}
        lines.append(
            f"| {label} | {counts.get('selected_techniques', 0)} | {counts.get('planned_techniques', 0)} | "
            f"{counts.get('reviewed_executed_cases', 0)} | {counts.get('model_generated_executed_cases', 0)} | "
            f"{counts.get('reproduced_techniques', 0)} | {counts.get('unsupported_techniques', 0)} | "
            f"{counts.get('not_tested_techniques', 0)} |"
        )
    lines.extend([
        "",
        "## Required professional review",
        "",
        "- Confirm that the target and customer environment were in the intended state for both runs.",
        "- Review every changed target, adapter, guardrail, catalog, model, and plan snapshot.",
        "- Inspect exact request, response, hash, evaluator, and reproduction evidence for persistent and new findings.",
        "- Mark a finding fixed only when relevant retest coverage and direct evidence support that disposition.",
        "- Record inconclusive, unavailable, and not-retested items explicitly.",
        "",
        "This draft does not replace the two immutable run evidence packages.",
        "",
    ])
    return "\n".join(lines)
