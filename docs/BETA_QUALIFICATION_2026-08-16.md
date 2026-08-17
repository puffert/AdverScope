# AdverScope Beta qualification — 2026-08-16

## Decision

**AdverScope meets its current benchmark Beta gate for the publicly retained qualification scope.**

The retained campaigns exercised OWASP Basileak, AI Goat, and representative AgentDojo scenarios; classified vulnerable and secure outcomes; retained finding-grade evidence; and reproduced confirmed vulnerabilities where reproduction was required. A separate owner-operated internal suite was also used during development, but its target records, solutions, infrastructure details, and evidence are intentionally excluded from the public repository and do not count as publicly reproducible qualification.

This decision does not claim coverage of every AI vulnerability, every AgentDojo task, every target architecture, every model, or every deployment platform. No recovered proof value, credential, ephemeral target URL, or private-suite solution is included in this record.

## Publicly retained results

| Suite | Supported scope | Gated result | Precision | Recall | Reproduction | Infrastructure errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| AI Goat | C1–C9 | 13/13 expectations: 10 true positives and 3 true negatives | 1.00 | 1.00 | 10/10 | 0 |
| AgentDojo | One pinned task from each of four official suites | 4/4 expectations: 1 true positive and 3 true negatives | 1.00 | 1.00 | 1/1 | 0 |
| OWASP Basileak | R4 protected-content disclosure | 1/1 true positive | 1.00 | 1.00 | 1/1 | 0 |

Authoritative public reports:

- [AI Goat Qwen3.8 qualification](../validation/aigoat/qualification-qwen38-2026-08-16.md)
- [AgentDojo representative Qwen3.8 qualification](../validation/agentdojo/qualification-qwen38-2026-08-16.md)
- [OWASP Basileak R4 Qwen3.8 qualification](../validation/basileak/qualification-qwen38-2026-08-16.md)

The adjacent JSON reports are the machine-readable authorities. The relevant scorers were run with their required gates against the final retained AdverScope records.

## Execution and evidence standard

- Each scenario was represented as an isolated AdverScope project with its own authorization, policy, target, guardrails, objectives, run configuration, traffic, evidence, findings, and review state.
- Campaigns used the ordinary AdverScope workflow. Oracle expectations were not supplied to planning, generation, target requests, or autonomous evaluation.
- Confirmed findings required target-backed deterministic evidence or an explicitly configured verified effect. Model opinion alone could not create an autonomous finding.
- Required reproduction used a separate retained request/response evidence pair.
- Public third-party targets were pinned to recorded source revisions where the suite supported that workflow.

## Final framework verification

The private qualification commit completed the full regression, focused MCP and deterministic-provenance checks, reliability controls, compilation, JavaScript syntax, Git whitespace validation, and a visible runtime health check. The clean public-source repository is independently rebuilt, retested, and scanned before publication; its current CI result is the authoritative release check.

## Boundaries and remaining release work

This Beta decision covers detection, classification, evidence, reproduction, secure controls, and project isolation only for the stated scopes. It does not close these v1.0 gates:

1. long-duration soak and resource observation;
2. independent product-security review;
3. retained Windows, Ubuntu, and macOS qualification for the exact release candidate;
4. broader independent secure/vulnerable target pairs for professionally claimed techniques;
5. independent usability evidence from working pentesters.

AgentDojo remains a representative four-suite qualification, not the complete task matrix. New adapters, techniques, models, or material evaluator changes require fresh qualification rather than inheriting this result.
