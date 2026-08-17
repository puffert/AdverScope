# Fresh multi-model target qualification — 2026-08-08

## Verdict

`LLM01-DIRECT` is now **validated**, not qualified. On the final code, both ASUS-hosted evaluators correctly separated an independent secure target from its vulnerable counterpart:

| Evaluator | Secure fixture | Vulnerable fixture | Reproduction | Evidence completeness |
|---|---:|---:|---:|---:|
| qwen3.6-27b | 0 findings / 4 cases | 1 finding / 1 case | confirmed | 100% |
| qwen3-4b-classifier | 0 findings / 4 cases | 1 finding / 1 case | confirmed | 100% |

The aggregate result is 2 true positives, 2 true negatives, no false positives, no false negatives, and no transport or infrastructure errors. This is a deliberately narrow supported-recall statement for one technique and one target family.

## What changed during qualification

The campaign found three real framework defects before the final passing runs:

1. AdverScope’s evidence gate correctly recognized semantic policy violations as candidates, but suppressed them before an approved reproduction could run.
2. The GUI displayed the model-review reproduction checkbox but serialized it as false unless deterministic proof mode was selected.
3. The 4B evaluator confused assessment policy text with target-response evidence and returned a logically contradictory safe verdict.

The fixes are generic. A model-reviewed semantic candidate now remains non-final until the configured exact or statistical reproduction threshold is met. A successful reproduction creates an open finding clearly labelled as reproduced semantic evidence that still requires human confirmation. Consequential tool, MCP, RAG, and state-changing workflows continue to require target-owned deterministic proof.

The evaluator prompt now separates assessment context, attack prompt, and target response into explicit roles, applies objective criteria as textual entailment, and forbids treating attack-prompt wording as proof.

## Retained final runs

- 27B secure: `run_9d61b0820c1e`
- 27B vulnerable: `run_1d483c2f4436`
- 4B secure: `run_b77099f196e5`
- 4B vulnerable: `run_ec11218cadb6`

Each project was configured and executed through the visible AdverScope GUI with its own rules of engagement, policy, target, guardrail, objective, technique selection, run, evidence, and review boundary.

## Qualification boundary

This result does not establish full OWASP coverage, general cross-target recall, or production readiness for every AI architecture. It promotes `LLM01-DIRECT` from experimental to validated because one independent target family now has both secure and vulnerable evidence across two model sizes. A qualified claim requires a second unrelated target family, repeated campaigns, and precision/recall gates that remain at or above 95%.

The full machine-readable record is in `fresh-multi-model-qualification-2026-08-08.json`. It intentionally contains no target secret, proof value, private key, or recovered protected content.
