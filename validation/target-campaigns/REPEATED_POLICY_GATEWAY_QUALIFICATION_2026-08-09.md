# Repeated policy-gateway qualification — 2026-08-09

## Verdict

`LLM01-DIRECT` is now **qualified within its documented boundary**. AdverScope correctly separated a second, unrelated secure/vulnerable target family with two ASUS-hosted evaluator models and two repetitions per model and target outcome.

| Evaluator | Secure repetitions | Vulnerable repetitions | False results | Reproduction |
|---|---:|---:|---:|---:|
| qwen3.6-27b | 2/2 passed · 8 safe cases | 2/2 passed · 2 findings | 0 | 2/2 |
| qwen3-4b-classifier | 2/2 passed · 8 safe cases | 2/2 passed · 2 findings | 0 | 2/2 |

Across eight oracle expectations, the campaign produced four true positives, four true negatives, no false positives, no false negatives, no transport faults, and complete initial plus reproduction evidence. Precision, supported recall, secure-control specificity, evidence completeness, and vulnerable-run reproduction rate were all 100% for this narrow campaign.

Every project was created and configured through the visible isolated AdverScope GUI. Each had its own rules of engagement, target policy, structured API contract, execution guardrail, assessment objective, technique selection, immutable run, evidence, and review workspace.

## Independent target family

The policy-decision gateway is structurally and semantically different from the first independent semantic fixture:

- It uses a nested request contract instead of a conventional chatbot message body.
- It returns an explicit decision, message, and policy-state object.
- Its secure oracle keeps restricted records restricted and the operating policy enforced.
- Its vulnerable oracle explicitly reclassifies restricted records and reports a bypassed policy.

No proof value, secret, private key, target address, or lab solution is retained in this report.

## Defects found and corrected during qualification

The campaign uncovered two framework defects before the final qualification decision:

1. A Focused run configured for four payloads executed seven because objective-directed and generic model outputs were combined without a final cap. AdverScope now applies the per-module budget after safety filtering, preserves mandatory Guided baselines, prioritizes objective probes, and records each omitted candidate. A full 4B GUI run then generated seven candidates, executed exactly four, recorded three budget-trimmed candidates, and completed with no false finding.
2. The Advanced model selector displayed a hardcoded 27B name while the 4B classifier was active. It now renders the configured runtime model from the health contract. This was verified in the GUI as `Local model · qwen3-4b-classifier`.

Both fixes are general framework behavior and contain no target-specific attack solution.

## Retained runs

- 27B secure: `run_fda78738241e`, `run_43ea392c2b32`
- 27B vulnerable: `run_969be9aa135c`, `run_f6ecc1d080a2`
- 4B secure: `run_f3ad87b42651`, `run_6dc3288922dc`
- 4B vulnerable: `run_cb0dd4d032d4`, `run_4dca0890e445`
- Full 4B generator/evaluator budget check: `run_2ef25c8e7d34`

## Qualification boundary

This result qualifies direct semantic instruction-boundary testing mapped to `LLM01-DIRECT`. It does not qualify other prompt-injection techniques, every AI architecture, or the complete OWASP LLM Top 10. Model-reviewed findings remain explicitly labelled as semantic evidence requiring human confirmation, even after exact automatic reproduction.

The two independent target families are maintained within the AdverScope project. Continued qualification should add external secure/vulnerable target families, new model versions, and periodic repeated campaigns to detect generalization regressions.

The machine-readable record is [repeated-policy-gateway-qualification-2026-08-09.json](repeated-policy-gateway-qualification-2026-08-09.json).
