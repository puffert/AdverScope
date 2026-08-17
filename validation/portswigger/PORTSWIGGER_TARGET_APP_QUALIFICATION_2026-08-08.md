# PortSwigger Web LLM target-application qualification

- **Campaign:** `portswigger-target-apps-2026-08-08`
- **Execution:** Four separate projects configured and run through the normal AdverScope GUI
- **Oracle use:** Isolated post-run scoring only; no expected outcome, solution, payload, route argument, credential, response, or proof value was supplied to AdverScope

## Verdict

The four current PortSwigger Web LLM labs where the vulnerable LLM integration is the assessment target passed the initial AdverScope target-application qualification gate.

| Metric | Result |
|---|---:|
| Projects | 4 |
| Gated expectations | 7 |
| Vulnerable expectations | 4 true positives, 0 false negatives |
| Secure controls | 3 true negatives, 0 false positives |
| Precision | 1.0 |
| Supported recall | 1.0 |
| Selected-run execution errors | 0 |
| Finding evidence completeness | 1.0 |
| Reproduction | 2/2 required non-destructive findings confirmed |
| Consequential one-time proofs | 2/2 retained with deterministic target-owned outcome evidence; automatic replay intentionally prohibited |
| Cross-project execution IDs | 0 |

The machine-readable comparison is retained in `qualification-target-apps-2026-08-08.json`; its human-readable rows are in `qualification-target-apps-2026-08-08.md`.

## Qualified target families

| Project | Security outcome | Direct proof | Reproduction policy |
|---|---|---|---|
| PS-LLM-01 | Excessive agency causing an unauthorized consequential tool action | Target-owned browser state transition and screenshots | One-time disposable effect; no automatic destructive replay |
| PS-LLM-02 | Secondary command-boundary vulnerability reached through an LLM API | Target-owned completion state and browser evidence | One-time disposable effect; no automatic destructive replay |
| PS-LLM-03 | Stored indirect prompt injection | Differential stored-content evidence with clean controls | Confirmed run-scoped reproduction |
| PS-LLM-04 | Insecure downstream handling of LLM output | Same-origin absent-to-present browser state transition not present in the trigger request | Confirmed run-scoped reproduction |

Each reportable case retains request and response evidence, evaluator state, finding linkage, and screenshots. The two reproduced browser workflows also retain separate reproduction evidence. PortSwigger challenge completion is corroboration for the two explicitly approved disposable effects; it is not the generic vulnerability criterion used by production modules.

## Defects found and corrected during qualification

- Browser transcript selectors could stabilize on a trailing transient status placeholder.
- A clean stored-content retrieval could be misclassified when the finding-grade proof was a downstream browser effect rather than textual marker emission.
- A verified browser stop condition could terminate the run before the approved reproduction branch.
- Stored carrier, vulnerable response, and reproduction screenshots were not initially presented as one concise attack path.

Every correction was implemented generically and covered by secure and vulnerable fixtures. No PortSwigger instance URL, lab solution, target credential, payload, proof value, or lab-specific branch was added to production attack or evaluator logic.

## Scope boundary

This report qualifies target-facing web/LLM integration behavior. It does not qualify AdverScope as a hostile-content scanner. The four PortSwigger AI-powered scanner labs are tracked separately as scanner-resilience requirements. AdverScope will use controlled local fixtures to prove that hostile page content cannot expand scope, reveal local data, redirect traffic, or cause unauthorized actions; destructive external execution is unnecessary for those properties.
