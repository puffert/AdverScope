# AdverScope Milestone 5 Tester Preview

Version 0.9.0 Beta · independent qualification

This guide helps independent pentesters qualify the public Beta on authorized AI implementations so the project can measure professional reliability and usability. Public source availability is not a stable-release claim and is not permission to test any third-party system.

## Preview package and readiness check

The preview package consists of this guide, the [full User Manual](USER_MANUAL.md), the [installation guide](INSTALLATION.md), the [support matrix](SUPPORT_MATRIX.md), and the [coordinator checklist](TESTER_PREVIEW_COORDINATOR.md). The coordinator supplies an exact version or commit, an opaque session ID, an approved target package, and private support and confidential-evidence routes.

From the pinned checkout, verify that the onboarding assets, screenshots, feedback contract, and CI enforcement are current:

```powershell
uv run python scripts/check_tester_preview.py
```

This check establishes preview-package readiness only. It does not claim that an independent target, model, technique, or operating system passed qualification.

## Who should receive access

A preview tester should be able to:

- understand and follow written rules of engagement;
- operate a local security-testing application;
- identify and safely handle confidential assessment evidence;
- distinguish a model opinion from deterministic target proof;
- review false positives, reproduction, cleanup, and limitations;
- provide a sanitized technical report.

Start with a small cohort. Give each tester a named contact, a supported installation path, a synthetic or explicitly authorized target, and a private defect-reporting route.

## Entry gates

Before a tester starts:

1. The tester has explicit written authorization for the exact target.
2. The target is a synthetic fixture, lab, non-production environment, or independently owned authorized system.
3. The rules of engagement define routes, identities, permitted actions, traffic limits, stop conditions, and whether reversible changes are allowed.
4. The tester uses an encrypted, access-controlled local volume.
5. The tester has a verified AdverScope backup and knows how to restore it.
6. The selected local or remote model is approved for the target data classification.
7. Provider keys are supplied through environment variables or the memory-only session field.
8. Customer data, credentials, private keys, recovered values, and full internal bundles will not be placed in GitHub issues.

## Recommended first qualification

Use the bundled synthetic tutorial before a customer-like target:

```powershell
python scripts/bootstrap.py
uv run adverscope doctor
uv run adverscope tutorial create
uv run adverscope tutorial target
uv run adverscope serve
```

Complete the tutorial through the visible GUI. The tester should be able to:

- find and open the generated project;
- explain the difference between scope, target policy, guardrail, objective, and proof;
- run a connection check;
- review the immutable run definition;
- find the exact curl request and raw response;
- distinguish initial evidence from reproduction;
- accept or reject a finding;
- export a redacted run bundle;
- create and verify a backup.

## Independent target procedure

Create one project per target and work as a normal user:

1. Record project ownership, environment, and classification.
2. Import the real rules of engagement and target policy.
3. Map the exact target interfaces and only the capabilities that exist.
4. Configure environment-backed authentication without storing secret values.
5. Add target-owned proof contracts, fixtures, or factual oracles when required.
6. Approve bounded guardrails and stop conditions.
7. Define reportable objectives with success criteria and false-positive exclusions.
8. Run **Test connection**.
9. Use Guided mode for a conventional one-endpoint JSON chatbot; otherwise use Advanced mode.
10. Review the proposed plan, OWASP techniques, applicability, model roles, and request estimate before target traffic.
11. Observe the live log and stop if authorization, target behavior, or network conditions change.
12. Review Assess, Evidence, and Review after completion.
13. Adjudicate every candidate finding and every expected weakness the run missed.
14. Export the smallest authorized evidence package.
15. Back up the local project according to the retention plan.

## What the preview must measure

For each target and model profile, record:

- applicable expected vulnerable and secure controls;
- selected, planned, executed, skipped, unsupported, and errored techniques;
- true positives, false positives, false negatives, and true negatives where a benchmark oracle exists;
- finding-level and attempt-level reproduction;
- evidence completeness and cleanup success;
- time to first configured run and time to first defensible finding;
- model-generation failures, evaluator disagreements, and cross-model variance;
- transport, restart, and recovery faults;
- places where the tester needed developer help;
- unclear labels, excessive density, hidden controls, and missing explanations.

Do not score an inapplicable control as a miss. Do not score an inconclusive result as secure. Record the benchmark oracle separately from AdverScope's verdict.

## Milestone 5 proposed exit gates

These are release gates for the project, not claims already achieved:

- At least three independent pentesters complete the tutorial and one unfamiliar target without direct developer operation.
- At least 90% of the documented core tasks are completed without assistance.
- Every professionally supported technique family has secure and vulnerable qualification on at least two independent target implementations, or is explicitly demoted from supported coverage.
- Aggregate precision is at least 95% and supported recall at least 90% on the frozen independent evaluator corpus.
- Finding-level reproduction succeeds at least 90% of the time for deterministic applicable findings.
- No unresolved critical or high-severity AdverScope security defect remains.
- Long-run cancellation, restart recovery, transfer, backup, restore, and evidence-integrity gates pass on every supported platform.
- Repeated qualification on approved local and remote model profiles reports variance, latency, and cost rather than assuming model equivalence.
- Documentation, screenshots, installation, support matrix, and limitations match the release candidate.

If a gate is not met, publish the limitation or reduce the support claim. Do not tune only to a benchmark lab or encode its answer in a generic attack module.

## Feedback package

Submit one sanitized package containing:

- tester role and experience level;
- operating system and installation method;
- AdverScope version and build revision;
- model provider kind, model ID, and assigned role without keys or URLs containing credentials;
- sanitized target type, capabilities, and adapter;
- run IDs and affected technique IDs;
- expected benchmark/control outcome;
- actual AdverScope verdict and human adjudication;
- exact failure stage: planning, generation, transport, extraction, evaluation, proof, reproduction, cleanup, review, report, or recovery;
- redacted bundle or minimal synthetic reproduction;
- usability task, elapsed time, and point of confusion;
- suggested severity and whether the issue blocks further testing.

Use the [M5 tester feedback issue form](https://github.com/puffert/AdverScope/issues/new?template=m5-tester-feedback.yml) when the material is safe for GitHub. Report a product security issue through [SECURITY.md](../SECURITY.md). Share confidential evidence only through the coordinator's approved private channel.

A session may be recorded as completed, blocked, or safely stopped. Blocked and safely stopped sessions are valuable qualification evidence, but they are not passing security outcomes. Record uncertainty as inconclusive rather than forcing a secure or vulnerable verdict.

## Stop conditions

Stop the preview immediately if:

- the target or route is no longer authorized;
- a request reaches an unexpected origin;
- a destructive or consequential action was not explicitly approved;
- cleanup cannot be completed;
- repeated 5xx responses or transport faults exceed the guardrail;
- authentication or customer data appears in a log, screenshot, export, or issue unexpectedly;
- the local assessment store appears damaged or points to the wrong data directory;
- a recovered value or model-provider key may have been exposed.

Preserve the existing evidence, stop the run, create a verified backup, and contact the preview coordinator. Do not “test through” an unclear boundary.
