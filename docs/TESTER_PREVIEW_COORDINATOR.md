# AdverScope Milestone 5 Preview Coordinator Checklist

This checklist turns public-Beta testing into a controlled qualification exercise. It is for the person coordinating testers, not a substitute for the [Tester Preview Guide](TESTER_PREVIEW_GUIDE.md) or the target's rules of engagement.

M5.0 is complete when the preview package is current, self-checking, safe to hand off, and provides a structured feedback route. Independent target results belong to M5.1-M5.4 and are not implied by M5.0 completion.

## 1. Freeze the preview baseline

Before inviting a tester:

1. Choose an exact AdverScope tag or commit and record it in the private cohort register.
2. Run `uv run python scripts/check_tester_preview.py` from that checkout.
3. Confirm the release identity, automated tests, and supported-platform gates pass for the selected build.
4. Confirm the [User Manual](USER_MANUAL.md), [Tester Preview Guide](TESTER_PREVIEW_GUIDE.md), screenshots, installation instructions, support matrix, and issue forms match that build.
5. Do not describe the build as a stable production release.

The cohort register may identify people and engagements, so keep it outside the repository in an approved access-controlled system. Give each session an opaque identifier such as `M5-T001`; do not encode a customer or target name in it.

## 2. Prepare the tester handoff

Give each tester:

- the pinned AdverScope tag or commit;
- the supported installation path for their operating system;
- the tester guide and full user manual;
- a named coordinator and a private support route;
- a synthetic tutorial assignment before any unfamiliar target;
- an approved target package for the independent exercise;
- the sanitized GitHub feedback route and the private security-reporting route;
- the session identifier and expected completion date.

Never send API keys, private keys, cookies, customer evidence, recovered values, or browser profiles in the handoff document. Provider secrets must use an approved secret-delivery channel and AdverScope's environment-variable or memory-only session mechanism.

## 3. Build the authorized target package

The target package must be usable without the tester inventing authorization or success criteria. It should contain:

- exact authorized origin, routes, environment, test identities, and time window;
- rules of engagement and stop conditions;
- target policy and prohibited behavior;
- permitted request, runtime, error, cost, and reproduction budgets;
- permitted read-only, reversible-write, consequential, and destructive action classes;
- required cleanup and independent cleanup verification;
- target capabilities and known interface documentation without vulnerability answers;
- reportable objectives, success criteria, and false-positive exclusions;
- target-owned proof contracts or benchmark oracles kept separate from the attack prompt;
- data classification, retention, export, and model-provider restrictions.

The coordinator may know the benchmark oracle. Do not provide exploit strings, hidden values, or expected attack paths to AdverScope's planner or generator.

## 4. Confirm local custody and recovery

Before target traffic:

- confirm AdverScope is bound to loopback unless a different deployment was explicitly reviewed;
- confirm the local data directory is encrypted and access controlled;
- run `adverscope doctor` and retain the non-secret result;
- create the synthetic tutorial project and complete the documented tutorial tasks;
- create and verify a local backup;
- confirm the tester can identify the active data directory and restore procedure;
- confirm the chosen model profile is approved for the target data classification;
- confirm no secret value is stored in project documents, headers, screenshots, or issue text.

## 5. Observe without operating for the tester

The tester must use the visible GUI as a normal operator. The coordinator may answer documentation questions, but should not configure the project, select the winning technique, adjudicate the evidence, or operate the target on the tester's behalf.

Record assistance using these levels:

| Level | Meaning |
| --- | --- |
| 0 | No assistance |
| 1 | Documentation pointer only |
| 2 | Conceptual explanation without operating the product |
| 3 | Coordinator had to provide configuration or UI steps |
| 4 | Developer intervention or code change required |

Levels 3 and 4 mean the affected task was not completed independently.

## 6. Collect a complete session record

For every tutorial and independent-target session, retain:

- session ID, AdverScope version, build revision, operating system, and installation method;
- model provider kind, model ID, and assigned role without keys or credential-bearing URLs;
- sanitized target category, capabilities, and adapter;
- start/end time and time to first configured run and defensible finding;
- run IDs and selected, planned, executed, skipped, unsupported, and errored technique IDs;
- benchmark applicability and oracle recorded separately from AdverScope's verdict;
- true-positive, false-positive, false-negative, true-negative, and inconclusive adjudication;
- initial and reproduction outcomes;
- evidence, cleanup, cancellation, restart, recovery, export, and backup outcomes;
- assistance level per core task;
- usability friction, defect stage, severity, and whether progress was blocked.

Use the [M5 tester feedback issue form](https://github.com/puffert/AdverScope/issues/new?template=m5-tester-feedback.yml) only for fully sanitized material. Use [private security reporting](../SECURITY.md) for AdverScope vulnerabilities. Customer evidence and confidential target details must use the coordinator's approved private channel.

## 7. Triage without benchmark tuning

Classify each observation as one of:

- product defect;
- target or environment fault;
- model variance;
- missing target configuration or proof;
- documentation or usability defect;
- unsupported or inapplicable control;
- expected guarded behavior.

Fix general framework behavior and add reusable evaluator or transport coverage. Do not hardcode a benchmark's exploit, recovered value, target URL, or winning response. Preserve the original result and link any retest rather than rewriting historical evidence.

## 8. Close the preview session

A session is complete when the tester has either completed the assigned tasks or stopped safely with a documented blocker, adjudicated expected and observed outcomes, submitted sanitized feedback, verified cleanup, and followed the retention plan. A safely stopped or inconclusive session is valid qualification evidence; it is not a passing security result.

After each cohort, aggregate only sanitized metrics. M5.1-M5.5 gates must be calculated from frozen definitions and must not be weakened to make the release pass.
