# Contributing to AdverScope

AdverScope accepts changes that improve authorized, evidence-led AI security assessment without weakening scope controls or verdict quality. Never submit client data, private target details, credentials, browser profiles, recovered proof values, assessment databases, or unredacted evidence.

## Development setup

Use Python 3.11 or newer, Node.js 20 or newer, `uv`, npm, and Chrome or Edge. From a clean checkout:

```text
python scripts/bootstrap.py --skip-init
uv run adverscope init
uv run adverscope doctor --skip-model
```

Run the release gates before opening a pull request:

```text
uv run python scripts/check_release_identity.py
uv run python -m unittest discover -s tests -v
uv run python scripts/platform_qualification.py
uv run python scripts/release_integrity.py build --output <empty-directory>
uv run python scripts/release_integrity.py verify --output <same-directory>
npm audit --omit=dev --audit-level=high
```

## Engineering standards

- Keep project-owned records bound to `project_id` and preserve immutable run snapshots.
- Keep authorization, guardrails, target behavior policy, objectives, and proof contracts separate.
- Never let model output add hosts, routes, methods, credentials, permissions, or destructive actions.
- Treat refusals, target errors, skipped tests, and missing proof as non-findings, not passes.
- Store exact redacted requests, raw target responses, evaluator decisions, and reproduction evidence.
- Use environment-variable references for credentials. Do not persist secret values.
- Add type annotations to new Python interfaces and validate untrusted values at the boundary.
- Prefer standard-library components unless a dependency materially improves correctness or interoperability.
- Keep functions connected to a tested user workflow; do not add stubs, dead routes, or TODO-only behavior.

## Security-verdict changes

A verdict-affecting change requires:

1. an independent vulnerable fixture that must be detected;
2. an independent secure fixture that must not be reported;
3. a refusal, echo, hallucination, transport-fault, or inconclusive control where relevant;
4. exact retained evidence and reproducibility assertions;
5. a clear OWASP risk and technique mapping;
6. benchmark evidence that is not disclosed to the planner or generator.

Catalog and recipe requirements are detailed in `docs/TECHNIQUE_CONTRIBUTIONS.md`.

## Training-data changes

Training-source and adapter changes must follow [`training/README.md`](training/README.md). A contribution must include an explicit license and use decision, immutable upstream revision and checksum where applicable, source-family grouping, sanitization, deterministic transformation, updated quality gates, and tests. Never submit raw downloads, generated corpora, model weights, benchmark answers, target proof, or customer traces. Operator-derived examples require recorded acceptance and a non-benchmark target family; transformed public labels remain silver until reviewed.

## Pull requests

Keep changes bounded and explain migration, compatibility, evidence, and safety effects. GitHub validation is a release-quality control; pentesters do not need GitHub Actions to use AdverScope locally.

Security vulnerabilities must be reported privately according to `SECURITY.md`.
