# AdverScope public roadmap

AdverScope is developed as a professional, local-first AI security assessment workbench. This roadmap records public product direction without customer evidence, private benchmark material, credentials, recovered values, or internal operational notes.

## Current release

Version 0.9.0 is a public Beta. The core workflow is available end to end: isolated projects, attack-surface configuration, Guided and Advanced assessments, bounded execution, exact evidence, reproduction, human review, reporting, model-provider roles, browser targets, tool-calling systems, MCP, RAG, and additional AI-system control lanes.

Beta means the software is appropriate for authorized evaluation and controlled professional pilots. It does not mean every target type, model, technique, platform, or deployment has been independently qualified. Human review remains mandatory for reportable findings.

## Completed foundations

- **Milestone 1 — professional assessment:** bounded execution, target-owned proof, reproducible evidence, false-positive controls, and OWASP-oriented coverage.
- **Milestone 2 — usability:** Guided and Advanced workflows, project/run separation, readable traffic, screenshots, result review, coverage views, and operator documentation.
- **Milestone 3 — distribution:** source installation, local state separation, backup/recovery, release integrity, container boundary, and cross-platform release gates.
- **Milestone 4 — broader AI systems:** tool and agent authorization, current and legacy MCP, RAG, supply-chain artifacts, multimodal, model pipelines, privacy, resource/cost, and operational controls.

## Milestone 5 — field qualification and Beta hardening

Current priorities are:

1. expand independent secure/vulnerable target pairs for each professionally claimed technique;
2. repeat qualification across local and approved remote model families;
3. measure precision, supported recall, reproduction, transport reliability, cleanup, and evidence completeness;
4. run longer soak and resource-observation campaigns;
5. complete independent product-security review;
6. collect structured usability feedback from pentesters;
7. retain a passing Windows, Ubuntu, and macOS matrix for each release candidate.

Qualification status must remain explicit. A technique can be implemented without being field-qualified, and an unexecuted or unproven control must never be presented as passed.

## Milestone 6 — specialized model motor

The optional model-motor track focuses on a smaller, faster model for attack planning, adaptive follow-up, and evidence evaluation. Promotion requires licensed and reviewed data, strict separation from qualification benchmarks and customer evidence, tokenizer-specific audits, reproducible training records, and repeated candidate-versus-baseline qualification. A fine-tuned model will not replace deterministic proof or human review.

## Toward v1.0

The v1.0 gate requires stable migrations and release artifacts, retained cross-platform qualification, acceptable independent field precision and recall for supported claims, recovery and evidence-custody assurance, independent security review, and documentation that a new tester can follow without private assistance.

See the [qualification blueprint](docs/AI_SECURITY_TECHNIQUE_QUALIFICATION_BLUEPRINT.md), [OWASP automation matrix](docs/OWASP_AUTOMATION_MATRIX.md), [support matrix](docs/SUPPORT_MATRIX.md), and [changelog](CHANGELOG.md) for the detailed public record.
