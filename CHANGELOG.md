# Changelog

AdverScope uses semantic product versions. Persisted formats and API contracts have independent schema identifiers recorded in each export and run.

## [Unreleased]

### Added

- A project-scoped Assessment Reasoning workspace with reviewed framework-synthesis methodology cards, typed component/trust/data-flow maps, and explicit `FACT` / `INFERENCE` / `HYPOTHESIS` / `FAILURE` classifications paired with `GO` / `HOLD` / `NO-GO` decisions. The library does not ingest source notes or create fine-tuning material.
- Append-only evidence checkpoints that separate model proposal, application response, tool execution, backend change, and independently verified impact, with correction links and optional references to retained run evidence.
- A reproducible, license-aware AdverScope 8B motor dataset pipeline with pinned public sources, source-specific adapters, privacy sanitization, exact and near-duplicate control, target-family-isolated splits, benchmark exclusion, human-review queues, trainer-neutral chat JSONL, tamper-evident manifests, and automated quality gates.
- A 6,108-record pilot corpus build covering guided planning, attack generation, objective-directed generation, response evaluation, and untrusted-content triage across 25 AdverScope techniques and six OWASP risks. Generated source data and corpus artifacts remain local and excluded from Git.
- An installation-scoped Model Lab that exposes the exact review queue, correction and rejection workflows, integrity-chained decisions, independent second review for evaluator gold labels, sanitized non-benchmark operator-trajectory intake, immutable reviewed releases, and deliberately created model experiments.
- A tokenizer-specific no-truncation audit and reproducible CUDA QLoRA runner using pinned model revisions, disabled remote code, four-bit NF4 quantization, assistant-completion-only loss, retained adapter hashes, and repeated candidate-versus-27B qualification gates. Training never starts from the GUI merely by creating an experiment.
- Frozen M5.1 field-qualification, M5.2 model-role, and M5.4 reliability/custody corpora with deterministic generated support reports and CI freshness gates.
- An executable 43-control reliability matrix covering transport faults, cancellation and stale recovery, cleanup and reproduction, transfer and restore, evidence integrity, secrets, and browser/callback boundaries.

### Changed

- Assessment runs now retain an immutable, target-filtered reasoning snapshot and provenance digest; professional Markdown reports include the current advisory reasoning record under report schema `1.1`.
- Upgraded the database schema to `4` and the API contract to `2026.08.14.2`. Schema-3 live stores migrate transactionally, but project-transfer archives containing a schema-3 database are not directly importable after the upgrade and must be re-exported from an upgraded source store.
- Professional support reporting now distinguishes controlled mechanism qualification from independent field qualification and publishes missing target, role, provider, model-family, telemetry, soak, platform, and review evidence as open gates.
- Model interaction traces retain provider-reported prompt, completion, and total token usage when available, including structured-output and repair attempts.
- Model-development storage now has its own configurable `training_root`, independent from both the project database and evidence directories.

### Security

- Methodology cards, system-map relationships, reasoning claims, decisions, and checkpoints are advisory only. They cannot add authorization, scope, routes, identities, permissions, evidence, findings, or verdicts.

## [0.9.0] - 2026-08-11

### Added

- Milestone 4 `structured-agent-trace-v1` adapter for deterministic planner/executor and human-approval boundary testing.
- Target-owned agent identities, allowed/denied/approval-required actions, authoritative JSON trace paths, verifier-backed reversible effects, mandatory cleanup with post-cleanup baseline verification, normalized agent protocol events, reproduction, and report support.
- Independent secure/vulnerable agentic fixtures and a synthetic qualification record covering precision, recall, cancellation, isolation, re-evaluation, GUI setup, and false-positive controls.
- A versioned 62-control AI-system registry spanning multimodal, agentic/A2A, MCP, RAG/vector, model/training, privacy/inference, resource/cost, and operational/client domains.
- Forty-three editable deterministic-oracle recipes that require exact control/case identity, immutable fixture digest, oracle version, measured acceptance boundary, non-secret evidence identity, and reproduction.
- Local MCP over pinned `stdio` executables with no shell, environment-reference isolation, bounded output/time, exact JSON-RPC custody, preflight, reproduction, and guaranteed child termination.
- Two independent secure/vulnerable Milestone 4 contract fixtures and machine-readable qualification evidence.

### Changed

- The Attack Surface now exposes explicit native-adapter versus configured-deterministic-oracle coverage claims and the customer configuration required before a control is considered tested.
- Professional Markdown reports now include every assessment contract and testing-tool run instead of silently truncating large assessments, and derive request/assertion totals from immutable pipeline metrics.
- The API contract is `2026.08.11.2`; contract recipes are `2026.08.3`.

### Security

- Local MCP executables must use existing absolute paths and exact SHA-256 pins. Literal identity secrets are rejected; child environment values are resolved only at runtime and never retained.
- Milestone 4 contract findings cannot be produced from HTTP success, model prose, inventory visibility, or an unversioned target boolean.

## 0.8.3 - 2026-08-10

### Added

- Versioned transactional database migrations with an automatically verified pre-upgrade SQLite backup and migration ledger.
- Integrity-checked single-project transfer archives containing the isolated project database, evidence, screenshots, and artifact bytes.
- Complete local assessment backup and offline restore with a retained rollback journal and automatic interrupted-restore recovery.
- GUI and CLI workflows for sensitive-data acknowledgement, project export/import, local backup, and archive verification.
- Cross-platform API, browser-capture, screenshot, login, and persistent-session qualification with a published support matrix.
- An optional non-root, read-only, host-loopback API container and an isolated synthetic first-assessment tutorial.
- Verified release manifests, SHA-256 checksums, CycloneDX SBOMs, artifact attestations for public releases, dependency audits, and clean installed-wheel smoke tests.
- Contributor, architecture, responsible-use, support, network, container, release, security-response, and technique-contribution guidance.

### Changed

- Upgraded the database schema to `3` and added independent `1.0` schemas for project transfer and local backup archives.
- Browser login sessions are excluded from backups and transfers by default and require a separate explicit opt-in.
- Large evidence files and recovery archives are streamed instead of being loaded into memory as one response.
- Upgraded the optional MCP qualification client to `1.28.1` after dependency auditing identified vulnerabilities in the former pin.

### Security

- Archive import rejects modified files, undeclared content, duplicate or unsafe paths, symbolic links, schema mismatches, foreign-key failures, duplicate project IDs, and evidence-directory collisions.
- Replacement restore requires AdverScope to be stopped. The previous database, evidence tree, and provider profile remain recoverable until final integrity verification succeeds.
- The application does not claim forensic secure erasure on SSDs or copy-on-write storage; retention and disposal boundaries are documented explicitly.
- Direct non-loopback serving is API-only and requires explicit acknowledgement, environment-backed bearer authentication, and TLS; loopback remains the default.
- Release construction rejects local databases, project evidence, browser sessions, local configuration, environment files, recovery journals, and private-key formats.

## 0.8.2 - 2026-08-10

### Added

- Named local and approved remote OpenAI-compatible model profiles.
- Explicit planner, generator, evaluator, and optional adjudicator role assignments.
- Profile connection verification with visible professional-qualification warnings.

### Changed

- Upgraded the non-secret provider profile schema to `2.0` with backward-compatible loading of `1.0` provider selections.
- Model traces now identify the exact profile, provider kind, model, and role used for each planning, generation, and evaluation interaction.
- Expanded the model dialog and packaged CLI for profile creation, role assignment, connection checks, and safe deletion of unassigned custom profiles.
- Added operator guidance for Ollama, llama.cpp, vLLM, generic OpenAI-compatible services, remote-data approval, and role qualification.

### Security

- Remote profiles require HTTPS and reject embedded credentials, query parameters, and fragments; official provider origins cannot be overridden.
- API-key values remain one-way environment or memory-only inputs and are excluded from profile files, project data, evidence, telemetry, reports, logs, and API responses.

## 0.8.1 - 2026-08-10

### Added

- Professional project isolation, immutable run records, target profiles, guided and advanced assessments, evidence review, retesting, and run comparison.
- Qualified chatbot, browser, RAG, tool/agent, MCP, artifact, and deterministic-contract testing foundations mapped to the OWASP Top 10 for LLM Applications 2025.
- Local, OpenAI, and Z.AI model-provider selection with environment-referenced or memory-only credentials.
- Versioned qualification registries, benchmark telemetry, evidence bundles, and synthetic secure/vulnerable fixtures.
- Local installation commands, non-secret first-run initialization, and installation diagnostics.

### Changed

- Consolidated product and persisted-schema identity into one authoritative release module.
- Hardened target fault handling, reproduction, transport evidence, browser sessions, and professional result presentation.

### Security

- Runtime project data, browser sessions, evidence, local configuration, and disposable qualification logs are excluded from release source control.
- Target and provider secrets are resolved from environment references or held only for the running process.

[0.9.0]: https://github.com/puffert/AdverScope/releases/tag/v0.9.0
