<p align="center">
  <img src="https://github.com/puffert/AdverScope/releases/download/v0.9.0-beta/adverscope-mark.png" width="104" alt="AdverScope logo">
</p>

<h1 align="center">AdverScope</h1>

<p align="center"><strong>Autonomous AI security testing. Bounded execution. Reproducible evidence.</strong></p>

<p align="center">
  Local-first · Open source · Python 3.11+ · Apache-2.0 · v0.9.0 Beta
</p>

AdverScope is a model-assisted workbench for professional, authorized security assessment of AI systems. A pentester defines the engagement boundary and target-owned proof; AdverScope plans and executes bounded tests, preserves exact traffic, reproduces finding-grade evidence, and hands the result to human review.

It can use a local OpenAI-compatible model or tester-approved OpenAI and Z.AI profiles. Client projects, evidence, screenshots, findings, and reports remain isolated in the tester's local data store.

[![AdverScope assessment results dashboard](https://github.com/puffert/AdverScope/releases/download/v0.9.0-beta/06-assessment-results.jpg)](docs/images/manual/06-assessment-results.jpg)

> **Project status:** AdverScope v0.9.0 is a public Beta. It is suitable for authorized evaluation and controlled professional pilots, but it is not yet a stable v1.0 production release. Findings still require qualified human review.

## Why AdverScope

AI security assessment needs more than a list of jailbreak prompts. A professional result must show what was authorized, what was sent, what the target returned, why that evidence satisfies a defined security objective, whether it reproduced, and what a human reviewer accepted.

AdverScope keeps those elements connected:

1. **Projects** isolate each client or assessment.
2. **Attack surface** records authorization, target policy, interfaces, capabilities, proof, and guardrails.
3. **Assessments** run model-assisted and deterministic tests within those boundaries.
4. **Evidence** retains exact requests, responses, hashes, screenshots, model traces, and reproduction.
5. **Review** separates autonomous observations from professional finding disposition and reporting.

## Highlights

- **Guided and Advanced workflows** — start from one exact chatbot endpoint or configure target-specific APIs, browser flows, identities, tools, MCP, RAG, artifacts, and evidence contracts.
- **Machine-enforced boundaries** — scope gates, same-origin route allowlists, request/runtime/error limits, stop conditions, screenshot permission, cleanup, and reproduction budgets.
- **Evidence before verdicts** — model confidence, HTTP 200, plausible secrets, and conversational claims cannot independently create a finding.
- **Complete execution custody** — copyable redacted curl, serialized request, raw response, timing, hashes, evaluator records, and initial/reproduction relationships.
- **OWASP-oriented coverage** — all OWASP Top 10 for LLM Applications 2025 risks remain visible, with whole-risk or fine-grained selection and honest `confirmed`, `control held`, `inconclusive`, `needs configuration`, `not applicable`, and `not tested` states.
- **AI-system testing beyond chatbots** — native or target-configured lanes for prompt injection, disclosure, output handling, agency, MCP, RAG, supply-chain artifacts, misinformation, multimodal, agent/A2A, model pipelines, privacy, resource/cost, and operational controls.
- **Pentester workbench** — bounded campaigns, exact request replay, multi-step workflows, interaction monitoring, run comparison, controlled retesting, and professional evidence exports.
- **Local-first custody** — project transfer, verified backup/restore, environment-backed provider secrets, persistent browser sessions, and redacted or full internal report bundles.
- **Gated Model Lab** — installation-scoped review journals, accepted non-benchmark trajectories, exact tokenizer audits, reproducible QLoRA experiments, and repeated candidate-versus-baseline qualification without mixing model-development data into client projects.

## Supported target styles

| Target | Assessment path |
| --- | --- |
| Conventional JSON chatbot | Guided or Advanced |
| OpenAI/Ollama-compatible API | Advanced target adapter |
| Browser chatbot | Selector mapping, persistent session, network evidence, screenshots |
| Tool-calling or agentic API | Structured calls, identity policy, approval and verifier contracts |
| MCP server | Sessionless HTTP, Streamable HTTP, authorized legacy HTTP+SSE, or pinned `stdio` |
| RAG or external-content system | Baseline, ingestion, positive retrieval control, attack, cleanup, verification |
| Model or supply-chain artifact | Project-isolated static assessment without loading or execution |
| Specialized AI control | Versioned deterministic evidence contract with customer-owned oracle |

A supported execution lane is not automatically applicable to every target. Missing capabilities or customer-owned proof remain visible as configuration or applicability limitations.

## Quick start

Requirements are Python 3.11+, [`uv`](https://docs.astral.sh/uv/), and access to a local or approved remote model. Browser targets additionally require Node.js 20+ and Edge, Chrome, or Chromium.

```powershell
git clone https://github.com/puffert/AdverScope.git
cd AdvScope
python scripts/bootstrap.py
uv run adverscope doctor
uv run adverscope serve
```

Open the loopback address printed by AdverScope.

For a safe first assessment, create the bundled synthetic tutorial and run its target in a second terminal:

```powershell
uv run adverscope tutorial create
uv run adverscope tutorial target
```

Then complete the project through the visible GUI. See the [installation guide](docs/INSTALLATION.md) for API-only setup, model providers, network environments, upgrades, and diagnostics.

## Model providers

AdverScope separates the Planner, Generator, Evaluator, and optional Adjudicator roles. Each role can use a named local OpenAI-compatible, OpenAI, Z.AI, or approved compatible profile.

Persistent API keys are referenced by environment-variable name and are never stored as project data. A session key entered in the GUI remains in process memory only. Endpoint reachability does not establish professional model-role qualification; Milestone 5 measures role quality and cross-model variance separately.

Read [model providers and roles](docs/MODEL_PROVIDERS.md) for supported configurations and secret-handling rules.

## Documentation

| Document | Use it for |
| --- | --- |
| [User Manual](docs/USER_MANUAL.md) | Complete screenshot-led operator workflow, evidence review, troubleshooting, and checklists |
| [Tester Preview Guide](docs/TESTER_PREVIEW_GUIDE.md) | Milestone 5 access gates, independent qualification procedure, metrics, and stop conditions |
| [Preview Coordinator Checklist](docs/TESTER_PREVIEW_COORDINATOR.md) | Pinned-build handoff, target package, assistance scoring, safe feedback, and session closure |
| [Installation](docs/INSTALLATION.md) | Bootstrap, diagnostics, upgrades, providers, and startup |
| [OWASP Automation Matrix](docs/OWASP_AUTOMATION_MATRIX.md) | Native versus configured coverage, inputs, proof thresholds, and limitations |
| [M5 Field Qualification](docs/M5_FIELD_QUALIFICATION.md) | Independent-target depth, professionally supportable techniques, and explicit evidence gaps |
| [M5 Model-Role Qualification](docs/M5_MODEL_ROLE_QUALIFICATION.md) | Repeated planner, generator, evaluator, provider-family, latency, token, and cost evidence |
| [M5 Reliability Qualification](docs/M5_RELIABILITY_QUALIFICATION.md) | Executable transport, recovery, cleanup, backup, evidence-custody, secret, and browser-boundary gates |
| [8B Motor and Model Lab](training/README.md) | Licensed sources, human review, operator trajectories, tokenizer audit, gated QLoRA, and baseline comparison |
| [Support Matrix](docs/SUPPORT_MATRIX.md) | Qualified platforms and workflow-specific support claims |
| [Architecture](docs/ARCHITECTURE.md) | Components, data boundaries, and execution lanes |
| [Backup and Recovery](docs/BACKUP_AND_RECOVERY.md) | Project transfer, full backup, verification, restore, and retention |
| [Network Environments](docs/NETWORK_ENVIRONMENTS.md) | Proxy, VPN, corporate CA, firewall, and remote-access boundaries |
| [Responsible Use](RESPONSIBLE_USE.md) | Authorization and safe-use expectations |
| [Contributing](CONTRIBUTING.md) | Development, tests, and contribution workflow |

The repository's versioned `docs/` directory is the authoritative documentation source. A release PDF will be generated from the User Manual during a later Milestone 5 release-documentation step; the PDF will not be maintained as a separate editable manual.

## Security and evidence principles

- Test only systems you own or are explicitly authorized to assess.
- Imported architecture material never expands authorization.
- Expected protected values and factual oracles remain evaluator-only.
- Reversible effects require approved verification and cleanup.
- An unavailable baseline or proof contract is inconclusive, not secure.
- Unexecuted techniques are never reported as passed.
- Final findings require human review.

See [SECURITY.md](SECURITY.md) for reporting an AdverScope vulnerability. Never place customer traffic, credentials, private keys, session material, recovered values, or full internal evidence bundles in a public issue.

## Development and release status

Milestones 1–4 established the professional assessment workflow, usability, installation/recovery/release foundation, and 62 bounded AI-system control lanes. Milestone 5 is focused on independent field qualification, repeated multi-model testing, usability research, reliability, product security, and v1.0 release gates. The generated [M5 field-qualification report](docs/M5_FIELD_QUALIFICATION.md) deliberately separates controlled mechanism qualification from independent field support.

The public development priorities are tracked in the [roadmap](ROADMAP.md). Release changes are recorded in the [changelog](CHANGELOG.md).

## License

AdverScope is licensed under the [Apache License 2.0](LICENSE).
