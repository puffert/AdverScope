# AdverScope architecture

AdverScope is a local-first Python application with a static browser interface, SQLite project store, filesystem evidence store, model-provider gateway, target adapters, bounded execution engine, deterministic evaluators, and human review workflow.

## Trust boundaries

```text
Operator and written authorization
        |
        v
Project boundary -> target map -> approved guardrail -> immutable run snapshot
        |                                                  |
        |                                                  v
        |                                      model-assisted planning
        |                                      and payload generation
        |                                                  |
        +---------------- reviewed capabilities -----------+
                                                           v
                                                target adapter / browser
                                                           |
                                                           v
                                       exact redacted request and raw response
                                                           |
                                                           v
                                      deterministic proof + model review + human review
```

The model is untrusted orchestration input. It cannot add a host, route, method, identity, credential, tool permission, destructive action, or evidence rule. Target-owned contracts and deterministic observations control security verdicts where effects, authorization, RAG, MCP, tools, artifacts, or protected values are involved.

## Main components

- `osai_security/db.py`: transactional project records and immutable run boundaries.
- `osai_security/evidence_store.py`: project-scoped evidence and protected browser-session directories.
- `osai_security/http_app.py`: local HTTP API and static interface; optional authenticated TLS remote API.
- `osai_security/engine.py`: bounded test selection, execution, evaluation, stop handling, and reproduction.
- `osai_security/methodology.py`: reviewed framework-synthesis cards and advisory model-context rendering; it does not ingest source notes or create training data.
- `osai_security/model_gateway.py` and `model_providers.py`: local and remote model roles using environment-referenced credentials.
- `osai_security/motor_dataset.py`: licensed-source transformation, sanitization, leakage-resistant splitting, review queues, and tamper-evident dataset releases.
- `osai_security/motor_lab.py`: installation-scoped review journals, independent evaluator second review, accepted operator trajectories, and immutable experiment gates.
- `osai_security/motor_training.py`: exact tokenizer audit, deliberately invoked QLoRA, retained adapter metadata, and candidate-versus-baseline qualification.
- `osai_security/targets.py` and `browser_targets.py`: exact API and browser adapters with scope enforcement.
- `osai_security/evaluation_profiles.py`: deterministic target-owned proof contracts.
- `osai_security/agentic_security.py`: deterministic planner, approval, and executor trace policy evaluation; trace fields never widen target authorization.
- `osai_security/agentic_trace_fixture.py`: independent secure/vulnerable M4.2 qualification target.
- `osai_security/mcp_stdio.py`: digest-pinned, no-shell local MCP process transport with bounded JSON-RPC custody and guaranteed termination.
- `osai_security/m4_security.py`: versioned 62-control Milestone 4 registry and editable configured-oracle recipes across eight AI-system domains.
- `osai_security/m4_control_fixture.py`: two independent target-oracle shapes used to qualify secure/vulnerable contract behavior and reproduction.
- `osai_security/recovery.py`: versioned project transfer, backup, verification, migration, and rollback.
- `browser/`: Playwright-based capture, screenshots, persistent sessions, and login-session launcher.

## Persistence and isolation

Every project-owned database query requires `project_id`. Each run snapshots target mapping, capabilities, guardrail, objectives, model roles, catalog, evaluation configuration, and test plan. Updating a target never rewrites historical runs. Browser profiles live below each project in `_browser_sessions` and are excluded from normal transfers and backups.

Model-development state uses a separate installation-level `training_root`. It is not selected by `project_id`, included in client-project transfers, or treated as assessment evidence. Public raw sources, generated datasets, review journals, accepted sanitized trajectories, experiment configurations, tokenizer audits, adapters, and qualification comparisons remain in that boundary. Reserved benchmark families and customer evidence are prohibited from training input.

Database schema `4` adds project methodology pins, reasoning nodes and edges, classified claims, and evidence checkpoints. The API contract is `2026.08.14.2`; the assessment-reasoning schema is `1.0`, and professional reports carrying the new section use report schema `1.1`. Live schema-3 stores follow the transactional migration path and receive a verified pre-upgrade backup. A project-transfer archive whose embedded database is still schema 3 is not directly importable into schema 4: exact schema validation rejects it, so the compatible source store must be upgraded and exported again.

## Assessment reasoning boundary

Assessment reasoning is a project-scoped operator aid, not an authority or verdict lane. The built-in library contains reviewed AdverScope framework-synthesis cards rather than fine-tuning records or ingested source notes. Pinning stores the complete reviewed card snapshot, version, provenance, and digest in the project; it does not store or modify the notes that may have inspired a generalized framework idea.

The system map stores typed nodes for components, identities, credential references, data, artifacts, consumers, sinks, and routes, plus typed data-flow, trust, authority, credential-use, trigger, production, reach, and consumption edges. Claims keep **FACT**, **INFERENCE**, **HYPOTHESIS**, and **FAILURE** separate from the independent **GO**, **HOLD**, and **NO-GO** decision. This prevents a plausible relationship or failed path from silently becoming a confirmed target fact.

Evidence checkpoints are append-only. Each record separates five observable stages: model proposed, application returned, tool executed, backend changed, and impact independently verified. It can also link to an existing project evidence record. A correction references the earlier checkpoint; it never overwrites it. Neither a checkpoint nor its status is finding-grade evidence by itself.

At run creation, AdverScope copies the target-filtered reasoning workspace into the immutable assessment plan and records its digest in execution provenance. Only pinned, framework-authored card guidance may be rendered into advisory model context; operator claims and graph notes do not widen model authority. Later project edits do not rewrite historical snapshots. Professional reports include the current reasoning record under an explicit advisory notice.

Across every path, methodology cards, maps, claims, and checkpoints cannot add scope, routes, identities, permissions, authorization, evidence, findings, or verdicts. Existing project authorization, guardrails, adapters, retained target observations, deterministic proof contracts, and human review remain authoritative.

## Milestone 4 execution lanes

A Milestone 4 control uses one of two evidence lanes:

- A **native adapter** understands a protocol or artifact boundary directly, such as structured agent traces, MCP, RAG, tool/agent rounds, or static artifact analysis.
- A **configured deterministic oracle** calls only an authorized customer route and requires exact control/case identity, immutable fixture SHA-256, oracle version, measured acceptance boundary, non-secret evidence identity, failed requirement, and reproduction.

The registry's `qualified` status applies to the execution and evidence lane. It does not make a control applicable to every target and does not authorize discovery of customer routes, identities, policies, fixtures, thresholds, or effects. Those facts remain project-owned Attack Surface configuration.

Local MCP `stdio` is a process trust boundary rather than a network route. The application requires an absolute executable and SHA-256, invokes it without a shell, supplies only explicitly mapped environment references plus a minimal runtime environment, bounds response time and bytes, records exact newline-delimited JSON-RPC, and closes the child after each case. HTTP MCP remains restricted to exact same-origin routes, including explicitly authorized legacy HTTP+SSE paths.

## Deployment boundaries

Normal use binds to loopback and has no remote authentication because it is not remotely reachable. Direct non-loopback use is API-only and requires explicit acknowledgement, a bearer token supplied through an environment variable, and TLS certificate/key paths. The optional container publishes only to host loopback and excludes the Node/browser runtime.

See `docs/NETWORK_ENVIRONMENTS.md`, `docs/SUPPORT_MATRIX.md`, and `docs/RELEASE_PROCESS.md`.
