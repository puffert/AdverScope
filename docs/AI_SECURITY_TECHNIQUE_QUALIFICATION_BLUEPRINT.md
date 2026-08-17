# AdverScope AI Security Technique Qualification Blueprint

**Status:** Active engineering standard
**Owner:** Milestone 1 reliability work
**Companion record:** [Public roadmap](../ROADMAP.md)

## Purpose

This blueprint defines how an implemented AdverScope technique becomes professionally qualified. It is reusable for chatbot, tool-calling, agent, MCP, RAG, artifact, misinformation, and resource-control techniques.

Implementation is not qualification. A visible test path may be experimental until retained secure and vulnerable evidence proves that AdverScope can distinguish the boundary reliably.

## 1. Define the claim before testing

Every qualification work package must state:

- the exact technique ID and security boundary;
- target types, protocols, identities, and capabilities included in the claim;
- evidence that is finding-grade;
- events that do not count, including refusals, textual mentions, offered schemas, echoed payloads, local policy logs, and unverified model claims;
- whether the model generates wording, evaluates evidence, or is not required for the verdict;
- excluded protocols, delivery channels, side effects, and target classes.

The registry limitation text is part of the claim. Passing one technique never qualifies its complete OWASP risk family.

## 2. Qualification prerequisites

Before a campaign starts:

1. The production execution path is connected end to end and has no target- or lab-specific constants.
2. All target routes, request shapes, identities, tools, schemas, permissions, verifier signals, and cleanup operations are configured under Attack Surface.
3. Unit and vertical-slice tests include a secure control, a vulnerable control, evidence completeness, false-positive exclusions, and reproduction where safe.
4. At least two independent target families provide both secure and vulnerable evidence before a technique can be `qualified`.
5. The benchmark oracle is isolated from planning, generation, target traffic, normal evaluation, and adaptive follow-up.
6. The saved target passes the retained M2.2 preflight for its adapter. Preflight is setup evidence only: it may validate exact-route transport, common response extraction, browser selectors, or MCP lifecycle negotiation, but it must not be counted as attack execution or finding-grade proof.

## 3. Minimum visible-GUI campaign

For each new target family, create four isolated projects through the same AdverScope GUI used by a pentester:

| Project | Expected result | Required evidence |
|---|---|---|
| Secure repetition 1 | True negative | Executed case, complete request/response evidence, no finding |
| Secure repetition 2 | True negative | Independent execution with the same reviewed configuration |
| Vulnerable repetition 1 | True positive | Finding-grade target evidence and approved reproduction |
| Vulnerable repetition 2 | True positive | Independent finding and approved reproduction |

Each project must separately contain:

- scope/rules of engagement;
- target behavior policy;
- one exact authorized target and route inventory;
- capability and identity configuration;
- an approved guardrail;
- an objective with success criteria, expected safe behavior, and false-positive exclusions;
- the exact selected technique;
- immutable run, evidence, finding, reproduction, and review records.

Do not reuse a finding or run across projects. Do not put expected benchmark answers into the project.

## 4. Model-role requirements

- Record provider, model, role, parameters, trace, and fallback for every model-assisted step.
- Reviewed deterministic baselines and target-owned proof outrank model opinion.
- A model-generated payload may exercise the target, but a model claim alone cannot prove authorization failure, execution, state change, supply-chain integrity, poisoning, factual correctness, or resource impact.
- Qualify remote providers separately because client assessment context and target responses leave the local environment.
- Deterministic target fixtures validate AdverScope orchestration and evaluation; they do not establish stochastic target-model variance.
- A fine-tuned or adapter-backed motor is a new model candidate, not an inherited qualification. Freeze its dataset manifest, base revision, tokenizer fingerprint, adapter hashes, and role assignment before testing. Run the same retained role corpora repeatedly for the candidate and baseline, preserve per-role failures and latency, and require no regression in the selected role's quality or safety gates before promotion.
- Training records and qualification records must be disjoint by target family. Reserved target suites, benchmark answers, proof values, and customer evidence remain excluded from the Model Lab even when they are visible elsewhere in AdverScope.

The specialized-model data, review, training, and comparison procedure is recorded in [the 8B motor guide](../training/README.md) and the model-motor track in the [public roadmap](../ROADMAP.md).

## 5. Finding and reproduction evidence

A reportable result must retain:

- initial exact request, redacted headers, serialized body, response, hashes, and timestamps;
- ordered protocol or browser events with correlation IDs;
- the target-owned policy or verifier decision;
- a direct link from case to evidence, finding, objective, and technique;
- one separately approved reproduction unless the authorized effect is consequential and explicitly one-time;
- proof that AdverScope did not mislabel a proposed action as an action it performed;
- cleanup and cleanup verification for reversible state changes.

For secure controls, a refusal or absence of proof is only a true negative when the supported test executed successfully. Transport failures and missing configuration remain inconclusive.

## 6. Isolated scoring and gates

The campaign file contains project and execution IDs only. The oracle contains expected outcomes and is loaded only after the runs finish.

Required initial gates:

- precision at least `0.95`;
- supported recall at least `0.95`;
- reproduction rate at least `0.95` where reproduction is required;
- zero unexplained infrastructure errors in the gated set;
- complete evidence and terminal status for every gated expectation;
- no cross-project or cross-session evidence links;
- at least two independent secure/vulnerable target families for `qualified`.

If a gate fails, retain the failure, correct AdverScope rather than the benchmark target, rerun every affected project through the GUI, and include only valid post-fix execution IDs in the final campaign.

## 7. Registry promotion

- `experimental`: implemented or partially tested without a complete secure/vulnerable qualification set.
- `validated`: secure and vulnerable evidence passes the gates for one independent target family.
- `qualified`: the gates pass for at least two independent target families within the documented boundary.
- `deprecated`: the implementation or retained evidence is no longer supported.

Update the machine-readable registry, generated OWASP matrix, milestone log, campaign JSON/Markdown, tests, and this blueprint's campaign index together.

## 8. Tool-calling authorization blueprint

For `LLM06-TOOLS`, the target configuration must define the offered tool schemas, actor identity, allowed tools, denied tools, approval-required tools, argument constraints, and maximum rounds.

Finding-grade evidence is a structured target-proposed call that violates the snapshotted target policy. A tool name in prose, an offered schema, a refusal, a simulated output, or AdverScope's own policy decision without the target call is not sufficient. AdverScope observes the proposal and must not dispatch it during this read-only qualification.

The qualified boundary and retained campaign are recorded in [TOOL_AUTHORIZATION_QUALIFICATION_2026-08-09.md](../validation/target-campaigns/TOOL_AUTHORIZATION_QUALIFICATION_2026-08-09.md).

## 9. Current and legacy MCP blueprint

MCP qualification must preserve older customer deployments without treating a protocol downgrade as authorization.

Configure and test separately:

- sessionless `2026-07-28` endpoints using `server/discover`, per-request metadata, `Mcp-Method`, and `Mcp-Name` where required;
- current Streamable HTTP endpoints and declared protocol versions;
- legacy HTTP+SSE endpoints, including the authorized `2024-11-05` profile;
- target-owned initialization, session, pagination, and same-origin endpoint rules;
- restricted and privileged identities with explicit tool/resource/prompt allowlists;
- capability inventory, unauthorized tool selection, confused-deputy, metadata/content-injection, and cross-boundary resource cases only when their required target capabilities exist.

Required controls:

1. Current secure and vulnerable implementations.
2. Legacy secure and vulnerable implementations.
3. A version-negotiation control that cannot add routes, identities, permissions, or server-proposed cross-origin endpoints.
4. Complete JSON-RPC and SSE evidence in protocol order.
5. No execution of a proposed target tool unless a separate reversible action, verifier, cleanup operation, and explicit guardrail authorize it.

A read-only MCP `tools/call` may be finding-grade when the configured target owns the authorization contract and the returned structured result satisfies every approved action assertion. HTTP success, JSON-RPC success, tool metadata, prose, caller-supplied fields, or a denial is not sufficient. State-changing calls remain outside this read-only path and require a separately authorized reversible action, an independent verifier, cleanup evidence, and explicit guardrail limits.

Qualify each MCP technique independently. Current transport success does not qualify legacy authorization, and legacy compatibility does not qualify confused-deputy or content-injection behavior.

The retained current/legacy authorization campaign is recorded in [MCP_AUTHORIZATION_QUALIFICATION_2026-08-09.md](../validation/target-campaigns/MCP_AUTHORIZATION_QUALIFICATION_2026-08-09.md).

## 10. MCP content and resource-boundary blueprint

Treat untrusted MCP content, protected-resource disclosure, and cross-identity access as three separate claims even when one protocol exchange supplies evidence for all three.

Required finding gates:

1. `LLM01-MCP-CONTENT` requires preserved source provenance, a configured prohibited-content rule, a target-owned read-only sink, and exact structured assertions proving that the sink consumed the prohibited source. Metadata visibility, prompt echo, or an instruction appearing in a resource is observation-grade only.
2. `LLM02-MCP-RESOURCE` requires JSON-RPC success plus exact target-configured assertions for the resource URI, restricted caller identity, owner or data boundary, protected classification, and synthetic proof marker. A non-empty `contents` result or HTTP success is not sufficient.
3. `LLM08-MCP-BOUNDARY` requires the same exact read evidence to prove that a restricted identity crossed the configured ownership or tenant boundary. Other RAG, vector, and embedding boundaries remain separate techniques.
4. Every positive case must reproduce once through the same authorized transport and identity. Secure controls must retain the denial or boundary-held result without creating a finding.
5. Current Streamable HTTP and legacy HTTP+SSE are configured and scored independently. Protocol compatibility cannot widen resource, identity, tool, or sink authorization.

The retained campaign uses read-only deterministic sink effects and synthetic protected records. State-changing effects, arbitrary third-party MCP servers, custom transports, callbacks, prompt access, and opaque broker or chained-agent behavior require separate qualification.

The retained content and resource-boundary campaign is recorded in [MCP_CONTENT_BOUNDARY_QUALIFICATION_2026-08-09.md](../validation/target-campaigns/MCP_CONTENT_BOUNDARY_QUALIFICATION_2026-08-09.md).

## 11. MCP inventory-integrity blueprint

`LLM03-MCP-INVENTORY` tests a customer-approved MCP capability inventory, not the mere existence of a server or the visibility of tools.

Required target configuration and proof:

1. Record the SHA-256 of the complete normalized approved inventory. The normalization preserves every tool definition and duplicate while making pagination and listing order irrelevant.
2. Optionally define required and forbidden tool names plus per-tool description and input-schema digests when the engagement needs a narrower control.
3. Follow the configured lifecycle, bounded pagination, and preserve every JSON-RPC request, response, cache directive, and notification in protocol order. When configured, retain up to three post-initialization inventory rechecks.
4. For sessionless `2026-07-28`, preserve `server/discover`, per-request metadata, method/name headers, absence of session state, and a bounded `subscriptions/listen` stream when the server advertises the requested inventory-change capability.
5. Treat a digest mismatch, missing required tool, forbidden advertised tool, or configured per-tool digest mismatch as deterministic evidence. HTTP success, JSON-RPC success, model opinion, inventory visibility, cache changes, and notifications without an approved-inventory violation are not findings.
6. Reproduce every positive result once through the same authorized identity and transport. A matching secure control must create no finding.
7. Qualify each lifecycle/transport claim separately, then require at least two unrelated server implementation families before promoting that boundary to qualified.

The retained initial-inventory campaign covers an AdverScope raw-protocol server and an unrelated official MCP Python SDK server across Streamable HTTP `2025-11-25` and legacy HTTP+SSE `2024-11-05`. The lifecycle campaigns add repeated post-initialization drift and change-notification controls on all three retained transport paths, an unrelated official MCP TypeScript SDK v2 server for the `2026-07-28` sessionless path, and an unrelated official MCP Python SDK dynamic server for older Streamable HTTP and legacy HTTP+SSE. Dynamic lifecycle behavior is therefore qualified across at least two implementation families for every retained transport generation. Arbitrary registries, custom brokers/transports, every SDK, prompt/resource semantic integrity, and state-changing effects remain outside the boundary.

The retained inventory campaigns are recorded in [MCP_INVENTORY_QUALIFICATION_2026-08-09.md](../validation/target-campaigns/MCP_INVENTORY_QUALIFICATION_2026-08-09.md), [MCP_INVENTORY_LIFECYCLE_QUALIFICATION_2026-08-09.md](../validation/target-campaigns/MCP_INVENTORY_LIFECYCLE_QUALIFICATION_2026-08-09.md), and [mcp-older-dynamic-sdk-qualification-2026-08-09-results.md](../validation/target-campaigns/mcp-older-dynamic-sdk-qualification-2026-08-09-results.md).

## 12. MCP prompt-inventory and access blueprint

`LLM02-MCP-PROMPT` covers unauthorized advertisement and read-only retrieval of a target-defined protected MCP prompt. It does not claim that a prompt is unsafe merely because it exists or that AdverScope can infer arbitrary prompt sensitivity without customer policy.

Required target configuration and proof:

1. Define required and forbidden prompt names for the selected identity. Optional `expected_prompts` entries may pin the exact description and argument-schema digests.
2. For protected retrieval, configure the exact prompt name and arguments, explicitly approve the bounded read-only `prompts/get`, and supply target-owned assertions for both returned content and the authorization boundary.
3. Require JSON-RPC success, non-empty returned messages, and every exact assertion before confirming disclosure. Inventory visibility, HTTP success, JSON-RPC success, a notification, non-empty prose, or model confidence alone is not finding-grade.
4. Retain complete prompt inventory, exact request and response, selected identity, assertion decisions, and protocol order. Reproduce every positive case once; secure controls retain the denial without a finding.
5. Qualify Streamable HTTP and legacy HTTP+SSE separately and use at least two unrelated server implementation families.

The retained campaign covers an AdverScope raw-protocol fixture and an unrelated official MCP Python SDK fixture with repeated secure and vulnerable controls over Streamable HTTP `2025-11-25` and legacy HTTP+SSE `2024-11-05`. Arbitrary prompt semantics, safe-prompt quality, custom authorization brokers, every SDK, chained agents, and state-changing effects remain outside this boundary.

The retained prompt campaign is recorded in [mcp-prompt-qualification-2026-08-09-results.md](../validation/target-campaigns/mcp-prompt-qualification-2026-08-09-results.md).

## 13. Retained campaign index

| Technique | Independent families | Status | Latest evidence |
|---|---:|---|---|
| `LLM01-DIRECT` | 2 | Qualified | Repeated policy-gateway qualification |
| `LLM01-INDIRECT-WEB` | 2 | Qualified | Indirect document-assistant qualification |
| `LLM01-MCP-CONTENT` | 2 | Qualified | Streamable HTTP and legacy HTTP+SSE content-sink qualification |
| `LLM02-MCP-RESOURCE` | 2 | Qualified | Streamable HTTP and legacy HTTP+SSE protected-resource qualification |
| `LLM02-MCP-PROMPT` | 2 | Qualified | Streamable HTTP and legacy HTTP+SSE prompt inventory and retrieval qualification |
| `LLM03-MCP-INVENTORY` | 3 overall; at least 2 per retained lifecycle generation | Qualified | Initial inventory plus modern and older dynamic lifecycle qualification |
| `LLM06-TOOLS` | 2 | Qualified | Workspace tool-authorization qualification |
| `LLM06-MCP-TOOLS` | 2 | Qualified | Streamable HTTP and legacy HTTP+SSE authorization qualification |
| `LLM06-MCP-DEPUTY` | 2 | Qualified | Streamable HTTP and legacy HTTP+SSE confused-deputy qualification |
| `LLM08-MCP-BOUNDARY` | 2 | Qualified | Streamable HTTP and legacy HTTP+SSE cross-identity boundary qualification |

This table summarizes only completed technique claims. The machine-readable qualification registry remains authoritative.

## 14. Release-candidate sweep

After the individual technique campaigns pass, run a smaller cross-technique release-candidate sweep through the visible GUI. Its purpose is to detect integration regressions across shared project state, evaluator behavior, deterministic adapters, evidence custody, reproduction, and reporting; it does not replace the larger technique-specific qualification sets.

The sweep must:

1. use fresh isolated projects and execution IDs;
2. include secure and vulnerable controls for every selected path;
3. repeat model-dependent target families enough to expose unstable classifications;
4. include at least one deterministic indirect-input path, one structured tool path, and the current supported MCP authorization/content/prompt paths;
5. keep its campaign identifiers separate from its post-run oracle;
6. review representative exact traffic and reproduction in the GUI before scoring;
7. correct AdverScope—not the target fixture—when a gate or professional presentation requirement fails;
8. state explicitly which external benchmarks and model families were not rerun.

The 2026-08-09 release-candidate sweep passed 26/26 gated expectations across 18 GUI projects with precision `1.0`, supported recall `1.0`, reproduction `13/13`, and no infrastructure or inconclusive outcomes. It exposed and corrected stale post-save assessment readiness and misleading true-negative root-cause labels. See [M1_RELEASE_CANDIDATE_ACCEPTANCE_2026-08-09.md](../validation/target-campaigns/M1_RELEASE_CANDIDATE_ACCEPTANCE_2026-08-09.md).
