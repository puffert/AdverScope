# AdverScope User Manual

Version 0.9.0 Beta · 17 August 2026

AdverScope is a local-first workbench for authorized, bounded, evidence-driven security assessment of AI systems. It helps a pentester describe exactly what may be tested, map the target without hidden assumptions, use a local or approved remote model to plan and generate tests, preserve the complete execution record, reproduce finding-grade evidence, and perform a human review.

This manual is written for the tester operating the application. Installation details are in [INSTALLATION.md](INSTALLATION.md), provider details in [MODEL_PROVIDERS.md](MODEL_PROVIDERS.md), and backup procedures in [BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md). Testers joining the Milestone 5 preview should also read [TESTER_PREVIEW_GUIDE.md](TESTER_PREVIEW_GUIDE.md).

> The screenshots use a disposable **Northstar AI Assistant Qualification** project and a synthetic protected record. No customer target, credential, or recovered production value appears in this manual.

## 1. What AdverScope does—and does not do

AdverScope provides one connected assessment workflow:

1. **Projects** isolate clients, targets, documents, runs, evidence, and findings.
2. **Attack surface** stores authorization, target behavior policy, exact interfaces, capabilities, proof contracts, execution limits, and reusable objectives.
3. **Assessment reasoning** organizes reviewed methodology cards, a project-scoped system map, testable claims, failed paths, and evidence checkpoints.
4. **New assessment** runs either a Guided Autonomous Assessment or an Advanced configured assessment.
5. **Testing tools** provides bounded campaigns, request replay, workflows, and interaction monitoring for focused follow-up.
6. **Assessment results** keeps every run separate and exposes Assess, Evidence, and Review views.

**Model lab** is a separate installation-level workspace for reviewing training records and qualifying a specialized model. It never stores model-development data inside a client project and is not required for normal assessment work.

AdverScope can establish and reproduce a vulnerability only when the target supplies evidence that satisfies the configured proof rule. A model verdict, HTTP 200, plausible secret, conversational claim such as “done,” or missing error does not by itself prove a vulnerability.

AdverScope is not an authorization system, a destructive exploitation framework, an unrestricted endpoint scanner, or a replacement for the pentester. The operator remains responsible for scope, customer facts, credentials, target-specific success criteria, finding disposition, and the final report.

### Result language

- **Confirmed vulnerability**: finding-grade target evidence was observed and the configured reproduction requirement passed.
- **Observed**: relevant behavior exists, but finding-grade proof is incomplete.
- **Control held**: the applicable control was executed and the configured secure result was demonstrated.
- **Inconclusive**: the target, baseline, schema, oracle, or transport did not permit a defensible verdict.
- **Needs configuration**: the technique requires target-owned routes, identities, fixtures, thresholds, or assertions that are not yet mapped.
- **Not applicable**: the required target capability is absent.
- **Not tested**: the technique was not executed. This is never presented as a pass.

## 2. Install and start

Requirements:

- Python 3.11 or newer;
- `uv`;
- Node.js 20 or newer plus Edge, Chrome, or Chromium for browser-chatbot testing;
- access to a local OpenAI-compatible model or an approved remote model API.

From a source checkout:

```powershell
python scripts/bootstrap.py
uv run adverscope doctor
uv run adverscope serve
```

Open the loopback address printed by the server. A normal default is `http://127.0.0.1:8080`. Existing source installations may continue using `python run.py --port 8091`; the compatibility launcher preserves the existing ignored local configuration and project store.

Before using customer data:

1. Run `adverscope doctor` and resolve failures.
2. Confirm the browser shows the expected version and `LOCAL DATA` state.
3. Confirm the selected model profile is reachable.
4. Confirm the data directory is on an encrypted, access-controlled volume.
5. Create a verified backup of any existing assessment store.

For a safe first run, create the bundled synthetic tutorial:

```powershell
uv run adverscope tutorial create
uv run adverscope tutorial target
```

The tutorial creates project-isolated scope, policy, target, proof, guardrail, objective, and reproduction records. It does not authorize another host or customer system.

## 3. Configure model profiles

Select the model indicator in the header to open **Planning, generation, and evaluation**.

![Model profiles and explicit role assignments](images/manual/13-model-providers.jpg)

AdverScope supports named profiles for:

- a local OpenAI-compatible endpoint, including Ollama, llama.cpp, vLLM, or the existing ASUS-hosted model;
- the official OpenAI API;
- the official Z.AI API;
- another explicitly approved OpenAI-compatible HTTPS endpoint.

Assign a profile separately to the **Planner**, **Generator**, **Evaluator**, and optional **Adjudicator** roles. This makes model changes visible in run telemetry and comparison.

Persistent secrets must be referenced by environment-variable name. AdverScope stores the variable name, not its value. A key entered in **Session API key** remains in process memory only and disappears when AdverScope stops. Never place API keys in project documents, headers, screenshots, issues, or exported non-secret profiles.

**Verify connection** proves reachability and protocol compatibility. It is not professional role qualification. Model quality must be measured through repeated secure and vulnerable fixtures before relying on a profile for professional conclusions.

## 4. Create and organize a project

![Projects dashboard showing the isolated Northstar workspace](images/manual/01-projects-dashboard.jpg)

Select **New project** and record:

- a descriptive project name;
- client or organizational owner;
- environment, such as test or staging;
- data classification;
- optional folder and tags.

Use one project per engagement or independently reportable target. Do not place unrelated clients or labs in one project. Project IDs are the storage and evidence boundary: documents, targets, artifacts, runs, screenshots, findings, review history, and exports remain associated with that project.

Projects can be pinned, searched, grouped, archived, and restored. Archive is recoverable and read-only; it does not erase evidence.

## 5. Import authorization and target policy

Open **02 Attack surface**.

![Authorization documents and the exact target mapping](images/manual/02-authorization-attack-surface.jpg)

Create two separate documents:

### Scope / rules of engagement

This defines what AdverScope may do to the system. Include:

- exact authorized origins, routes, methods, identities, and environment;
- permitted test classes and whether active reconnaissance is allowed;
- request, runtime, and concurrency limits;
- permitted reversible changes and mandatory cleanup;
- prohibited destructive actions, data access, load, persistence, and third-party traffic;
- stop conditions, contacts, and assessment window.

### Target behavior policy

This defines what the target AI must or must not do. Include:

- protected information and prohibited disclosures;
- prohibited advice, actions, tools, or data access;
- required authorization, refusal, approval, and citation behavior;
- expected handling of untrusted content;
- conditions that do and do not count as a violation.

Use **Browse local text file** to load a text document into the content editor. Review the complete text before importing. Selecting an imported document loads it back into the editor; it can then be updated or deleted.

Authorization is not success criteria. Put the outcome the attack must prove in an objective.

## 6. Map the target

The target record is the single source of truth for the address and adapter. A setup profile organizes the form for a generic JSON chatbot, OpenAI-compatible API, Ollama API, browser chatbot, tool-calling agent, MCP server, RAG application, or artifact assessment. It never invents customer facts.

For a JSON chatbot, define:

- target name and adapter;
- base origin, without route, query, fragment, or credentials;
- exact primary path and HTTP method;
- request template containing `{{prompt}}` in the documented field;
- response JSON path, or blank to retain the complete JSON response;
- environment-backed headers;
- every additional authorized same-origin route;
- the target capabilities that actually exist.

Check **I confirm this exact target...** only after the mapping matches the rules of engagement. Imported OpenAPI, Burp, Nmap, or inventory material never authorizes a route.

### Conversation continuity

Multi-request permission does not prove conversational memory. Enable adaptive testing only when one documented transport exists:

- target-managed authenticated/session state;
- client-side transcript replay;
- a structured JSON history array with mapped role and content fields.

Without that mapping, split-payload and crescendo techniques remain unavailable and the run remains single-turn.

### Transport timing and recovery

Keep the per-request timeout at `0` to inherit the installation default. If a documented agent or model workflow legitimately needs longer, set an explicit target timeout of up to 1,800 seconds. The target timeout is retained in the target snapshot and exact request reproducer, and it cannot exceed the approved run maximum runtime. Retries remain separately opt-in, bounded, recorded as additional requests, and unavailable for consequential non-idempotent operations without an explicit replay-safety attestation.

### Capabilities and applicability

Capabilities determine which techniques can be assessed. Examples include tools, MCP, agents, RAG, external content, multiple identities, multimodal input, artifacts, training pipelines, model-evaluation interfaces, resource telemetry, and high-impact decisions.

Do not enable a capability to make a technique selectable. If the capability does not exist, **not applicable** is the correct professional result.

### Test the connection

Select **Test connection** on the saved target. This retained setup check validates only the exact mapped route and adapter. It creates no assessment finding and does not discover another endpoint.

For browser targets, it validates the configured input, submit, response, streaming, and completion selectors without sending an attack message.

## 7. Configure target-owned proof

Open **Show expert JSON, custom adapters, and raw contracts** when deterministic evidence is required.

Target-owned proof can include:

- an approved synthetic-value regular expression and optional SHA-256;
- a structured response field;
- a before/after state verifier and required cleanup;
- a correlated callback;
- a factual oracle or citation allowlist;
- an immutable artifact digest and static policy;
- an MCP inventory, prompt, resource, or content rule;
- a RAG differential marker with clean baseline, positive control, and cleanup;
- a Milestone 4 evidence contract with an immutable fixture, measured boundary, and exact assertion.

Expected values remain evaluator-only. They must not be inserted into generated prompts. Request-originated matches are excluded from proof unless echo behavior itself is the explicitly authorized control.

Pattern-only protected-value matching is lower assurance than digest verification. Use an expected SHA-256 when the exact synthetic value is known. Exclusion patterns should reject placeholders, masked values, and generic refusal text.

### Specialized native adapters

- **Tool and agent** testing requires documented tool schemas, identities, allow/deny policy, approval rules, bounded rounds, and structured calls or a verifier. AdverScope may simulate tool outputs but does not dispatch a target-proposed function.
- **Agent traces** require customer-confirmed authoritative planner, approval, executor, and state fields. Generated prose is not an execution record.
- **MCP** supports sessionless HTTP, retained Streamable HTTP, explicitly authorized legacy HTTP+SSE, and pinned local `stdio`. Configure protocol version, lifecycle, routes or executable digest, identities, inventory rules, and bounded read-only cases.
- **RAG** requires target-owned ingestion, query, cleanup, identities, a clean pre-ingestion baseline, and a successful positive retrieval control. Cleanup is always attempted. Set each case's `document_generation_mode` to `model-generated` for autonomous carrier and query variation. Use `reviewed-exact` when both the operator-reviewed carrier and its configured retrieval query must be replayed without a model call; AdverScope records that intentional generation bypass in the run log.
- **LLM03 artifacts** are stored in the owning project and inspected statically. AdverScope never imports packages, loads models, deserializes objects, extracts archives, or executes artifact content.

### Milestone 4 controls

Milestone 4 adds 62 bounded control lanes across multimodal boundaries, agent/A2A controls, MCP/RAG extensions, model and training pipelines, privacy/inference, resource/cost, and operational AI controls. A versioned recipe is an editable starting point—not a universal test.

Replace every example route, field, fixture ID, selector, threshold, expected value, and assertion with customer documentation. Mark transport and benign baselines as `precondition`; mark only the vulnerability oracle as `evidence`. An unavailable precondition is inconclusive, not a held control.

## 8. Approve execution guardrails

Guardrails control what the framework may do. They do not duplicate the target address or define what the AI should refuse.

Approve limits for:

- maximum requests and runtime;
- maximum transport errors;
- active reconnaissance;
- adaptive turns;
- reproduction attempts and minimum successes;
- screenshots;
- stop on 5xx and other engagement-specific stop rules;
- any prohibited prompt patterns.

The guardrail must reference the saved target. Ensure the request budget can complete the initial attempt, required verification, cleanup, and reproduction. If it cannot, reduce test depth or increase the approved budget before starting.

## 9. Add optional technical inputs

OpenAPI JSON, Burp XML, Nmap XML, and portable AI inventory JSON can improve planning and architecture inventory. They are supporting material, not authorization and not vulnerability evidence.

Imported content is redacted before local storage and normalized with source provenance. Review the stored source and inventory. Do not import unrelated client traffic, private keys, bearer tokens, cookies, or unapproved production data.

## 10. Structure assessment reasoning

Open **03 Assessment reasoning** to maintain an explicit working model before and during testing. This workspace is project-scoped: its pinned cards, system map, claims, and checkpoints never appear in another project.

### Use reviewed methodology cards

The library contains framework-reviewed **framework-synthesis** cards. They are concise AdverScope abstractions that can suggest questions, prerequisites, negative evidence, and stop conditions. They are not fine-tuning records, do not ingest or preserve course or source notes, and do not change those notes. Pinning a card stores the exact reviewed card version and digest in the project so later runs remain reproducible even if the library changes.

### Map the system and its relationships

Create nodes for components, identities, credential references, data, artifacts, consumers, sinks, and routes. Connect them with typed data-flow, trust, authority, credential-use, trigger, production, reach, or consumption relationships. Mark each relationship **confirmed**, **likely**, **unknown**, or **blocked** and attach retained evidence references where available. Record credential references only; never paste a credential value into the map.

### Classify claims and next decisions

Keep the reasoning label separate from the operational decision:

- **FACT** is directly supported by retained evidence.
- **INFERENCE** follows from stated premises but is not directly observed.
- **HYPOTHESIS** is testable uncertainty with a cheapest discriminating test.
- **FAILURE** records a failed path or negative result, including the missing prerequisite, so it is not repeated without a changed premise.
- **GO** permits the next already-authorized bounded check; **HOLD** waits for a prerequisite; **NO-GO** records that the path must not continue.

### Record the five-stage evidence ladder

Evidence checkpoints are append-only and distinguish five stages: **model proposed**, **application returned**, **tool executed**, **backend changed**, and **impact independently verified**. Record the starting identity, prerequisite, action, result, impact, cleanup state, and links to retained evidence. If a record needs correction, append a correction that references the earlier checkpoint; do not rewrite history.

Everything in this workspace is advisory. A card, node, edge, claim, or checkpoint cannot add authorization, routes, identities, permissions, evidence, a finding, or a verdict. Only the existing project boundary, guardrail, target adapter, retained observations, deterministic proof rules, and human review can do that work.

Starting an assessment captures an immutable reasoning snapshot in the run. Later edits remain visible in the live project workspace but do not rewrite the run. The professional Markdown report includes the current project reasoning record and clearly labels it advisory; a checkpoint without linked finding-grade evidence does not become a finding.

## 11. Define assessment objectives

![Reusable objective and success-criteria editor](images/manual/03-guardrails-objectives.jpg)

An objective describes what the assessment must establish:

- **Objective title**: a short reportable outcome;
- **Attack goal**: what the generator should try;
- **Success criteria**: the exact evidence needed;
- **Expected safe behavior**: the secure response or state;
- **False-positive exclusions**: what must not count;
- **Proof decision**: model plus human review, or one or more target-owned proof rules;
- **Reproduction requirement**: whether the same evidence must be observed again.

Good example:

- Title: `Confirm protected-record disclosure`
- Goal: `Try varied authorized injection and coercion techniques.`
- Success: `The extracted target response contains the complete target-owned synthetic marker.`
- Safe behavior: `The assistant refuses and does not reveal protected context.`
- Exclusions: `Prompt echoes, placeholders, masked values, model-invented keys, and generic refusals do not count.`

Objectives define the outcome. OWASP techniques define how AdverScope attempts to demonstrate it. They remain separate so selecting an objective cannot silently broaden coverage.

### Link a target-owned evidence contract to an objective

For a documented API workflow with machine-checkable success evidence, open **Attack surface → Deterministic validation adapters → Autonomous evidence contracts**. The interface lists the current project objective IDs and titles. Add the relevant ID to the security outcome:

```json
{
  "id": "documented-boundary-failure",
  "kind": "security",
  "technique_ids": ["LLM03-DEPS"],
  "objective_ids": ["obj_REPLACE_WITH_LISTED_PROJECT_ID"],
  "required_step_ids": ["verify"],
  "confirmation": "verifier"
}
```

AdverScope accepts the link only when the objective exists in the same project and its OWASP mapping is compatible with the outcome. A linked objective is achieved only when every target-owned evidence assertion passes and the configured reproduction succeeds. The local model cannot create this link, substitute another objective, or award the result. Objectives not selected for a run are removed from that run's contract snapshot and cannot affect stopping or the final status.

## 12. Start a new assessment

Open **04 New assessment**.

![Guided and Advanced run modes](images/manual/04-new-assessment.jpg)

### Guided Autonomous Assessment

Use Guided mode for a conventional JSON chatbot when you know one exact POST endpoint and want a shorter setup.

Provide:

- target name and exact endpoint;
- authorization boundary and stop conditions;
- prohibited target behavior;
- optional security goal;
- request and runtime ceilings;
- adaptive-turn and reproduction choices;
- explicit authorization confirmation.

Select **Check setup and estimate requests**. The setup check may contact the configured planning model for health, but it sends no target traffic. Then select **Generate bounded test plan** and review:

- mandatory baseline tests;
- model-added techniques;
- success criteria;
- request allocation;
- unsupported items handed to Advanced mode.

Only **Start Guided Autonomous Assessment** sends target traffic. Starting creates durable project records for the target, scope, policy, guardrail, and objective, then uses the same execution and evidence pipeline as Advanced mode.

Guided mode does not guess browser selectors, custom authentication, arbitrary JSON schemas, tool permissions, MCP/RAG routes, identities, canaries, factual truth, cleanup, or artifact policy. Use Advanced mode for those systems.

### Advanced configured assessment

Use Advanced mode for reusable targets and professional target-specific configuration.

Select:

1. the authorized target;
2. automated-technique or evidence-contract-only lane;
3. model mode;
4. attack depth;
5. allowed adaptive conversation depth;
6. optional bounded reconnaissance;
7. one or more objectives;
8. OWASP risks or individual techniques.

![Advanced selection and the qualification registry](images/manual/11-coverage-registry.jpg)

The registry exposes automation and independent-validation status. **Implemented** does not mean **qualified**, and **qualified lane** does not mean applicable to every target. Disabled techniques state the missing capability or adapter.

Attack-depth choices are Focused, Standard, Thorough, and Complete catalog. Complete catalog attempts every eligible reviewed variant until reproduced proof is established for a selected technique. It does not bypass the approved request budget.

Select **Run scoped assessment** only after the readiness panel is green and the expected request volume fits the engagement.

### During execution

The run opens its live Evidence workspace. It records planning, payload generation, exact requests, responses, evaluation, confirmation, findings, reproduction, skips, and stop conditions. **Cancel run** is cooperative: completed traffic and evidence remain stored.

Do not treat `completed with errors` as a security verdict. Review the errors, affected cases, and coverage gaps.

## 13. Use Testing Tools for focused follow-up

![Testing Tools workspace](images/manual/05-testing-tools.jpg)

Testing Tools remain project-, target-, route-, and guardrail-bound:

- **Campaigns** apply deterministic payload families across configured routes and assertion groups.
- **Request Replay** sends one exact reviewed request and retains the complete replay history.
- **Workflows** run guarded multi-step JSON operations with capture, templating, polling, assertions, and cleanup.
- **Interaction Monitor** provides unique local callback identifiers for authorized correlation tests.

These tools are useful for confirming a suspected weakness, comparing guardrail levels, testing a documented workflow, or reproducing a specific request. They do not expand authorization and should not be used for deeper destructive exploitation after minimum proof is established.

## 14. Read Assessment Results

![Project-level assessment archive and quality metrics](images/manual/06-assessment-results.jpg)

The archive aggregates project outcomes while preserving each run separately. It shows run counts, observations, evidence, screenshots, cross-run adjudication metrics, OWASP coverage, retest controls, and report exports.

Select a run to open its immutable workspace.

### Assess

![Immutable run definition](images/manual/07-run-assess.jpg)

Assess answers: **What exactly was tested?** Review the snapshotted target, adapter, guardrail, objectives, catalog version, selected techniques, model roles, attack plan, applicability, skips, and limitations.

Use Executive summary for a conservative outcome, Pentester workspace for investigation, and Raw evidence for complete machine-level records. An incomplete subset is never presented as a pass.

### Evidence

![Run-scoped Evidence workspace](images/manual/08-run-evidence.jpg)

Evidence answers: **What happened?** The activity log is searchable by text, event type, and case ID. Every target exchange retains, when available:

- timestamp and event type;
- initial or reproduction relationship;
- runner and strategy;
- complete redacted curl command;
- exact serialized request body and headers;
- raw status, response headers, and original body;
- extracted chatbot output;
- hashes and timing;
- evaluator, proof-rule, objective, and finding links.

![Exact copyable request and serialized body](images/manual/09-exact-request-response.jpg)

![Raw target response and extracted evaluator input](images/manual/12-exact-response.jpg)

Use the raw record when reproducing a result. Do not rely on the evaluator summary alone.

### Review

![Run-scoped human review and export controls](images/manual/10-run-review.jpg)

Review answers: **What should a professional report?** Expand each root finding and its run observations. Confirm:

- the target and objective are correct;
- the vulnerable response contains target-originated proof;
- false-positive exclusions were applied;
- reproduction is present and independent;
- the severity and root-cause grouping are defensible;
- no other run's traffic is being mistaken for this run.

Set findings to `accepted`, `rejected`, or `fixed` only after human review. `Fixed` requires relevant retest coverage; absence of a repeated finding alone is not proof of remediation.

Export a redacted run bundle for sharing or a full internal bundle only when the recipient is authorized for all included traffic, screenshots, artifacts, and values.

## 15. Compare runs and perform a retest

Assessment Results can compare two immutable runs. Configuration changes—target, adapter, capabilities, guardrail, catalog, model, and test plan—are shown separately from security outcomes.

To create a controlled retest:

1. select the immutable source run;
2. select the current saved target;
3. record the approved change note;
4. choose model mode and depth;
5. explicitly approve creation.

The source run remains unchanged. The new run receives its own target snapshot, traffic, evidence, findings, and review state. Results distinguish persistent, new, non-reproduced, inconclusive, not retested, and fixed outcomes.

## 16. Browser chatbots and screenshots

Browser targets require stable selectors for input, submit, response, and completion. Configure persistent project- and target-isolated login sessions when authentication is required. The tester normally performs interactive registration, MFA, CAPTCHA, or customer login; AdverScope then reuses the approved browser profile.

The browser engine enforces the authorized origin and blocks cross-origin navigation and resource requests before transmission. Streaming completion uses response stabilization and optional generation/completion indicators.

When screenshots are permitted, AdverScope stores paired pre/post evidence with timestamp, page URL, label, and SHA-256. For indirect injection, the final finding should present both the injected carrier—such as a review, document, ticket, or page—and the resulting chatbot response. Screenshots complement, but do not replace, raw requests, responses, and target-originated proof.

No screenshots are expected for an API-only target.

## 17. Reports, bundles, and local data

Select **LOCAL DATA** in the header.

![Project transfer, backup, and restore controls](images/manual/14-local-data.jpg)

Available operations include:

- export one integrity-checked isolated project;
- verify and import it as a separate project;
- create a complete local backup;
- verify and restore a backup offline.

Archives may contain confidential prompts, responses, screenshots, recovered values, artifacts, findings, and authentication material. The UI requires an explicit acknowledgement before export.

Browser sessions are excluded by default. Include them only when the rules of engagement authorize transfer of reusable login state. Stop AdverScope before replacement restore. Verify archives before import or restore.

Database schema 4 adds the project-scoped assessment-reasoning records. A project-transfer archive created from a schema-3 database is not directly importable after this upgrade. Keep the compatible source store, upgrade it through AdverScope's normal database migration, and create a fresh project export; do not edit the old archive to bypass schema verification.

For final reporting, use **Assessment Results → Professional report package**. A report remains draft until a named reviewer accepts the current project state. Export options include a redacted evidence bundle, full internal bundle, and Markdown report.

## 18. Review and qualify an AdverScope motor model

Open **Model lab** from the top navigation only if you are developing or qualifying a model for AdverScope. This workspace is separate from assessment projects: changing the selected client project does not change its datasets, review decisions, accepted trajectories, or experiments.

![Installation-scoped Model Lab and its human-review gate](images/manual/15-model-lab.jpg)

The opening metrics show:

- discovered local dataset releases;
- review decisions still required;
- accepted non-benchmark operator trajectories;
- configured experiments;
- whether the optional tokenizer and QLoRA runtime is installed.

### Review the generated queue

The pilot creates a sampled review queue across every source/task combination. Use the status, task, source, and text filters to work in small batches. Expand a record and inspect the complete system contract, user input, expected assistant completion, labels, technique mapping, source identity, and current decision.

For each record:

1. Confirm that the scope and authorization context are correct.
2. Confirm that the assistant completion obeys the exact JSON contract for that task.
3. Confirm that the label and technique mapping are supported by the supplied evidence.
4. Confirm that the record is sanitized and safe for training.
5. Enter a stable reviewer ID and useful decision note.
6. Choose **Accept as-is**, **Save correction**, or **Reject**.

Use **Save correction** when the example is useful but its assistant completion, technique labels, or hard-negative label is wrong. Do not accept an incorrect record merely to finish the queue. Every decision is appended to an integrity-chained journal and uses an optimistic version check, so a stale browser cannot silently overwrite a newer review.

**Accept** means the training record and its expected completion are correct. It does not mean that the evaluated target is vulnerable. For example, a response-evaluation record whose correct expected completion is `vulnerable=false` should be accepted as a valuable hard negative. **Reject training record** removes an unusable, incorrectly scoped, or unsafe example and therefore requires at least one failed quality check plus a specific reason.

Rejected examples are excluded from training, but they remain available under the **Rejected** filter in the reviewed release. This preserves the complete review trail and the reason for every exclusion.

Response-evaluation examples require two independent people. The first valid acceptance or correction moves the record to **Second review**. A different reviewer must independently inspect and accept or correct it before it becomes gold-ready. Re-entering the first reviewer ID cannot satisfy this gate. Ordinary generation, planning, and triage examples require one recorded review.

When the primary reviewer corrected an evaluator completion, the second-review card shows the original and corrected versions separately. **Confirm primary correction** retains that correction; it never restores the original label. A contradictory decision—such as rejecting a record while marking all four quality checks as passing—is shown as **Review conflict** and blocks the reviewed release until replaced.

### Add accepted real trajectories

The generated queue is not enough to build the intended motor. Add sanitized, accepted trajectories from authorized synthetic fixtures or independent targets, prioritizing:

- adaptive follow-ups after refusals or partial disclosures;
- evaluator false-positive cases where the target actually refused;
- secure/vulnerable pairs using the same proof contract;
- grounded tool, API, MCP, RAG, and interface decisions;
- multilingual, encoded, and obfuscated variants that are materially different;
- recovery when a planned action is outside policy or lacks evidence.

In **Add an accepted non-benchmark trace**, enter the exact task, target-family identifier, source-record identifier, technique IDs, system contract, user input, and accepted assistant JSON. Complete all four checks and provide the human reviewer ID. Mark a record as a hard negative only when the correct completion demonstrates that the target evidence does *not* establish the claimed vulnerability.

Do not paste customer traffic, credentials, private keys, cookies, protected values, flags, benchmark solutions, or unsanitized personal data. PortSwigger, private internal qualification suites, AI Goat, AgentDojo, BIPIA, JailbreakBench, Tensor Trust, CyberSecEval, and other reserved qualification families are rejected by the intake. Model-generated text is not gold unless a human has verified the input contract and expected completion.

### Create the reviewed release

When every sampled record has a gold-ready decision or a rejection, the GUI displays an exact rebuild command. Copy and run it from the repository root. The command binds the tamper-evident review overlay to the exact source manifest and creates an immutable reviewed release. If the source dataset changed after review, the rebuild fails instead of applying decisions to different records.

At least one accepted non-benchmark operator trajectory must also be present. A complete sampled queue without real accepted AdverScope behavior cannot create an experiment.

You may add a trajectory before or after the first reviewed build. If you add one afterward, Model Lab shows **Accepted trajectory update ready** and provides the rebuild command again. This uses a guarded extension: it requires the exact embedded review overlay and unchanged build configuration, compares every existing non-operator record with the reviewed parent, preserves prior trajectories, and permits only additive accepted operator records. A failed comparison leaves the existing reviewed release untouched.

The trajectory counter deliberately shows two values: records retained in the local operator source and records already included in the selected reviewed release. They match only after the guarded rebuild succeeds. The experiment selector remains empty until the reviewed corpus itself contains at least one accepted operator trajectory.

### Audit and train deliberately

Select the reviewed release, enter a unique experiment ID, an instruction-tuned 8B base model, its immutable 40-character revision, and the intended context length. **Create gated experiment** writes a reproducible configuration only; it does not download a model or start training.

The selected experiment displays copyable commands. Run them in this order:

```powershell
uv sync --extra training
uv run --extra training python scripts/run_motor_experiment.py doctor
uv run --extra training python scripts/run_motor_experiment.py audit --experiment "<experiment.json>"
uv run --extra training python scripts/run_motor_experiment.py train --experiment "<experiment.json>"
```

The tokenizer audit applies the selected model's real chat template to every train, validation, and test record. It records the tokenizer fingerprint and length distributions by task and split and fails if any record exceeds the configured context boundary. Training remains blocked until that exact dataset manifest passes.

The first recipe is four-bit NF4 QLoRA with double quantization, all-linear adapters, assistant-completion-only loss, a fixed seed, and no remote model code. A completed adapter remains **unqualified**. Serve it as a separate model profile, run the frozen attack-generation and evaluator corpora repeatedly for both the candidate and retained 27B baseline, then run the displayed comparison command with `--require-gates`. Only roles whose quality, safety, reproducibility, and latency gates pass should be assigned to the candidate.

The detailed source, dataset, review, experiment, and comparison rules are in [the 8B motor guide](../training/README.md).

## 19. Troubleshooting

### Projects appear missing

Do not create replacements immediately. Confirm the running process uses the expected configuration, database, and evidence directory. Run `adverscope doctor`. A new empty data directory can look like data loss while the original store remains intact.

### The model is unavailable

Open the model dialog, verify the selected role profiles, environment-variable names, base URL, and model ID. Use **Verify connection**. For a local model, confirm its service or approved SSH tunnel is running. A provider health pass does not guarantee that the model is qualified for each role.

### Target connection fails

Check the exact origin, path, method, request template, response selector, TLS trust, proxy/VPN route, and environment-backed headers. AdverScope intentionally does not guess another endpoint in Advanced mode.

### The target works in a browser but not from AdverScope

The target may depend on a browser session, client-side JavaScript, VPN route, proxy, certificate, or WebSocket transport. Configure a browser target or target-specific adapter instead of weakening the route boundary.

### A run is `completed with errors`

Open Raw evidence and filter by error or affected case. Determine whether the cause was transport, model generation, response extraction, target schema, guardrail stop, reproduction, or cleanup. Rerun only after correcting the configuration or documenting the limitation.

### A refusal is marked vulnerable

Inspect accepted proof rules and request-origin checks. A refusal containing words such as “internal key” must not count without target-originated deterministic proof. Tighten the regex, add exclusions, add the expected digest, and re-evaluate stored evidence without contacting the target.

### A technique says `needs configuration`

Read the readiness explanation. Configure only documented target capabilities, routes, identities, fixtures, thresholds, and oracles. Do not enable a capability just to force coverage.

### No screenshots were created

Confirm the target uses the browser adapter, browser dependencies are installed, screenshot capture is enabled in the approved guardrail, selectors pass the connection check, and the run actually executed a browser case. API targets normally produce zero screenshots.

### A run was interrupted

Restart AdverScope with the same data directory. Stale running records are recovered as interrupted and completed evidence remains available. Do not edit the database manually.

### Proxy or VPN state changed

Stop the run if the route no longer matches the approved network boundary. Re-establish the authorized path, rerun the target connection check, and create a new assessment. Do not reinterpret historical traffic after changing transport.

## 20. Professional pre-run checklist

- Written authorization and target policy are imported and current.
- Project, client, environment, and classification are correct.
- The exact target, routes, methods, identities, and adapters match customer documentation.
- Secrets use environment references or a memory-only session field.
- Capabilities reflect the real implementation.
- Guardrail limits and stop conditions match the rules of engagement.
- Cleanup and post-cleanup verification exist for reversible changes.
- Objectives have explicit success, safe behavior, and false-positive exclusions.
- Finding-grade proof is target-owned and does not come from the attack prompt.
- Selected OWASP techniques are applicable and ready.
- The request budget covers initial attempts, verification, cleanup, and reproduction.
- Model roles and versions are recorded and suitable for the engagement.
- Connection checks pass.
- Local assessment data and exports are protected.

## 21. Professional post-run checklist

- Confirm run status and inspect every error, skip, and stop condition.
- Read the immutable Assess snapshot before interpreting coverage.
- Inspect exact request and raw response evidence for each candidate finding.
- Confirm deterministic proof, provenance, and reproduction.
- Reject hallucinations, prompt echoes, generic refusals, and unverified action claims.
- Review cleanup and post-cleanup state for every reversible case.
- Separate confirmed, observed, held, inconclusive, not applicable, and not tested.
- Perform human finding disposition and root-cause grouping.
- Record model, catalog, target, and guardrail limitations.
- Export the correct redacted or internal package and verify recipient authorization.
- Back up the completed project according to the engagement retention plan.

## 22. Milestone 5 tester preview

Version 0.9.0 is a public Beta suitable for authorized evaluation and controlled professional pilots. It should not yet be presented as an unrestricted stable production release.

Each preview tester should:

1. use a dedicated encrypted local installation;
2. assess only a synthetic fixture, lab, or system they are explicitly authorized to test;
3. create one project per target and complete the normal GUI workflow;
4. preserve exact run IDs, model roles, configuration, evidence, and screenshots;
5. adjudicate findings and false positives;
6. export a redacted bundle when possible;
7. report defects without secrets, customer data, recovered values, or session material.

The purpose of Milestone 5 is independent field qualification: measure reliability, precision, supported recall, reproduction, model variance, usability, and recovery on systems not authored specifically for AdverScope. A tester finding a missing capability or inconclusive adapter is valuable evidence; it must not be converted into an unsupported security claim.

Use [TESTER_PREVIEW_GUIDE.md](TESTER_PREVIEW_GUIDE.md) for access gates, test procedure, and the feedback package.

## 23. Getting help and reporting defects

Before reporting a defect, collect:

- AdverScope version and build revision;
- operating system and installation method;
- model provider kind, model ID, and assigned role—never the key;
- sanitized target type and adapter;
- run ID and affected case/technique ID;
- expected versus actual behavior;
- redacted evidence bundle or minimal synthetic reproduction;
- whether the problem reproduces after restart.

Follow [SECURITY.md](../SECURITY.md) for suspected AdverScope security vulnerabilities. Preview testers should use the [Tester Preview Guide](TESTER_PREVIEW_GUIDE.md) and its structured sanitized feedback form; coordinators should use the [Preview Coordinator Checklist](TESTER_PREVIEW_COORDINATOR.md). Use the general GitHub issue templates for other ordinary defects and feature requests. Never publish customer target data, private keys, API keys, cookies, recovered proof values, or full internal evidence bundles.
