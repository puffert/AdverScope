# Model providers and model roles

AdverScope can use one model profile for every model-assisted task or assign different profiles to planning, attack generation, evidence evaluation, and optional adjudication. Profiles belong to the local AdverScope installation, not to a client project. A run records the non-secret profile ID, provider kind, model identifier, role, parameters, and professional-qualification state that were used.

The model provider is not the target adapter. Provider profiles tell AdverScope where its own planning and evaluation models run. The Attack Surface still defines the authorized target, request schema, identities, capabilities, guardrails, proof rules, and permitted effects.

## Role model

| Role | Purpose | Required | Recommended trust boundary |
| --- | --- | --- | --- |
| Planner | Proposes a bounded Guided assessment plan from the reviewed catalog | Yes | Local or engagement-approved remote model |
| Generator | Creates additional attack wording and adaptive follow-up candidates | Yes | Local is preferred when target data is sensitive |
| Evaluator | Classifies ambiguous retained responses; deterministic proof remains authoritative | Yes | Use a pinned, separately qualified model |
| Adjudicator | Optional second opinion for evaluator disagreement | No | Prefer a different qualified model family when independence matters |

Role separation is useful for quality and cost control, but it is not mandatory. A single local profile can fill all required roles. AdverScope will not save a configuration with a missing planner, generator, or evaluator.

## Configure profiles in the GUI

1. Select the model indicator at the top right.
2. Select an existing profile or choose **New named profile**.
3. Enter a stable lowercase profile ID, a readable name, provider kind, model, and endpoint where applicable.
4. For a remote profile, enter an environment-variable name or provide a temporary session key. Never put a key value in the environment-variable field.
5. Assign the planner, generator, evaluator, and optional adjudicator roles.
6. Save the profile and roles, then select **Verify connection**.

The connection result is process-local. It proves endpoint reachability, authentication, and model inventory only. It does not qualify the model for professional planning or findings evaluation.

## Supported provider kinds

| Kind | Endpoint behavior | Credential behavior |
| --- | --- | --- |
| Local OpenAI-compatible | Operator-supplied HTTP or HTTPS base ending at the compatible `/v1` API; optional configured SSH tunnel | No API-key header is sent; expose an unauthenticated loopback endpoint or use a separately approved local gateway design |
| OpenAI API | Fixed official `https://api.openai.com/v1` endpoint; model remains operator-selectable | `OPENAI_API_KEY` by default or a memory-only session key |
| Z.AI API | Fixed official `https://api.z.ai/api/paas/v4` endpoint; model remains operator-selectable | `ZAI_API_KEY` by default or a memory-only session key |
| Approved remote OpenAI-compatible | Operator-supplied HTTPS endpoint | Named environment variable or memory-only session key required |

Remote URLs must use HTTPS and may not contain embedded credentials, query parameters, or fragments. Official provider URLs cannot be overridden through a profile. Local profiles can opt into the SSH tunnel configured by `adverscope init` or the compatibility launcher; profile management never accepts or reads a private-key path.

## Required OpenAI-compatible surface

AdverScope currently expects:

- `GET {base_url}/models` for connection and model-inventory checks;
- `POST {base_url}/chat/completions` with a Chat Completions-style `messages` array;
- a normal `choices[0].message.content` result;
- JSON object response mode when available, with an automatic prompt-only fallback only when that profile explicitly rejects `response_format`.

The optional **disable thinking** compatibility flag adds `chat_template_kwargs.enable_thinking=false`. Enable it only when the selected local server and model template support that request field.

## Local runtime examples

These examples describe protocol configuration, not installation or security endorsement. Bind the runtime to loopback unless a separately protected network service is intentionally required.

### Ollama

Ollama documents an OpenAI-compatible API and uses a base such as:

```text
http://127.0.0.1:11434/v1
```

Use the exact model identifier returned by `/v1/models`. See the [Ollama OpenAI compatibility reference](https://docs.ollama.com/api/openai-compatibility).

### llama.cpp server

Use the server's OpenAI-compatible `/v1` base, commonly:

```text
http://127.0.0.1:8080/v1
```

The selected model must have a usable chat template. See the [llama.cpp server reference](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).

### vLLM

Point the profile at the `/v1` base exposed by the vLLM OpenAI-compatible server. The model name must match the served model name, and chat requests require a compatible chat template. See the [vLLM OpenAI-compatible server reference](https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/).

### Other compatible servers

Create a **Local OpenAI-compatible** profile for a loopback or configured SSH-tunnel endpoint. Use **Approved remote OpenAI-compatible** only for an HTTPS service whose processing, retention, region, and account controls are approved for the engagement.

## Command-line management

List the current profiles and assignments:

```text
adverscope profiles list
```

Add a local planner profile and assign roles:

```text
adverscope profiles add planner-local --label "Planner local" --kind local-openai-compatible --base-url http://127.0.0.1:11434/v1 --model approved-planner-model
adverscope profiles roles --planner planner-local --generator local --evaluator local --adjudicator none
```

Add an approved remote evaluator without supplying a secret value on the command line:

```text
adverscope profiles add evaluation-api --label "Approved evaluator" --kind remote-openai-compatible --base-url https://models.example.invalid/v1 --model approved-evaluator --api-key-env ADVERSCOPE_EVALUATOR_KEY
adverscope profiles roles --evaluator evaluation-api
```

Official OpenAI and Z.AI profiles use fixed endpoints, so `--base-url` is optional for those kinds:

```text
adverscope profiles add openai-evaluator --label "OpenAI evaluator" --kind openai --model approved-model --api-key-env OPENAI_API_KEY
```

Verify connectivity or remove an unassigned custom profile:

```text
adverscope profiles test planner-local
adverscope profiles remove planner-local
```

Use `--config PATH` immediately after `profiles` when managing a non-default installation.

## Secret and data-transfer rules

- Persistent configuration stores only an environment-variable name, never the value.
- A GUI session key is held in process memory, is never returned to the browser, and disappears when AdverScope stops.
- Provider URLs containing usernames or passwords are rejected.
- Keys are excluded from SQLite, project documents, evidence, model traces, telemetry, reports, logs, and profile API responses.
- A remote role receives the assessment context needed for that role. This can include objectives, policy text, generated prompts, and target responses. The engagement must explicitly permit that transfer.
- Provider and role changes are blocked while a background assessment or Testing Tool execution is active.

## Connection versus professional qualification

**Connection verified** means AdverScope reached the endpoint, authenticated where needed, and found the configured model in its inventory. It does not establish that the model is accurate, secure against evidence poisoning, sufficiently reproducible, or suitable for a professional finding.

Professional qualification requires retained repeated campaigns against independent secure and vulnerable fixtures. At minimum, qualify each role/model/version combination for false-positive rate, supported recall, reproduction stability, transport-fault behavior, and cross-run variance. Pin the model identifier and provider configuration for a benchmark. Deterministic proof, exact target evidence, reproduction, and human review remain the finding gate regardless of model choice.

## Upgrading an existing provider file

AdverScope reads the legacy single-provider schema without rewriting it. The GUI and CLI expose a migration warning. The next explicit provider or role update writes schema `2.0`, maps the old selection to the three required roles, and keeps API-key values absent. Back up the local state directory before any application upgrade even though this profile migration is additive.

## Troubleshooting

- **Configured model is absent:** compare the exact profile model ID with `GET /v1/models`.
- **Chat request fails but inventory works:** verify the model has a chat template and accepts Chat Completions requests.
- **Structured output was rejected:** AdverScope falls back per profile only for an explicit `response_format` compatibility rejection; network and model failures remain failures.
- **Remote profile is not ready:** set the named environment variable before starting AdverScope or enter a temporary session key in the GUI.
- **SSH local port is occupied:** stop the unrelated listener or choose a different configured local tunnel port. AdverScope will not take over an unknown process.
- **Connection verified but qualification still says not established:** this is intentional; run and retain the evaluator/provider qualification corpus before relying on that role professionally.
