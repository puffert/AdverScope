# AdverScope 8B motor dataset

This directory defines the reproducible data pipeline for a small, specialized model that can serve AdverScope's model-assisted roles. It does not contain raw downloaded data, generated training examples, customer evidence, credentials, benchmark answers, or model weights.

The first release is a supervised fine-tuning bootstrap. It teaches the exact JSON contracts used by AdverScope for:

- Guided assessment planning;
- reviewed attack generation;
- operator-objective attack generation;
- response evaluation;
- untrusted-content triage.

Adaptive multi-turn follow-up is deliberately not synthesized from unrelated prompt lists. That role remains open until accepted, non-benchmark AdverScope trajectories can be reviewed and imported.

## Safety and qualification boundary

Training a model and qualifying a security tool are different activities.

- Public training sources are license-reviewed, revision-pinned, normalized, sanitized, and attributed.
- Target families stay together in one split to prevent train/test leakage.
- Reserved benchmarks never enter training data.
- A generated corpus must pass automated quality gates and then human review.
- Fine-tuning success does not establish professional recall, precision, evidence quality, or safe autonomous operation.
- The tuned model must be tested on frozen, independent targets and compared with the existing 27B baseline before it can be selected in AdverScope.

PortSwigger Web Security Academy, private internal qualification suites, AI Goat, AgentDojo, BIPIA, JailbreakBench, Tensor Trust, CyberSecEval, and any future qualification family are reserved for evaluation unless an explicit new policy partitions a non-overlapping training release. Benchmark solutions, flags, protected values, and customer evidence must never be added to training.

## Source policy

[`public-sources-v1.json`](public-sources-v1.json) is the authoritative source registry. Every source records its intended use, adapter, pinned revision, license, provenance, and download policy.

The pilot selects:

| Source | Use in the motor | License | Quality |
|---|---|---|---|
| AdverScope reviewed catalog | Exact generator contract and framework-reviewed probes | Apache-2.0 | Gold |
| Anthropic HH red-team attempts | Human-authored objective probes and balanced, single-turn response-evaluator labels from rating extremes | MIT | Silver |
| deepset prompt injections | Prompt-injection triage positives and hard negatives | Apache-2.0 | Silver |
| InjecAgent | Indirect-injection planning and synthetic tool-boundary generation | MIT | Silver |

WildJailbreak is registered but not selected because access requires separately accepting its responsible-use terms. Tensor Trust, BIPIA, AgentDojo, JailbreakBench, and CyberSecEval are explicitly benchmark-only.

## Build the pilot

Run these commands from the repository root:

```powershell
uv run python scripts/build_motor_dataset.py sources
uv run python scripts/build_motor_dataset.py download
uv run python scripts/build_motor_dataset.py build
uv run python scripts/build_motor_dataset.py validate --dataset-id adverscope-8b-motor
```

Or download and build in one command:

```powershell
uv run python scripts/build_motor_dataset.py build --download
```

Raw sources and generated datasets are written below `data/training/`, which is excluded from Git. The build never prints record content. Remote files are accepted only from pinned HTTPS locations and, where direct files are used, only after exact SHA-256 verification.

The default output is:

```text
data/training/adverscope-8b-motor-v0.1/
├── manifest.json
├── quality-report.json
├── DATASET_CARD.md
├── corpus/
│   └── records.jsonl
├── sft/
│   ├── train.jsonl
│   ├── validation.jsonl
│   └── test.jsonl
├── review/
│   └── review-queue.jsonl
└── provenance/
    ├── source-registry.json
    └── build-config.json
```

The output also contains `provenance/source-registry.json` and `provenance/build-config.json` with the exact non-secret licensing, benchmark, split, and quality policy used for the build.

`manifest.json` pins every generated file and every pipeline source by SHA-256. `validate` fails on altered or undeclared content, invalid schemas, duplicate record IDs, missing files, provenance drift, benchmark contamination, or a target family crossing splits.

## Training format

Each SFT row is trainer-neutral chat data:

```json
{
  "id": "motor_<stable-id>",
  "messages": [
    {"role": "system", "content": "<AdverScope role contract>"},
    {"role": "user", "content": "<bounded assessment data>"},
    {"role": "assistant", "content": "<strict JSON completion>"}
  ],
  "metadata": {
    "task": "guided-planning",
    "risk_ids": ["LLM01"],
    "technique_ids": ["LLM01-INDIRECT"],
    "quality_tier": "silver",
    "hard_negative": false,
    "source_id": "injecagent",
    "source_record_id": "<source identity>",
    "license_spdx": "MIT",
    "split_group_sha256": "<family identity>"
  }
}
```

The `messages` field works with chat-template SFT loaders such as TRL or Axolotl after selecting a compatible base model. Metadata supports task-balanced sampling, gold-record weighting, error analysis, and source/license attribution without putting those fields into the model prompt.

The pipeline enforces a 12,000-character record ceiling, but characters are not model tokens. After choosing the exact 8B base model, audit all three splits with that model's tokenizer and chat template. Training must stop if examples are silently truncated, the base model has no valid chat template, or its license is incompatible with AdverScope's intended distribution.

## Model Lab workflow

Start AdverScope normally and open **06 Model lab**. This is an installation-scoped development workspace. Its review data, accepted trajectories, datasets, and experiments live below the configured `training_root`; none of them are attached to the currently selected client project.

The workspace implements three explicit gates:

1. **Review the generated sample queue.** Inspect the exact system, user, and assistant contract; verify the technique labels and hard-negative state; then accept, correct, or reject the record.
2. **Add accepted non-benchmark trajectories.** Retain sanitized real AdverScope behavior from authorized synthetic or independent targets. At least one accepted operator trajectory must be present in the canonical reviewed corpus.
3. **Create a reviewed release and experiment.** After the queue is complete, run the exact rebuild command shown in the GUI. If trajectories are added afterward, run the guarded update command that reappears in the GUI. Only a reviewed release that actually contains an operator trajectory may be selected for a tokenizer audit or QLoRA experiment.

Review decisions are append-only, integrity chained, timestamped, version checked, and bound to the source dataset manifest hash. Editing a source release after review prevents the overlay from being reused. Review decisions in a reviewed release are read-only. A later accepted operator trajectory can be added only through the guarded extension path: registry and configuration must be unchanged, all existing non-operator records and prior traces must be preserved, and promotion is atomic.

Rejected examples never enter the canonical corpus or SFT splits, but their exact reviewed records and rejection reasons remain in the read-only audit queue. The queue therefore continues to account for every sampled disposition after release creation.

Creating an experiment in the GUI only writes a non-secret, reproducible configuration. It does **not** install packages, download a model, or start training.

## Human review

The generated review queue samples every source/task combination. For each record the reviewer must confirm:

1. the prompt remains inside the stated synthetic or policy boundary;
2. the assistant output follows the exact AdverScope JSON contract;
3. technique and OWASP labels are supported by the source;
4. safe responses and exclusions are not mislabeled as vulnerabilities;
5. no personal data, credential, proof value, benchmark answer, or target-specific solution remains;
6. the record is useful rather than a cosmetic duplicate.

Use **Accept as-is** only when the completion and labels are already correct. Use **Save correction** for a useful record with an incorrect completion, technique mapping, or hard-negative label. Use **Reject** when the record cannot be made reliable from its available evidence. A stale browser version cannot overwrite a newer decision.

Response-evaluation gold labels require two independent reviewers. The first acceptance or correction moves the record to `second-review`; a different reviewer must independently accept or correct it before `gold_ready` becomes true. Generation, planning, and triage records require one reviewer.

Do not mark the generated pilot production-ready merely by completing the sampled queue. Accepted corrections and real AdverScope traces are separate requirements. The GUI stores accepted traces in the registered `adverscope-operator-reviewed` source with a non-benchmark `target_family`, explicit accepted review, and its own source manifest. The adapter rejects unreviewed rows and reserved benchmark families.

Every accepted operator row must include a non-secret reviewer ID, a timezone-qualified ISO review timestamp, and all four review checks set to `true`:

```json
{
  "review": {
    "status": "accepted",
    "reviewer_id": "team-reviewer-01",
    "reviewed_at": "2026-08-14T12:00:00Z",
    "scope_correct": true,
    "output_contract_correct": true,
    "label_correct": true,
    "safe_for_training": true
  }
}
```

Prioritize real trajectories that public prompt collections do not provide:

- adaptive follow-ups after a refusal, partial response, or new target observation;
- false-positive evaluator cases and explicit refusal handling;
- secure/vulnerable pairs using the same proof rule;
- grounded tool, API, MCP, RAG, and interface decisions;
- multilingual, encoding, and spacing variants;
- recovery from an out-of-policy plan without expanding scope.

When the queue is complete, use the GUI's exact overlay path:

```powershell
uv run python scripts/build_motor_dataset.py build --review-overlay "<review-overlay.json>"
```

The build fails closed if the overlay does not belong to the current source manifest, if any sampled record lacks a final disposition, if an evaluator acceptance lacks independent second review, or if an accepted source record is missing or changed.

## Tokenizer audit and QLoRA experiment

Choose an instruction-tuned base model whose license permits the intended internal and open-source use. For a Hugging Face model, record its immutable 40-character commit revision; mutable branches such as `main` are rejected. Remote model code is disabled.

After creating the experiment in Model Lab, use its displayed paths and run:

```powershell
uv sync --extra training
uv run --extra training python scripts/run_motor_experiment.py doctor
uv run --extra training python scripts/run_motor_experiment.py audit --experiment "<experiment.json>"
uv run --extra training python scripts/run_motor_experiment.py status --experiment "<experiment.json>"
```

The audit applies the selected tokenizer's real chat template to every canonical record, fingerprints the tokenizer and template, records length distributions by task and split, and fails on any configured overflow. There is no silent truncation allowance in the first recipe.

Only after reading and accepting the audit result should an operator deliberately start the expensive step:

```powershell
uv run --extra training python scripts/run_motor_experiment.py train --experiment "<experiment.json>"
```

The default recipe is four-bit NF4 QLoRA with double quantization, `all-linear` adapters, rank 32, alpha 64, dropout 0.05, completion-only loss, deterministic data and training seeds, no Hub push, and no remote model code. It requires CUDA and records dependency versions, device identity, metrics, duration, dataset and audit hashes, adapter files, and checksums. The resulting status is `completed-unqualified`.

Serve the adapter as a separate AdverScope model profile and generate repeated frozen-corpus reports for both the candidate and retained 27B baseline. Then compare them:

```powershell
uv run --extra training python scripts/run_motor_experiment.py compare `
  --experiment "<experiment.json>" `
  --baseline-attack "<27b-attack-report.json>" `
  --candidate-attack "<8b-attack-report.json>" `
  --baseline-evaluator "<27b-evaluator-report.json>" `
  --candidate-evaluator "<8b-evaluator-report.json>" `
  --require-gates
```

The comparison checks repeated attack quality, evaluator precision and recall, pass rates, errors, safety violations, latency, and regression against the retained baseline. Qualification is role-specific: a candidate may replace only the roles whose independent gates pass.

## Recommended first fine-tune

Use QLoRA or LoRA for the first 8B experiment rather than a full-parameter tune. Keep the model's normal chat template, use low learning rates, and compare checkpoints on the validation split. Because the pilot is intentionally multi-task and imbalanced, use `metadata.task` to prevent the large objective-generation and evaluator groups from drowning the smaller framework-reviewed attack catalog. Keep task sampling and quality weighting in the training recipe, not by duplicating rows in the canonical corpus.

Do not optimize against the held-out qualification suites while training. Select the checkpoint using the source-family validation split, then run blind qualification against reserved secure/vulnerable targets. Compare at minimum:

- schema-valid output rate;
- scope and boundary violations;
- attack diversity and supported recall;
- evaluator precision, recall, and refusal false positives;
- grounded tool/interface use;
- repeatability across seeds;
- latency, token use, memory, and throughput;
- end-to-end AdverScope finding reproduction.

The 8B motor replaces the current 27B model only if it meets or exceeds the role-specific qualification gates while being materially faster. Size alone is not evidence of quality.

## Current pilot result

The original 2026-08-14 pilot produced 6,108 records from four sources. Human review then produced a validated 6,106-record release with 5,543 train, 290 validation, and 273 test records, 122 gold records, and 1,346 hard negatives. All 48 sampled records have final dispositions: 39 accepted, seven corrected, and two rejected. All automated provenance, balance, split, role-split, size, secret-scan, review-overlay, and integrity gates pass.

The reviewed release currently contains zero accepted real AdverScope trajectories. M6.1 therefore remains open, and experiment creation correctly stays blocked. Base-model selection, tokenizer audit, training, and multi-model qualification have not been started or marked complete.
