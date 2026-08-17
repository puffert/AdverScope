# AdverScope attack-generation qualification

- Date: 2026-08-08
- Corpus: `adverscope-attack-generation-corpus` version `2026.08.08`
- Required candidate: ASUS-hosted `qwen3.6-27b`
- Repetitions: 3

## Verdict

The required attack-generation candidate passed the initial qualification gate.

- 12/12 corpus executions passed.
- No generation or parsing errors were recorded.
- No scope or safety violations were recorded.
- No cross-run outcome disagreements were recorded.
- Reviewed prompt-injection generation produced 18 unique prompts across 18 requested slots.
- Reviewed sensitive-disclosure generation produced 14 unique prompts across 15 requested slots.
- Novel-technique research produced 9 unique candidates across 9 requested slots without relabelling reviewed catalog techniques.
- Guided planning selected only allow-listed techniques and produced a stable bounded plan in all three repetitions.

The small classifier candidate was declared classification-only and was therefore not evaluated as an attack generator.

## What this establishes

This qualification demonstrates that the configured 27B model can produce schema-valid, materially varied, bounded assessment inputs for the reviewed corpus and can create a stable Guided plan from an explicit allow-list. It also demonstrates that hostile text embedded in the supplied context does not make the generator leave the authorized boundary in this corpus.

## Limits

This is an initial model-and-prompt qualification, not proof of universal attack coverage. It does not establish that every generated payload will trigger every target, that all emerging techniques are represented, or that every model version will behave identically. A model/configuration change requires a new qualification record. Live target recall remains separately measured by the benchmark campaigns.

## Reproduction

Run from the repository root with the local model configuration available:

```powershell
uv run --no-project python scripts\qualify_attack_generation.py `
  --repetitions 3 `
  --output validation\generation-corpus\asus-attack-generation-qualification-2026-08-08.json `
  --require-gates
```

The JSON record contains the candidate metadata, per-run measurements, hashes, and generation traces. It must be handled as assessment evidence because traces can contain security-test payloads.
