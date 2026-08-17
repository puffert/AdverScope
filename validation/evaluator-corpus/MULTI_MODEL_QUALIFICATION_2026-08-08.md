# AdverScope evaluator and multi-model qualification

- Date: 2026-08-08
- Corpus: `adverscope-chatbot-evaluator-corpus` version `2026.08.08`
- Framework: AdverScope `0.8.0` working tree
- Qualification source: `multi-model-qualification-2026-08-08.json`

## Purpose

This qualification measures whether AdverScope's response evaluator preserves target-backed proof, rejects false evidence, and produces stable classifications across repeated local-model runs. It does not measure attack-generation breadth, target vulnerability recall, or GPU efficiency.

The corpus contains 25 synthetic, non-secret cases covering refusals, partial refusals, policy explanations, prompt repetition, hypothetical output, hallucinated and request-originated canaries, exact and reconstructed disclosures, multilingual refusals, structured sensitive output, and unsafe output with and without a verified downstream sink.

## Defect found during qualification

The first pre-fix 27B run produced two false positives and one transient transport error:

- an LLM judge overruled a target-configured digest mismatch;
- an LLM judge overruled request-origin provenance rejection;
- one model connection reset was not retried.

The retained pre-fix report is `pre-fix-failure-qwen3.6-27b-run-1.json`.

The generic fixes were:

- deterministic target-provenance rejection cannot be converted into proof by an LLM opinion;
- an observation that lacks its configured target-side verifier remains inconclusive;
- one bounded retry is permitted for retryable model transport failures, while persistent and client errors remain visible.

No benchmark answer, target route, lab name, recovered proof value, or customer secret was added to production evaluator logic.

## Final repeated qualification

| Candidate | Intended role | Required | Runs | Minimum precision | Minimum recall | Minimum pass rate | Errors | Cross-run disagreements | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `qwen3.6-27b` | Attack generation and evaluation | Yes | 3 | 1.00 | 1.00 | 1.00 | 0 | 0 | Qualified for this evaluator corpus |
| `qwen3-4b-classifier` | Classification candidate | No | 3 | 1.00 | 1.00 | 1.00 | 0 | 0 | Qualified for this evaluator corpus |

The required-candidate gate passed. The optional classifier also passed, but this result does not establish that it can replace the 27B model for creative payload generation, multi-step attack planning, or agentic reasoning.

## Deterministic and regression gates

- Offline corpus: precision `1.00`, recall `1.00`, pass rate `1.00`, zero errors.
- Post-fix 27B smoke: precision `1.00`, recall `1.00`, pass rate `1.00`, zero errors.
- Full regression pass 1: 309 tests and 10 subtests passed.
- Full regression pass 2: 309 tests and 10 subtests passed.
- The RAG regression fixture was separately repeated ten times before the full passes; every repetition passed.

## Reproduction

The candidate manifest intentionally contains no SSH host, username, key, password, or API secret. Connection identity remains local environment configuration.

```powershell
python scripts\evaluate_corpus.py --model-mode offline --require-gates --output validation\evaluator-corpus\offline-qualification-2026-08-08.json
python scripts\qualify_models.py --candidates validation\evaluator-corpus\asus-model-candidates.json --repetitions 3 --output validation\evaluator-corpus\multi-model-qualification-2026-08-08.json --require-gates
uv run --no-project --with pytest pytest -q
```

## Scope and limitations

- These models are qualified only for the versioned evaluator corpus and recorded roles.
- The result is not a claim that all 46 OWASP techniques are professionally qualified.
- Payload diversity, technique-selection variance, adaptive attack quality, target-side reproduction variance, and larger-model cost/performance remain separate M1.7 measurements.
- Deterministic target evidence remains authoritative regardless of model size.
