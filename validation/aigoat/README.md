# AI Goat qualification

This directory keeps three concerns separate:

- `campaign-*.json` selects existing AdverScope project, assessment-run, and Testing Tool execution IDs. It contains no expected result.
- `oracle.json` describes expected vulnerable and secure outcomes plus the names of already configured AdverScope objectives, stable reviewed variants, or Testing Tool outcome IDs that can prove them. It contains no endpoint, payload, response, credential, pattern, or proof value.
- Generated JSON and Markdown reports compare the two only after execution. Oracle content is never sent to AdverScope planning, generation, target requests, or autonomous evaluation.

Benchmark proof objectives remain visible but are not professional release gates. A vulnerability expectation is confirmed only by retained finding-grade evidence and, when required, successful reproduction. An observed but unreproduced result is inconclusive and lowers supported recall.

Validate the separation:

```text
python scripts/benchmark_validation.py validate --campaign validation/aigoat/campaign-m1.1-pre-fix-2026-08-06.json --oracle validation/aigoat/oracle.json
```

Score without modifying AdverScope:

```text
python scripts/benchmark_validation.py score --api http://127.0.0.1:8091 --campaign validation/aigoat/campaign-m1.1-pre-fix-2026-08-06.json --oracle validation/aigoat/oracle.json
```

Use `--record-adjudications` only after reviewing the selected immutable executions. It writes safe post-run oracle classifications through AdverScope's public API so they appear in Assessment Results. Use `--require-gates` to require at least `0.95` precision, `0.95` supported recall, zero infrastructure errors, and zero inconclusive gated expectations.

## Pinned Windows qualification runtime

The upstream Docker entrypoint is stored with Windows-style carriage returns in
the pinned benchmark commit. On Docker Desktop, start it with the qualification
override so the shell receives the same script text with transport-only line
ending normalization. The override changes neither benchmark source nor target
behavior:

```powershell
docker compose `
  -f <AIGoat checkout>/docker/docker-compose.yml `
  -f validation/aigoat/docker-compose.windows-qualification.yml `
  up -d backend
```
