# PortSwigger Web LLM qualification

The folder contains two intentionally separate tracks:

- `PORTSWIGGER_TARGET_APP_QUALIFICATION_2026-08-08.md` qualifies AdverScope against vulnerable LLM integrations.
- `SCANNER_RESILIENCE_QUALIFICATION_2026-08-08.md` qualifies AdverScope itself against controlled hostile-content fixtures derived from the AI-powered scanner threat model.

This directory keeps the live campaign, isolated post-run oracle, generated qualification reports, and the dated official inventory separate.

- `inventory-2026-08-06.json` records the visible official lab inventory at campaign start.
- `campaign-target-apps-2026-08-08.json` selects only retained AdverScope project and run IDs. It contains no expected result or target secret.
- `oracle-target-apps.json` contains only expected security and secure-control outcomes. It contains no ephemeral instance URL, payload, route argument, response, credential, proof value, or solution step.
- Generated reports compare the two only after all GUI executions are immutable.

The target-application campaign covers the four current PortSwigger Web LLM labs where the vulnerable LLM integration is the assessment target. The four AI-powered scanner labs are a separate scanner-resilience qualification track. They do not extend the target-application denominator and do not need destructive external execution: equivalent hostile-content fixtures must prove that AdverScope cannot be redirected, induced to disclose local data, or made to expand scope.

Validate oracle separation:

```text
python scripts/benchmark_validation.py validate --campaign validation/portswigger/campaign-target-apps-2026-08-08.json --oracle validation/portswigger/oracle-target-apps.json
```

Score the immutable GUI runs without modifying AdverScope:

```text
python scripts/benchmark_validation.py score --api http://127.0.0.1:8094 --campaign validation/portswigger/campaign-target-apps-2026-08-08.json --oracle validation/portswigger/oracle-target-apps.json --require-gates --json-output validation/portswigger/qualification-target-apps-2026-08-08.json --markdown-output validation/portswigger/qualification-target-apps-2026-08-08.md
```

Consequential one-time Academy completion effects are accepted without automatic replay only when the selected project explicitly authorizes that disposable action and retains deterministic target-owned proof. Reproducible indirect-injection and unsafe-output effects require a separate run-scoped confirmation.
