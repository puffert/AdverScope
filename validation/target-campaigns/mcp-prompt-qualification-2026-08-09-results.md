# adverscope-mcp-prompt-current-legacy-raw-sdk qualification report

- Campaign: `mcp-prompt-qualification-2026-08-09`
- Generated: 2026-08-09T15:21:11+00:00
- Projects: 16
- Gated expectations: 32
- Precision: 1.0
- Recall: 1.0
- Reproduction: 16/16 required expectations

The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.

## Results

| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |
|---|---|---|---|---|---|---|---|---|
| raw-current-secure-1 | Protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a7da90c3464d` |
| raw-current-secure-1 | Protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a7da90c3464d` |
| raw-current-vulnerable-1 | Protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_9ac0c0f83ea7` |
| raw-current-vulnerable-1 | Protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_9ac0c0f83ea7` |
| raw-current-secure-2 | Protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_14f133b266d6` |
| raw-current-secure-2 | Protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_14f133b266d6` |
| raw-current-vulnerable-2 | Protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e6b6ba1d8361` |
| raw-current-vulnerable-2 | Protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e6b6ba1d8361` |
| raw-legacy-secure-1 | Protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_ec8426bcb1ca` |
| raw-legacy-secure-1 | Protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_ec8426bcb1ca` |
| raw-legacy-vulnerable-1 | Protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_8205442dbb05` |
| raw-legacy-vulnerable-1 | Protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_8205442dbb05` |
| raw-legacy-secure-2 | Protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_f0f49dee07f4` |
| raw-legacy-secure-2 | Protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_f0f49dee07f4` |
| raw-legacy-vulnerable-2 | Protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_d0d5e55481f7` |
| raw-legacy-vulnerable-2 | Protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_d0d5e55481f7` |
| sdk-current-secure-1 | SDK protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_7a7597e38ca7` |
| sdk-current-secure-1 | SDK protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_7a7597e38ca7` |
| sdk-current-vulnerable-1 | SDK protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_5beab7d580f8` |
| sdk-current-vulnerable-1 | SDK protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_5beab7d580f8` |
| sdk-current-secure-2 | SDK protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_adf5abaf4b42` |
| sdk-current-secure-2 | SDK protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_adf5abaf4b42` |
| sdk-current-vulnerable-2 | SDK protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_a94319a0bd71` |
| sdk-current-vulnerable-2 | SDK protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_a94319a0bd71` |
| sdk-legacy-secure-1 | SDK protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_cf7f606d4849` |
| sdk-legacy-secure-1 | SDK protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_cf7f606d4849` |
| sdk-legacy-vulnerable-1 | SDK protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_c8952a5321c6` |
| sdk-legacy-vulnerable-1 | SDK protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_c8952a5321c6` |
| sdk-legacy-secure-2 | SDK protected prompt is absent from restricted inventory | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_570c077e9299` |
| sdk-legacy-secure-2 | SDK protected prompt retrieval is denied | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_570c077e9299` |
| sdk-legacy-vulnerable-2 | SDK protected prompt is advertised to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_24e6a227d3b1` |
| sdk-legacy-vulnerable-2 | SDK protected prompt is returned to a restricted identity | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_24e6a227d3b1` |
