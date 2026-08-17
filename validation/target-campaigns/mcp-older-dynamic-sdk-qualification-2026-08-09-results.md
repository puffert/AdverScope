# adverscope-mcp-older-dynamic-official-python-sdk qualification report

- Campaign: `mcp-older-dynamic-sdk-qualification-2026-08-09`
- Generated: 2026-08-09T15:21:10+00:00
- Projects: 8
- Gated expectations: 8
- Precision: 1.0
- Recall: 1.0
- Reproduction: 4/4 required expectations

The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.

## Results

| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |
|---|---|---|---|---|---|---|---|---|
| sdk-current-secure-1 | Approved SDK inventory remains stable after notification | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_ccdbacc6fe3d` |
| sdk-current-vulnerable-1 | Unapproved SDK inventory drift is detected after notification | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_b2b6e17f130e` |
| sdk-current-secure-2 | Approved SDK inventory remains stable after notification | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_70d6d6fa8eb0` |
| sdk-current-vulnerable-2 | Unapproved SDK inventory drift is detected after notification | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_3faa53f43561` |
| sdk-legacy-secure-1 | Approved legacy SDK inventory remains stable after notification | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_930c69a83c87` |
| sdk-legacy-vulnerable-1 | Unapproved legacy SDK inventory drift is detected after notification | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_66241b7582ad` |
| sdk-legacy-secure-2 | Approved legacy SDK inventory remains stable after notification | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a0755d66b05d` |
| sdk-legacy-vulnerable-2 | Unapproved legacy SDK inventory drift is detected after notification | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_36439c077c5e` |
