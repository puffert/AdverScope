# adverscope-mcp-inventory-lifecycle-current-legacy-modern qualification report

- Campaign: `mcp-inventory-lifecycle-qualification-2026-08-09`
- Generated: 2026-08-09T13:45:12+00:00
- Projects: 16
- Gated expectations: 16
- Precision: 1.0
- Recall: 1.0
- Reproduction: 8/8 required expectations

The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.

## Results

| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |
|---|---|---|---|---|---|---|---|---|
| raw-stateless-secure-1 | Approved stateless inventory remains stable after initialization - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_be94d2132532` |
| raw-stateless-secure-2 | Approved stateless inventory remains stable after initialization - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_7530bef4fcc3` |
| raw-stateless-vulnerable-1 | Unapproved stateless inventory drift is detected with notification custody - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_f0a2ca1b5b3f` |
| raw-stateless-vulnerable-2 | Unapproved stateless inventory drift is detected with notification custody - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_c3d3e5bcaba4` |
| raw-streamable-secure-1 | Approved Streamable HTTP inventory remains stable after initialization - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_2715a75e3cdb` |
| raw-streamable-secure-2 | Approved Streamable HTTP inventory remains stable after initialization - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_816c2334f948` |
| raw-streamable-vulnerable-1 | Unapproved Streamable HTTP inventory drift is detected with notification custody - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_a701f487a83d` |
| raw-streamable-vulnerable-2 | Unapproved Streamable HTTP inventory drift is detected with notification custody - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_a513a47fb5ae` |
| raw-legacy-secure-1 | Approved legacy inventory remains stable after initialization - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_9f0600a4f742` |
| raw-legacy-secure-2 | Approved legacy inventory remains stable after initialization - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_149297998038` |
| raw-legacy-vulnerable-1 | Unapproved legacy inventory drift is detected with notification custody - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e297ff976e94` |
| raw-legacy-vulnerable-2 | Unapproved legacy inventory drift is detected with notification custody - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_03d96b4a8e0f` |
| sdk-v2-stateless-secure-1 | Official SDK approved stateless inventory remains stable - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_cc4c8ae5bd2b` |
| sdk-v2-stateless-secure-2 | Official SDK approved stateless inventory remains stable - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_14193ffb6947` |
| sdk-v2-stateless-vulnerable-1 | Official SDK unapproved stateless inventory drift is detected - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_093895ec767c` |
| sdk-v2-stateless-vulnerable-2 | Official SDK unapproved stateless inventory drift is detected - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_8ac6fd545cba` |
