# adverscope-current-legacy-mcp-authorization-fixtures qualification report

- Campaign: `mcp-authorization-qualification-2026-08-09`
- Generated: 2026-08-09T10:35:40+00:00
- Projects: 8
- Gated expectations: 16
- Precision: 1.0
- Recall: 1.0
- Reproduction: 8/8 required expectations

The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.

## Results

| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |
|---|---|---|---|---|---|---|---|---|
| current-secure-1 | Restricted Streamable HTTP tool authorization remains enforced - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_25972d32c3c2` |
| current-secure-1 | Streamable HTTP service deputy preserves caller authorization - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_25972d32c3c2` |
| current-secure-2 | Restricted Streamable HTTP tool authorization remains enforced - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a990094173d9` |
| current-secure-2 | Streamable HTTP service deputy preserves caller authorization - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a990094173d9` |
| current-vulnerable-1 | Restricted caller receives protected Streamable HTTP tool result - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_a1a909baba38` |
| current-vulnerable-1 | Streamable HTTP deputy applies elevated service authority - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_a1a909baba38` |
| current-vulnerable-2 | Restricted caller receives protected Streamable HTTP tool result - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_856108816cc0` |
| current-vulnerable-2 | Streamable HTTP deputy applies elevated service authority - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_856108816cc0` |
| legacy-secure-1 | Restricted legacy MCP tool authorization remains enforced - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_01bce1709010` |
| legacy-secure-1 | Legacy MCP service deputy preserves caller authorization - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_01bce1709010` |
| legacy-secure-2 | Restricted legacy MCP tool authorization remains enforced - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_c893bb29005e` |
| legacy-secure-2 | Legacy MCP service deputy preserves caller authorization - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_c893bb29005e` |
| legacy-vulnerable-1 | Restricted caller receives protected legacy MCP tool result - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_4c7b9f7119ca` |
| legacy-vulnerable-1 | Legacy MCP deputy applies elevated service authority - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_4c7b9f7119ca` |
| legacy-vulnerable-2 | Restricted caller receives protected legacy MCP tool result - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_8d304ae8b104` |
| legacy-vulnerable-2 | Legacy MCP deputy applies elevated service authority - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_8d304ae8b104` |
