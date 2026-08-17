# adverscope-independent-current-legacy-mcp-inventory-fixtures qualification report

- Campaign: `mcp-inventory-qualification-2026-08-09`
- Generated: 2026-08-09T12:25:50+00:00
- Projects: 16
- Gated expectations: 16
- Precision: 1.0
- Recall: 1.0
- Reproduction: 8/8 required expectations

The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.

## Results

| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |
|---|---|---|---|---|---|---|---|---|
| native-current-secure-1 | AdverScope raw-protocol Streamable HTTP approved inventory remains exact - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_6e2b0bccc8e6` |
| native-current-secure-2 | AdverScope raw-protocol Streamable HTTP approved inventory remains exact - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_d7ed4990d036` |
| native-current-vulnerable-1 | AdverScope raw-protocol Streamable HTTP inventory drift is confirmed - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_59ddc5b29912` |
| native-current-vulnerable-2 | AdverScope raw-protocol Streamable HTTP inventory drift is confirmed - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e304182b96de` |
| native-legacy-secure-1 | AdverScope raw-protocol legacy HTTP+SSE approved inventory remains exact - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_64fb962e71f7` |
| native-legacy-secure-2 | AdverScope raw-protocol legacy HTTP+SSE approved inventory remains exact - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_6aef8815e866` |
| native-legacy-vulnerable-1 | AdverScope raw-protocol legacy HTTP+SSE inventory drift is confirmed - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_33967b384238` |
| native-legacy-vulnerable-2 | AdverScope raw-protocol legacy HTTP+SSE inventory drift is confirmed - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_7705f63cd72b` |
| sdk-current-secure-1 | Official MCP Python SDK 1.25 Streamable HTTP approved inventory remains exact - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_e732e67bb925` |
| sdk-current-secure-2 | Official MCP Python SDK 1.25 Streamable HTTP approved inventory remains exact - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_54f856f2ca5a` |
| sdk-current-vulnerable-1 | Official MCP Python SDK 1.25 Streamable HTTP inventory drift is confirmed - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e59b048ee2cd` |
| sdk-current-vulnerable-2 | Official MCP Python SDK 1.25 Streamable HTTP inventory drift is confirmed - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_f7c17f75e969` |
| sdk-legacy-secure-1 | Official MCP Python SDK 1.25 legacy HTTP+SSE approved inventory remains exact - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_783cdf27be7b` |
| sdk-legacy-secure-2 | Official MCP Python SDK 1.25 legacy HTTP+SSE approved inventory remains exact - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_260bf50cffeb` |
| sdk-legacy-vulnerable-1 | Official MCP Python SDK 1.25 legacy HTTP+SSE inventory drift is confirmed - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_8ec133f4635a` |
| sdk-legacy-vulnerable-2 | Official MCP Python SDK 1.25 legacy HTTP+SSE inventory drift is confirmed - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_7bf8d7d7a07d` |
