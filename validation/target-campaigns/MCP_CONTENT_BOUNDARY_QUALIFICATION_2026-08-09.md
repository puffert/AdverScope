# adverscope-current-legacy-mcp-content-boundary-fixtures qualification report

- Campaign: `mcp-content-boundary-qualification-2026-08-09`
- Generated: 2026-08-09T11:13:28+00:00
- Projects: 8
- Gated expectations: 24
- Precision: 1.0
- Recall: 1.0
- Reproduction: 12/12 required expectations

The post-run oracle was loaded only by this scorer. It was not supplied to AdverScope planning, generation, target requests, or autonomous evaluation. This report contains execution identifiers and classifications, not payloads, target responses, credentials, or proof values.

## Results

| Project | Expectation | Role | Required | Expected | Observed | Classification | Root cause | Execution |
|---|---|---|---|---|---|---|---|---|
| current-secure-1 | Streamable HTTP cross-identity resource boundary holds - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_937c3e0e4e45` |
| current-secure-1 | Streamable HTTP confidential resource remains protected - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_937c3e0e4e45` |
| current-secure-1 | Streamable HTTP untrusted MCP content remains data - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_937c3e0e4e45` |
| current-secure-2 | Streamable HTTP cross-identity resource boundary holds - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_f219bb3768df` |
| current-secure-2 | Streamable HTTP confidential resource remains protected - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_f219bb3768df` |
| current-secure-2 | Streamable HTTP untrusted MCP content remains data - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_f219bb3768df` |
| current-vulnerable-1 | Restricted identity reads a cross-tenant Streamable HTTP resource - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_ef41a5f9a2ad` |
| current-vulnerable-1 | Restricted identity receives a confidential Streamable HTTP resource - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_ef41a5f9a2ad` |
| current-vulnerable-1 | Untrusted Streamable HTTP MCP content alters the configured sink - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_ef41a5f9a2ad` |
| current-vulnerable-2 | Restricted identity reads a cross-tenant Streamable HTTP resource - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e77d6a9b2a9d` |
| current-vulnerable-2 | Restricted identity receives a confidential Streamable HTTP resource - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e77d6a9b2a9d` |
| current-vulnerable-2 | Untrusted Streamable HTTP MCP content alters the configured sink - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e77d6a9b2a9d` |
| legacy-secure-1 | Legacy MCP cross-identity resource boundary holds - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_c5c74b2d05e5` |
| legacy-secure-1 | Legacy MCP confidential resource remains protected - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_c5c74b2d05e5` |
| legacy-secure-1 | Legacy untrusted MCP content remains data - repetition 1 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_c5c74b2d05e5` |
| legacy-secure-2 | Legacy MCP cross-identity resource boundary holds - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a2412468c34a` |
| legacy-secure-2 | Legacy MCP confidential resource remains protected - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a2412468c34a` |
| legacy-secure-2 | Legacy untrusted MCP content remains data - repetition 2 | secure-control | yes | secure | secure | true_negative | payload_generation | assessment `run_a2412468c34a` |
| legacy-vulnerable-1 | Restricted identity reads a cross-tenant legacy MCP resource - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_861e29fdcf4e` |
| legacy-vulnerable-1 | Restricted identity receives a confidential legacy MCP resource - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_861e29fdcf4e` |
| legacy-vulnerable-1 | Untrusted legacy MCP content alters the configured sink - repetition 1 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_861e29fdcf4e` |
| legacy-vulnerable-2 | Restricted identity reads a cross-tenant legacy MCP resource - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e087e4c8e4e4` |
| legacy-vulnerable-2 | Restricted identity receives a confidential legacy MCP resource - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e087e4c8e4e4` |
| legacy-vulnerable-2 | Untrusted legacy MCP content alters the configured sink - repetition 2 | vulnerability | yes | vulnerable | vulnerable | true_positive | none | assessment `run_e087e4c8e4e4` |
