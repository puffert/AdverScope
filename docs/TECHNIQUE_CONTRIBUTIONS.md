# Attack catalog and assessment recipe contributions

A technique contribution must improve general AI-system assessment. It must not hard-code a training-lab solution, customer endpoint, recovered secret, account, file path, prompt answer, or benchmark oracle.

## Required definition

Provide a stable technique ID, title, OWASP risk mapping, capability prerequisites, safe description, payload family, expected secure behavior, possible vulnerable behavior, false-positive exclusions, required evidence, reproduction policy, request budget, stop behavior, and source/research provenance.

Model-generated variants must remain descendants of a reviewed family and may only use the saved target map, policy, objectives, and allowed technique IDs. They cannot add routes, methods, identities, permissions, tools, or effects.

## Qualification evidence

Each verdict-affecting technique or recipe requires:

- at least one independent vulnerable fixture with target-originated proof;
- at least one independent secure fixture;
- refusal, echo, hallucination, malformed response, transport fault, and inconclusive controls where applicable;
- exact request/response and reproduction assertions;
- false-positive and false-negative expectations;
- benchmark separation so the planner/generator does not receive the solution or expected proof;
- repeated qualification when behavior is stochastic;
- evaluation with every model role claimed as supported.

Fixtures should test the security property, not merely a flag. A benchmark completion token may support comparison but is not the sole professional finding requirement.

## Review rules

Changes that lower evidence requirements, turn model opinion into deterministic proof, mark untested coverage as safe, bypass scope gates, or suppress unsupported/error states are rejected. Catalog and recipe versions must be updated through the authoritative release module when persisted or report-visible behavior changes.
