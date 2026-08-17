# Responsible use and supported scope

AdverScope is for authorized security assessment of AI systems. It helps a qualified tester establish and reproduce vulnerabilities; it does not grant authorization, replace professional judgment, or make an automated result a final pentest conclusion.

## Required authorization

Before sending target traffic, the operator must have written authority that identifies the systems, routes, methods, identities, time window, request limits, permitted effects, prohibited actions, stop conditions, evidence handling, and retention requirements. The saved Attack Surface and approved execution guardrail are the executable boundary.

Authorization for one origin does not authorize adjacent hosts, redirects, third-party callbacks, cloud resources, user accounts, MCP servers, tools, or data stores. A model may select only reviewed techniques inside the configured boundary.

## Safe defaults

AdverScope defaults to local loopback use, non-destructive validation, bounded request and time budgets, stop conditions, explicit target mappings, redacted logging, and human review. State-changing verification requires a specifically authorized, reversible contract with cleanup and a verifier. Destructive exploitation remains a manual decision outside ordinary automated assessment.

## Prohibited use

Do not use AdverScope to access systems without permission; discover or exploit out-of-scope systems; obtain real secrets or personal data without an approved handling plan; cause denial of service; bypass account controls for unrelated purposes; deploy malware; or conceal activity from the system owner.

## Result interpretation

“Vulnerable” requires target-originated evidence that satisfies the configured proof contract and, when required, controlled reproduction. “Safe” applies only to the exact executed technique and conditions. Unsupported, skipped, stopped, errored, inconclusive, and not-tested states must remain visible. OWASP coverage is a mapping of executed evidence, not a certification.

Users are responsible for applicable law, contractual restrictions, professional standards, data protection, customer communication, and final reporting.
