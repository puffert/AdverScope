# Security policy

AdverScope is an authorized security-testing tool. Use it only against systems covered by an explicit scope and rules of engagement.

## Reporting a vulnerability

Report AdverScope vulnerabilities through a [private GitHub security advisory](https://github.com/puffert/AdverScope/security/advisories/new). Do not open a public issue containing exploit details, credentials, private client data, raw assessment evidence, target identities, recovered proof values, or browser-session material.

Include the affected AdverScope version, supported platform, security impact, a minimal synthetic reproduction, and suggested mitigation when known. Do not test a report against a third party or attach a real assessment database.

The maintainers aim to acknowledge a report within three business days, provide an initial triage within seven business days, and coordinate disclosure after a fix or documented mitigation is available. These are response targets for the Beta project, not a commercial service-level agreement. If the private-advisory link is unavailable, contact the repository owner without including vulnerability details and request a private channel.

Supported versions and platform boundaries are published in [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md). Security fixes are prioritized for the current release line.

## Evidence handling

- Keep `data/` outside version control.
- Reference credentials through environment variables; never place secret values in target definitions.
- Treat screenshots and model responses as confidential assessment evidence.
- Treat `_browser_sessions/` as secret authentication state; never archive or publish it.
- Use an operating-system encrypted volume for the state root. Application-level evidence encryption is not currently provided.
- Treat Interaction Monitor callback URLs as engagement data; disable tokens after use and do not expose the local callback listener beyond explicitly authorized networks.
- Callback headers and bodies are redacted before storage, but that safeguard does not replace evidence review before export.
- Review and redact exported material before sharing it outside the assessment team.
