# AdverScope support policy

AdverScope is currently a **Beta** security-testing tool. Beta releases are suitable for authorized evaluation and controlled professional pilots by experienced testers, but require human review of every result and preserved reproduction.

## Release channels

- **Alpha:** interfaces and schemas may change; migrations are documented but backward compatibility is not guaranteed until the migration gate passes.
- **Beta:** supported workflows and schemas are frozen except for security or correctness changes; Windows and Linux qualification is required.
- **Release candidate:** installation, upgrade, backup/restore, security, and platform gates have passed and only release-blocking defects may change behavior.
- **Stable:** supported versions receive security and correctness fixes according to the published support matrix. Breaking changes require a new major version and a documented migration path.

## Current supported use

- Windows 11 x64 is the primary qualified local platform.
- Ubuntu 24.04 LTS x64 is supported for source, API, and qualified Chrome/Chromium browser workflows.
- macOS 15 Apple Silicon is supported for source, API, and qualified Chrome browser workflows from version 0.8.3.
- API-only container use is supported through the supplied host-loopback Compose boundary.
- Local OpenAI-compatible models and the built-in OpenAI and Z.AI provider profiles are supported when their connection and role qualification checks pass.

## Current limitations

- The current release is not declared stable; platform claims remain workflow-specific.
- Direct remote binding is API-only and requires explicit acknowledgement, TLS, and environment-provided bearer authentication.
- Native installers remain deferred; the source bootstrap and optional API-only container are the supported Beta distribution paths.
- Findings remain draft until a qualified human reviewer accepts the evidence and reproduction.

See [the detailed support matrix](docs/SUPPORT_MATRIX.md), [network guidance](docs/NETWORK_ENVIRONMENTS.md), and [responsible-use policy](RESPONSIBLE_USE.md).

Security reports must follow [SECURITY.md](SECURITY.md). Never include client evidence, credentials, browser profiles, or recovered proof values in public issues.
