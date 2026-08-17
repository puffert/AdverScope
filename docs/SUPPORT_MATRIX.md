# Support matrix and known limitations

Version 0.9.0 Beta support is deliberately narrow. A platform is supported only for the workflows marked below; source compatibility is not the same as qualified professional support. The platform qualification established for 0.8.3 remains the supported installation baseline; 0.9.0 adds Milestone 4 AI-system execution lanes without broadening the operating-system matrix.

| Platform | API targets | Browser capture/login | Local model | Remote provider | Status |
|---|---:|---:|---:|---:|---|
| Windows 11 x64, current security updates | Yes | Chrome or Edge | Yes | Yes | Primary supported platform; locally qualified |
| Ubuntu 24.04 LTS x64 | Yes | Chrome/Chromium | OpenAI-compatible HTTP | Yes | Supported from 0.8.3; qualified by the release matrix |
| macOS 15, Apple Silicon | Yes | Chrome | OpenAI-compatible HTTP | Yes | Supported from 0.8.3; qualified on macOS 15 ARM64 |
| API-only container on Docker Engine 27+ | Yes | No | Host/network endpoint only | Yes | Optional host-loopback deployment |

Python 3.11 through 3.13 and Node.js 20 or newer are accepted for source use. Official release gates use Python 3.12 and Node.js 20. Windows Server, older macOS versions, Linux distributions other than Ubuntu 24.04, ARM Linux, Firefox, Safari, remote interactive GUI access, Kubernetes, and native installers are not currently qualified.

## Known limitations

- The application is Beta software. Findings require human review before professional reporting.
- Browser capture requires an installed Chrome, Edge, or Chromium executable. The container has no browser runtime, persistent login window, or screenshot capability.
- Direct remote binding is API-only. The static GUI does not store or inject the remote bearer token.
- Corporate TLS interception can affect model, target, npm, Python, and browser traffic differently; all relevant runtimes must trust the approved CA.
- Full browser sessions can contain live credentials. They are not ordinary evidence, are excluded from default backup/export, and should be retained only when the engagement requires them.
- Application-level evidence encryption is not included. Use BitLocker, FileVault, LUKS, or an equivalently managed encrypted volume and encrypt exported archives according to engagement policy.
- Model behavior remains stochastic. Deterministic target-owned proof, controlled reproduction, independent secure/vulnerable fixtures, and human review remain necessary.
- OWASP coverage describes executed mapped techniques. It is not a guarantee that every variant or future attack is tested.

The cross-platform release workflow runs API, screenshot, login, and persistent-profile qualification on Windows, Ubuntu, and macOS. A failed job blocks platform promotion and a tagged release.

## Version 0.9.0 platform qualification record

The 0.9.0 release candidate passed the cross-platform release matrix on 2026-08-11. Windows 2025, Ubuntu 24.04, and macOS 15 passed the API target, browser capture, screenshot, login-workflow, and persistent-session gates. The same qualification passed the complete regression, clean installation and release-artifact verification, API-only container build, and Python/npm dependency-security jobs.

The clean public Git history begins with 0.9.0. Public GitHub Actions runs are authoritative for subsequent tags; a tag must not be promoted when its public release matrix fails.

Milestone 4's control-lane qualification is recorded separately under `validation/milestone4/`. It qualifies 62 bounded native or configured deterministic execution lanes; it does not claim universal target applicability or automatic discovery.
