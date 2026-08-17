# Release integrity and verification

Every official AdverScope release contains a wheel, source archive, CycloneDX 1.7 SBOM, release manifest, and `SHA256SUMS`.

Build in an empty directory:

```text
uv run python scripts/release_integrity.py build --output <empty-directory>
uv run python scripts/release_integrity.py verify --output <same-directory>
```

The gate rejects unversioned packages, missing licenses, malformed checksums, and archive entries matching local databases, browser sessions, evidence/output directories, environment files, private keys, local configuration, or recovery journals.

Tagged public GitHub builds create a GitHub artifact attestation with the pinned `actions/attest` action. Consumers should verify `SHA256SUMS`, then verify the GitHub attestation against `puffert/AdverScope` before installing. Private repositories cannot use GitHub attestations on all plans; do not describe a private pre-release artifact as officially attested.

Dependency gates verify the Python and npm locks, run `pip-audit` and `npm audit`, execute the full regression, build the API-only container, and run the cross-platform API/browser matrix. A release is not promoted when a required gate fails.

For a locally connected candidate model, complete the installed-wheel tutorial gate after `adverscope tutorial create`:

```text
<installed-python> scripts/qualify_tutorial_install.py --config <isolated-config.json>
```

The command starts only the independent synthetic fixture, executes one bounded model-assisted assessment through the installed HTTP API, and requires a completed run with test cases, evidence, and a finding. Run it from isolated disposable state; it must never point at an existing assessment database.

The project does not automatically publish to PyPI or a container registry. Publication remains a deliberate maintainer action after version, changelog, migration, benchmark, documentation, and security review.
