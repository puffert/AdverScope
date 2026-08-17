# Installing AdverScope locally

This guide covers the supported Beta source installation. It keeps application state outside the checkout, stores no API-key values in configuration, and can be diagnosed without editing source files.

## Prerequisites

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Node.js 20 or newer for browser targets
- Microsoft Edge, Google Chrome, or Chromium for browser targets
- A supported local model endpoint or approved remote model account

API-only testing does not require Node.js or a browser.

## Bootstrap

From a clean checkout, run:

```text
python scripts/bootstrap.py
```

This single command creates the locked Python environment, installs the locked browser runtime, and initializes non-secret local configuration and storage. It never asks for or stores an API key.

For API-only use:

```text
python scripts/bootstrap.py --skip-browser
```

For a local OpenAI-compatible model on another endpoint:

```text
python scripts/bootstrap.py --provider local --base-url http://127.0.0.1:8001/v1 --model qwen3.8-27b
```

For an approved remote provider, configure only the environment-variable name:

```text
python scripts/bootstrap.py --provider openai --model gpt-5.5 --api-key-env OPENAI_API_KEY
```

Set the actual key in the process environment before starting AdverScope. Z.AI uses `--provider zai` and defaults to `ZAI_API_KEY`. Key values are never written to the configuration, provider profile, database, evidence, reports, or logs.

After initialization, named profiles and role assignments can be managed through the top-right model dialog or `adverscope profiles`. A connection test verifies the endpoint and model inventory but does not establish professional planner or evaluator qualification. See [Model providers and model roles](MODEL_PROVIDERS.md) for supported provider kinds, local runtime examples, role separation, secret handling, and migration behavior.

Before upgrading an existing installation, create and verify a local assessment backup. Supported database upgrades also create an automatic verified pre-migration SQLite backup before changing the schema. See [Backup, recovery, and project transfer](BACKUP_AND_RECOVERY.md) for GUI and CLI workflows, offline restore, interruption recovery, retention, and disposal boundaries.

## Diagnose the installation

```text
uv run adverscope doctor
```

The diagnostic checks Python, configuration, data and evidence storage, database schema, local port, Node.js, browser capture dependencies, Chrome/Edge, provider metadata, and the selected model. Use `--skip-model` when intentionally validating an offline or disconnected installation.

Warnings identify optional browser limitations. A failure means the configured workflow is not ready and produces a non-zero exit status. For machine-readable diagnostics, add `--json`.

## Start AdverScope

```text
uv run adverscope serve
```

Open the local address shown in the terminal. The supported interactive workflow binds to loopback; direct remote operation is a separately gated API-only mode.

Local loopback remains the default and recommended workflow. Direct non-loopback use is API-only and requires all of the following:

```text
set ADVERSCOPE_REMOTE_TOKEN=<unpredictable value of at least 32 characters>
uv run adverscope serve --host <authorized-interface> --remote-access-token-env ADVERSCOPE_REMOTE_TOKEN --tls-cert <certificate.pem> --tls-key <private-key.pem> --acknowledge-remote-exposure
```

Restrict the interface with a firewall and rotate the token after the engagement. Prefer an approved reverse proxy that terminates identity and TLS while AdverScope remains on loopback. See [Corporate network, proxy, CA, VPN, and firewall setup](NETWORK_ENVIRONMENTS.md).

The default state root is:

- Windows: `%LOCALAPPDATA%\AdverScope`
- macOS: `~/Library/Application Support/AdverScope`
- Linux: `$XDG_STATE_HOME/adverscope` or `~/.local/state/adverscope`

Set `ADVERSCOPE_HOME` to choose another state root or `ADVERSCOPE_CONFIG` to choose an explicit configuration file. `adverscope init --force` updates configuration without deleting the existing database, projects, evidence, or browser sessions.

## Existing source installations

`python run.py` remains a compatibility launcher for existing checkouts using the ignored `data/local-config.json`. It preserves the existing local database and evidence paths. New installations should use `adverscope init`, `adverscope doctor`, and `adverscope serve`.

## Synthetic first assessment

Create a complete isolated tutorial after initialization:

```text
uv run adverscope tutorial create
uv run adverscope tutorial target
```

Keep the target command running, open AdverScope, select **AdverScope Synthetic Tutorial**, test the saved connection, and create an Advanced assessment with the saved objective. The project contains synthetic scope, policy, target, approved guardrail, deterministic proof rule, and reproduction requirement. It does not use a customer target or secret.

## API-only container

Run the optional host-loopback container with:

```text
docker compose up --build
```

The image intentionally omits Node.js and browser capture. Do not expose its internal listener remotely. See [API-only container deployment](CONTAINER_DEPLOYMENT.md).

## Uninstalling the application

Removing the checkout or Python environment does not remove the external state directory. Create and verify an AdverScope local backup before upgrades. Remove state only when its projects, evidence, browser sessions, migration backups, and transfer archives are no longer required under the engagement retention policy. Ordinary file deletion is not presented as forensic secure erasure.

Native installers remain deferred during Beta. Verify downloaded artifacts using [the release-integrity process](RELEASE_PROCESS.md).
