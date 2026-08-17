from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import AppConfig
from .http_app import run_server
from .local_setup import SetupError, default_config_path, doctor_report, initialize_local_state, render_doctor_report
from .model_gateway import ModelGateway
from .model_providers import PROVIDER_KINDS
from .recovery import (
    RecoveryError,
    create_local_backup,
    export_project,
    import_project,
    recover_interrupted_restore,
    restore_local_backup,
    verify_archive,
)
from .db import Repository
from .deployment_security import validate_serve_security
from .runtime_lifecycle import RuntimeAlreadyActiveError, RuntimeLock, runtime_lock_path
from .qualification_fixture import FIXTURE_MODES, QualificationFixtureServer
from .tutorial import TUTORIAL_PORT, create_tutorial_project


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adverscope", description="Local-first AI security assessment workbench")
    parser.add_argument("--version", action="version", version=f"AdverScope {__version__}")
    commands = parser.add_subparsers(dest="command")

    serve = commands.add_parser("serve", help="Start the local AdverScope application")
    serve.add_argument("--config", default=str(default_config_path()))
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--database")
    serve.add_argument("--evidence-root")
    serve.add_argument("--model-profiles-path")
    serve.add_argument("--llm-base-url")
    serve.add_argument("--llm-model")
    serve.add_argument("--browser-executable")
    serve.add_argument("--ssh-tunnel", action="store_true")
    serve.add_argument("--ssh-local-port", type=int)
    serve.add_argument("--ssh-remote-port", type=int)
    serve.add_argument("--gx10-user")
    serve.add_argument("--gx10-host")
    serve.add_argument("--remote-access-token-env", default="", help="Environment variable containing the bearer token for direct remote API access")
    serve.add_argument("--tls-cert", default="", help="PEM certificate required for direct remote API access")
    serve.add_argument("--tls-key", default="", help="PEM private key required for direct remote API access")
    serve.add_argument("--acknowledge-remote-exposure", action="store_true", help="Confirm that the selected non-loopback interface is authorized and network-restricted")

    initialize = commands.add_parser("init", help="Create non-secret local configuration and storage")
    initialize.add_argument("--config", default=str(default_config_path()))
    initialize.add_argument("--data-dir")
    initialize.add_argument("--evidence-dir")
    initialize.add_argument("--host", default="127.0.0.1")
    initialize.add_argument("--port", type=int, default=8080)
    initialize.add_argument("--provider", choices=["local", "openai", "zai"], default="local")
    initialize.add_argument("--model", default="")
    initialize.add_argument("--base-url", default="")
    initialize.add_argument("--api-key-env", default="")
    initialize.add_argument("--browser-executable", default="")
    initialize.add_argument("--force", action="store_true", help="Update configuration without deleting existing project data")
    initialize.add_argument("--json", action="store_true", dest="json_output")

    doctor = commands.add_parser("doctor", help="Diagnose installation, storage, browser, port, and model readiness")
    doctor.add_argument("--config", default=str(default_config_path()))
    doctor.add_argument("--skip-model", action="store_true", help="Do not contact the configured model endpoint")
    doctor.add_argument("--json", action="store_true", dest="json_output")

    profiles = commands.add_parser("profiles", help="Manage named non-secret model profiles and role assignments")
    profiles.add_argument("--config", default=str(default_config_path()))
    profile_commands = profiles.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_commands.add_parser("list", help="List profiles and role assignments")
    profile_list.add_argument("--json", action="store_true", dest="json_output")
    profile_add = profile_commands.add_parser("add", help="Create or update a named provider profile")
    profile_add.add_argument("profile_id")
    profile_add.add_argument("--label", required=True)
    profile_add.add_argument("--kind", choices=PROVIDER_KINDS, required=True)
    profile_add.add_argument("--base-url", default="", help="Required for local and generic remote profiles; official OpenAI and Z.AI endpoints are fixed")
    profile_add.add_argument("--model", required=True)
    profile_add.add_argument("--api-key-env", default="")
    profile_add.add_argument("--ssh-tunnel", action="store_true")
    profile_add.add_argument("--disable-thinking", action="store_true")
    profile_add.add_argument("--json", action="store_true", dest="json_output")
    profile_roles = profile_commands.add_parser("roles", help="Assign profiles to model roles")
    profile_roles.add_argument("--planner")
    profile_roles.add_argument("--generator")
    profile_roles.add_argument("--evaluator")
    profile_roles.add_argument("--adjudicator", help="Profile ID or 'none' to disable the optional adjudicator")
    profile_roles.add_argument("--json", action="store_true", dest="json_output")
    profile_test = profile_commands.add_parser("test", help="Verify profile connectivity and model inventory")
    profile_test.add_argument("profile_id")
    profile_test.add_argument("--json", action="store_true", dest="json_output")
    profile_remove = profile_commands.add_parser("remove", help="Delete an unassigned custom profile")
    profile_remove.add_argument("profile_id")

    backup = commands.add_parser("backup", help="Create, verify, or restore a complete local assessment backup")
    backup.add_argument("--config", default=str(default_config_path()))
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_create = backup_commands.add_parser("create", help="Create an integrity-checked local assessment backup")
    backup_create.add_argument("destination")
    backup_create.add_argument("--acknowledge-sensitive-data", action="store_true", required=True)
    backup_create.add_argument("--include-browser-sessions", action="store_true", help="Include credential-bearing browser state only when explicitly required")
    backup_create.add_argument("--json", action="store_true", dest="json_output")
    backup_verify = backup_commands.add_parser("verify", help="Verify a local backup without restoring it")
    backup_verify.add_argument("archive")
    backup_verify.add_argument("--json", action="store_true", dest="json_output")
    backup_restore = backup_commands.add_parser("restore", help="Restore a verified backup while AdverScope is stopped")
    backup_restore.add_argument("archive")
    backup_restore.add_argument("--acknowledge-sensitive-data", action="store_true", required=True)
    backup_restore.add_argument("--yes", action="store_true", required=True, help="Confirm replacement of the current local assessment store")
    backup_restore.add_argument("--json", action="store_true", dest="json_output")

    projects = commands.add_parser("projects", help="Export or import one isolated assessment project")
    projects.add_argument("--config", default=str(default_config_path()))
    project_commands = projects.add_subparsers(dest="project_command", required=True)
    project_export = project_commands.add_parser("export", help="Export one project with its retained evidence")
    project_export.add_argument("project_id")
    project_export.add_argument("destination")
    project_export.add_argument("--acknowledge-sensitive-data", action="store_true", required=True)
    project_export.add_argument("--include-browser-sessions", action="store_true")
    project_export.add_argument("--json", action="store_true", dest="json_output")
    project_import = project_commands.add_parser("import", help="Import an integrity-checked project transfer")
    project_import.add_argument("archive")
    project_import.add_argument("--acknowledge-sensitive-data", action="store_true", required=True)
    project_import.add_argument("--json", action="store_true", dest="json_output")
    project_verify = project_commands.add_parser("verify", help="Verify a project transfer without importing it")
    project_verify.add_argument("archive")
    project_verify.add_argument("--json", action="store_true", dest="json_output")

    tutorial = commands.add_parser("tutorial", help="Create and run the isolated local synthetic tutorial")
    tutorial.add_argument("--config", default=str(default_config_path()))
    tutorial_commands = tutorial.add_subparsers(dest="tutorial_command", required=True)
    tutorial_create = tutorial_commands.add_parser("create", help="Create a complete synthetic tutorial project")
    tutorial_create.add_argument("--port", type=int, default=TUTORIAL_PORT)
    tutorial_create.add_argument("--json", action="store_true", dest="json_output")
    tutorial_target = tutorial_commands.add_parser("target", help="Run the independent synthetic tutorial target")
    tutorial_target.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "::1"])
    tutorial_target.add_argument("--port", type=int, default=TUTORIAL_PORT)
    tutorial_target.add_argument("--mode", choices=sorted(FIXTURE_MODES), default="vulnerable")
    return parser


def _serve(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser().resolve()
    if not config_path.is_file():
        raise SetupError(f"configuration does not exist: {config_path}; run adverscope init first")
    config = AppConfig.from_sources(config_path)
    overrides = {
        "host": args.host,
        "port": args.port,
        "database_path": Path(args.database).expanduser().resolve() if args.database else None,
        "evidence_root": Path(args.evidence_root).expanduser().resolve() if args.evidence_root else None,
        "model_profiles_path": Path(args.model_profiles_path).expanduser().resolve() if args.model_profiles_path else None,
        "llm_base_url": args.llm_base_url,
        "llm_model": args.llm_model,
        "browser_executable": args.browser_executable,
        "ssh_local_port": args.ssh_local_port,
        "ssh_remote_port": args.ssh_remote_port,
        "gx10_user": args.gx10_user,
        "gx10_host": args.gx10_host,
        "remote_access_token_env": args.remote_access_token_env or None,
        "tls_cert_path": args.tls_cert or None,
        "tls_key_path": args.tls_key or None,
    }
    config = replace(config, **{key: value for key, value in overrides.items() if value is not None})
    if args.ssh_tunnel:
        config = replace(config, ssh_tunnel=True)
    if args.acknowledge_remote_exposure:
        config = replace(config, remote_exposure_acknowledged=True)
    deployment = validate_serve_security(config)
    if deployment.get("warning"):
        print(f"AdverScope warning: {deployment['warning']}", file=sys.stderr)
    run_server(config=config)
    return 0


def _profiles(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser().resolve()
    if not config_path.is_file():
        raise SetupError(f"configuration does not exist: {config_path}; run adverscope init first")
    gateway = ModelGateway(AppConfig.from_sources(config_path))
    try:
        if args.profile_command == "list":
            result = gateway.public_provider_profiles()
            if args.json_output:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print("AdverScope model profiles")
                for profile in result["providers"]:
                    roles = ", ".join(profile["assigned_roles"]) or "unassigned"
                    print(f"- {profile['id']}: {profile['label']} · {profile['model']} · {roles}")
                print("Professional qualification is not established by connectivity alone.")
            return 0
        if args.profile_command == "add":
            result = gateway.upsert_provider_profile(
                args.profile_id,
                label=args.label,
                kind=args.kind,
                base_url=args.base_url,
                model=args.model,
                api_key_env=args.api_key_env,
                use_ssh_tunnel=args.ssh_tunnel,
                supports_disable_thinking=args.disable_thinking,
            )
            print(json.dumps(result, indent=2, sort_keys=True) if args.json_output else f"Saved model profile {args.profile_id}.")
            return 0
        if args.profile_command == "roles":
            assignments = {
                role: (None if value == "none" else value)
                for role, value in {
                    "planner": args.planner,
                    "generator": args.generator,
                    "evaluator": args.evaluator,
                    "adjudicator": args.adjudicator,
                }.items()
                if value is not None
            }
            if not assignments:
                raise SetupError("provide at least one model-role assignment")
            result = gateway.configure_model_roles(assignments)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json_output else "Model-role assignments updated.")
            return 0
        if args.profile_command == "test":
            result = gateway.qualify_provider_profile(args.profile_id)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json_output else f"{result['status']}: {result['summary']}")
            return 0 if result["status"] == "connection-verified" else 1
        if args.profile_command == "remove":
            gateway.delete_provider_profile(args.profile_id)
            print(f"Removed model profile {args.profile_id}.")
            return 0
        raise SetupError("unknown model profile command")
    finally:
        gateway.close()


def _configured_storage(config_path: str) -> tuple[AppConfig, RuntimeLock]:
    source = Path(config_path).expanduser().resolve()
    if not source.is_file():
        raise SetupError(f"configuration does not exist: {source}; run adverscope init first")
    config = AppConfig.from_sources(source)
    lock = RuntimeLock(runtime_lock_path(config.database_path, config.port), port=config.port)
    lock.acquire()
    try:
        recover_interrupted_restore(config)
    except Exception:
        lock.release()
        raise
    return config, lock


def _print_recovery_result(result: dict[str, object], *, json_output: bool, summary: str) -> None:
    if json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(summary)
        if result.get("archive_sha256"):
            print(f"SHA-256: {result['archive_sha256']}")


def _backup(args: argparse.Namespace) -> int:
    if args.backup_command == "verify":
        result = verify_archive(args.archive, expected_kind="adverscope-local-backup")
        _print_recovery_result(result, json_output=args.json_output, summary="Local backup integrity verified.")
        return 0
    config, lock = _configured_storage(args.config)
    try:
        if args.backup_command == "restore":
            result = restore_local_backup(config, args.archive, acknowledge_sensitive=args.acknowledge_sensitive_data)
            _print_recovery_result(result, json_output=args.json_output, summary=f"Restored {result['project_count']} projects and retained evidence.")
            return 0
        repository = Repository(config.database_path)
        try:
            result = create_local_backup(
                repository,
                config,
                args.destination,
                acknowledge_sensitive=args.acknowledge_sensitive_data,
                include_browser_sessions=args.include_browser_sessions,
            )
        finally:
            repository.close()
        _print_recovery_result(result, json_output=args.json_output, summary=f"Created verified local backup with {result['project_count']} projects.")
        return 0
    finally:
        lock.release()


def _projects(args: argparse.Namespace) -> int:
    if args.project_command == "verify":
        result = verify_archive(args.archive, expected_kind="adverscope-project-transfer")
        _print_recovery_result(result, json_output=args.json_output, summary=f"Project transfer {result['project']['id']} is valid.")
        return 0
    config, lock = _configured_storage(args.config)
    try:
        repository = Repository(config.database_path)
        try:
            if args.project_command == "export":
                result = export_project(
                    repository,
                    config.evidence_root,
                    args.project_id,
                    args.destination,
                    acknowledge_sensitive=args.acknowledge_sensitive_data,
                    include_browser_sessions=args.include_browser_sessions,
                )
                summary = f"Exported project {args.project_id} with integrity verification."
            else:
                result = import_project(
                    repository,
                    config.evidence_root,
                    args.archive,
                    acknowledge_sensitive=args.acknowledge_sensitive_data,
                )
                summary = f"Imported isolated project {result['project']['id']}."
        finally:
            repository.close()
        _print_recovery_result(result, json_output=args.json_output, summary=summary)
        return 0
    finally:
        lock.release()


def _tutorial(args: argparse.Namespace) -> int:
    if args.tutorial_command == "target":
        fixture = QualificationFixtureServer(args.mode, host=args.host, port=args.port).start()
        try:
            print(f"AdverScope synthetic tutorial target listening on {fixture.base_url}; press Ctrl+C to stop")
            fixture.thread.join()
        except KeyboardInterrupt:
            pass
        finally:
            fixture.close()
        return 0
    config, lock = _configured_storage(args.config)
    try:
        result = create_tutorial_project(config, target_port=args.port)
    finally:
        lock.release()
    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Created isolated tutorial project {result['project']['id']}.")
        for step in result["next_steps"]:
            print(f"- {step}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        values = ["serve"]
    parser = _parser()
    args = parser.parse_args(values)
    try:
        if args.command == "init":
            result = initialize_local_state(
                config_path=args.config,
                data_directory=args.data_dir,
                evidence_directory=args.evidence_dir,
                host=args.host,
                port=args.port,
                provider=args.provider,
                model=args.model,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
                browser_executable=args.browser_executable,
                force=args.force,
            )
            if args.json_output:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"AdverScope initialized at {result['config_path']}")
                print(f"Data: {result['data_directory']}")
                print(f"Evidence: {result['evidence_directory']}")
                if result["api_key_environment"]:
                    print(f"Set {result['api_key_environment']} in the environment before starting AdverScope.")
                print(f"Next: adverscope doctor --config \"{result['config_path']}\"")
            return 0
        if args.command == "doctor":
            report = doctor_report(args.config, probe_model=not args.skip_model)
            print(json.dumps(report, indent=2, sort_keys=True) if args.json_output else render_doctor_report(report))
            return 0 if report["ok"] else 1
        if args.command == "profiles":
            return _profiles(args)
        if args.command == "backup":
            return _backup(args)
        if args.command == "projects":
            return _projects(args)
        if args.command == "tutorial":
            return _tutorial(args)
        if args.command == "serve":
            return _serve(args)
        parser.print_help()
        return 0
    except (SetupError, RecoveryError, ValueError, RuntimeAlreadyActiveError) as exc:
        print(f"AdverScope: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
