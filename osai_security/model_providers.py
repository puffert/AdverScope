from __future__ import annotations

import json
import os
import re
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import AppConfig
from .release import MODEL_PROVIDER_SCHEMA_VERSION
from .deployment_security import secure_directory, secure_file


PROVIDER_SCHEMA_VERSION = MODEL_PROVIDER_SCHEMA_VERSION
MODEL_ROLES = ("planner", "generator", "evaluator", "adjudicator")
REQUIRED_MODEL_ROLES = MODEL_ROLES[:3]
PROVIDER_KINDS = (
    "local-openai-compatible",
    "openai",
    "zai",
    "remote-openai-compatible",
)
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


@dataclass(frozen=True)
class ModelProvider:
    id: str
    label: str
    kind: str
    base_url: str
    model: str
    remote: bool
    api_key_env: str = ""
    session_api_key: str = ""
    use_ssh_tunnel: bool = False
    supports_disable_thinking: bool = False
    built_in: bool = False

    @property
    def credential_source(self) -> str:
        if not self.remote:
            return "not-required"
        if self.session_api_key:
            return "session"
        if self.api_key_env and os.environ.get(self.api_key_env, "").strip():
            return "environment"
        return "missing"

    @property
    def api_key(self) -> str:
        if not self.remote:
            return ""
        return self.session_api_key or os.environ.get(self.api_key_env, "").strip()


class ModelProviderRegistry:
    """Versioned non-secret provider profiles and model-role assignments."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.path = Path(config.model_profiles_path)
        self._lock = threading.RLock()
        self._session_keys: dict[str, str] = {}
        self._profiles: dict[str, dict[str, Any]] = {}
        selected = config.llm_provider if config.llm_provider in {"local", "openai", "zai"} else "local"
        self._role_profiles: dict[str, str | None] = {
            "planner": selected,
            "generator": selected,
            "evaluator": selected,
            "adjudicator": None,
        }
        self._loaded_schema = PROVIDER_SCHEMA_VERSION
        self._migration_pending = False
        self._load_warning = ""
        self._load()

    def _defaults(self) -> dict[str, ModelProvider]:
        return {
            "local": ModelProvider(
                id="local",
                label="Default local model",
                kind="local-openai-compatible",
                base_url=self.config.llm_base_url.rstrip("/"),
                model=self.config.llm_model,
                remote=False,
                use_ssh_tunnel=bool(self.config.ssh_tunnel),
                supports_disable_thinking=True,
                built_in=True,
            ),
            "openai": ModelProvider(
                id="openai",
                label="OpenAI API",
                kind="openai",
                base_url="https://api.openai.com/v1",
                model="gpt-5.5",
                remote=True,
                api_key_env="OPENAI_API_KEY",
                built_in=True,
            ),
            "zai": ModelProvider(
                id="zai",
                label="Z.AI API",
                kind="zai",
                base_url="https://api.z.ai/api/paas/v4",
                model="glm-5.2",
                remote=True,
                api_key_env="ZAI_API_KEY",
                built_in=True,
            ),
        }

    @staticmethod
    def _profile_document(provider: ModelProvider) -> dict[str, Any]:
        return {
            "label": provider.label,
            "kind": provider.kind,
            "base_url": provider.base_url,
            "model": provider.model,
            "api_key_env": provider.api_key_env,
            "use_ssh_tunnel": provider.use_ssh_tunnel,
            "supports_disable_thinking": provider.supports_disable_thinking,
            "built_in": provider.built_in,
        }

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._load_warning = "provider profile file is unreadable; built-in defaults are active"
            return
        if not isinstance(document, dict):
            self._load_warning = "provider profile file is not an object; built-in defaults are active"
            return
        schema = str(document.get("schema_version") or "1.0")
        self._loaded_schema = schema
        if schema == "1.0":
            self._load_v1(document)
            self._migration_pending = PROVIDER_SCHEMA_VERSION != "1.0"
            return
        if schema != PROVIDER_SCHEMA_VERSION:
            self._load_warning = f"unsupported provider profile schema {schema}; built-in defaults are active"
            return
        profiles = document.get("profiles") or {}
        if not isinstance(profiles, dict):
            self._load_warning = "provider profiles must be an object; built-in defaults are active"
            return
        for profile_id, value in profiles.items():
            if not isinstance(value, dict):
                continue
            try:
                self._profiles[str(profile_id)] = self._normalize_profile(str(profile_id), value, loading=True)
            except ValueError:
                continue
        roles = document.get("role_profiles") or {}
        if isinstance(roles, dict):
            for role in MODEL_ROLES:
                profile_id = str(roles.get(role) or "").strip()
                if profile_id and profile_id in self._all_profile_ids():
                    self._role_profiles[role] = profile_id
                elif role == "adjudicator":
                    self._role_profiles[role] = None

    def _load_v1(self, document: dict[str, Any]) -> None:
        selected = str(document.get("selected_provider") or "local")
        profiles = document.get("profiles") or {}
        defaults = self._defaults()
        if isinstance(profiles, dict):
            for profile_id, value in profiles.items():
                if profile_id not in defaults or not isinstance(value, dict):
                    continue
                default = defaults[profile_id]
                self._profiles[profile_id] = self._profile_document(ModelProvider(
                    **{
                        **default.__dict__,
                        "model": str(value.get("model") or default.model)[:200],
                        "api_key_env": str(value.get("api_key_env") or default.api_key_env)[:160],
                    }
                ))
        if selected in self._all_profile_ids():
            for role in REQUIRED_MODEL_ROLES:
                self._role_profiles[role] = selected

    def _all_profile_ids(self) -> set[str]:
        return set(self._defaults()) | set(self._profiles)

    def _assert_writable(self) -> None:
        if self._load_warning and self.path.is_file():
            raise ValueError(f"provider configuration cannot be changed: {self._load_warning}")

    def _save(self) -> None:
        self._assert_writable()
        secure_directory(self.path.parent)
        document = {
            "schema_version": PROVIDER_SCHEMA_VERSION,
            "selected_provider": self._role_profiles.get("generator"),
            "role_profiles": self._role_profiles,
            "profiles": self._profiles,
        }
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            secure_file(temporary)
            temporary.replace(self.path)
            secure_file(self.path)
        finally:
            temporary.unlink(missing_ok=True)
        self._loaded_schema = PROVIDER_SCHEMA_VERSION
        self._migration_pending = False

    @staticmethod
    def _validate_environment_name(value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_") or not all(
            character.isalnum() or character == "_" for character in cleaned
        ):
            raise ValueError("API key environment variable must be a valid variable name")
        return cleaned[:160]

    @staticmethod
    def _validate_profile_id(value: str) -> str:
        cleaned = str(value or "").strip().lower()
        if not _PROFILE_ID.fullmatch(cleaned):
            raise ValueError("profile ID must start with a letter and contain 2-64 lowercase letters, numbers, underscores, or hyphens")
        return cleaned

    @staticmethod
    def _validate_base_url(value: str, *, remote: bool) -> str:
        cleaned = str(value or "").strip().rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("provider base URL must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("provider base URL cannot contain credentials, query parameters, or fragments")
        if remote and parsed.scheme != "https":
            raise ValueError("remote provider profiles require HTTPS")
        return cleaned[:1000]

    def _normalize_profile(self, profile_id: str, value: dict[str, Any], *, loading: bool = False) -> dict[str, Any]:
        profile_id = self._validate_profile_id(profile_id)
        defaults = self._defaults()
        existing = defaults.get(profile_id)
        kind = str(value.get("kind") or (existing.kind if existing else "local-openai-compatible")).strip()
        if kind not in PROVIDER_KINDS:
            raise ValueError(f"provider kind must be one of: {', '.join(PROVIDER_KINDS)}")
        built_in = profile_id in defaults
        if built_in and existing and kind != existing.kind:
            raise ValueError("built-in provider kind cannot be changed")
        remote = kind in {"openai", "zai", "remote-openai-compatible"}
        fixed_url = defaults[kind].base_url if kind in {"openai", "zai"} else ""
        base_url = self._validate_base_url(fixed_url or str(value.get("base_url") or ""), remote=remote)
        model = str(value.get("model") or (existing.model if existing else "")).strip()[:200]
        if not model:
            raise ValueError("model name is required")
        label = str(value.get("label") or (existing.label if existing else profile_id)).strip()[:120]
        if not label:
            raise ValueError("profile name is required")
        api_key_env = ""
        if remote:
            api_key_env = self._validate_environment_name(
                str(value.get("api_key_env") or (existing.api_key_env if existing else ""))
            )
        use_ssh_tunnel = bool(value.get("use_ssh_tunnel", existing.use_ssh_tunnel if existing else False))
        if remote and use_ssh_tunnel:
            raise ValueError("remote API profiles cannot use the local SSH tunnel")
        if use_ssh_tunnel:
            parsed = urlparse(base_url)
            endpoint_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or endpoint_port != int(self.config.ssh_local_port):
                raise ValueError("SSH-tunnel profiles must use the configured loopback tunnel port")
        supports_disable_thinking = bool(value.get(
            "supports_disable_thinking",
            existing.supports_disable_thinking if existing else False,
        ))
        if remote and supports_disable_thinking:
            raise ValueError("disable-thinking compatibility is available only for explicitly compatible local models")
        return {
            "label": existing.label if built_in and existing else label,
            "kind": kind,
            "base_url": base_url,
            "model": model,
            "api_key_env": api_key_env,
            "use_ssh_tunnel": use_ssh_tunnel,
            "supports_disable_thinking": supports_disable_thinking,
            "built_in": built_in,
        }

    def provider(self, profile_id: str | None = None) -> ModelProvider:
        with self._lock:
            selected = str(profile_id or self._role_profiles["generator"] or "local")
            defaults = self._defaults()
            if selected not in self._all_profile_ids():
                raise ValueError("unknown model provider profile")
            document = self._profile_document(defaults[selected]) if selected in defaults else {}
            document.update(self._profiles.get(selected) or {})
            kind = str(document["kind"])
            remote = kind in {"openai", "zai", "remote-openai-compatible"}
            return ModelProvider(
                id=selected,
                label=str(document["label"]),
                kind=kind,
                base_url=str(document["base_url"]),
                model=str(document["model"]),
                remote=remote,
                api_key_env=str(document.get("api_key_env") or ""),
                session_api_key=self._session_keys.get(selected, ""),
                use_ssh_tunnel=bool(document.get("use_ssh_tunnel")),
                supports_disable_thinking=bool(document.get("supports_disable_thinking")),
                built_in=bool(document.get("built_in")),
            )

    def provider_for_role(self, role: str) -> ModelProvider | None:
        normalized = str(role or "").strip().lower()
        if normalized not in MODEL_ROLES:
            raise ValueError("unknown model role")
        profile_id = self._role_profiles.get(normalized)
        return self.provider(profile_id) if profile_id else None

    def upsert_profile(
        self,
        profile_id: str,
        *,
        label: str,
        kind: str,
        base_url: str,
        model: str,
        api_key_env: str = "",
        use_ssh_tunnel: bool = False,
        supports_disable_thinking: bool = False,
    ) -> ModelProvider:
        with self._lock:
            normalized_id = self._validate_profile_id(profile_id)
            self._profiles[normalized_id] = self._normalize_profile(normalized_id, {
                "label": label,
                "kind": kind,
                "base_url": base_url,
                "model": model,
                "api_key_env": api_key_env,
                "use_ssh_tunnel": use_ssh_tunnel,
                "supports_disable_thinking": supports_disable_thinking,
            })
            self._save()
            return self.provider(normalized_id)

    def delete_profile(self, profile_id: str) -> None:
        with self._lock:
            normalized_id = self._validate_profile_id(profile_id)
            if normalized_id in self._defaults():
                raise ValueError("built-in provider profiles cannot be deleted")
            assigned = [role for role, selected in self._role_profiles.items() if selected == normalized_id]
            if assigned:
                raise ValueError(f"profile is assigned to model role(s): {', '.join(assigned)}")
            if normalized_id not in self._profiles:
                raise ValueError("unknown model provider profile")
            self._profiles.pop(normalized_id, None)
            self._session_keys.pop(normalized_id, None)
            self._save()

    def assign_roles(self, assignments: dict[str, str | None]) -> dict[str, str | None]:
        with self._lock:
            updated = dict(self._role_profiles)
            for role in MODEL_ROLES:
                if role not in assignments:
                    continue
                profile_id = str(assignments.get(role) or "").strip()
                if not profile_id:
                    if role in REQUIRED_MODEL_ROLES:
                        raise ValueError(f"{role} requires a model profile")
                    updated[role] = None
                    continue
                if profile_id not in self._all_profile_ids():
                    raise ValueError(f"unknown model provider profile for {role}")
                updated[role] = profile_id
            for role in REQUIRED_MODEL_ROLES:
                if not updated.get(role):
                    raise ValueError(f"{role} requires a model profile")
            self._role_profiles = updated
            self._save()
            return dict(self._role_profiles)

    def select(self, provider_id: str, *, model: str = "", api_key_env: str = "") -> ModelProvider:
        """Backward-compatible global selection mapped to the three active roles."""
        with self._lock:
            current = self.provider(provider_id)
            selected_model = str(model or current.model).strip()[:200]
            selected_env = api_key_env or current.api_key_env
            self.upsert_profile(
                provider_id,
                label=current.label,
                kind=current.kind,
                base_url=current.base_url,
                model=selected_model,
                api_key_env=selected_env,
                use_ssh_tunnel=current.use_ssh_tunnel,
                supports_disable_thinking=current.supports_disable_thinking,
            )
            self.assign_roles({role: provider_id for role in REQUIRED_MODEL_ROLES})
            return self.provider(provider_id)

    def set_session_key(self, profile_id: str, api_key: str) -> None:
        with self._lock:
            provider = self.provider(profile_id)
            if not provider.remote:
                raise ValueError("the selected local profile does not use an API key")
            value = str(api_key or "").strip()
            if len(value) < 8 or len(value) > 1000:
                raise ValueError("API key must be between 8 and 1000 characters")
            self._session_keys[profile_id] = value

    def clear_session_key(self, profile_id: str) -> None:
        with self._lock:
            self._session_keys.pop(profile_id, None)

    def public(self) -> dict[str, Any]:
        with self._lock:
            providers = []
            role_map = dict(self._role_profiles)
            for profile_id in [*self._defaults(), *sorted(set(self._profiles) - set(self._defaults()))]:
                provider = self.provider(profile_id)
                source = provider.credential_source
                assigned_roles = [role for role, selected in role_map.items() if selected == profile_id]
                providers.append({
                    "id": provider.id,
                    "label": provider.label,
                    "kind": provider.kind,
                    "base_url": provider.base_url,
                    "model": provider.model,
                    "remote": provider.remote,
                    "requires_api_key": provider.remote,
                    "api_key_env": provider.api_key_env,
                    "credential_source": source,
                    "credential_ready": source != "missing",
                    "use_ssh_tunnel": provider.use_ssh_tunnel,
                    "supports_disable_thinking": provider.supports_disable_thinking,
                    "built_in": provider.built_in,
                    "assigned_roles": assigned_roles,
                    "selected": profile_id == role_map.get("generator"),
                })
            return {
                "schema_version": PROVIDER_SCHEMA_VERSION,
                "loaded_schema_version": self._loaded_schema,
                "migration_pending": self._migration_pending,
                "configuration_warning": self._load_warning,
                "selected_provider": role_map.get("generator"),
                "selected_profile": role_map.get("generator"),
                "role_profiles": role_map,
                "roles": [
                    {
                        "id": role,
                        "required": role in REQUIRED_MODEL_ROLES,
                        "profile_id": role_map.get(role),
                    }
                    for role in MODEL_ROLES
                ],
                "providers": providers,
                "provider_kinds": list(PROVIDER_KINDS),
                "credential_policy": "API keys are read from the named environment variable or held in memory for this process only. They are never returned or persisted.",
                "qualification_policy": "A successful connection test proves protocol reachability and model inventory only. Professional planner, generator, and evaluator qualification requires retained repeated benchmark evidence.",
            }
