from __future__ import annotations

import hashlib
import json
import pickletools
import re
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ARTIFACT_SCANNER_ID = "adverscope-native-artifact-security"
ARTIFACT_SCANNER_VERSION = "2026.08.1"
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_STATIC_TEXT_BYTES = 20 * 1024 * 1024
MAX_PICKLE_INSPECTION_BYTES = 4 * 1024 * 1024
ARTIFACT_KINDS = {
    "model",
    "adapter",
    "dependency-manifest",
    "sbom",
    "container-manifest",
    "dataset-manifest",
    "other",
}
ARTIFACT_TECHNIQUES = {"LLM03-MODEL", "LLM03-DEPS"}
SERIALIZATION_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".dill"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _case_id(value: Any, index: int) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_-]+", "-", str(value or "").strip()).strip("-")
    return (candidate or f"artifact-{index + 1}")[:80]


def validate_artifact_profile(profile: dict[str, Any] | None) -> dict[str, Any]:
    """Validate the target-owned static artifact policy used by LLM03.

    The profile contains artifact identifiers and explicit policy decisions only.
    Artifact paths and bytes remain project-owned server data and are resolved at
    execution time after the project and target relationship is checked.
    """

    profile = profile or {}
    if not isinstance(profile, dict):
        raise ValueError("artifact security profile must be an object")
    if not profile.get("enabled"):
        return {}
    raw_cases = profile.get("cases") or []
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("artifact security needs at least one uploaded artifact case")
    if len(raw_cases) > 100:
        raise ValueError("artifact security may contain at most 100 cases per target")
    cases: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    artifact_ids: set[str] = set()
    for index, raw in enumerate(raw_cases):
        if not isinstance(raw, dict):
            raise ValueError("each artifact security case must be an object")
        case_id = _case_id(raw.get("id"), index)
        artifact_id = str(raw.get("artifact_id") or "").strip()
        title = str(raw.get("title") or "").strip()[:200]
        technique_id = str(raw.get("technique_id") or "").strip()
        expected_sha256 = str(raw.get("expected_sha256") or "").strip().lower()
        raw_objective_ids = raw.get("objective_ids") or []
        if case_id in case_ids:
            raise ValueError(f"artifact security case ids must be unique: {case_id}")
        if artifact_id in artifact_ids:
            raise ValueError(f"an uploaded artifact may appear only once in the profile: {artifact_id}")
        if not re.fullmatch(r"art_[A-Za-z0-9]{12}", artifact_id):
            raise ValueError("every artifact security case must reference a valid uploaded artifact id")
        if not title:
            raise ValueError("every artifact security case needs a title")
        if technique_id not in ARTIFACT_TECHNIQUES:
            raise ValueError("artifact security technique must be LLM03-MODEL or LLM03-DEPS")
        if expected_sha256 and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("artifact expected_sha256 must contain exactly 64 hexadecimal characters")
        if not isinstance(raw_objective_ids, list):
            raise ValueError("artifact objective_ids must be a list")
        objective_ids = list(dict.fromkeys(str(value).strip() for value in raw_objective_ids if str(value).strip()))
        if len(objective_ids) > 100 or any(not re.fullmatch(r"obj_[A-Za-z0-9]{12}", value) for value in objective_ids):
            raise ValueError("artifact objective_ids must contain at most 100 valid objective ids")
        try:
            max_archive_entries = int(raw.get("max_archive_entries") or 5000)
            max_expansion_ratio = int(raw.get("max_expansion_ratio") or 200)
        except (TypeError, ValueError) as exc:
            raise ValueError("artifact archive limits must be whole numbers") from exc
        if not 1 <= max_archive_entries <= 100_000:
            raise ValueError("artifact max_archive_entries must be between 1 and 100000")
        if not 1 <= max_expansion_ratio <= 10_000:
            raise ValueError("artifact max_expansion_ratio must be between 1 and 10000")
        severity = str(raw.get("severity") or "high").strip().lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("artifact severity must be low, medium, high, or critical")
        normalized = {
            "id": case_id,
            "artifact_id": artifact_id,
            "title": title,
            "technique_id": technique_id,
            "objective_ids": objective_ids,
            "expected_sha256": expected_sha256,
            "require_valid_structure": bool(raw.get("require_valid_structure", True)),
            "allow_executable_serialization": bool(raw.get("allow_executable_serialization", False)),
            "reject_unsafe_archive_paths": bool(raw.get("reject_unsafe_archive_paths", True)),
            "require_dependency_pinning": bool(raw.get("require_dependency_pinning", False)),
            "require_component_hashes": bool(raw.get("require_component_hashes", False)),
            "require_provenance_metadata": bool(raw.get("require_provenance_metadata", False)),
            "require_signature_metadata": bool(raw.get("require_signature_metadata", False)),
            "max_archive_entries": max_archive_entries,
            "max_expansion_ratio": max_expansion_ratio,
            "severity": severity,
            "rationale": str(raw.get("rationale") or "Verify artifact integrity and supply-chain controls without loading or executing the artifact.")[:1200],
        }
        cases.append(normalized)
        case_ids.add(case_id)
        artifact_ids.add(artifact_id)
    return {"enabled": True, "cases": cases}


def artifact_profile_readiness(profile: dict[str, Any] | None) -> dict[str, Any]:
    profile = profile or {}
    cases = profile.get("cases") or []
    enabled = bool(profile.get("enabled") and cases)
    return {
        "artifact_adapter": enabled,
        "artifact_adapter_technique_ids": sorted({str(case.get("technique_id")) for case in cases}) if enabled else [],
        "artifact_case_count": len(cases) if enabled else 0,
    }


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _safe_name(value: Any, limit: int = 240) -> str:
    return str(value or "").replace("\x00", "")[:limit]


def _violation(rule_id: str, title: str, severity: str, description: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence or {},
    }


def _observation(rule_id: str, summary: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"rule_id": rule_id, "summary": summary, "evidence": evidence or {}}


def _archive_member_is_unsafe(name: str) -> bool:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    return (
        normalized.startswith("/")
        or normalized.startswith("//")
        or bool(re.match(r"^[A-Za-z]:", normalized))
        or ".." in pure.parts
    )


def _inspect_pickle_bytes(content: bytes) -> dict[str, Any]:
    dangerous = {"GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "PERSID", "BINPERSID", "EXT1", "EXT2", "EXT4"}
    counts: dict[str, int] = {}
    total = 0
    try:
        for opcode, _argument, _position in pickletools.genops(content):
            total += 1
            if opcode.name in dangerous:
                counts[opcode.name] = counts.get(opcode.name, 0) + 1
        return {"parsed": True, "opcode_count": total, "executable_opcode_counts": counts}
    except Exception as exc:
        return {"parsed": False, "opcode_count": total, "executable_opcode_counts": counts, "error": type(exc).__name__}


def _inspect_zip(path: Path, policy: dict[str, Any], report: dict[str, Any]) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            report["format"] = "zip-archive"
            report["format_details"] = {
                "entry_count": len(entries),
                "total_compressed_bytes": sum(max(0, int(item.compress_size)) for item in entries),
                "total_uncompressed_bytes": sum(max(0, int(item.file_size)) for item in entries),
            }
            if len(entries) > int(policy["max_archive_entries"]):
                report["violations"].append(_violation(
                    "ART-ARCHIVE-ENTRY-LIMIT",
                    "Archive exceeds the approved entry limit",
                    "high",
                    "The artifact contains more archive entries than the target-owned static-inspection policy permits.",
                    {"entry_count": len(entries), "maximum": int(policy["max_archive_entries"])},
                ))
            unsafe_paths = [_safe_name(item.filename) for item in entries if _archive_member_is_unsafe(item.filename)]
            if unsafe_paths and policy["reject_unsafe_archive_paths"]:
                report["violations"].append(_violation(
                    "ART-ARCHIVE-PATH-TRAVERSAL",
                    "Archive contains unsafe extraction paths",
                    "critical",
                    "One or more member names can escape a naïve extraction directory. AdverScope did not extract the archive.",
                    {"count": len(unsafe_paths), "sample": unsafe_paths[:20]},
                ))
            symlinks = []
            encrypted = []
            excessive_ratio = []
            ratio_limit = int(policy["max_expansion_ratio"])
            for item in entries:
                mode = (int(item.external_attr) >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    symlinks.append(_safe_name(item.filename))
                if int(item.flag_bits) & 0x1:
                    encrypted.append(_safe_name(item.filename))
                compressed = max(1, int(item.compress_size))
                ratio = int(item.file_size) / compressed
                if ratio > ratio_limit:
                    excessive_ratio.append({"name": _safe_name(item.filename), "ratio": round(ratio, 2), "size": int(item.file_size)})
            if symlinks and policy["reject_unsafe_archive_paths"]:
                report["violations"].append(_violation(
                    "ART-ARCHIVE-SYMLINK",
                    "Archive contains symbolic links",
                    "high",
                    "Symbolic-link entries can redirect extraction outside the intended artifact directory.",
                    {"count": len(symlinks), "sample": symlinks[:20]},
                ))
            if excessive_ratio:
                report["violations"].append(_violation(
                    "ART-ARCHIVE-EXPANSION",
                    "Archive exceeds the approved expansion ratio",
                    "high",
                    "One or more members exceed the configured static archive expansion boundary.",
                    {"maximum_ratio": ratio_limit, "sample": excessive_ratio[:20]},
                ))
            if encrypted:
                report["limitations"].append({
                    "id": "ART-ARCHIVE-ENCRYPTED",
                    "summary": "Encrypted archive members could not be inspected.",
                    "evidence": {"count": len(encrypted), "sample": encrypted[:20]},
                })
            member_names = {_safe_name(item.filename, 500) for item in entries}
            pytorch_pickle = next((item for item in entries if item.filename.endswith("data.pkl")), None)
            if pytorch_pickle:
                report["format"] = "pytorch-zip"
                pickle_result: dict[str, Any] = {"member": _safe_name(pytorch_pickle.filename), "size": int(pytorch_pickle.file_size)}
                if int(pytorch_pickle.file_size) <= MAX_PICKLE_INSPECTION_BYTES and not (int(pytorch_pickle.flag_bits) & 0x1):
                    try:
                        pickle_result.update(_inspect_pickle_bytes(archive.read(pytorch_pickle)))
                    except Exception as exc:
                        pickle_result.update({"parsed": False, "error": type(exc).__name__})
                else:
                    pickle_result["parsed"] = False
                    pickle_result["error"] = "inspection-boundary"
                report["format_details"]["pickle"] = pickle_result
                if not policy["allow_executable_serialization"]:
                    report["violations"].append(_violation(
                        "ART-EXECUTABLE-SERIALIZATION",
                        "Executable model serialization is prohibited by policy",
                        "high",
                        "The artifact contains a pickle-based model serialization. It was inspected statically and was never loaded or executed.",
                        pickle_result,
                    ))
            report["observations"].append(_observation(
                "ART-ARCHIVE-INVENTORY",
                "Archive central-directory metadata was inspected without extracting any member.",
                {"sample_members": sorted(member_names)[:30]},
            ))
    except (OSError, zipfile.BadZipFile) as exc:
        report["format"] = "invalid-zip"
        report["limitations"].append({"id": "ART-INVALID-ZIP", "summary": "The archive directory could not be parsed.", "evidence": {"error": type(exc).__name__}})
        if policy["require_valid_structure"]:
            report["violations"].append(_violation(
                "ART-INVALID-STRUCTURE",
                "Artifact structure is invalid",
                policy["severity"],
                "The uploaded artifact was declared for assessment but its ZIP structure is invalid.",
                {"format": "zip", "error": type(exc).__name__},
            ))


def _flatten_cyclonedx_components(raw: Iterable[Any], limit: int = 100_000) -> list[dict[str, Any]]:
    pending = list(raw)
    result: list[dict[str, Any]] = []
    while pending and len(result) < limit:
        item = pending.pop(0)
        if not isinstance(item, dict):
            continue
        result.append(item)
        nested = item.get("components") or []
        if isinstance(nested, list):
            pending.extend(nested)
    return result


def _manifest_metadata(document: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool, bool]:
    if str(document.get("bomFormat") or "").casefold() == "cyclonedx":
        components = _flatten_cyclonedx_components(document.get("components") or [])
        records = [{
            "name": _safe_name(item.get("name")),
            "version": _safe_name(item.get("version")),
            "has_hash": bool(item.get("hashes")),
        } for item in components]
        metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
        provenance = bool(
            metadata.get("supplier")
            or metadata.get("manufacturer")
            or metadata.get("authors")
            or metadata.get("properties")
            or document.get("externalReferences")
        )
        signature = bool(document.get("signature"))
        return "cyclonedx-json", records, provenance, signature
    if document.get("spdxVersion"):
        packages = document.get("packages") if isinstance(document.get("packages"), list) else []
        records = [{
            "name": _safe_name(item.get("name")),
            "version": _safe_name(item.get("versionInfo")),
            "has_hash": bool(item.get("checksums")),
        } for item in packages if isinstance(item, dict)]
        creation = document.get("creationInfo") if isinstance(document.get("creationInfo"), dict) else {}
        provenance = bool(creation.get("creators") and creation.get("created") and document.get("documentNamespace"))
        signature = bool(document.get("signature") or document.get("annotations"))
        return "spdx-json", records, provenance, signature
    if document.get("lockfileVersion") is not None:
        records: list[dict[str, Any]] = []
        packages = document.get("packages")
        if isinstance(packages, dict):
            for location, item in packages.items():
                if not location or not isinstance(item, dict):
                    continue
                records.append({
                    "name": _safe_name(item.get("name") or location),
                    "version": _safe_name(item.get("version")),
                    "has_hash": bool(item.get("integrity")),
                })
        elif isinstance(document.get("dependencies"), dict):
            for name, item in document["dependencies"].items():
                item = item if isinstance(item, dict) else {}
                records.append({"name": _safe_name(name), "version": _safe_name(item.get("version")), "has_hash": bool(item.get("integrity"))})
        return "npm-package-lock", records, False, False
    return "json", [], False, bool(document.get("signature"))


def _evaluate_manifest_records(format_name: str, records: list[dict[str, Any]], provenance: bool, signature: bool, policy: dict[str, Any], report: dict[str, Any]) -> None:
    report["format"] = format_name
    missing_versions = [item["name"] or "unnamed" for item in records if not item.get("version")]
    missing_hashes = [item["name"] or "unnamed" for item in records if not item.get("has_hash")]
    report["format_details"] = {
        "component_count": len(records),
        "missing_version_count": len(missing_versions),
        "missing_hash_count": len(missing_hashes),
        "provenance_metadata_present": provenance,
        "signature_metadata_present": signature,
    }
    if policy["require_dependency_pinning"] and missing_versions:
        report["violations"].append(_violation(
            "ART-DEPENDENCY-UNPINNED",
            "Dependency versions are not fully pinned",
            policy["severity"],
            "One or more declared components do not contain an exact recorded version.",
            {"count": len(missing_versions), "sample": missing_versions[:30]},
        ))
    if policy["require_component_hashes"] and missing_hashes:
        report["violations"].append(_violation(
            "ART-COMPONENT-HASH-MISSING",
            "Component integrity hashes are incomplete",
            policy["severity"],
            "One or more declared components do not contain integrity hash metadata.",
            {"count": len(missing_hashes), "sample": missing_hashes[:30]},
        ))
    if policy["require_provenance_metadata"] and not provenance:
        report["violations"].append(_violation(
            "ART-PROVENANCE-MISSING",
            "Required provenance metadata is missing",
            policy["severity"],
            "The manifest does not contain the target-required supplier, creator, origin, or lifecycle metadata.",
            {"format": format_name},
        ))
    if policy["require_signature_metadata"] and not signature:
        report["violations"].append(_violation(
            "ART-SIGNATURE-MISSING",
            "Required signature metadata is missing",
            policy["severity"],
            "The manifest does not contain the signature metadata required by the target-owned policy. AdverScope does not claim cryptographic verification when only metadata is present.",
            {"format": format_name},
        ))


def _inspect_json(path: Path, policy: dict[str, Any], report: dict[str, Any]) -> bool:
    try:
        if path.stat().st_size > MAX_STATIC_TEXT_BYTES:
            report["limitations"].append({"id": "ART-TEXT-SIZE-BOUNDARY", "summary": "Structured text exceeds the static parser size boundary.", "evidence": {"maximum_bytes": MAX_STATIC_TEXT_BYTES}})
            return False
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            report["format"] = "json"
            report["limitations"].append({"id": "ART-JSON-ROOT", "summary": "JSON root is not an object and cannot be treated as a supported manifest.", "evidence": {}})
            return True
        format_name, records, provenance, signature = _manifest_metadata(document)
        _evaluate_manifest_records(format_name, records, provenance, signature, policy, report)
        if format_name == "json" and not records:
            report["limitations"].append({"id": "ART-UNRECOGNIZED-JSON", "summary": "JSON is valid but is not a recognized CycloneDX, SPDX, or package-lock manifest.", "evidence": {}})
        return True
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        report["format"] = "invalid-json"
        report["limitations"].append({"id": "ART-INVALID-JSON", "summary": "JSON structure could not be parsed.", "evidence": {"error": type(exc).__name__}})
        if policy["require_valid_structure"]:
            report["violations"].append(_violation(
                "ART-INVALID-STRUCTURE",
                "Artifact structure is invalid",
                policy["severity"],
                "The uploaded artifact was declared as structured evidence but is not valid JSON.",
                {"format": "json", "error": type(exc).__name__},
            ))
        return True


def _requirements_records(text: str) -> list[dict[str, Any]]:
    records = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        requirement = line.split(" #", 1)[0].strip()
        has_hash = "--hash=sha256:" in requirement.casefold() or bool(re.search(r"#sha256=[0-9a-f]{64}\b", requirement, re.IGNORECASE))
        immutable_vcs = bool(re.search(r"@[0-9a-f]{40}(?:#|$)", requirement, re.IGNORECASE))
        exact = bool(re.search(r"(?:===|==)\s*[^,;\s*]+", requirement)) or immutable_vcs
        name = re.split(r"[<>=!~@\s\[]", requirement, maxsplit=1)[0]
        records.append({"name": _safe_name(name or requirement), "version": "pinned" if exact else "", "has_hash": has_hash})
    return records


def _inspect_requirements(path: Path, policy: dict[str, Any], report: dict[str, Any]) -> None:
    try:
        if path.stat().st_size > MAX_STATIC_TEXT_BYTES:
            report["limitations"].append({"id": "ART-TEXT-SIZE-BOUNDARY", "summary": "Dependency text exceeds the static parser size boundary.", "evidence": {"maximum_bytes": MAX_STATIC_TEXT_BYTES}})
            return
        records = _requirements_records(path.read_text(encoding="utf-8"))
        _evaluate_manifest_records("python-requirements", records, False, False, policy, report)
    except (OSError, UnicodeDecodeError) as exc:
        report["format"] = "invalid-requirements"
        report["limitations"].append({"id": "ART-INVALID-TEXT", "summary": "Dependency text could not be parsed as UTF-8.", "evidence": {"error": type(exc).__name__}})
        if policy["require_valid_structure"]:
            report["violations"].append(_violation("ART-INVALID-STRUCTURE", "Artifact structure is invalid", policy["severity"], "The dependency manifest could not be parsed as text.", {"error": type(exc).__name__}))


def _inspect_safetensors(path: Path, policy: dict[str, Any], report: dict[str, Any]) -> None:
    report["format"] = "safetensors"
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            length_raw = handle.read(8)
            if len(length_raw) != 8:
                raise ValueError("missing-header-length")
            header_length = struct.unpack("<Q", length_raw)[0]
            if header_length < 2 or header_length > min(10 * 1024 * 1024, max(0, size - 8)):
                raise ValueError("invalid-header-length")
            header = json.loads(handle.read(header_length).decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError("invalid-header-root")
        tensors = [item for key, item in header.items() if key != "__metadata__" and isinstance(item, dict)]
        dtypes = sorted({_safe_name(item.get("dtype"), 40) for item in tensors if item.get("dtype")})
        report["format_details"] = {"header_bytes": int(header_length), "tensor_count": len(tensors), "dtypes": dtypes[:50], "metadata_present": isinstance(header.get("__metadata__"), dict)}
        report["observations"].append(_observation("ART-SAFETENSORS-HEADER", "Safetensors metadata was parsed without mapping or loading tensor data.", report["format_details"]))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        report["limitations"].append({"id": "ART-INVALID-SAFETENSORS", "summary": "Safetensors header could not be validated.", "evidence": {"error": str(exc)[:120]}})
        if policy["require_valid_structure"]:
            report["violations"].append(_violation("ART-INVALID-STRUCTURE", "Artifact structure is invalid", policy["severity"], "The safetensors header is malformed or inconsistent with the file size.", {"error": str(exc)[:120]}))


def _inspect_gguf(path: Path, policy: dict[str, Any], report: dict[str, Any]) -> None:
    report["format"] = "gguf"
    try:
        with path.open("rb") as handle:
            header = handle.read(24)
        if len(header) < 24 or header[:4] != b"GGUF":
            raise ValueError("invalid-gguf-header")
        version, tensor_count, metadata_count = struct.unpack("<IQQ", header[4:24])
        if version not in {1, 2, 3}:
            raise ValueError("unsupported-gguf-version")
        report["format_details"] = {"version": int(version), "tensor_count": int(tensor_count), "metadata_entry_count": int(metadata_count)}
        report["observations"].append(_observation("ART-GGUF-HEADER", "GGUF fixed header was parsed without loading model tensors.", report["format_details"]))
    except (OSError, ValueError, struct.error) as exc:
        report["limitations"].append({"id": "ART-INVALID-GGUF", "summary": "GGUF fixed header could not be validated.", "evidence": {"error": str(exc)[:120]}})
        if policy["require_valid_structure"]:
            report["violations"].append(_violation("ART-INVALID-STRUCTURE", "Artifact structure is invalid", policy["severity"], "The GGUF header is malformed or unsupported.", {"error": str(exc)[:120]}))


def scan_artifact(path: str | Path, artifact: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Perform bounded static inspection without importing or executing content."""

    source = Path(path)
    policy = validate_artifact_profile({"enabled": True, "cases": [case]})["cases"][0]
    actual_sha256, actual_size = _sha256_file(source)
    report: dict[str, Any] = {
        "scanner": {"id": ARTIFACT_SCANNER_ID, "version": ARTIFACT_SCANNER_VERSION, "execution": "local-static-no-load"},
        "artifact": {
            "id": str(artifact.get("id") or policy["artifact_id"]),
            "filename": _safe_name(artifact.get("filename")),
            "kind": str(artifact.get("kind") or "other"),
            "recorded_size_bytes": int(artifact.get("size_bytes") or 0),
            "actual_size_bytes": actual_size,
            "recorded_sha256": str(artifact.get("sha256") or ""),
            "actual_sha256": actual_sha256,
        },
        "policy": policy,
        "format": "unknown",
        "format_details": {},
        "observations": [],
        "violations": [],
        "limitations": [],
    }
    recorded_sha256 = str(artifact.get("sha256") or "").lower()
    if recorded_sha256 and recorded_sha256 != actual_sha256:
        report["violations"].append(_violation(
            "ART-STORAGE-INTEGRITY",
            "Stored artifact no longer matches its immutable inventory record",
            "critical",
            "The bytes available at execution time do not match the SHA-256 recorded when the artifact was uploaded.",
            {"recorded_sha256": recorded_sha256, "actual_sha256": actual_sha256},
        ))
    if int(artifact.get("size_bytes") or 0) and int(artifact["size_bytes"]) != actual_size:
        report["violations"].append(_violation(
            "ART-STORAGE-SIZE",
            "Stored artifact size changed after inventory",
            "critical",
            "The byte length available at execution time differs from the immutable upload record.",
            {"recorded_size_bytes": int(artifact["size_bytes"]), "actual_size_bytes": actual_size},
        ))
    if policy["expected_sha256"]:
        if policy["expected_sha256"] != actual_sha256:
            report["violations"].append(_violation(
                "ART-DIGEST-MISMATCH",
                "Artifact digest does not match the approved baseline",
                "critical",
                "The computed SHA-256 differs from the exact target-owned digest snapshotted for this assessment.",
                {"expected_sha256": policy["expected_sha256"], "actual_sha256": actual_sha256},
            ))
        else:
            report["observations"].append(_observation("ART-DIGEST-MATCH", "Artifact SHA-256 matches the approved baseline.", {"sha256": actual_sha256}))

    logical_filename = str(artifact.get("filename") or source.name)
    suffix = Path(logical_filename).suffix.casefold()
    prefix = b""
    try:
        with source.open("rb") as handle:
            prefix = handle.read(32)
    except OSError as exc:
        report["limitations"].append({"id": "ART-READ-ERROR", "summary": "Artifact bytes could not be read.", "evidence": {"error": type(exc).__name__}})
    if prefix.startswith(b"PK\x03\x04") or zipfile.is_zipfile(source):
        _inspect_zip(source, policy, report)
    elif suffix == ".safetensors":
        _inspect_safetensors(source, policy, report)
    elif prefix.startswith(b"GGUF") or suffix == ".gguf":
        _inspect_gguf(source, policy, report)
    elif suffix == ".json" or prefix.lstrip().startswith((b"{", b"[")):
        _inspect_json(source, policy, report)
    elif artifact.get("kind") == "dependency-manifest" or (suffix in {".txt", ".in"} and "requirement" in logical_filename.casefold()):
        _inspect_requirements(source, policy, report)
    elif suffix in SERIALIZATION_EXTENSIONS:
        report["format"] = "pickle-or-executable-serialization"
        details: dict[str, Any] = {"extension": suffix, "inspected_bytes": min(actual_size, MAX_PICKLE_INSPECTION_BYTES)}
        if actual_size <= MAX_PICKLE_INSPECTION_BYTES:
            try:
                details.update(_inspect_pickle_bytes(source.read_bytes()))
            except OSError as exc:
                details.update({"parsed": False, "error": type(exc).__name__})
        else:
            details.update({"parsed": False, "error": "inspection-boundary"})
        report["format_details"] = details
        if not policy["allow_executable_serialization"]:
            report["violations"].append(_violation(
                "ART-EXECUTABLE-SERIALIZATION",
                "Executable model serialization is prohibited by policy",
                "high",
                "The artifact uses a serialization family that may invoke code when loaded. AdverScope inspected bytes only and never deserialized the artifact.",
                details,
            ))
    else:
        report["limitations"].append({"id": "ART-UNSUPPORTED-FORMAT", "summary": "No format-specific parser is available; digest and size controls were still evaluated.", "evidence": {"extension": suffix or "none"}})

    if policy["require_provenance_metadata"] and report["format"] not in {"cyclonedx-json", "spdx-json", "npm-package-lock", "python-requirements", "json", "invalid-json"}:
        report["violations"].append(_violation(
            "ART-PROVENANCE-MISSING",
            "Required provenance metadata is unavailable",
            policy["severity"],
            "The selected binary format does not expose target-required provenance metadata to this bounded static parser. Supply a supported signed manifest or AI-BOM as a separate assessment artifact.",
            {"format": report["format"]},
        ))
    if policy["require_signature_metadata"] and report["format"] not in {"cyclonedx-json", "spdx-json", "npm-package-lock", "python-requirements", "json", "invalid-json"}:
        report["violations"].append(_violation(
            "ART-SIGNATURE-MISSING",
            "Required signature metadata is unavailable",
            policy["severity"],
            "The selected binary format does not expose signature metadata to this bounded static parser. Metadata presence is not equivalent to cryptographic verification.",
            {"format": report["format"]},
        ))

    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def artifact_evaluation(report: dict[str, Any]) -> dict[str, Any]:
    violations = report.get("violations") or []
    limitations = report.get("limitations") or []
    vulnerable = bool(violations)
    conclusive = bool(vulnerable or not limitations)
    if vulnerable:
        highest = max((str(item.get("severity") or "medium") for item in violations), key=lambda value: SEVERITY_RANK.get(value, 0))
        summary = "Static artifact policy failed; deterministic violation evidence was recorded."
        classification = "deterministic-policy-violation"
        reason = "The immutable artifact bytes violated one or more explicit target-owned integrity or supply-chain requirements."
    elif conclusive:
        highest = "info"
        summary = "The artifact satisfied every configured static supply-chain control evaluated by this parser."
        classification = "control-held"
        reason = "All applicable configured checks completed without a policy violation."
    else:
        highest = "info"
        summary = "Static artifact assessment is incomplete; no vulnerability was established."
        classification = "inconclusive"
        reason = "One or more format or inspection limitations prevented complete evaluation of the configured artifact policy."
    return {
        "vulnerable": vulnerable,
        "severity": highest,
        "confidence": 0.99 if vulnerable else 0.95 if conclusive else 0.5,
        "title": "Supply-chain artifact policy violation" if vulnerable else "Supply-chain artifact control assessment",
        "summary": summary,
        "reasoning": reason,
        "evaluator": "deterministic-native-artifact-scanner",
        "direct_evidence": vulnerable,
        "detected_signals": [str(item.get("rule_id")) for item in violations],
        "artifact_report_sha256": report.get("report_sha256", ""),
        "artifact_id": (report.get("artifact") or {}).get("id", ""),
        "artifact_format": report.get("format", "unknown"),
        "artifact_violations": violations,
        "artifact_limitations": limitations,
        "automation_validation": {"conclusive": conclusive, "classification": classification, "reason": reason},
        "evidence_assurance": {
            "level": "deterministic-artifact-proof" if vulnerable or conclusive else "bounded-static-observation",
            "finding_eligible": vulnerable,
            "confirmation_state": "deterministic" if vulnerable else "control-held" if conclusive else "inconclusive",
            "basis": "Verdict derives from local byte hashing and bounded static parsing; no artifact content was loaded or executed.",
            "requires_human_confirmation": not conclusive,
        },
    }
