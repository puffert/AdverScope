from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
import tomllib
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
PREVIEW_SOURCE_REQUIRED = {
    "README.md",
    "SECURITY.md",
    "RESPONSIBLE_USE.md",
    "docs/USER_MANUAL.md",
    "docs/TESTER_PREVIEW_GUIDE.md",
    "docs/TESTER_PREVIEW_COORDINATOR.md",
    "docs/milestone5/m5.0-preview-manifest.json",
    ".github/ISSUE_TEMPLATE/m5-tester-feedback.yml",
    ".github/workflows/ci.yml",
    "scripts/check_tester_preview.py",
    "scripts/build_motor_dataset.py",
    "scripts/run_motor_experiment.py",
    "training/README.md",
    "training/public-sources-v1.json",
    "training/configs/motor-v0.1.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_names(path: Path) -> list[str]:
    if path.suffix == ".whl" or path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(path, "r:*") as archive:
            return archive.getnames()
    raise ValueError(f"unsupported release archive: {path.name}")


def unsafe_archive_entries(names: Iterable[str]) -> list[str]:
    unsafe: list[str] = []
    protected_directories = {"data", "output", "tmp", "validation", "node_modules", ".git", ".venv", "_browser_sessions"}
    protected_names = {".env", "local-config.json", "model-providers.json", "restore-in-progress.json"}
    protected_suffixes = {".sqlite3", ".db", ".pem", ".key", ".p12", ".pfx"}
    for raw_name in names:
        normalized = str(raw_name).replace("\\", "/").strip("/")
        path = PurePosixPath(normalized)
        lowered = [part.casefold() for part in path.parts]
        filename = path.name.casefold()
        if not normalized or path.is_absolute() or ".." in path.parts:
            unsafe.append(raw_name)
            continue
        if any(part in protected_directories for part in lowered):
            unsafe.append(raw_name)
            continue
        if filename in protected_names or filename.startswith(".env.") or (filename.startswith("local-config.") and filename != "local-config.example.json"):
            unsafe.append(raw_name)
            continue
        if any(filename.endswith(suffix) for suffix in protected_suffixes) or ".sqlite3-" in filename:
            unsafe.append(raw_name)
    return unsafe


def verify_distribution_archive(path: Path, version: str) -> dict[str, Any]:
    if version not in path.name.replace("-", "_"):
        raise ValueError(f"release archive is not versioned with {version}: {path.name}")
    names = _archive_names(path)
    unsafe = unsafe_archive_entries(names)
    if unsafe:
        raise ValueError(f"release archive contains protected local material: {', '.join(unsafe[:10])}")
    if not any(PurePosixPath(name).name == "LICENSE" for name in names):
        raise ValueError(f"release archive does not contain LICENSE: {path.name}")
    if path.name.endswith(".tar.gz"):
        normalized = {str(name).replace("\\", "/").strip("/") for name in names}
        missing = sorted(
            relative
            for relative in PREVIEW_SOURCE_REQUIRED
            if not any(name == relative or name.endswith(f"/{relative}") for name in normalized)
        )
        screenshot_names = {
            name
            for name in normalized
            if "/docs/images/manual/" in f"/{name}" and name.casefold().endswith(".jpg")
        }
        if missing:
            raise ValueError(f"source release is missing M5.0 preview assets: {', '.join(missing)}")
        if len(screenshot_names) < 14:
            raise ValueError(f"source release contains only {len(screenshot_names)} of 14 required manual screenshots")
    return {"filename": path.name, "sha256": sha256(path), "entries": len(names), "verified": True}


def _component(name: str, version: str, ecosystem: str, *, license_name: str = "") -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"pkg:{ecosystem}/{name}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}@{version}",
    }
    if license_name:
        component["licenses"] = [{"license": {"id": license_name}}]
    return component


def build_sbom(version: str) -> dict[str, Any]:
    python_lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    npm_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    components: dict[str, dict[str, Any]] = {}
    for package in python_lock.get("package") or []:
        name = str(package.get("name") or "")
        package_version = str(package.get("version") or "")
        if not name or not package_version or name == "adverscope":
            continue
        item = _component(name, package_version, "pypi")
        components[item["bom-ref"]] = item
    for package_path, package in (npm_lock.get("packages") or {}).items():
        if not package_path or not isinstance(package, dict):
            continue
        name = package_path.rsplit("node_modules/", 1)[-1]
        package_version = str(package.get("version") or "")
        if not name or not package_version:
            continue
        item = _component(name, package_version, "npm", license_name=str(package.get("license") or ""))
        components[item["bom-ref"]] = item
    serial_seed = hashlib.sha256((ROOT / "uv.lock").read_bytes() + (ROOT / "package-lock.json").read_bytes()).hexdigest()
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'adverscope:{version}:{serial_seed}')}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/adverscope@{version}",
                "name": "adverscope",
                "version": version,
                "purl": f"pkg:pypi/adverscope@{version}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            "properties": [{"name": "adverscope:browser-runtime-lock", "value": "package-lock.json"}],
        },
        "components": sorted(components.values(), key=lambda item: item["bom-ref"]),
    }


def build_release(output: Path) -> dict[str, Any]:
    from osai_security.release import PRODUCT_VERSION, release_manifest

    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError(f"release output directory must be empty: {output}")
    subprocess.run(["uv", "build", "--out-dir", str(output)], cwd=ROOT, check=True)
    archives = sorted([*output.glob("*.whl"), *output.glob("*.tar.gz")])
    if len(archives) != 2:
        raise ValueError("release build must produce exactly one wheel and one source archive")
    verified = [verify_distribution_archive(path, PRODUCT_VERSION) for path in archives]
    sbom_path = output / f"adverscope-{PRODUCT_VERSION}.cdx.json"
    sbom_path.write_text(json.dumps(build_sbom(PRODUCT_VERSION), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = output / f"adverscope-{PRODUCT_VERSION}.release.json"
    manifest = {
        **release_manifest(),
        "artifacts": [*verified, {"filename": sbom_path.name, "sha256": sha256(sbom_path), "verified": True}],
        "integrity": {
            "checksums": "SHA256SUMS",
            "sbom": sbom_path.name,
            "provenance": "official GitHub tag builds require a GitHub artifact attestation",
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_targets = [*archives, sbom_path, manifest_path]
    checksums_path = output / "SHA256SUMS"
    checksums_path.write_text("".join(f"{sha256(path)}  {path.name}\n" for path in checksum_targets), encoding="utf-8")
    return {"version": PRODUCT_VERSION, "output": str(output), "artifacts": [path.name for path in [*checksum_targets, checksums_path]]}


def verify_release(output: Path) -> dict[str, Any]:
    from osai_security.release import PRODUCT_VERSION

    checksums = output / "SHA256SUMS"
    if not checksums.is_file():
        raise ValueError("SHA256SUMS is missing")
    verified: list[str] = []
    for line in checksums.read_text(encoding="utf-8").splitlines():
        expected, separator, filename = line.partition("  ")
        if not separator or not filename or not expected:
            raise ValueError("SHA256SUMS contains a malformed entry")
        path = output / filename
        if not path.is_file() or sha256(path) != expected:
            raise ValueError(f"release checksum verification failed: {filename}")
        verified.append(filename)
        if filename.endswith((".whl", ".tar.gz")):
            verify_distribution_archive(path, PRODUCT_VERSION)
    if not any(name.endswith(".cdx.json") for name in verified):
        raise ValueError("release SBOM is missing from checksums")
    if not any(name.endswith(".release.json") for name in verified):
        raise ValueError("release manifest is missing from checksums")
    return {"version": PRODUCT_VERSION, "verified": verified, "ok": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and verify clean AdverScope release artifacts")
    parser.add_argument("command", choices=["build", "verify"])
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()
    output = Path(args.output).expanduser().resolve()
    result = build_release(output) if args.command == "build" else verify_release(output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
