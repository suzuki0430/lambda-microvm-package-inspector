"""Perform bounded static inspection of npm tarballs without extraction."""

from __future__ import annotations

import json
import posixpath
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from package_inspector.types import JSONObject, JSONValue

MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_JSON_BYTES = 1024 * 1024
MAX_PATTERN_SCAN_BYTES = 2 * 1024 * 1024
MAX_PATTERN_FILE_BYTES = 256 * 1024

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("child-process", re.compile(r"\b(?:child_process|spawn|execFile|execSync)\b")),
    ("dynamic-code", re.compile(r"\b(?:eval|Function)\s*\(")),
    ("network-api", re.compile(r"\b(?:https?|net|dns)\b")),
    ("aws-credentials-path", re.compile(r"\.aws[/\\]credentials")),
    ("npmrc-path", re.compile(r"\.npmrc")),
    ("environment-reference", re.compile(r"\bprocess\.env\b")),
    ("shell-download-pipe", re.compile(r"\b(?:curl|wget)\b[^\n|]{0,256}\|")),
)


class StaticAnalysisError(ValueError):
    """Raised when an archive cannot be inspected safely and deterministically."""


@dataclass(frozen=True, slots=True)
class StaticAnalysisResult:
    """Contain normalized static package evidence and a compact CycloneDX SBOM."""

    analysis: JSONObject
    sbom: JSONObject


def inspect_npm_archive(artifact_path: Path) -> StaticAnalysisResult:
    """Inspect one npm tarball without writing archive members to disk.

    Args:
        artifact_path: Local, integrity-verified npm ``.tgz`` artifact.

    Returns:
        Normalized package metadata, archive warnings, patterns, and SBOM.

    Raises:
        StaticAnalysisError: If limits are exceeded or package.json is invalid.
    """

    warnings: list[str] = []
    files: list[str] = []
    patterns: list[JSONValue] = []
    package_document: JSONObject | None = None
    total_bytes = 0
    pattern_bytes = 0

    try:
        with tarfile.open(artifact_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_FILES:
                raise StaticAnalysisError(
                    f"archive file count exceeds {MAX_ARCHIVE_FILES}"
                )

            for member in members:
                normalized = _validate_member(member, warnings)
                files.append(normalized)
                if member.isfile():
                    total_bytes += member.size
                    if total_bytes > MAX_ARCHIVE_BYTES:
                        raise StaticAnalysisError(
                            f"archive size exceeds {MAX_ARCHIVE_BYTES} bytes"
                        )

                if normalized == "package/package.json":
                    package_document = _read_package_json(archive, member)

                if (
                    member.isfile()
                    and member.size <= MAX_PATTERN_FILE_BYTES
                    and pattern_bytes < MAX_PATTERN_SCAN_BYTES
                    and _is_text_candidate(normalized)
                ):
                    remaining = MAX_PATTERN_SCAN_BYTES - pattern_bytes
                    content = _read_member(archive, member, min(member.size, remaining))
                    pattern_bytes += len(content)
                    patterns.extend(_scan_patterns(normalized, content))
    except (OSError, tarfile.TarError) as error:
        raise StaticAnalysisError(f"cannot inspect npm archive: {error}") from error

    if package_document is None:
        raise StaticAnalysisError("archive does not contain package/package.json")

    scripts = _string_map(package_document.get("scripts"))
    dependencies = _string_map(package_document.get("dependencies"))
    license_value = package_document.get("license")
    license_name = license_value if isinstance(license_value, str) else None
    metadata = _selected_metadata(package_document)

    file_values: list[JSONValue] = []
    file_values.extend(sorted(files))
    warning_values: list[JSONValue] = []
    warning_values.extend(sorted(set(warnings)))
    analysis: JSONObject = {
        "packageMetadata": metadata,
        "files": file_values,
        "lifecycleScripts": scripts,
        "directDependencies": dependencies,
        "license": license_name,
        "patterns": patterns,
        "archiveWarnings": warning_values,
    }
    return StaticAnalysisResult(
        analysis=analysis,
        sbom=_build_sbom(package_document, dependencies, license_name),
    )


def _validate_member(member: tarfile.TarInfo, warnings: list[str]) -> str:
    """Normalize an archive member and record path or link hazards."""

    raw_name = member.name.replace("\\", "/")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or ".." in path.parts:
        warnings.append(f"unsafe archive path: {raw_name}")
    normalized = posixpath.normpath(raw_name).lstrip("/")
    if normalized in {"", "."}:
        warnings.append(f"empty archive path: {raw_name}")
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname.replace("\\", "/"))
        if link.is_absolute() or ".." in link.parts:
            warnings.append(f"unsafe archive link: {raw_name} -> {member.linkname}")
    if member.isdev() or member.isfifo():
        warnings.append(f"special archive entry: {raw_name}")
    return normalized


def _read_package_json(archive: tarfile.TarFile, member: tarfile.TarInfo) -> JSONObject:
    """Read and validate bounded package.json bytes from a tar member."""

    if member.size > MAX_PACKAGE_JSON_BYTES:
        raise StaticAnalysisError("package.json exceeds size limit")
    content = _read_member(archive, member, MAX_PACKAGE_JSON_BYTES)
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StaticAnalysisError(f"invalid package.json: {error}") from error
    if not isinstance(document, dict):
        raise StaticAnalysisError("package.json must contain a JSON object")
    return cast(JSONObject, document)


def _read_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int
) -> bytes:
    """Read at most ``limit`` bytes from one regular archive member."""

    source = archive.extractfile(member)
    if source is None:
        return b""
    with source:
        return source.read(limit)


def _is_text_candidate(path: str) -> bool:
    """Return whether a package file is useful for bounded textual rules."""

    return Path(path).suffix.lower() in {
        ".cjs",
        ".js",
        ".json",
        ".mjs",
        ".node-gyp",
        ".sh",
        ".ts",
    }


def _scan_patterns(path: str, content: bytes) -> list[JSONValue]:
    """Find rule identifiers without copying attacker-controlled source snippets."""

    text = content.decode("utf-8", errors="ignore")
    matches: list[JSONValue] = []
    for rule_id, pattern in PATTERNS:
        if pattern.search(text):
            matches.append({"ruleId": rule_id, "path": path})
    return matches


def _string_map(value: JSONValue | None) -> dict[str, JSONValue]:
    """Return sorted string-to-string entries from an untrusted JSON object."""

    if not isinstance(value, dict):
        return {}
    output: dict[str, JSONValue] = {}
    for key, raw in sorted(value.items()):
        if isinstance(raw, str):
            output[key[:256]] = raw[:4096]
    return output


def _selected_metadata(document: JSONObject) -> JSONObject:
    """Copy only bounded, report-relevant package metadata fields."""

    output: JSONObject = {}
    for field in ("name", "version", "description", "main", "type"):
        value = document.get(field)
        if isinstance(value, str):
            output[field] = value[:4096]
    engines = _string_map(document.get("engines"))
    if engines:
        output["engines"] = engines
    return output


def _build_sbom(
    document: JSONObject,
    dependencies: dict[str, JSONValue],
    license_name: str | None,
) -> JSONObject:
    """Build a compact CycloneDX document from immutable fixture metadata."""

    name = document.get("name") if isinstance(document.get("name"), str) else "unknown"
    version = (
        document.get("version")
        if isinstance(document.get("version"), str)
        else "unknown"
    )
    component: JSONObject = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:npm/{name}@{version}",
    }
    if license_name is not None:
        component["licenses"] = [{"license": {"id": license_name}}]

    components: list[JSONValue] = []
    for dependency_name, dependency_version in sorted(dependencies.items()):
        components.append(
            {
                "type": "library",
                "name": dependency_name,
                "version": dependency_version,
                "purl": f"pkg:npm/{dependency_name}@{dependency_version}",
                "scope": "required",
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": component},
        "components": components,
    }
