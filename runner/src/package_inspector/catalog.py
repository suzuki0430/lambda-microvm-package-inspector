"""Load and validate the immutable package fixture catalog."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import cast

from package_inspector.types import CatalogEntry, JSONObject

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class CatalogError(ValueError):
    """Raised when a catalog is malformed or an artifact fails integrity checks."""


class Catalog:
    """Resolve exact npm package identities to trusted local artifacts.

    Args:
        entries: Validated immutable catalog entries.

    Raises:
        CatalogError: If duplicate package identities are provided.
    """

    def __init__(self, entries: list[CatalogEntry]) -> None:
        """Index validated entries and reject duplicate package coordinates."""

        self._entries: dict[tuple[str, str, str], CatalogEntry] = {}
        for entry in entries:
            if entry.key in self._entries:
                raise CatalogError(f"duplicate catalog entry: {entry.key}")
            self._entries[entry.key] = entry

    def resolve(self, ecosystem: str, name: str, version: str) -> CatalogEntry:
        """Resolve and integrity-check one exact package identity.

        Args:
            ecosystem: Exact ecosystem identifier.
            name: Exact npm package name.
            version: Exact npm package version.

        Returns:
            The immutable catalog entry after size and digest verification.

        Raises:
            CatalogError: If the identity is not allowlisted or integrity fails.
        """

        key = (ecosystem, name, version)
        try:
            entry = self._entries[key]
        except KeyError as error:
            raise CatalogError(
                f"package is not allowlisted: {name}@{version}"
            ) from error

        stat = entry.artifact_path.stat()
        if stat.st_size != entry.size_bytes:
            raise CatalogError(
                f"artifact size mismatch for {name}@{version}: "
                f"expected {entry.size_bytes}, got {stat.st_size}"
            )

        digest = _sha256(entry.artifact_path)
        if digest != entry.sha256:
            raise CatalogError(
                f"artifact SHA-256 mismatch for {name}@{version}: "
                f"expected {entry.sha256}, got {digest}"
            )
        return entry


def load_catalog(path: Path) -> Catalog:
    """Load a fixture catalog from disk.

    Args:
        path: Path to catalog.json. Relative artifacts are resolved beside it.

    Returns:
        A validated catalog.

    Raises:
        CatalogError: If JSON fields, artifact names, or digests are invalid.
    """

    try:
        document = cast(JSONObject, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"cannot load catalog {path}: {error}") from error

    if document.get("schemaVersion") != "1.0.0":
        raise CatalogError("unsupported catalog schemaVersion")
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        raise CatalogError("catalog entries must be an array")

    entries: list[CatalogEntry] = []
    for index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict):
            raise CatalogError(f"catalog entry {index} must be an object")
        entries.append(_parse_entry(path.parent, index, cast(JSONObject, raw_entry)))
    return Catalog(entries)


def _parse_entry(directory: Path, index: int, raw: JSONObject) -> CatalogEntry:
    """Validate one raw catalog entry without accepting arbitrary paths."""

    required = ("ecosystem", "name", "version", "artifact", "sha256", "sizeBytes")
    for field in required:
        if field not in raw:
            raise CatalogError(f"catalog entry {index} is missing {field}")

    ecosystem = raw["ecosystem"]
    name = raw["name"]
    version = raw["version"]
    artifact = raw["artifact"]
    digest = raw["sha256"]
    size_bytes = raw["sizeBytes"]
    if not isinstance(ecosystem, str):
        raise CatalogError(f"catalog entry {index} ecosystem must be a string")
    if not isinstance(name, str):
        raise CatalogError(f"catalog entry {index} name must be a string")
    if not isinstance(version, str):
        raise CatalogError(f"catalog entry {index} version must be a string")
    if not isinstance(artifact, str):
        raise CatalogError(f"catalog entry {index} artifact must be a string")
    if not isinstance(digest, str):
        raise CatalogError(f"catalog entry {index} sha256 must be a string")
    if not all((ecosystem, name, version, artifact, digest)):
        raise CatalogError(f"catalog entry {index} contains a non-string field")
    if ecosystem != "npm":
        raise CatalogError(f"catalog entry {index} uses unsupported ecosystem")
    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes < 0
    ):
        raise CatalogError(f"catalog entry {index} has invalid sizeBytes")
    if not SHA256_PATTERN.fullmatch(digest):
        raise CatalogError(f"catalog entry {index} has invalid sha256")

    artifact_path = Path(artifact)
    if artifact_path.is_absolute() or len(artifact_path.parts) != 1:
        raise CatalogError(f"catalog entry {index} artifact must be a filename")
    resolved = (directory / artifact_path).resolve(strict=True)
    if resolved.parent != directory.resolve(strict=True):
        raise CatalogError(f"catalog entry {index} escapes the catalog directory")

    return CatalogEntry(ecosystem, name, version, resolved, digest, size_bytes)


def _sha256(path: Path) -> str:
    """Stream a file into SHA-256 without loading unbounded input into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
