"""Tests for the immutable fixture allowlist and artifact integrity checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from package_inspector.catalog import Catalog, CatalogError, load_catalog


def test_catalog_resolves_exact_good_fixture(catalog: Catalog) -> None:
    """An exact allowlisted coordinate resolves to its verified tarball."""

    entry = catalog.resolve("npm", "@demo/good", "1.0.0")

    assert entry.artifact_path.name.endswith(".tgz")
    assert entry.size_bytes == entry.artifact_path.stat().st_size


def test_catalog_rejects_non_allowlisted_version(catalog: Catalog) -> None:
    """A package version absent from the catalog cannot reach npm."""

    with pytest.raises(CatalogError, match="not allowlisted"):
        catalog.resolve("npm", "@demo/good", "9.9.9")


def test_catalog_rejects_modified_artifact(tmp_path: Path, catalog: Catalog) -> None:
    """A changed tarball is rejected before any static or dynamic execution."""

    original = catalog.resolve("npm", "@demo/good", "1.0.0")
    artifact = tmp_path / original.artifact_path.name
    artifact.write_bytes(original.artifact_path.read_bytes() + b"tampered")
    document = {
        "schemaVersion": "1.0.0",
        "entries": [
            {
                "ecosystem": "npm",
                "name": "@demo/good",
                "version": "1.0.0",
                "artifact": artifact.name,
                "sha256": original.sha256,
                "sizeBytes": artifact.stat().st_size,
            }
        ],
    }
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(document), encoding="utf-8")

    tampered_catalog = load_catalog(catalog_path)
    with pytest.raises(CatalogError, match="SHA-256"):
        tampered_catalog.resolve("npm", "@demo/good", "1.0.0")
