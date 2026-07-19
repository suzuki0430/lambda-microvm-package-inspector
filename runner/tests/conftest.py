"""Shared paths and report helpers for runner tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from package_inspector.catalog import Catalog, load_catalog
from package_inspector.types import JSONObject


@pytest.fixture(scope="session")
def repository_root() -> Path:
    """Return the repository root containing generated fixture artifacts."""

    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def catalog(repository_root: Path) -> Catalog:
    """Load the immutable local npm fixture catalog."""

    return load_catalog(repository_root / "fixtures" / "catalog.json")


@pytest.fixture(scope="session")
def report_validator(repository_root: Path) -> Callable[[JSONObject], None]:
    """Return a typed report validator with RFC 3339 checks enabled."""

    schema = (
        repository_root / "api" / "report-schema" / "report.schema.json"
    ).read_text(encoding="utf-8")
    validator = Draft202012Validator(
        json.loads(schema),
        format_checker=FormatChecker(),
    )

    def validate(report: JSONObject) -> None:
        """Validate one report while containing untyped jsonschema internals."""

        validator.validate(report)  # pyright: ignore[reportUnknownMemberType]

    return validate
