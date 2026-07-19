"""End-to-end local tests for good and harmless canary npm fixtures."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from package_inspector.catalog import Catalog
from package_inspector.inspector import InspectionError, Inspector, validate_report_size
from package_inspector.types import ExecutionLimits, JSONObject


def _inspect(catalog: Catalog, workspace: Path, name: str) -> JSONObject:
    """Inspect one test package using production execution limits and code paths."""

    return Inspector(catalog, workspace_root=workspace).inspect(
        ecosystem="npm",
        name=name,
        version="1.0.0",
        limits=ExecutionLimits(timeout_seconds=20),
        scan_id=f"test-{name.rsplit('/', 1)[-1]}",
    )


def test_good_package_has_no_lifecycle_script(
    catalog: Catalog,
    report_validator: Callable[[JSONObject], None],
    tmp_path: Path,
) -> None:
    """The benign fixture installs successfully without canary evidence."""

    report = _inspect(catalog, tmp_path, "@demo/good")
    report_validator(report)

    execution = cast(JSONObject, report["execution"])
    static = cast(JSONObject, report["staticAnalysis"])
    dynamic = cast(JSONObject, report["dynamicAnalysis"])
    assert execution["outcome"] == "succeeded"
    assert static["lifecycleScripts"] == {}
    assert dynamic["environmentReads"] == []
    assert dynamic["dns"] == []


def test_canary_surfaces_bounded_expected_behavior(
    catalog: Catalog,
    report_validator: Callable[[JSONObject], None],
    tmp_path: Path,
) -> None:
    """The harmless canary produces visible file, process, DNS, and env evidence."""

    report = _inspect(catalog, tmp_path, "@demo/canary")
    report_validator(report)

    static = cast(JSONObject, report["staticAnalysis"])
    scripts = cast(JSONObject, static["lifecycleScripts"])
    dynamic = cast(JSONObject, report["dynamicAnalysis"])
    categories = ("processes", "fileAccesses", "dns", "network", "environmentReads")
    raw_canary_types = (
        event.get("canaryType")
        for category in categories
        for event in cast(list[JSONObject], dynamic[category])
    )
    canary_types = {value for value in raw_canary_types if isinstance(value, str)}
    assert scripts["postinstall"] == "node postinstall.js"
    assert {
        "child-process",
        "credential-path-open",
        "dns-attempt",
        "http-result",
        "environment-read",
    } <= canary_types
    assert any(
        event.get("path") == "/tmp/demo-canary.txt"
        for event in cast(list[JSONObject], dynamic["filesystem"])
    )


def test_oversized_report_is_rejected_before_transport() -> None:
    """The runner refuses evidence that exceeds the controller response bound."""

    report: JSONObject = {"oversized": "x" * (2 * 1024 * 1024)}
    with pytest.raises(InspectionError, match="report exceeds"):
        validate_report_size(report)
