"""Coordinate static and dynamic inspection into one deterministic report."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from package_inspector import __version__
from package_inspector.catalog import Catalog
from package_inspector.execution import run_npm_install
from package_inspector.filesystem import diff, snapshot
from package_inspector.static_analysis import inspect_npm_archive
from package_inspector.trace import credential_path_category
from package_inspector.types import (
    ExecutionLimits,
    ExecutionResult,
    JSONObject,
    JSONValue,
)

CANARY_TEMP_FILE = Path("/tmp/demo-canary.txt")
MAX_REPORT_BYTES = 2 * 1024 * 1024


class InspectionError(RuntimeError):
    """Raised when trusted inspection setup or report construction fails."""


class Inspector:
    """Run one allowlisted npm artifact in a fresh bounded workspace.

    Args:
        catalog: Immutable package allowlist with expected integrity metadata.
        workspace_root: Optional trusted directory for transient workspaces.

    The Inspector is intentionally stateless. The service layer enforces one
    scan per MicroVM, while local CLI callers may create separate Inspector
    instances for deterministic test runs.
    """

    def __init__(self, catalog: Catalog, workspace_root: Path | None = None) -> None:
        """Store the immutable catalog and optional trusted workspace root."""

        self._catalog = catalog
        self._workspace_root = workspace_root

    def inspect(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        limits: ExecutionLimits,
        scan_id: str | None = None,
    ) -> JSONObject:
        """Inspect one exact package and return JSON-safe evidence.

        Args:
            ecosystem: Must be ``npm`` in report schema version 1.
            name: Exact allowlisted package name.
            version: Exact allowlisted package version.
            limits: Hard execution and output limits.
            scan_id: Optional externally generated opaque identifier.

        Returns:
            Package inspection report conforming to schema version 1.0.0.

        Raises:
            CatalogError: If the package is not allowlisted or integrity fails.
            InspectionError: If trusted setup or package metadata is inconsistent.
        """

        entry = self._catalog.resolve(ecosystem, name, version)
        static = inspect_npm_archive(entry.artifact_path)
        _verify_subject(static.analysis, name=name, version=version)
        identifier = scan_id or str(uuid.uuid4())
        started_at = datetime.now(UTC)

        workspace_base = self._workspace_root
        if workspace_base is not None:
            workspace_base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="package-inspection-",
            dir=workspace_base,
        ) as temporary:
            workspace = Path(temporary)
            project = workspace / "project"
            observer = workspace / ".observer"
            project.mkdir(parents=True)
            observer.mkdir(parents=True)

            # The demo canary uses one fixed harmless path. Removing only this
            # explicit file makes local repeated runs deterministic; a fresh
            # MicroVM does not normally contain it.
            CANARY_TEMP_FILE.unlink(missing_ok=True)
            try:
                observed_roots = [project, workspace / "home", CANARY_TEMP_FILE]
                before = snapshot(observed_roots, excluded_prefixes=(observer,))

                execution = run_npm_install(
                    artifact_path=entry.artifact_path,
                    project_directory=project,
                    observer_directory=observer,
                    limits=limits,
                )
                after = snapshot(observed_roots, excluded_prefixes=(observer,))
                filesystem_events = diff(before, after)
                self_reported = _parse_canary_events(execution.stdout.text)
                dynamic = _dynamic_analysis(
                    execution=execution,
                    filesystem_events=filesystem_events,
                    self_reported=self_reported,
                )

                finished_at = datetime.now(UTC)
                report: JSONObject = {
                    "schemaVersion": "1.0.0",
                    "scan": {
                        "id": identifier,
                        "startedAt": _timestamp(started_at),
                        "finishedAt": _timestamp(finished_at),
                        "runnerVersion": __version__,
                        "policyVersion": "npm-demo-v1",
                    },
                    "subject": {
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                    },
                    "artifact": {
                        "filename": entry.artifact_path.name,
                        "sha256": entry.sha256,
                        "sizeBytes": entry.size_bytes,
                        "integrityVerified": True,
                    },
                    "environment": _environment(),
                    "staticAnalysis": static.analysis,
                    "dynamicAnalysis": dynamic,
                    "sbom": static.sbom,
                    "limits": {
                        "timeoutSeconds": limits.timeout_seconds,
                        "cpuSeconds": limits.cpu_seconds,
                        "stdoutBytes": limits.stdout_bytes,
                        "stderrBytes": limits.stderr_bytes,
                        "processes": limits.processes,
                        "fileBytes": limits.file_bytes,
                    },
                    "execution": {
                        "outcome": _execution_outcome(execution),
                        "exitCode": execution.exit_code,
                        "timedOut": execution.timed_out,
                        "killedForOutputLimit": execution.killed_for_output_limit,
                        "errors": list(execution.errors),
                    },
                }
                validate_report_size(report)
                return report
            finally:
                CANARY_TEMP_FILE.unlink(missing_ok=True)


def write_report_bundle(report: JSONObject, output_directory: Path) -> None:
    """Write normalized report and CycloneDX documents with restricted modes.

    Args:
        report: Valid package inspection report.
        output_directory: Trusted output directory selected by the operator.

    Raises:
        OSError: If the directory or output files cannot be written.
        InspectionError: If the report does not contain an SBOM object.
    """

    output_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    sbom = report.get("sbom")
    if not isinstance(sbom, dict):
        raise InspectionError("report is missing its SBOM document")
    _write_json(output_directory / "report.json", report)
    _write_json(output_directory / "sbom.cdx.json", cast(JSONObject, sbom))


def _write_json(path: Path, document: JSONObject) -> None:
    """Write stable UTF-8 JSON and restrict the resulting file mode."""

    path.write_text(
        f"{json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)}\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def validate_report_size(report: JSONObject) -> None:
    """Reject a report that cannot cross the bounded controller protocol."""

    encoded = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    if len(encoded) > MAX_REPORT_BYTES:
        raise InspectionError(f"report exceeds {MAX_REPORT_BYTES} bytes")


def _verify_subject(analysis: JSONObject, *, name: str, version: str) -> None:
    """Reject a catalog artifact whose internal identity does not match its key."""

    metadata = analysis.get("packageMetadata")
    if not isinstance(metadata, dict):
        raise InspectionError("static analysis did not produce package metadata")
    if metadata.get("name") != name or metadata.get("version") != version:
        raise InspectionError(
            "artifact package identity does not match its allowlisted catalog key"
        )


def _dynamic_analysis(
    *,
    execution: ExecutionResult,
    filesystem_events: list[JSONObject],
    self_reported: list[JSONObject],
) -> JSONObject:
    """Group syscall and explicit canary evidence into stable report categories."""

    processes: list[JSONValue] = []
    file_accesses: list[JSONValue] = []
    dns_events: list[JSONValue] = []
    network_events: list[JSONValue] = []
    environment_reads: list[JSONValue] = []

    for event in execution.trace_events:
        event_type = event.get("type")
        if event_type in {"process-exec", "process-child"}:
            processes.append(event)
        elif event_type == "file-open":
            file_accesses.append(event)
        elif event_type == "network-connect":
            network_events.append(event)

    for event in self_reported:
        event_type = event.get("canaryType")
        if event_type == "child-process":
            processes.append(event)
        elif event_type == "credential-path-open":
            file_accesses.append(event)
        elif event_type in {"dns-attempt", "dns-result"}:
            dns_events.append(event)
        elif event_type == "http-result":
            network_events.append(event)
        elif event_type == "environment-read":
            environment_reads.append(event)

    filesystem_values: list[JSONValue] = []
    filesystem_values.extend(filesystem_events)
    return {
        "filesystem": filesystem_values,
        "processes": processes,
        "fileAccesses": file_accesses,
        "dns": dns_events,
        "network": network_events,
        "environmentReads": environment_reads,
        "resources": {
            "wallTimeMs": execution.wall_time_ms,
            "userCpuMs": execution.user_cpu_ms,
            "systemCpuMs": execution.system_cpu_ms,
            "peakRssBytes": execution.peak_rss_bytes,
            "processEventCount": len(processes),
            "traceAvailable": execution.trace_available,
        },
        "output": {
            "stdout": execution.stdout.as_json(),
            "stderr": execution.stderr.as_json(),
        },
    }


def _parse_canary_events(stdout: str, *, max_events: int = 100) -> list[JSONObject]:
    """Parse explicitly labeled harmless fixture events from bounded stdout."""

    events: list[JSONObject] = []
    for line in stdout.splitlines():
        if not line.startswith("CANARY_EVENT "):
            continue
        try:
            loaded = json.loads(line.removeprefix("CANARY_EVENT "))
        except json.JSONDecodeError:
            continue
        if not isinstance(loaded, dict):
            continue
        raw = cast(JSONObject, loaded)
        canary_type = raw.get("type")
        if not isinstance(canary_type, str):
            continue
        event: JSONObject = {
            "eventId": f"canary-{len(events) + 1:04d}",
            "type": "canary-event",
            "canaryType": canary_type[:64],
            "evidenceType": "canary-self-report",
        }
        for key, value in raw.items():
            if key == "type":
                continue
            event[key[:64]] = _bounded_json(value)
        path = event.get("path")
        if isinstance(path, str):
            category = credential_path_category(path)
            if category is not None:
                event["credentialPathCategory"] = category
        events.append(event)
        if len(events) >= max_events:
            break
    return events


def _bounded_json(value: object) -> JSONValue:
    """Copy simple canary values without accepting recursive untrusted objects."""

    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:4096]
    return str(value)[:4096]


def _execution_outcome(execution: ExecutionResult) -> str:
    """Map process termination facts to the report's stable outcome enum."""

    if execution.timed_out:
        return "timed-out"
    if execution.killed_for_output_limit:
        return "killed"
    return "succeeded" if execution.exit_code == 0 else "failed"


def _environment() -> JSONObject:
    """Collect non-secret runtime versions needed to reproduce a scan."""

    return {
        "architecture": platform.machine() or "unknown",
        "operatingSystem": _operating_system(),
        "pythonVersion": platform.python_version(),
        "nodeVersion": _command_version(("node", "--version")),
        "npmVersion": _command_version(("npm", "--version")),
        "microvmImageVersion": os.environ.get(
            "INSPECTOR_MICROVM_IMAGE_VERSION", "local-development"
        )[:256],
    }


def _operating_system() -> str:
    """Return a bounded human-readable operating system identifier."""

    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.partition("=")[2].strip('"')[:128]
        except OSError:
            pass
    return f"{platform.system()} {platform.release()}"[:128]


def _command_version(command: tuple[str, ...]) -> str:
    """Run a fixed version command with a short timeout and bounded output."""

    executable = shutil.which(command[0])
    if executable is None:
        return "unavailable"
    try:
        result = subprocess.run(
            (executable, *command[1:]),
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    return (result.stdout or result.stderr).strip()[:64] or "unknown"


def _timestamp(value: datetime) -> str:
    """Format a UTC timestamp using JSON Schema date-time syntax."""

    return (
        value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
