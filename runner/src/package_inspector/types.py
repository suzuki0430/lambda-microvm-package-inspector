"""Shared typed models for the package inspection runner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """Describe one immutable package artifact allowed by the runner.

    Args:
        ecosystem: Package ecosystem identifier. MVP only accepts ``npm``.
        name: Exact npm package name.
        version: Exact package version.
        artifact_path: Absolute path to the local tarball.
        sha256: Expected lowercase SHA-256 digest.
        size_bytes: Expected tarball size in bytes.

    Example:
        >>> entry = CatalogEntry(
        ...     "npm", "@demo/good", "1.0.0", Path("x.tgz"), "a" * 64, 1
        ... )
        >>> entry.key
        ('npm', '@demo/good', '1.0.0')
    """

    ecosystem: str
    name: str
    version: str
    artifact_path: Path
    sha256: str
    size_bytes: int

    @property
    def key(self) -> tuple[str, str, str]:
        """Return the immutable lookup key for this catalog entry."""

        return (self.ecosystem, self.name, self.version)


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    """Bound resources consumed by one untrusted npm installation.

    Args:
        timeout_seconds: Wall-clock limit for the npm process group.
        cpu_seconds: Kernel-enforced CPU time limit inherited by each process.
        stdout_bytes: Maximum captured stdout bytes.
        stderr_bytes: Maximum captured stderr bytes.
        processes: Per-user process limit requested by the sandbox wrapper.
        file_bytes: Maximum size of a file created by the process.
        open_files: Maximum number of open file descriptors.
    """

    timeout_seconds: int = 90
    cpu_seconds: int = 60
    stdout_bytes: int = 65_536
    stderr_bytes: int = 65_536
    processes: int = 64
    file_bytes: int = 16 * 1024 * 1024
    open_files: int = 256


@dataclass(frozen=True, slots=True)
class CapturedOutput:
    """Represent bounded bytes captured from one process stream."""

    text: str
    captured_bytes: int
    observed_bytes: int
    truncated: bool
    captured_sha256: str

    def as_json(self) -> JSONObject:
        """Return a JSON-serializable representation."""

        return {
            "text": self.text,
            "capturedBytes": self.captured_bytes,
            "observedBytes": self.observed_bytes,
            "truncated": self.truncated,
            "capturedSHA256": self.captured_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Contain process execution evidence and normalized trace events."""

    command: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    killed_for_output_limit: bool
    stdout: CapturedOutput
    stderr: CapturedOutput
    wall_time_ms: int
    user_cpu_ms: int
    system_cpu_ms: int
    peak_rss_bytes: int
    trace_available: bool
    trace_events: tuple[JSONObject, ...]
    errors: tuple[str, ...]
