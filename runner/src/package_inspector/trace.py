"""Parse a deliberately small, bounded subset of Linux strace output."""

from __future__ import annotations

import re
from pathlib import Path

from package_inspector.types import JSONObject

TIMESTAMP = r"(?P<timestamp>\d+\.\d+)"
EXECVE_PATTERN = re.compile(
    rf'^{TIMESTAMP}\s+execve\("(?P<executable>(?:[^"\\]|\\.)*)",\s*'
    r"\[(?P<arguments>.*?)\],.*?\)\s+=\s+(?P<result>.+)$"
)
OPEN_PATTERN = re.compile(
    rf"^{TIMESTAMP}\s+(?P<call>open|openat|openat2)\([^\n]*?"
    r'"(?P<path>(?:[^"\\]|\\.)*)"[^\n]*\)\s+=\s+(?P<result>.+)$'
)
CONNECT_PATTERN = re.compile(
    rf"^{TIMESTAMP}\s+connect\([^\n]*?sin_port=htons\((?P<port>\d+)\),\s*"
    r'sin_addr=inet_addr\("(?P<address>[^"\\]+)"\)[^\n]*\)\s+=\s+'
    r"(?P<result>.+)$"
)
CLONE_PATTERN = re.compile(
    rf"^{TIMESTAMP}\s+(?P<call>clone|clone3|fork|vfork)\([^\n]*\)\s+=\s+"
    r"(?P<child>\d+)$"
)


def parse_trace_files(prefix: Path, *, max_events: int = 10_000) -> list[JSONObject]:
    """Parse matching ``strace -ff -o PREFIX`` files deterministically.

    Args:
        prefix: Output prefix provided to strace.
        max_events: Hard ceiling on normalized events.

    Returns:
        Supported process, file-open, and IPv4 connect events.
    """

    events: list[JSONObject] = []
    for trace_path in sorted(prefix.parent.glob(f"{prefix.name}*")):
        pid = _pid_from_trace_path(trace_path, prefix)
        try:
            lines = trace_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            continue
        for line in lines:
            event = parse_trace_line(line, pid=pid, event_index=len(events) + 1)
            if event is not None:
                events.append(event)
                if len(events) >= max_events:
                    return events
    return events


def parse_trace_line(
    line: str, *, pid: int | None, event_index: int
) -> JSONObject | None:
    """Parse one supported strace line into stable JSON evidence.

    Args:
        line: One raw line emitted by strace with epoch timestamps.
        pid: Process ID inferred from the ``-ff`` filename.
        event_index: Stable index used for event identifiers.

    Returns:
        A normalized event, or ``None`` for unsupported syscalls.
    """

    exec_match = EXECVE_PATTERN.match(line)
    if exec_match:
        return {
            "eventId": f"trace-{event_index:04d}",
            "type": "process-exec",
            "evidenceType": "strace",
            "pid": pid,
            "timestamp": exec_match.group("timestamp"),
            "executable": _unescape(exec_match.group("executable"))[:4096],
            "argumentsRaw": exec_match.group("arguments")[:8192],
            "result": exec_match.group("result")[:256],
        }

    open_match = OPEN_PATTERN.match(line)
    if open_match:
        path = _unescape(open_match.group("path"))[:4096]
        event: JSONObject = {
            "eventId": f"trace-{event_index:04d}",
            "type": "file-open",
            "evidenceType": "strace",
            "pid": pid,
            "timestamp": open_match.group("timestamp"),
            "operation": open_match.group("call"),
            "path": path,
            "result": open_match.group("result")[:256],
        }
        category = credential_path_category(path)
        if category is not None:
            event["credentialPathCategory"] = category
        return event

    connect_match = CONNECT_PATTERN.match(line)
    if connect_match:
        return {
            "eventId": f"trace-{event_index:04d}",
            "type": "network-connect",
            "evidenceType": "strace",
            "pid": pid,
            "timestamp": connect_match.group("timestamp"),
            "destinationIP": connect_match.group("address"),
            "destinationPort": int(connect_match.group("port")),
            "result": connect_match.group("result")[:256],
        }

    clone_match = CLONE_PATTERN.match(line)
    if clone_match:
        return {
            "eventId": f"trace-{event_index:04d}",
            "type": "process-child",
            "evidenceType": "strace",
            "pid": pid,
            "childPid": int(clone_match.group("child")),
            "timestamp": clone_match.group("timestamp"),
            "operation": clone_match.group("call"),
        }
    return None


def credential_path_category(path: str) -> str | None:
    """Classify well-known credential paths without reading their contents."""

    normalized = path.replace("\\", "/")
    if normalized.endswith("/.aws/credentials") or normalized.endswith("/.aws/config"):
        return "aws-shared-credentials"
    if normalized.endswith("/.npmrc"):
        return "npm-credentials"
    if normalized.endswith("/.pypirc") or normalized.endswith("/pip.conf"):
        return "python-package-credentials"
    if normalized.endswith("/.config/gcloud/application_default_credentials.json"):
        return "gcp-application-default-credentials"
    return None


def _pid_from_trace_path(path: Path, prefix: Path) -> int | None:
    """Extract a numeric PID from strace's output suffix."""

    suffix = path.name.removeprefix(prefix.name).lstrip(".")
    return int(suffix) if suffix.isdigit() else None


def _unescape(value: str) -> str:
    """Decode common strace quoted-string escapes without executing content."""

    return value.replace(r"\"", '"').replace(r"\\", "\\")
