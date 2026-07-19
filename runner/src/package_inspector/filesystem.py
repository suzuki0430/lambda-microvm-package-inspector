"""Create bounded filesystem snapshots and normalized difference events."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from package_inspector.types import JSONObject, JSONValue

MAX_SNAPSHOT_FILES = 10_000
MAX_HASH_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class FileState:
    """Describe one observed filesystem path without following symbolic links."""

    path: str
    kind: str
    mode: int
    size_bytes: int
    sha256: str | None
    link_target: str | None

    def as_json(self) -> JSONObject:
        """Return a JSON-safe file state."""

        return {
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
            "sizeBytes": self.size_bytes,
            "sha256": self.sha256,
            "linkTarget": self.link_target,
        }


def snapshot(
    roots: list[Path], *, excluded_prefixes: tuple[Path, ...] = ()
) -> dict[str, FileState]:
    """Snapshot selected roots with strict file count and hashing bounds.

    Args:
        roots: Files or directories to observe. Missing paths are ignored.
        excluded_prefixes: Observer-owned paths to omit from evidence.

    Returns:
        Mapping from normalized absolute path to immutable state.

    Raises:
        RuntimeError: If the total observed path count exceeds the safe limit.
    """

    states: dict[str, FileState] = {}
    excluded = tuple(path.absolute() for path in excluded_prefixes)
    for root in roots:
        absolute_root = root.absolute()
        if _is_excluded(absolute_root, excluded) or not absolute_root.exists():
            continue
        if absolute_root.is_dir() and not absolute_root.is_symlink():
            for directory, directory_names, file_names in os.walk(
                absolute_root, followlinks=False
            ):
                directory_path = Path(directory)
                directory_names[:] = [
                    name
                    for name in sorted(directory_names)
                    if not _is_excluded(directory_path / name, excluded)
                ]
                for name in sorted(file_names):
                    path = directory_path / name
                    if not _is_excluded(path, excluded):
                        _add_state(states, path)
                if directory_path != absolute_root:
                    _add_state(states, directory_path)
        else:
            _add_state(states, absolute_root)
    return states


def diff(before: dict[str, FileState], after: dict[str, FileState]) -> list[JSONObject]:
    """Return deterministic create, modify, and delete events."""

    events: list[JSONObject] = []
    index = 1
    for path in sorted(set(before) | set(after)):
        previous = before.get(path)
        current = after.get(path)
        operation: str | None = None
        if previous is None:
            operation = "create"
        elif current is None:
            operation = "delete"
        elif previous != current:
            operation = "modify"
        if operation is None:
            continue
        event: JSONObject = {
            "eventId": f"file-{index:04d}",
            "type": "filesystem",
            "evidenceType": "snapshot-diff",
            "operation": operation,
            "path": path,
            "before": previous.as_json() if previous else None,
            "after": current.as_json() if current else None,
        }
        events.append(event)
        index += 1
    return events


def _add_state(states: dict[str, FileState], path: Path) -> None:
    """Add one lstat-based path to a bounded snapshot."""

    if len(states) >= MAX_SNAPSHOT_FILES:
        raise RuntimeError(f"filesystem snapshot exceeds {MAX_SNAPSHOT_FILES} paths")
    try:
        metadata = path.lstat()
    except OSError:
        return

    mode = stat.S_IMODE(metadata.st_mode)
    digest: str | None = None
    target: str | None = None
    if stat.S_ISREG(metadata.st_mode):
        kind = "file"
        if metadata.st_size <= MAX_HASH_BYTES:
            digest = _sha256(path)
    elif stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
    elif stat.S_ISLNK(metadata.st_mode):
        kind = "symlink"
        try:
            target = os.readlink(path)
        except OSError:
            target = None
    else:
        kind = "other"

    normalized = str(path.absolute())
    states[normalized] = FileState(
        path=normalized,
        kind=kind,
        mode=mode,
        size_bytes=metadata.st_size,
        sha256=digest,
        link_target=target,
    )


def _sha256(path: Path) -> str | None:
    """Hash one bounded regular file, returning None on observation errors."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _is_excluded(path: Path, excluded: tuple[Path, ...]) -> bool:
    """Return whether a path is within an observer-owned excluded prefix."""

    absolute = path.absolute()
    return any(absolute == prefix or prefix in absolute.parents for prefix in excluded)


def file_events_to_json(events: list[JSONObject]) -> list[JSONValue]:
    """Widen filesystem event typing for composition into generic JSON."""

    return list(events)
