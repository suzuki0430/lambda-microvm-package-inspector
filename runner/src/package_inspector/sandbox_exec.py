"""Apply process limits and drop privileges immediately before npm execution."""

from __future__ import annotations

import argparse
import os
import resource
import sys
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Build the internal sandbox wrapper argument parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    parser.add_argument("--processes", type=int, required=True)
    parser.add_argument("--cpu-seconds", type=int, required=True)
    parser.add_argument("--open-files", type=int, required=True)
    parser.add_argument("--file-bytes", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def apply_resource_limits(
    *,
    processes: int,
    cpu_seconds: int,
    open_files: int,
    file_bytes: int,
    process_account_isolated: bool,
) -> None:
    """Apply hard limits without constraining an unrelated shared user.

    ``RLIMIT_NPROC`` is counted across the process's real user rather than only
    across this inspection. Applying it while developing or testing under a
    shared host account can prevent npm from spawning any child at all. The
    process limit is therefore installed only when the wrapper is about to
    switch to the MicroVM's dedicated sandbox UID. The other limits are scoped
    to this process and remain active in every environment.

    Args:
        processes: Maximum processes owned by the dedicated sandbox UID.
        cpu_seconds: Maximum CPU seconds consumed by the process tree.
        open_files: Maximum simultaneously open file descriptors.
        file_bytes: Maximum size of files created by the process.
        process_account_isolated: Whether execution will switch to a dedicated
            real UID before npm starts.
    """

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    if (
        process_account_isolated
        and sys.platform.startswith("linux")
        and hasattr(resource, "RLIMIT_NPROC")
    ):
        resource.setrlimit(resource.RLIMIT_NPROC, (processes, processes))


def main(argv: Sequence[str] | None = None) -> int:
    """Apply rlimits, clear supplementary groups, drop UID/GID, and exec.

    Args:
        argv: Optional command-line arguments used by tests.

    Returns:
        Only returns a non-zero status when no command was supplied. Successful
        execution replaces this process with the requested command.

    Raises:
        OSError: If privilege dropping or exec fails. The parent runner captures
            this as bounded stderr and an execution failure.
    """

    arguments = build_parser().parse_args(argv)
    command = list(arguments.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return 2

    running_as_root = os.geteuid() == 0
    apply_resource_limits(
        processes=arguments.processes,
        cpu_seconds=arguments.cpu_seconds,
        open_files=arguments.open_files,
        file_bytes=arguments.file_bytes,
        process_account_isolated=running_as_root and arguments.uid is not None,
    )

    if arguments.gid is not None and running_as_root:
        os.setgroups([])
        os.setgid(arguments.gid)
    if arguments.uid is not None and running_as_root:
        os.setuid(arguments.uid)

    os.execvpe(command[0], command, dict(os.environ))
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
