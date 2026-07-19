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

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_CPU, (arguments.cpu_seconds, arguments.cpu_seconds)
    )
    resource.setrlimit(
        resource.RLIMIT_NOFILE, (arguments.open_files, arguments.open_files)
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE, (arguments.file_bytes, arguments.file_bytes)
    )
    # RLIMIT_NPROC is counted across the real user. Applying the MicroVM's
    # dedicated-user limit during macOS development can block all child
    # processes because the interactive user already owns many processes.
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(
            resource.RLIMIT_NPROC, (arguments.processes, arguments.processes)
        )

    if arguments.gid is not None and os.geteuid() == 0:
        os.setgroups([])
        os.setgid(arguments.gid)
    if arguments.uid is not None and os.geteuid() == 0:
        os.setuid(arguments.uid)

    os.execvpe(command[0], command, dict(os.environ))
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
