"""Run one npm installation with bounded output, time, and process resources."""

from __future__ import annotations

import hashlib
import os
import platform
import pwd
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from types import TracebackType

from package_inspector.trace import parse_trace_files
from package_inspector.types import (
    CapturedOutput,
    ExecutionLimits,
    ExecutionResult,
)


class _BoundedBuffer:
    """Accumulate a prefix of one byte stream and count all observed bytes."""

    def __init__(self, limit: int) -> None:
        """Initialize an empty buffer with a hard captured-byte limit."""

        self._limit = limit
        self._captured = bytearray()
        self.observed = 0

    def append(self, chunk: bytes) -> None:
        """Record a chunk while retaining at most the configured prefix."""

        self.observed += len(chunk)
        remaining = self._limit - len(self._captured)
        if remaining > 0:
            self._captured.extend(chunk[:remaining])

    @property
    def exceeded(self) -> bool:
        """Return whether observed bytes exceeded the capture limit."""

        return self.observed > self._limit

    def finish(self) -> CapturedOutput:
        """Create normalized output evidence from captured bytes."""

        captured = bytes(self._captured)
        return CapturedOutput(
            text=captured.decode("utf-8", errors="replace"),
            captured_bytes=len(captured),
            observed_bytes=self.observed,
            truncated=self.exceeded,
            captured_sha256=hashlib.sha256(captured).hexdigest(),
        )


class _SelectorContext:
    """Close a selector reliably without suppressing exceptions."""

    def __init__(self) -> None:
        """Create the platform-appropriate selector."""

        self.selector = selectors.DefaultSelector()

    def __enter__(self) -> selectors.BaseSelector:
        """Return the managed selector."""

        return self.selector

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        """Close the selector and allow any active exception to propagate."""

        self.selector.close()
        return False


def run_npm_install(
    *,
    artifact_path: Path,
    project_directory: Path,
    observer_directory: Path,
    limits: ExecutionLimits,
) -> ExecutionResult:
    """Execute an offline npm install and collect bounded behavioral evidence.

    Args:
        artifact_path: Integrity-verified local npm tarball.
        project_directory: Writable npm prefix owned by the sandbox user.
        observer_directory: Trusted directory for strace output.
        limits: Wall-clock, stream, process, and file limits.

    Returns:
        Normalized execution result even when npm fails, times out, or is killed.
    """

    project_directory.mkdir(parents=True, exist_ok=True)
    observer_directory.mkdir(parents=True, exist_ok=True)
    home_directory = project_directory.parent / "home"
    cache_directory = project_directory.parent / "npm-cache"
    home_directory.mkdir(parents=True, exist_ok=True)
    cache_directory.mkdir(parents=True, exist_ok=True)

    uid, gid = _sandbox_identity()
    if os.geteuid() == 0 and uid is not None and gid is not None:
        _chown_tree(project_directory.parent, uid, gid)

    npm_command = (
        "npm",
        "install",
        "--offline",
        "--no-audit",
        "--no-fund",
        "--foreground-scripts",
        "--ignore-scripts=false",
        "--prefix",
        str(project_directory),
        "--cache",
        str(cache_directory),
        str(artifact_path),
    )
    wrapper_command = _sandbox_wrapper(npm_command, limits, uid=uid, gid=gid)
    trace_prefix = observer_directory / "trace"
    trace_available = (
        platform.system() == "Linux" and shutil.which("strace") is not None
    )
    command = wrapper_command
    if trace_available:
        command = (
            "strace",
            "-ff",
            "-ttt",
            "-T",
            "-yy",
            "-s",
            "256",
            "-o",
            str(trace_prefix),
            "-e",
            "trace=process,file,network",
            *wrapper_command,
        )

    environment = _safe_environment(home_directory)
    before_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=project_directory,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stdout, stderr, timed_out, output_killed = _communicate_bounded(
        process,
        timeout_seconds=limits.timeout_seconds,
        stdout_limit=limits.stdout_bytes,
        stderr_limit=limits.stderr_bytes,
    )
    wall_time_ms = round((time.monotonic() - started) * 1000)
    after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)

    trace_events = (
        tuple(parse_trace_files(trace_prefix, max_events=10_000))
        if trace_available
        else ()
    )
    errors: list[str] = []
    if not trace_available:
        errors.append("strace unavailable on this operating system")
    return ExecutionResult(
        command=npm_command,
        exit_code=process.returncode,
        timed_out=timed_out,
        killed_for_output_limit=output_killed,
        stdout=stdout,
        stderr=stderr,
        wall_time_ms=wall_time_ms,
        user_cpu_ms=max(
            0, round((after_usage.ru_utime - before_usage.ru_utime) * 1000)
        ),
        system_cpu_ms=max(
            0, round((after_usage.ru_stime - before_usage.ru_stime) * 1000)
        ),
        peak_rss_bytes=_peak_rss_bytes(after_usage.ru_maxrss),
        trace_available=trace_available,
        trace_events=trace_events,
        errors=tuple(errors),
    )


def _communicate_bounded(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
) -> tuple[CapturedOutput, CapturedOutput, bool, bool]:
    """Drain process pipes incrementally and kill the group on hard limits."""

    if process.stdout is None or process.stderr is None:
        raise RuntimeError("process pipes were not created")
    stdout_buffer = _BoundedBuffer(stdout_limit)
    stderr_buffer = _BoundedBuffer(stderr_limit)
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    buffers: dict[int, _BoundedBuffer] = {
        stdout_fd: stdout_buffer,
        stderr_fd: stderr_buffer,
    }
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_killed = False
    group_killed = False

    with _SelectorContext() as selector:
        for descriptor in buffers:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0 and process.poll() is None:
                timed_out = True
                group_killed = _kill_process_group(process) or group_killed
            events = selector.select(timeout=max(0.01, min(0.1, remaining)))
            for key, _ in events:
                descriptor = key.fd
                try:
                    chunk = os.read(descriptor, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                buffer = buffers[descriptor]
                buffer.append(chunk)
                if buffer.exceeded and process.poll() is None:
                    output_killed = True
                    group_killed = _kill_process_group(process) or group_killed

            if process.poll() is not None and not events:
                for key in list(selector.get_map().values()):
                    descriptor = key.fd
                    try:
                        chunk = os.read(descriptor, 65_536)
                    except BlockingIOError:
                        chunk = b""
                    if chunk:
                        buffers[descriptor].append(chunk)
                    selector.unregister(descriptor)

    if process.poll() is None:
        group_killed = _kill_process_group(process) or group_killed
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    process.stdout.close()
    process.stderr.close()
    _ = group_killed
    return stdout_buffer.finish(), stderr_buffer.finish(), timed_out, output_killed


def _kill_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Terminate the entire untrusted process group, escalating after a grace period."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    return True


def _sandbox_wrapper(
    command: tuple[str, ...],
    limits: ExecutionLimits,
    *,
    uid: int | None,
    gid: int | None,
) -> tuple[str, ...]:
    """Build the fixed trusted wrapper command that applies rlimits and UID drop."""

    wrapper = [
        sys.executable,
        "-m",
        "package_inspector.sandbox_exec",
        "--processes",
        str(limits.processes),
        "--cpu-seconds",
        str(limits.cpu_seconds),
        "--open-files",
        str(limits.open_files),
        "--file-bytes",
        str(limits.file_bytes),
    ]
    if uid is not None and gid is not None:
        wrapper.extend(("--uid", str(uid), "--gid", str(gid)))
    wrapper.extend(("--", *command))
    return tuple(wrapper)


def _safe_environment(home_directory: Path) -> dict[str, str]:
    """Create a secret-free environment instead of inheriting the runner environment."""

    return {
        "HOME": str(home_directory),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_offline": "true",
        "npm_config_update_notifier": "false",
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
    }


def _sandbox_identity() -> tuple[int | None, int | None]:
    """Return the dedicated sandbox account only when running as root."""

    if os.geteuid() != 0:
        return None, None
    try:
        account = pwd.getpwnam("sandbox")
    except KeyError:
        return None, None
    return account.pw_uid, account.pw_gid


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    """Give the untrusted UID ownership only of its dedicated workspace."""

    os.chown(root, uid, gid)
    for directory, directory_names, file_names in os.walk(root):
        for name in (*directory_names, *file_names):
            try:
                os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)
            except OSError:
                continue


def _peak_rss_bytes(raw_peak_rss: int) -> int:
    """Normalize ru_maxrss units across macOS and Linux."""

    return raw_peak_rss if platform.system() == "Darwin" else raw_peak_rss * 1024
