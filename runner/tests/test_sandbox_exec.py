"""Resource-limit tests for the trusted npm sandbox wrapper."""

from __future__ import annotations

import resource

import pytest

from package_inspector import sandbox_exec


def _capture_limits(monkeypatch: pytest.MonkeyPatch) -> dict[int, tuple[int, int]]:
    """Replace ``setrlimit`` with a recorder and return captured limits.

    Args:
        monkeypatch: Pytest helper used to restore the resource module after the
            test.

    Returns:
        A dictionary populated with each resource and its requested bounds.
    """

    captured: dict[int, tuple[int, int]] = {}

    def record_limit(resource_id: int, bounds: tuple[int, int]) -> None:
        """Record one resource limit without changing the test process."""

        captured[resource_id] = bounds

    monkeypatch.setattr(sandbox_exec.resource, "setrlimit", record_limit)
    monkeypatch.setattr(sandbox_exec.sys, "platform", "linux")
    return captured


def test_shared_process_account_skips_user_wide_process_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shared CI or developer UID must not receive ``RLIMIT_NPROC``."""

    captured = _capture_limits(monkeypatch)

    sandbox_exec.apply_resource_limits(
        processes=32,
        cpu_seconds=60,
        open_files=256,
        file_bytes=1_048_576,
        process_account_isolated=False,
    )

    assert resource.RLIMIT_NPROC not in captured
    assert captured[resource.RLIMIT_CPU] == (60, 60)
    assert captured[resource.RLIMIT_NOFILE] == (256, 256)
    assert captured[resource.RLIMIT_FSIZE] == (1_048_576, 1_048_576)
    assert captured[resource.RLIMIT_CORE] == (0, 0)


def test_dedicated_process_account_receives_process_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dedicated MicroVM sandbox UID receives the process-count bound."""

    captured = _capture_limits(monkeypatch)

    sandbox_exec.apply_resource_limits(
        processes=32,
        cpu_seconds=60,
        open_files=256,
        file_bytes=1_048_576,
        process_account_isolated=True,
    )

    assert captured[resource.RLIMIT_NPROC] == (32, 32)
