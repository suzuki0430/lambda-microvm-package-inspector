"""HTTP contract tests for Lambda lifecycle hooks and one-shot scan admission."""

from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Generator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import cast

from package_inspector.catalog import Catalog
from package_inspector.inspector import Inspector
from package_inspector.service import (
    LIFECYCLE_HOOKS,
    LIFECYCLE_PREFIX,
    ScanManager,
    make_handler,
)


@contextmanager
def _server(catalog: Catalog, workspace: Path) -> Generator[tuple[str, int]]:
    """Run the real request handler on an ephemeral loopback-only port."""

    manager = ScanManager(Inspector(catalog, workspace_root=workspace))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(manager))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = cast(tuple[str, int], server.server_address)
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_all_lambda_lifecycle_hooks_are_acknowledged(
    catalog: Catalog, tmp_path: Path
) -> None:
    """Image build and runtime hooks all return success with bounded bodies."""

    with _server(catalog, tmp_path) as (host, port):
        for hook in sorted(LIFECYCLE_HOOKS):
            connection = http.client.HTTPConnection(host, port, timeout=2)
            connection.request(
                "POST",
                f"{LIFECYCLE_PREFIX}{hook}",
                body=b'{"microvmId":"test"}',
                headers={"content-type": "application/json"},
            )
            response = connection.getresponse()
            body = json.loads(response.read())
            connection.close()

            assert response.status == 200
            assert body == {"status": "ok", "hook": hook}


def test_service_accepts_only_one_exact_scan(catalog: Catalog, tmp_path: Path) -> None:
    """A MicroVM cannot be reused for a second package or broader request."""

    payload = json.dumps(
        {
            "scanId": "test-idempotent-scan",
            "ecosystem": "npm",
            "package": {"name": "@demo/good", "version": "1.0.0"},
            "timeoutSeconds": 20,
        }
    )
    with _server(catalog, tmp_path) as (host, port):
        statuses: list[int] = []
        for request_body in (
            payload,
            payload,
            payload.replace("test-idempotent-scan", "different-scan"),
        ):
            connection = http.client.HTTPConnection(host, port, timeout=2)
            connection.request(
                "POST",
                "/v1/scans",
                body=request_body,
                headers={"content-type": "application/json"},
            )
            response = connection.getresponse()
            statuses.append(response.status)
            response.read()
            connection.close()

    assert statuses == [202, 202, 409]
