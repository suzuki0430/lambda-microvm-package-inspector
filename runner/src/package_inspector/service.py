"""Expose the one-scan-per-MicroVM runner over a minimal bounded HTTP API."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

from package_inspector.inspector import Inspector
from package_inspector.types import ExecutionLimits, JSONObject

MAX_REQUEST_BYTES = 16 * 1024
SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
LIFECYCLE_PREFIX = "/aws/lambda-microvms/runtime/v1/"
LIFECYCLE_HOOKS = frozenset(
    {"ready", "validate", "run", "resume", "suspend", "terminate"}
)


@dataclass(slots=True)
class ScanRecord:
    """Hold the state and optional report for the MicroVM's single scan."""

    scan_id: str
    state: str
    report: JSONObject | None = None
    error: str | None = None


class ScanManager:
    """Accept exactly one scan and run it outside the HTTP request thread."""

    def __init__(self, inspector: Inspector) -> None:
        """Initialize an empty single-scan state machine for one inspector."""

        self._inspector = inspector
        self._lock = threading.Lock()
        self._record: ScanRecord | None = None

    def accept(self, request: JSONObject) -> ScanRecord:
        """Validate and accept the MicroVM's only scan.

        Args:
            request: Strict JSON request containing package name, version, and timeout.

        Returns:
            Newly accepted scan record.

        Raises:
            ValueError: If input is malformed or a scan was already accepted.
        """

        scan_id, ecosystem, name, version, timeout = _validate_scan_request(request)
        with self._lock:
            if self._record is not None:
                if self._record.scan_id == scan_id:
                    return self._record
                raise ValueError("this MicroVM has already accepted a scan")
            record = ScanRecord(scan_id=scan_id, state="accepted")
            self._record = record

        thread = threading.Thread(
            target=self._run,
            args=(record, ecosystem, name, version, timeout),
            name=f"scan-{record.scan_id}",
            daemon=True,
        )
        thread.start()
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        """Return a snapshot of the accepted scan record by identifier."""

        with self._lock:
            if self._record is None or self._record.scan_id != scan_id:
                return None
            return ScanRecord(
                scan_id=self._record.scan_id,
                state=self._record.state,
                report=self._record.report,
                error=self._record.error,
            )

    def _run(
        self, record: ScanRecord, ecosystem: str, name: str, version: str, timeout: int
    ) -> None:
        """Execute inspection and publish terminal state without leaking tracebacks."""

        with self._lock:
            record.state = "inspecting"
        try:
            report = self._inspector.inspect(
                ecosystem=ecosystem,
                name=name,
                version=version,
                limits=ExecutionLimits(timeout_seconds=timeout),
                scan_id=record.scan_id,
            )
        except Exception as error:
            with self._lock:
                record.state = "failed"
                record.error = f"{type(error).__name__}: {str(error)[:512]}"
            return
        with self._lock:
            record.report = report
            record.state = "completed"


def make_handler(manager: ScanManager) -> type[BaseHTTPRequestHandler]:
    """Create a request handler bound to one ScanManager instance."""

    class Handler(BaseHTTPRequestHandler):
        """Handle the fixed runner API without serving arbitrary files."""

        server_version = "PackageInspector/0.1"

        def do_GET(self) -> None:
            """Serve health, scan state, and completed report endpoints."""

            if self.path == "/healthz":
                self._json(HTTPStatus.OK, {"status": "ok"})
                return
            parts = [part for part in self.path.split("/") if part]
            if len(parts) not in {3, 4} or parts[:2] != ["v1", "scans"]:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            record = manager.get(parts[2])
            if record is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "scan not found"})
                return
            if len(parts) == 4:
                if parts[3] != "report":
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                if record.state != "completed" or record.report is None:
                    self._json(HTTPStatus.CONFLICT, {"error": "report not ready"})
                    return
                self._json(HTTPStatus.OK, record.report)
                return
            response: JSONObject = {
                "scanId": record.scan_id,
                "state": record.state,
            }
            if record.error is not None:
                response["error"] = record.error
            self._json(HTTPStatus.OK, response)

        def do_POST(self) -> None:
            """Acknowledge Lambda hooks or accept the MicroVM's single scan."""

            lifecycle_hook = self.path.removeprefix(LIFECYCLE_PREFIX)
            if self.path.startswith(LIFECYCLE_PREFIX):
                if lifecycle_hook not in LIFECYCLE_HOOKS:
                    self._json(
                        HTTPStatus.NOT_FOUND, {"error": "unknown lifecycle hook"}
                    )
                    return
                if not self._discard_bounded_body():
                    return
                self._json(HTTPStatus.OK, {"status": "ok", "hook": lifecycle_hook})
                return

            if self.path != "/v1/scans":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            length_text = self.headers.get("content-length")
            if length_text is None or not length_text.isdigit():
                self._json(
                    HTTPStatus.LENGTH_REQUIRED, {"error": "content-length required"}
                )
                return
            length = int(length_text)
            if length > MAX_REQUEST_BYTES:
                self._json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large"}
                )
                return
            try:
                raw = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
                return
            if not isinstance(raw, dict):
                self._json(
                    HTTPStatus.BAD_REQUEST, {"error": "request must be an object"}
                )
                return
            try:
                record = manager.accept(cast(JSONObject, raw))
            except ValueError as error:
                self._json(HTTPStatus.CONFLICT, {"error": str(error)[:512]})
                return
            self._json(
                HTTPStatus.ACCEPTED,
                {"scanId": record.scan_id, "state": record.state},
            )

        def _discard_bounded_body(self) -> bool:
            """Drain a lifecycle request body without logging or retaining it."""

            length_text = self.headers.get("content-length", "0")
            if not length_text.isdigit():
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid content-length"})
                return False
            length = int(length_text)
            if length > MAX_REQUEST_BYTES:
                self._json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": "request too large"},
                )
                return False
            if length:
                self.rfile.read(length)
            return True

        def log_message(self, format: str, *args: object) -> None:
            """Emit metadata-only access logs without headers or request bodies."""

            message = format % args
            print(f"runner-http {self.client_address[0]} {message}", flush=True)

        def _json(self, status: HTTPStatus, document: JSONObject) -> None:
            """Write one bounded JSON response with security headers."""

            body = json.dumps(
                document, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(manager: ScanManager, *, host: str = "0.0.0.0", port: int = 8080) -> None:
    """Serve requests until the MicroVM is terminated.

    Args:
        manager: One-scan state manager.
        host: Bind address. Lambda's ingress proxy targets the guest port.
        port: Port exposed through the port-scoped Lambda JWE token.
    """

    server = ThreadingHTTPServer((host, port), make_handler(manager))
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.25)


def _validate_scan_request(request: JSONObject) -> tuple[str, str, str, str, int]:
    """Strictly validate scan input and reject unknown capabilities."""

    if set(request) != {"scanId", "ecosystem", "package", "timeoutSeconds"}:
        raise ValueError("request contains missing or unknown fields")
    scan_id = request.get("scanId")
    ecosystem = request.get("ecosystem")
    package = request.get("package")
    timeout = request.get("timeoutSeconds")
    if not isinstance(scan_id, str) or SCAN_ID_PATTERN.fullmatch(scan_id) is None:
        raise ValueError("invalid scanId")
    if ecosystem != "npm" or not isinstance(package, dict):
        raise ValueError("only npm package objects are accepted")
    if set(package) != {"name", "version"}:
        raise ValueError("package requires exact name and version")
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not 1 <= len(name) <= 214:
        raise ValueError("invalid package name")
    if not isinstance(version, str) or not 1 <= len(version) <= 128:
        raise ValueError("invalid package version")
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 300
    ):
        raise ValueError("timeoutSeconds must be between 1 and 300")
    return scan_id, "npm", name, version, timeout
