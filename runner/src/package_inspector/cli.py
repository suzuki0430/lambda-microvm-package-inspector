"""Command-line entry points for local inspection and MicroVM service mode."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from package_inspector.catalog import load_catalog
from package_inspector.inspector import Inspector, write_report_bundle
from package_inspector.service import ScanManager, serve
from package_inspector.types import ExecutionLimits


def build_parser() -> argparse.ArgumentParser:
    """Build the package-inspector command parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run one local allowlisted inspection")
    scan.add_argument("--catalog", type=Path, required=True)
    scan.add_argument("--package", required=True)
    scan.add_argument("--version", required=True)
    scan.add_argument("--timeout", type=int, default=90)
    scan.add_argument("--output", type=Path, required=True)

    server = subparsers.add_parser("serve", help="serve one scan inside a MicroVM")
    server.add_argument("--catalog", type=Path, required=True)
    server.add_argument("--workspace", type=Path, default=Path("/work/scans"))
    server.add_argument("--host", default="0.0.0.0")
    server.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a local scan or start the MicroVM HTTP service.

    Args:
        argv: Optional command-line arguments used by unit tests.

    Returns:
        Process exit status. Package install failure remains a successful scan
        and is represented inside report.json.
    """

    arguments = build_parser().parse_args(argv)
    catalog = load_catalog(arguments.catalog)
    if arguments.command == "scan":
        if not 1 <= arguments.timeout <= 300:
            raise SystemExit("--timeout must be between 1 and 300")
        report = Inspector(catalog).inspect(
            ecosystem="npm",
            name=arguments.package,
            version=arguments.version,
            limits=ExecutionLimits(timeout_seconds=arguments.timeout),
        )
        write_report_bundle(report, arguments.output)
        print(arguments.output / "report.json")
        return 0

    manager = ScanManager(Inspector(catalog, workspace_root=arguments.workspace))
    serve(manager, host=arguments.host, port=arguments.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
