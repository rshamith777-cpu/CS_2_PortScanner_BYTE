"""Command-line interface (CLI) for PortScope."""

import argparse
import sys
from typing import Optional

from .models import PortStatus, ScanConfig
from .reporters import export_csv, export_json
from .scanner import PortScanner
from .validation import (
    resolve_and_validate_target,
    validate_format_and_output,
    validate_ports,
    validate_timeout,
    validate_workers,
)

NOTICE_BANNER = """===================================================================
[*] PortScope - Authorized TCP Port Scanner
[!] NOTICE: Authorized testing only. Scan targets you own or have
    explicit written permission to test (e.g., localhost).
==================================================================="""


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser with comprehensive help."""
    parser = argparse.ArgumentParser(
        prog="portscope",
        description="A Python TCP port scanner for authorized security testing.",
        epilog="Example: portscope --target 127.0.0.1 --ports 80,443,8000-8010 --format json --output report.json",
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target host or IP address (e.g., 127.0.0.1 or localhost)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="Port specification: single (80), comma-separated (22,80,443), range (1-100), or mixed (22,80,8000-8010)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.5,
        help="Connection timeout in seconds per port (default: 2.5)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent worker threads (1-100, default: 10)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output report format: json or csv (default: json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="File path to save the structured scan report",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress live port result printing; print summary only",
    )

    return parser


def main(argv: Optional[list] = None) -> int:
    """CLI application entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    print(NOTICE_BANNER)

    # Validate inputs safely without raw Python stack traces on user input mistakes
    try:
        resolved_ip = resolve_and_validate_target(args.target)
        port_list = validate_ports(args.ports)
        timeout = validate_timeout(args.timeout)
        workers = validate_workers(args.workers)
        fmt, output_path = validate_format_and_output(args.format, args.output)
    except ValueError as val_err:
        print(f"\n[!] Input Validation Error: {val_err}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"\n[!] Unexpected Error during validation: {exc}", file=sys.stderr)
        return 2

    config = ScanConfig(
        target=args.target,
        resolved_ip=resolved_ip,
        ports=port_list,
        timeout=timeout,
        workers=workers,
    )

    print(f"\n[*] Target           : {config.target}")
    print(f"[*] Resolved IP      : {config.resolved_ip}")
    print(f"[*] Ports to scan    : {len(config.ports)} ports ({config.ports[0]}..{config.ports[-1]})")
    print(f"[*] Timeout per port : {config.timeout}s")
    print(f"[*] Worker threads   : {config.workers}")
    print(f"[*] Scanning in progress...\n")

    scanner = PortScanner(config)

    # Optional live progress output
    def on_port_result(res):
        if not args.quiet:
            status_tag = f"[{res.status.value.upper()}]"
            latency = f"{res.latency_ms:.1f}ms" if res.latency_ms is not None else "---"
            if res.status == PortStatus.OPEN:
                print(f"  {status_tag:<10} Port {res.port:<5} | TCP | Latency: {latency}")

    report = scanner.run(progress_callback=on_port_result)

    # Concise terminal summary
    print("\n---------------- Scan Summary ----------------")
    print(f"Target          : {report.metadata.target}")
    print(f"Resolved IP     : {report.metadata.resolved_address}")
    print(f"Ports Scanned   : {report.metadata.port_count}")
    print(f"Open Ports      : {len(report.open_ports)}")
    print(f"Closed Ports    : {len(report.closed_ports)}")
    print(f"Filtered Ports  : {len(report.filtered_ports)}")
    print(f"Scan Duration   : {report.metadata.duration_ms:.2f} ms")

    if output_path:
        if fmt == "json":
            saved_file = export_json(report, output_path)
        else:
            saved_file = export_csv(report, output_path)
        print(f"Report Saved    : {saved_file} ({fmt.upper()})")
    else:
        print("Report Saved    : None specified (use -o/--output to save)")
    print("----------------------------------------------")

    return 0


if __name__ == "__main__":
    sys.exit(main())
