"""Command-line interface: reads arguments, runs the scan, writes the reports.

Run `netscan-report --help` (or `python -m netscan_report --help`) for usage.
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from netscan_report import __version__
from netscan_report.models import ScanResult
from netscan_report.parser import ParseError, parse_nmap_xml
from netscan_report.report import render_console, use_colour, write_reports
from netscan_report.risk import assess_hosts
from netscan_report.scanner import (
    ScanError,
    build_nmap_command,
    find_nmap,
    run_nmap,
    validate_ports,
    validate_target,
)

LEGAL_REMINDER = (
    "Reminder: only scan networks you own or have explicit written permission "
    "to test.\nUnauthorised scanning may be an offence under the UK Computer "
    "Misuse Act 1990 (and similar laws elsewhere).\n"
)

# Exit codes, so scripts can tell what went wrong.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line options."""
    parser = argparse.ArgumentParser(
        prog="netscan-report",
        description=(
            "Scan a host or network with nmap, flag common risky findings and "
            "write Markdown, HTML and JSON reports."
        ),
        epilog=(
            "Examples:\n"
            "  netscan-report 192.168.1.10\n"
            "  netscan-report 192.168.1.0/24 --fast\n"
            "  netscan-report scanme.nmap.org -p 22,80,443 -o my-reports\n"
            "  netscan-report --from-xml old-scan.xml\n\n"
            "Only scan systems you own or have explicit permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="IP address, hostname or CIDR range, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "-p", "--ports",
        help="ports to scan, e.g. 22,80,443 or 1-1024 (default: nmap's top 1000)",
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="scan only the top 100 ports (quicker)",
    )
    parser.add_argument(
        "-o", "--output-dir", default="reports",
        help="folder to write reports into (default: ./reports)",
    )
    parser.add_argument(
        "--timeout", type=int, default=None, metavar="SECONDS",
        help="stop the scan if it runs longer than this many seconds",
    )
    parser.add_argument(
        "--no-files", action="store_true",
        help="only print the console summary; do not write report files",
    )
    parser.add_argument(
        "--from-xml", metavar="FILE",
        help="build reports from an existing nmap XML file (nmap -oX) instead of scanning",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable coloured console output",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def scan(target: str, ports: Optional[str], fast: bool, timeout: Optional[int]) -> ScanResult:
    """Validate input, run nmap and return a ScanResult (without findings yet)."""
    target = validate_target(target)
    if ports:
        ports = validate_ports(ports)
    nmap_path = find_nmap()
    command = build_nmap_command(nmap_path, target, ports=ports, fast=fast)

    started_at = datetime.now().isoformat(timespec="seconds")
    print(f"Scanning {target} ... (this can take a few minutes for large ranges)",
          file=sys.stderr)
    start = time.monotonic()
    xml_output = run_nmap(command, timeout=timeout)
    elapsed = round(time.monotonic() - start, 1)

    hosts, metadata = parse_nmap_xml(xml_output)
    return ScanResult(
        target=target,
        started_at=started_at,
        nmap_command=metadata["command"],
        nmap_version=metadata["version"],
        hosts=hosts,
        elapsed_seconds=elapsed,
    )


def load_from_xml(path: str) -> ScanResult:
    """Build a ScanResult from a saved nmap XML file."""
    xml_text = Path(path).read_text(encoding="utf-8")
    hosts, metadata = parse_nmap_xml(xml_text)
    # Use the target from the original nmap command line if we can find it.
    command = metadata["command"]
    target = command.split()[-1] if command else Path(path).stem
    return ScanResult(
        target=target,
        started_at=metadata["started_at"] or datetime.now().isoformat(timespec="seconds"),
        nmap_command=command,
        nmap_version=metadata["version"],
        hosts=hosts,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns an exit code (0 = success)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.target and not args.from_xml:
        parser.print_usage(sys.stderr)
        print("error: please give a target (or --from-xml FILE)", file=sys.stderr)
        return EXIT_USAGE

    print(LEGAL_REMINDER, file=sys.stderr)

    try:
        if args.from_xml:
            result = load_from_xml(args.from_xml)
        else:
            result = scan(args.target, args.ports, args.fast, args.timeout)
    except (ScanError, ParseError, OSError) as error:
        # ScanError covers nmap missing, bad targets and permission problems.
        # OSError covers things like a --from-xml file that does not exist.
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return EXIT_INTERRUPTED

    # Apply the risk rules and show the summary.
    result.findings = assess_hosts(result.hosts)
    print(render_console(result, colour=use_colour() and not args.no_color))

    if not args.no_files:
        try:
            written = write_reports(result, args.output_dir)
        except OSError as error:
            print(f"Error writing reports: {error}", file=sys.stderr)
            return EXIT_ERROR
        print("Reports written:")
        for name, path in written.items():
            print(f"  {name:<8} {path}")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
