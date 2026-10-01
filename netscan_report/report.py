"""Produce human-readable output from a ScanResult.

Four outputs are supported:
  * a console summary (plain text, optionally coloured),
  * a Markdown report (great for GitHub, tickets or notes),
  * a self-contained HTML report (open it in any browser),
  * a JSON file with the full structured results (for other tools or scripts).
"""

import html
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List

from netscan_report.models import Finding, Host, ScanResult
from netscan_report.risk import HIGH, LOW, MEDIUM, address_sort_key, count_by_severity

DISCLAIMER = (
    "This report was produced by an automated scan. Findings are indicators "
    "for a human to verify, not confirmed vulnerabilities. Only scan systems "
    "you own or have explicit written permission to test."
)

# ANSI escape codes for terminal colours.
_COLOURS = {HIGH: "\033[91m", MEDIUM: "\033[93m", LOW: "\033[94m"}
_BOLD, _RESET = "\033[1m", "\033[0m"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def findings_for_host(findings: List[Finding], host: Host) -> List[Finding]:
    """Return only the findings that belong to `host`."""
    return [f for f in findings if f.host == host.address]


def sorted_hosts(hosts: List[Host]) -> List[Host]:
    """Return hosts in numeric IP order."""
    return sorted(hosts, key=lambda h: address_sort_key(h.address))


def safe_filename(text: str) -> str:
    """Make a target such as '192.168.1.0/24' safe to use in a file name."""
    return re.sub(r"[^A-Za-z0-9.-]+", "_", text).strip("_") or "scan"


def use_colour() -> bool:
    """Only colour output when writing to a real terminal (and NO_COLOR is unset)."""
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
def render_console(result: ScanResult, colour: bool = False) -> str:
    """Build the text summary printed to the terminal."""

    def paint(text: str, severity: str) -> str:
        if not colour:
            return text
        return f"{_COLOURS.get(severity, '')}{text}{_RESET}"

    def bold(text: str) -> str:
        return f"{_BOLD}{text}{_RESET}" if colour else text

    counts = count_by_severity(result.findings)
    lines = [
        bold(f"netscan-report: {result.target}"),
        f"Scan started: {result.started_at}",
        f"Live hosts: {len(result.hosts)}   "
        f"Open ports: {sum(len(h.ports) for h in result.hosts)}   "
        f"Findings: {paint(f'{counts[HIGH]} High', HIGH)}, "
        f"{paint(f'{counts[MEDIUM]} Medium', MEDIUM)}, "
        f"{paint(f'{counts[LOW]} Low', LOW)}",
        "",
    ]

    if not result.hosts:
        lines.append("No live hosts with open ports were found.")
        return "\n".join(lines)

    for host in sorted_hosts(result.hosts):
        lines.append(bold(f"Host {host.display_name}"))
        if not host.ports:
            lines.append("  (no open ports found)")
        for port in host.ports:
            lines.append(f"  {port.number:>5}/{port.protocol:<4} {port.service_label}")
        host_findings = findings_for_host(result.findings, host)
        for finding in host_findings:
            tag = paint(f"[{finding.severity.upper()}]", finding.severity)
            lines.append(f"    {tag} port {finding.port}: {finding.title}")
        if host.ports and not host_findings:
            lines.append("    (no risky findings)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def _md_escape(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    """Build the Markdown report."""
    counts = count_by_severity(result.findings)
    lines = [
        f"# Network Scan Report: `{result.target}`",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Summary",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| Target | `{_md_escape(result.target)}` |",
        f"| Scan started | {result.started_at} |",
        f"| nmap version | {_md_escape(result.nmap_version) or 'n/a'} |",
        f"| Live hosts | {len(result.hosts)} |",
        f"| Open ports | {sum(len(h.ports) for h in result.hosts)} |",
        f"| High / Medium / Low | {counts[HIGH]} / {counts[MEDIUM]} / {counts[LOW]} |",
        "",
        "## Findings",
        "",
    ]

    if result.findings:
        lines += [
            "| Severity | Host | Port | Finding | Recommendation |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in result.findings:
            lines.append(
                f"| **{f.severity}** | {f.host} | {f.port} | "
                f"**{_md_escape(f.title)}**: {_md_escape(f.description)} | "
                f"{_md_escape(f.recommendation)} |"
            )
    else:
        lines.append("No risky findings were flagged. :tada:")
    lines.append("")

    lines += ["## Hosts", ""]
    if not result.hosts:
        lines += ["No live hosts with open ports were found.", ""]
    for host in sorted_hosts(result.hosts):
        lines += [f"### {_md_escape(host.display_name)}", ""]
        if not host.ports:
            lines += ["No open ports found.", ""]
            continue
        lines += ["| Port | Service | Product | Version | Extra info |",
                  "| --- | --- | --- | --- | --- |"]
        for p in host.ports:
            lines.append(
                f"| {p.number}/{p.protocol} | {_md_escape(p.service)} | "
                f"{_md_escape(p.product)} | {_md_escape(p.version)} | "
                f"{_md_escape(p.extra_info)} |"
            )
        lines.append("")

    if result.nmap_command:
        lines += ["## Scan details", "", f"nmap command: `{result.nmap_command}`", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_HTML_STYLE = """
  :root { --bg:#f7f8fa; --card:#fff; --text:#1d2433; --muted:#5b6475; --border:#dde1e8;
          --high:#c62828; --medium:#b26a00; --low:#1565c0; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171c; --card:#1d2128; --text:#e6e9ef; --muted:#9aa3b2; --border:#2f3540;
            --high:#ef5350; --medium:#ffb74d; --low:#64b5f6; }
  }
  * { box-sizing: border-box; }
  body { margin:0; padding:24px 16px; background:var(--bg); color:var(--text);
         font:15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width:1000px; margin:0 auto; }
  h1 { font-size:1.6rem; margin:0 0 4px; }
  h2 { margin-top:32px; border-bottom:1px solid var(--border); padding-bottom:4px; }
  .muted { color:var(--muted); }
  .note { background:var(--card); border-left:4px solid var(--medium); padding:10px 14px;
          border-radius:4px; margin:16px 0; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:12px; }
  .card .n { font-size:1.8rem; font-weight:700; }
  .table-wrap { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--card); margin:8px 0 16px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border);
           vertical-align:top; }
  th { font-size:.85rem; text-transform:uppercase; letter-spacing:.03em; color:var(--muted); }
  .sev { font-weight:700; white-space:nowrap; }
  .sev-High { color:var(--high); } .sev-Medium { color:var(--medium); } .sev-Low { color:var(--low); }
  code { font-family:ui-monospace, Menlo, Consolas, monospace; font-size:.9em; }
"""


def render_html(result: ScanResult) -> str:
    """Build a self-contained HTML report (no external files needed)."""
    e = html.escape  # short alias: ALWAYS escape scan data before putting it in HTML
    counts = count_by_severity(result.findings)
    open_ports = sum(len(h.ports) for h in result.hosts)

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Scan report: {e(result.target)}</title>",
        f"<style>{_HTML_STYLE}</style></head><body><main>",
        f"<h1>Network Scan Report: <code>{e(result.target)}</code></h1>",
        f'<div class="muted">Scan started {e(result.started_at)}'
        f"{' &middot; nmap ' + e(result.nmap_version) if result.nmap_version else ''}</div>",
        f'<div class="note">{e(DISCLAIMER)}</div>',
        '<div class="cards">',
        f'<div class="card"><div class="n">{len(result.hosts)}</div>Live hosts</div>',
        f'<div class="card"><div class="n">{open_ports}</div>Open ports</div>',
    ]
    for severity in (HIGH, MEDIUM, LOW):
        parts.append(
            f'<div class="card"><div class="n sev-{severity}">{counts[severity]}</div>'
            f"{severity}</div>"
        )
    parts.append("</div>")

    # Findings table
    parts.append("<h2>Findings</h2>")
    if result.findings:
        parts.append('<div class="table-wrap"><table><thead><tr><th>Severity</th>'
                     "<th>Host</th><th>Port</th><th>Finding</th><th>Recommendation</th>"
                     "</tr></thead><tbody>")
        for f in result.findings:
            parts.append(
                f'<tr><td class="sev sev-{e(f.severity)}">{e(f.severity)}</td>'
                f"<td>{e(f.host)}</td><td>{f.port}</td>"
                f"<td><strong>{e(f.title)}</strong><br>{e(f.description)}</td>"
                f"<td>{e(f.recommendation)}</td></tr>"
            )
        parts.append("</tbody></table></div>")
    else:
        parts.append("<p>No risky findings were flagged.</p>")

    # Per-host tables
    parts.append("<h2>Hosts</h2>")
    if not result.hosts:
        parts.append("<p>No live hosts with open ports were found.</p>")
    for host in sorted_hosts(result.hosts):
        parts.append(f"<h3>{e(host.display_name)}</h3>")
        if not host.ports:
            parts.append("<p>No open ports found.</p>")
            continue
        parts.append('<div class="table-wrap"><table><thead><tr><th>Port</th>'
                     "<th>Service</th><th>Product</th><th>Version</th><th>Extra info</th>"
                     "</tr></thead><tbody>")
        for p in host.ports:
            parts.append(
                f"<tr><td>{p.number}/{e(p.protocol)}</td><td>{e(p.service)}</td>"
                f"<td>{e(p.product)}</td><td>{e(p.version)}</td>"
                f"<td>{e(p.extra_info)}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    if result.nmap_command:
        parts.append(f'<h2>Scan details</h2><p class="muted">nmap command: '
                     f"<code>{e(result.nmap_command)}</code></p>")
    parts.append("</main></body></html>")
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# JSON + writing files
# --------------------------------------------------------------------------- #
def render_json(result: ScanResult) -> str:
    """Return the full structured results as pretty-printed JSON."""
    return json.dumps(result.to_dict(), indent=2)


def write_reports(result: ScanResult, output_dir: str) -> Dict[str, Path]:
    """Write the Markdown, HTML and JSON reports into `output_dir`.

    File names include the target and a timestamp so repeated scans do not
    overwrite each other, e.g. `netscan_192.168.1.0_24_20260101-120000.md`.

    Returns:
        A dict mapping format name ("markdown", "html", "json") to the file path.

    Raises:
        OSError: If the directory cannot be created or a file cannot be written.
    """
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)

    # started_at looks like "2026-01-01T12:00:00"; keep just the digits.
    stamp = re.sub(r"\D", "", result.started_at)[:14]
    stamp = f"{stamp[:8]}-{stamp[8:]}" if len(stamp) == 14 else stamp
    # Note: we add the extension with an f-string rather than Path.with_suffix(),
    # because targets like "192.168.1.0" contain dots that with_suffix() would
    # mistake for an existing extension.
    base = f"netscan_{safe_filename(result.target)}_{stamp}"

    outputs = {
        "markdown": (folder / f"{base}.md", render_markdown(result)),
        "html": (folder / f"{base}.html", render_html(result)),
        "json": (folder / f"{base}.json", render_json(result)),
    }
    written = {}
    for name, (path, content) in outputs.items():
        path.write_text(content, encoding="utf-8")
        written[name] = path
    return written
