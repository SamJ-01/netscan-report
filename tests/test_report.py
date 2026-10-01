"""Tests for the console, Markdown, HTML and JSON outputs."""

import json

from netscan_report.cli import main
from netscan_report.models import Host, Port, ScanResult
from netscan_report.report import (
    render_console,
    render_html,
    render_json,
    render_markdown,
    write_reports,
)
from netscan_report.risk import assess_hosts

from tests.conftest import SAMPLE_XML


def make_result(hosts) -> ScanResult:
    result = ScanResult(target="192.168.56.0/24", started_at="2026-01-01T12:00:00",
                        hosts=hosts)
    result.findings = assess_hosts(hosts)
    return result


def test_console_summary(sample_hosts):
    text = render_console(make_result(sample_hosts))
    assert "Live hosts: 3" in text
    assert "7 High, 4 Medium, 1 Low" in text
    assert "[HIGH] port 23: Telnet exposed" in text


def test_markdown_report(sample_hosts):
    markdown = render_markdown(make_result(sample_hosts))
    assert markdown.startswith("# Network Scan Report")
    assert "| **High** | 192.168.56.101 | 23 |" in markdown
    assert "### 192.168.56.101 (metasploitable.lab)" in markdown


def test_html_report_escapes_scan_data():
    # A malicious service banner must not turn into real HTML/JavaScript.
    evil = Host("10.0.0.1", ports=[Port(80, service="http", product="<script>alert(1)</script>")])
    page = render_html(make_result([evil]))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_empty_scan_reports():
    result = make_result([])
    assert "No live hosts" in render_console(result)
    assert "No live hosts" in render_markdown(result)
    assert "No live hosts" in render_html(result)


def test_json_round_trip(sample_hosts):
    original = make_result(sample_hosts)
    rebuilt = ScanResult.from_dict(json.loads(render_json(original)))
    assert rebuilt == original


def test_write_reports_creates_three_files(tmp_path, sample_hosts):
    written = write_reports(make_result(sample_hosts), str(tmp_path / "out"))
    assert set(written) == {"markdown", "html", "json"}
    names = sorted(p.name for p in written.values())
    assert names == [
        "netscan_192.168.56.0_24_20260101-120000.html",
        "netscan_192.168.56.0_24_20260101-120000.json",
        "netscan_192.168.56.0_24_20260101-120000.md",
    ]
    assert all(p.stat().st_size > 0 for p in written.values())


def test_cli_from_xml_end_to_end(tmp_path, capsys):
    exit_code = main(["--from-xml", str(SAMPLE_XML), "-o", str(tmp_path), "--no-color"])
    assert exit_code == 0
    assert "Telnet exposed" in capsys.readouterr().out
    assert len(list(tmp_path.iterdir())) == 3


def test_cli_without_target_is_usage_error(capsys):
    assert main([]) == 2


def test_cli_invalid_target_is_error(capsys):
    assert main(["not a host!", "--no-files"]) == 1
    assert "not a valid" in capsys.readouterr().err
