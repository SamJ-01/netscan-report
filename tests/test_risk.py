"""Tests for the risk-flagging rules."""

import pytest

from netscan_report.models import Host, Port
from netscan_report.risk import (
    HIGH,
    LOW,
    MEDIUM,
    assess_host,
    assess_hosts,
    count_by_severity,
    is_version_below,
    parse_version,
)


def titles_for(port: Port):
    """Run the rules against a single port and return the finding titles."""
    return [f.title for f in assess_host(Host(address="10.0.0.1", ports=[port]))]


# --- version helpers ------------------------------------------------------- #
@pytest.mark.parametrize(
    "text, expected",
    [
        ("2.4.41", (2, 4, 41)),
        ("7.4p1 Debian", (7, 4)),
        ("5.0.51a-3ubuntu5", (5, 0, 51)),
        ("", None),
        ("unknown", None),
    ],
)
def test_parse_version(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    "version, baseline, expected",
    [
        ("2.4.41", "2.4.62", True),
        ("2.4.62", "2.4.62", False),
        ("2.4", "2.4.0", False),   # padded with zeros, so equal
        ("9.9p1", "9.8", False),
        ("1.24.0", "1.3", False),  # compared as numbers, not text
        ("weird", "1.0", False),   # unknown versions are never flagged
    ],
)
def test_is_version_below(version, baseline, expected):
    assert is_version_below(version, baseline) is expected


# --- risky services -------------------------------------------------------- #
@pytest.mark.parametrize(
    "port, expected_title",
    [
        (Port(23, service="telnet"), "Telnet exposed"),
        (Port(21, service="ftp"), "FTP exposed"),
        (Port(445, service="microsoft-ds"), "SMB exposed"),
        (Port(3389, service="ms-wbt-server"), "RDP exposed"),
        (Port(80, service="http"), "Unencrypted HTTP"),
    ],
)
def test_risky_services_are_flagged(port, expected_title):
    assert expected_title in titles_for(port)


def test_service_on_non_standard_port_is_still_flagged():
    assert titles_for(Port(2323, service="telnet")) == ["Telnet exposed"]


def test_port_number_is_used_when_service_is_unidentified():
    assert titles_for(Port(3389, service="tcpwrapped")) == ["RDP exposed"]


def test_identified_service_on_risky_port_is_not_misflagged():
    # SSH running on port 80 should not be called "Unencrypted HTTP".
    assert titles_for(Port(80, service="ssh")) == []


def test_https_is_not_flagged_as_unencrypted():
    assert titles_for(Port(443, service="ssl/http", product="nginx", version="1.26.2")) == []


# --- outdated versions ----------------------------------------------------- #
def test_backdoored_vsftpd_is_high():
    findings = assess_host(Host("10.0.0.1", ports=[
        Port(21, service="ftp", product="vsftpd", version="2.3.4")
    ]))
    backdoor = next(f for f in findings if f.title == "Backdoored vsftpd version")
    assert backdoor.severity == HIGH
    assert "vsftpd 2.3.4" in backdoor.description


def test_most_severe_version_rule_wins():
    # OpenSSH 4.7 matches both "Very old" (<7.0) and "Outdated" (<9.8); only
    # the more severe one should be reported.
    titles = titles_for(Port(22, service="ssh", product="OpenSSH", version="4.7p1"))
    assert titles == ["Very old OpenSSH"]


def test_slightly_old_openssh_is_medium():
    findings = assess_host(Host("10.0.0.1", ports=[
        Port(22, service="ssh", product="OpenSSH", version="8.9p1")
    ]))
    assert [(f.title, f.severity) for f in findings] == [("Outdated OpenSSH", MEDIUM)]


def test_current_versions_are_not_flagged():
    assert titles_for(Port(22, service="ssh", product="OpenSSH", version="9.9p1")) == []


def test_missing_version_is_not_flagged():
    assert titles_for(Port(22, service="ssh", product="OpenSSH")) == []


# --- whole sample scan ----------------------------------------------------- #
def test_sample_scan_counts(sample_hosts):
    findings = assess_hosts(sample_hosts)
    assert count_by_severity(findings) == {HIGH: 7, MEDIUM: 4, LOW: 1}


def test_findings_are_sorted_most_severe_first(sample_hosts):
    severities = [f.severity for f in assess_hosts(sample_hosts)]
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    assert severities == sorted(severities, key=order.get)


def test_clean_host_has_no_findings(sample_hosts):
    modern = next(h for h in sample_hosts if h.address == "192.168.56.5")
    assert assess_host(modern) == []
