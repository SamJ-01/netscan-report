"""Simple, rule-based risk flagging for scan results.

There are two kinds of rule:

1. **Risky services** - services that are dangerous to expose, whatever the
   version (e.g. Telnet sends passwords in plain text).
2. **Outdated versions** - products where nmap detected a version older than
   a baseline we consider reasonably current.

These rules are deliberately simple and are a starting point for a human to
investigate, NOT a replacement for a proper vulnerability scanner. In
particular, Linux distributions often "backport" security fixes without
changing the version number, so an "outdated" flag must be checked against
the vendor's own security advisories.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from netscan_report.models import Finding, Host, Port

HIGH, MEDIUM, LOW = "High", "Medium", "Low"

# Used to sort findings so the most serious ones are listed first.
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

# Service names that mean "nmap couldn't really tell what this is". For these
# we fall back to guessing the service from the port number.
UNIDENTIFIED_SERVICES = {"", "unknown", "tcpwrapped"}

# Cases where nmap's service name is misleading for a particular port.
# Samba answers on both 139 and 445, and nmap's version detection often labels
# BOTH as "netbios-ssn". Port 445 is direct SMB, though, so we treat it as
# "microsoft-ds" (SMB) to give it the correct, higher severity.
# (Found by scanning a real Samba server in the home lab.)
SERVICE_NAME_OVERRIDES = {
    (445, "netbios-ssn"): "microsoft-ds",
}


@dataclass(frozen=True)
class ServiceRule:
    """A service that is risky to expose, matched by nmap service name or port."""

    services: Tuple[str, ...]  # nmap service names, e.g. ("telnet",)
    ports: Tuple[int, ...]     # usual port numbers, used if the name is unknown
    severity: str
    title: str
    description: str
    recommendation: str


@dataclass(frozen=True)
class VersionRule:
    """A product version check.

    The rule matches if `product` appears in nmap's product string (case
    insensitive) AND either:
      * the detected version equals `exact_version`, or
      * the detected version is lower than `below`.
    """

    product: str
    severity: str
    title: str
    description: str
    recommendation: str
    below: Optional[str] = None
    exact_version: Optional[str] = None


SERVICE_RULES: List[ServiceRule] = [
    ServiceRule(
        ("telnet",), (23,), HIGH, "Telnet exposed",
        "Telnet sends usernames, passwords and all data in plain text, so anyone "
        "on the network path can read them.",
        "Disable Telnet and use SSH instead.",
    ),
    ServiceRule(
        ("microsoft-ds",), (445,), HIGH, "SMB exposed",
        "SMB file sharing has a long history of serious remote exploits "
        "(e.g. EternalBlue / WannaCry) and is a common ransomware entry point.",
        "Block port 445 at the firewall except for trusted internal hosts; "
        "disable SMBv1 and keep the system patched.",
    ),
    ServiceRule(
        ("ms-wbt-server",), (3389,), HIGH, "RDP exposed",
        "Remote Desktop is heavily targeted by password-guessing attacks and has "
        "had critical vulnerabilities (e.g. BlueKeep).",
        "Do not expose RDP directly. Put it behind a VPN or gateway, enforce "
        "Network Level Authentication, strong passwords and MFA.",
    ),
    ServiceRule(
        ("vnc",), (5900, 5901), HIGH, "VNC exposed",
        "VNC is often configured with weak or no passwords and traffic may be "
        "unencrypted.",
        "Restrict VNC to trusted hosts or tunnel it over SSH/VPN.",
    ),
    ServiceRule(
        ("exec", "login", "shell"), (512, 513, 514), HIGH, "Legacy r-services exposed",
        "rexec/rlogin/rsh are obsolete remote access services with weak, "
        "plain-text authentication.",
        "Disable these services and use SSH.",
    ),
    ServiceRule(
        ("redis",), (6379,), HIGH, "Redis exposed",
        "Redis often runs without authentication by default, allowing anyone who "
        "can reach it to read or change data, and sometimes to run commands.",
        "Bind Redis to localhost or a private interface and enable authentication.",
    ),
    ServiceRule(
        ("mongodb", "mongod"), (27017,), HIGH, "MongoDB exposed",
        "Exposed MongoDB instances are frequently found without authentication "
        "and are a common source of data leaks.",
        "Restrict network access and enable authentication.",
    ),
    ServiceRule(
        ("ftp",), (21,), MEDIUM, "FTP exposed",
        "FTP sends credentials and files in plain text and may allow anonymous "
        "login.",
        "Replace with SFTP or FTPS, and disable anonymous access.",
    ),
    ServiceRule(
        ("netbios-ssn",), (139,), MEDIUM, "NetBIOS session service exposed",
        "NetBIOS can leak information about the host, users and shares, and is "
        "an older way of reaching SMB.",
        "Disable NetBIOS over TCP/IP if it is not needed, or firewall it.",
    ),
    ServiceRule(
        ("mysql", "ms-sql-s", "postgresql", "oracle-tns"),
        (3306, 1433, 5432, 1521),
        MEDIUM, "Database port exposed",
        "Database servers should rarely be reachable directly from other "
        "networks; exposure invites password guessing and exploits.",
        "Firewall the database so only the application servers that need it "
        "can connect.",
    ),
    ServiceRule(
        ("http", "http-proxy", "http-alt"), (80, 8080, 8000), LOW, "Unencrypted HTTP",
        "The web service is served over plain HTTP, so traffic (including any "
        "logins) can be read or modified in transit.",
        "Serve the site over HTTPS and redirect HTTP to HTTPS.",
    ),
    ServiceRule(
        ("pop3", "imap"), (110, 143), LOW, "Unencrypted mail access",
        "POP3/IMAP without TLS sends mailbox passwords in plain text.",
        "Use POP3S (995) / IMAPS (993) or require STARTTLS.",
    ),
]

_OUTDATED_ADVICE = (
    "Check the vendor's security advisories (distributions may backport fixes "
    "without changing the version number) and upgrade if affected."
)

VERSION_RULES: List[VersionRule] = [
    VersionRule(
        "vsftpd", HIGH, "Backdoored vsftpd version",
        "vsftpd 2.3.4 was distributed with a known backdoor (CVE-2011-2523) "
        "that gives an attacker a root shell.",
        "Upgrade vsftpd immediately and investigate the host for compromise.",
        exact_version="2.3.4",
    ),
    VersionRule(
        "apache httpd", HIGH, "End-of-life Apache httpd",
        "Apache httpd versions before 2.4 are end-of-life and no longer receive "
        "security fixes.",
        "Upgrade to a supported Apache 2.4 release.",
        below="2.4",
    ),
    VersionRule(
        "apache httpd", MEDIUM, "Outdated Apache httpd",
        "This Apache 2.4 release is older than 2.4.62 and may be missing "
        "security fixes.",
        _OUTDATED_ADVICE,
        below="2.4.62",
    ),
    VersionRule(
        "openssh", HIGH, "Very old OpenSSH",
        "OpenSSH versions before 7.0 are many years old and affected by "
        "multiple known vulnerabilities.",
        _OUTDATED_ADVICE,
        below="7.0",
    ),
    VersionRule(
        "openssh", MEDIUM, "Outdated OpenSSH",
        "OpenSSH versions before 9.8 may be affected by known issues such as "
        "'regreSSHion' (CVE-2024-6387).",
        _OUTDATED_ADVICE,
        below="9.8",
    ),
    VersionRule(
        "nginx", MEDIUM, "Outdated nginx",
        "This nginx release is older than 1.24 and may be missing security fixes.",
        _OUTDATED_ADVICE,
        below="1.24",
    ),
    VersionRule(
        "microsoft iis", HIGH, "End-of-life Microsoft IIS",
        "IIS versions before 10.0 ship with Windows Server releases that are "
        "out of support.",
        "Migrate to a supported Windows Server / IIS version.",
        below="10.0",
    ),
    VersionRule(
        "proftpd", MEDIUM, "Outdated ProFTPD",
        "This ProFTPD release is older than 1.3.8 and may be missing security fixes.",
        _OUTDATED_ADVICE,
        below="1.3.8",
    ),
    VersionRule(
        "mysql", MEDIUM, "Outdated MySQL",
        "MySQL versions before 8.0 are end-of-life.",
        "Upgrade to a supported MySQL release.",
        below="8.0",
    ),
]


def parse_version(version: str) -> Optional[Tuple[int, ...]]:
    """Turn a version string into a tuple of numbers that can be compared.

    Only the leading dotted number is used, so "7.4p1" -> (7, 4) and
    "2.4.41" -> (2, 4, 41). Returns None if there is no number to read.

    >>> parse_version("2.4.41") < parse_version("2.4.62")
    True
    """
    match = re.match(r"\s*(\d+(?:\.\d+)*)", version or "")
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def is_version_below(version: str, baseline: str) -> bool:
    """Return True if `version` is lower than `baseline` (False if unknown)."""
    detected = parse_version(version)
    minimum = parse_version(baseline)
    if detected is None or minimum is None:
        return False
    # Pad the shorter tuple with zeros so (2, 4) compares equal to (2, 4, 0).
    length = max(len(detected), len(minimum))
    detected += (0,) * (length - len(detected))
    minimum += (0,) * (length - len(minimum))
    return detected < minimum


def matching_service_rule(port: Port) -> Optional[ServiceRule]:
    """Find the risky-service rule that applies to a port, if any.

    If nmap identified the service, we match on its name (so Telnet running on
    port 2323 is still caught, and SSH on port 80 is not called "HTTP").
    If the service is unidentified, we fall back to the port number.
    """
    service = port.service.lower()
    service = SERVICE_NAME_OVERRIDES.get((port.number, service), service)
    for rule in SERVICE_RULES:
        if service in UNIDENTIFIED_SERVICES:
            if port.number in rule.ports:
                return rule
        elif service in rule.services:
            return rule
    return None


def matching_version_rule(port: Port) -> Optional[VersionRule]:
    """Find the first outdated-version rule that applies to a port, if any.

    Rules for the same product are listed most severe first, so the first match
    is the most relevant one.
    """
    if not port.product or not port.version:
        return None
    product = port.product.lower()
    for rule in VERSION_RULES:
        if rule.product not in product:
            continue
        if rule.exact_version and port.version.strip() == rule.exact_version:
            return rule
        if rule.below and is_version_below(port.version, rule.below):
            return rule
    return None


def assess_host(host: Host) -> List[Finding]:
    """Return all findings for a single host."""
    findings = []
    for port in host.ports:
        service_rule = matching_service_rule(port)
        if service_rule:
            findings.append(
                Finding(
                    host=host.address,
                    port=port.number,
                    severity=service_rule.severity,
                    title=service_rule.title,
                    description=service_rule.description,
                    recommendation=service_rule.recommendation,
                )
            )

        version_rule = matching_version_rule(port)
        if version_rule:
            findings.append(
                Finding(
                    host=host.address,
                    port=port.number,
                    severity=version_rule.severity,
                    title=version_rule.title,
                    description=(
                        f"Detected {port.product} {port.version}. "
                        f"{version_rule.description}"
                    ),
                    recommendation=version_rule.recommendation,
                )
            )
    return findings


def assess_hosts(hosts: List[Host]) -> List[Finding]:
    """Return findings for every host, most severe first."""
    findings = [finding for host in hosts for finding in assess_host(host)]
    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), address_sort_key(f.host), f.port)
    )
    return findings


def address_sort_key(address: str) -> tuple:
    """Sort IPs numerically, so 192.168.1.5 comes before 192.168.1.10."""
    try:
        ip = ipaddress.ip_address(address)
        return (ip.version, int(ip), "")
    except ValueError:
        return (99, 0, address)


def count_by_severity(findings: List[Finding]) -> dict:
    """Return a dict like {"High": 2, "Medium": 1, "Low": 0}."""
    counts = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
