"""Tests for input validation and nmap error handling.

nmap is never actually run: where needed we "monkeypatch" (temporarily
replace) the functions that would call it.
"""

import subprocess

import pytest

from netscan_report import scanner
from netscan_report.scanner import (
    InvalidTargetError,
    NmapNotFoundError,
    ScanError,
    ScanPermissionError,
    build_nmap_command,
    validate_ports,
    validate_target,
)


@pytest.mark.parametrize(
    "target",
    ["192.168.1.10", "192.168.1.0/24", "10.0.0.5/16", "::1", "fe80::/120",
     "scanme.nmap.org", "router", "my-server.lab"],
)
def test_valid_targets(target):
    assert validate_target(f"  {target} ") == target


@pytest.mark.parametrize(
    "target",
    ["", "999.1.1.1", "192.168.1.0/33", "10.0.0.0/8", "-oN /tmp/out",
     "host;rm -rf /", "bad_host!", "-sS"],
)
def test_invalid_targets(target):
    with pytest.raises(InvalidTargetError):
        validate_target(target)


@pytest.mark.parametrize("ports", ["22", "22,80,443", "1-1024", "1-1024,8080"])
def test_valid_ports(ports):
    assert validate_ports(ports) == ports


@pytest.mark.parametrize("ports", ["0", "70000", "22;ls", "abc", "-p", "1-"])
def test_invalid_ports(ports):
    with pytest.raises(InvalidTargetError):
        validate_ports(ports)


def test_build_command_defaults():
    command = build_nmap_command("nmap", "192.168.1.0/24")
    assert command[0] == "nmap"
    assert "-sV" in command and "-oX" in command
    assert command[-1] == "192.168.1.0/24"  # target always last


def test_build_command_options():
    assert "-F" in build_nmap_command("nmap", "10.0.0.1", fast=True)
    with_ports = build_nmap_command("nmap", "10.0.0.1", ports="22,80", fast=True)
    assert with_ports[with_ports.index("-p") + 1] == "22,80"
    assert "-F" not in with_ports  # an explicit port list wins over --fast
    assert "-6" in build_nmap_command("nmap", "::1")


def test_missing_nmap_gives_helpful_error(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    with pytest.raises(NmapNotFoundError, match="apt install nmap"):
        scanner.find_nmap()


def fake_run(returncode=0, stdout="", stderr=""):
    """Return a stand-in for subprocess.run that gives a canned result."""
    def _run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)
    return _run


def test_permission_error_is_detected(monkeypatch):
    monkeypatch.setattr(
        scanner.subprocess, "run",
        fake_run(1, stderr="You requested a scan type which requires root privileges."),
    )
    with pytest.raises(ScanPermissionError):
        scanner.run_nmap(["nmap", "10.0.0.1"])


def test_nmap_failure_is_reported(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "run", fake_run(1, stderr="boom"))
    with pytest.raises(ScanError, match="boom"):
        scanner.run_nmap(["nmap", "10.0.0.1"])


def test_unresolvable_hostname(monkeypatch):
    monkeypatch.setattr(
        scanner.subprocess, "run",
        fake_run(0, stdout="<nmaprun/>", stderr='Failed to resolve "nope.invalid".'),
    )
    with pytest.raises(InvalidTargetError):
        scanner.run_nmap(["nmap", "nope.invalid"])


def test_successful_run_returns_xml(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "run", fake_run(0, stdout="<nmaprun/>"))
    assert scanner.run_nmap(["nmap", "10.0.0.1"]) == "<nmaprun/>"
