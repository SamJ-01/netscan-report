"""Everything to do with actually running nmap.

This module:
  1. checks the target the user typed is a sensible IP, CIDR range or hostname,
  2. checks nmap is installed,
  3. runs nmap as a subprocess and returns its XML output.

Turning that XML into Python objects is done separately in `parser.py`, which
means the parsing logic can be unit-tested without running a real scan.
"""

import ipaddress
import re
import shutil
import subprocess
from typing import List, Optional

# Refuse ranges bigger than a /16 (65,536 addresses). Scanning more than that
# by accident is slow, noisy and much more likely to hit something you are not
# authorised to test.
MAX_ADDRESSES = 65_536

# A hostname is one or more "labels" separated by dots. Each label is 1-63
# letters, digits or hyphens and cannot start or end with a hyphen (RFC 1123).
# Importantly, this also stops someone sneaking an nmap option such as
# "-oN /etc/passwd" in through the target argument.
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)

# Port lists like "22", "22,80,443" or "1-1024,8080".
PORTS_PATTERN = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class ScanError(Exception):
    """Base class for problems running a scan. The message is shown to the user."""


class NmapNotFoundError(ScanError):
    """Raised when the nmap program cannot be found on the PATH."""


class InvalidTargetError(ScanError):
    """Raised when the target is not a valid IP, CIDR range or hostname."""


class ScanPermissionError(ScanError):
    """Raised when nmap (or the OS) refuses to run the scan due to permissions."""


def validate_target(target: str) -> str:
    """Check the target is a single IP, a CIDR range or a hostname.

    Args:
        target: What the user typed, e.g. "192.168.1.10", "10.0.0.0/24",
            or "scanme.nmap.org".

    Returns:
        The cleaned-up target string (surrounding whitespace removed).

    Raises:
        InvalidTargetError: If the target is not valid, or the range is too big.
    """
    target = target.strip()
    if not target:
        raise InvalidTargetError("No target given.")

    # 1) A CIDR range such as 192.168.1.0/24.
    if "/" in target:
        try:
            # strict=False lets people type 192.168.1.5/24 and still mean the /24.
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise InvalidTargetError(
                f"'{target}' is not a valid CIDR range (example: 192.168.1.0/24)."
            ) from None
        if network.num_addresses > MAX_ADDRESSES:
            raise InvalidTargetError(
                f"'{target}' contains {network.num_addresses:,} addresses. "
                f"The limit is {MAX_ADDRESSES:,} (a /16) to avoid accidental huge scans."
            )
        return target

    # 2) A single IP address (IPv4 or IPv6).
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # 3) A hostname. Reject anything that looks like an IP but wasn't valid
    #    (e.g. "999.1.1.1"), otherwise it would be treated as a hostname.
    if re.fullmatch(r"[\d.]+", target):
        raise InvalidTargetError(f"'{target}' is not a valid IP address.")
    if HOSTNAME_PATTERN.match(target):
        return target

    raise InvalidTargetError(
        f"'{target}' is not a valid IP address, CIDR range or hostname."
    )


def is_ipv6(target: str) -> bool:
    """Return True if the target is an IPv6 address or range (nmap needs -6)."""
    try:
        return ipaddress.ip_network(target, strict=False).version == 6
    except ValueError:
        return False  # a hostname


def validate_ports(ports: str) -> str:
    """Check a port specification such as '22,80,443' or '1-1024'.

    Raises:
        InvalidTargetError: If the format is wrong or a port is out of range.
    """
    ports = ports.replace(" ", "")
    if not PORTS_PATTERN.match(ports):
        raise InvalidTargetError(
            f"'{ports}' is not a valid port list (examples: 22,80,443 or 1-1024)."
        )
    for number in re.findall(r"\d+", ports):
        if not 1 <= int(number) <= 65535:
            raise InvalidTargetError(f"Port {number} is out of range (1-65535).")
    return ports


def find_nmap() -> str:
    """Return the full path to the nmap executable.

    Raises:
        NmapNotFoundError: If nmap is not installed or not on the PATH.
    """
    path = shutil.which("nmap")
    if path is None:
        raise NmapNotFoundError(
            "nmap was not found. Install it first, for example:\n"
            "  Kali / Debian / Ubuntu:  sudo apt install nmap\n"
            "  macOS (Homebrew):        brew install nmap\n"
            "  Windows:                 https://nmap.org/download.html"
        )
    return path


def build_nmap_command(
    nmap_path: str, target: str, ports: Optional[str] = None, fast: bool = False
) -> List[str]:
    """Build the list of arguments used to run nmap.

    We pass a list (not a single string) to subprocess, so no shell is involved
    and the target can never be interpreted as extra shell commands.

    The options used are:
        -sV      detect service names and versions on open ports
        -T4      a faster timing template, sensible for local networks
        --open   only report open ports (keeps reports short)
        -oX -    write XML output to stdout so we can parse it
    """
    command = [nmap_path, "-sV", "-T4", "--open", "-oX", "-"]
    if is_ipv6(target):
        command.append("-6")
    if ports:
        command += ["-p", ports]
    elif fast:
        command.append("-F")  # top 100 ports instead of the default top 1000
    command.append(target)
    return command


def run_nmap(command: List[str], timeout: Optional[int] = None) -> str:
    """Run nmap and return its XML output as a string.

    Args:
        command: The argument list from `build_nmap_command`.
        timeout: Optional number of seconds after which to give up.

    Raises:
        ScanPermissionError: If the OS or nmap refuses because of permissions.
        ScanError: For any other failure (nmap error, timeout, ...).
    """
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except PermissionError:
        raise ScanPermissionError(
            "Permission denied when trying to run nmap. Check the nmap binary "
            "is executable by your user."
        ) from None
    except subprocess.TimeoutExpired:
        raise ScanError(
            f"The scan took longer than {timeout} seconds and was stopped. "
            "Try a smaller range, --fast, or a larger --timeout."
        ) from None

    stderr = completed.stderr.lower()
    if "root privileges" in stderr or "operation not permitted" in stderr:
        raise ScanPermissionError(
            "nmap reported a permissions problem. Some scan types need root; "
            "try running with sudo, but ONLY against systems you are authorised "
            f"to test.\nnmap said: {completed.stderr.strip()}"
        )
    if "failed to resolve" in stderr:
        raise InvalidTargetError(
            "nmap could not resolve that hostname. Check the spelling and your DNS."
        )
    if completed.returncode != 0:
        message = completed.stderr.strip() or "no error message"
        raise ScanError(f"nmap exited with code {completed.returncode}: {message}")
    if not completed.stdout.strip():
        raise ScanError("nmap produced no output.")
    return completed.stdout
