"""Simple data classes that hold scan results and findings.

Using dataclasses (rather than raw dictionaries) means every part of the
program agrees on what a "host" or a "port" looks like, and editors can
autocomplete the field names.
"""

from dataclasses import asdict, dataclass, field
from typing import List, Optional


@dataclass
class Port:
    """A single TCP port on a host, as reported by nmap."""

    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""    # e.g. "ssh", "http"
    product: str = ""    # e.g. "OpenSSH", "Apache httpd"
    version: str = ""    # e.g. "7.4"
    extra_info: str = ""  # e.g. "protocol 2.0"

    @property
    def service_label(self) -> str:
        """Human-friendly description such as 'ssh (OpenSSH 7.4)'."""
        details = " ".join(part for part in (self.product, self.version) if part)
        if details:
            return f"{self.service or 'unknown'} ({details})"
        return self.service or "unknown"


@dataclass
class Host:
    """A live host that nmap discovered, plus its open ports."""

    address: str
    hostname: str = ""
    state: str = "up"
    ports: List[Port] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """'192.168.1.10 (router.lan)' if a hostname is known, else just the IP."""
        return f"{self.address} ({self.hostname})" if self.hostname else self.address


@dataclass
class Finding:
    """A potential security issue spotted on a host."""

    host: str
    port: int
    severity: str  # "High", "Medium" or "Low"
    title: str
    description: str
    recommendation: str


@dataclass
class ScanResult:
    """Everything produced by one run of the tool."""

    target: str
    started_at: str
    nmap_command: str = ""
    nmap_version: str = ""
    hosts: List[Host] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    elapsed_seconds: Optional[float] = None

    def to_dict(self) -> dict:
        """Convert the whole result (including nested objects) into a plain dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Rebuild a ScanResult from a dict produced by `to_dict` (e.g. loaded JSON)."""
        hosts = [
            Host(
                address=h["address"],
                hostname=h.get("hostname", ""),
                state=h.get("state", "up"),
                ports=[Port(**p) for p in h.get("ports", [])],
            )
            for h in data.get("hosts", [])
        ]
        findings = [Finding(**f) for f in data.get("findings", [])]
        return cls(
            target=data["target"],
            started_at=data["started_at"],
            nmap_command=data.get("nmap_command", ""),
            nmap_version=data.get("nmap_version", ""),
            hosts=hosts,
            findings=findings,
            elapsed_seconds=data.get("elapsed_seconds"),
        )
