"""Turn nmap's XML output into Host and Port objects.

nmap's XML looks roughly like this (trimmed):

    <nmaprun args="nmap -sV ..." version="7.94">
      <host>
        <status state="up"/>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.4"/>
          </port>
        </ports>
      </host>
    </nmaprun>

Keeping this in its own module means we can test it with saved XML samples
instead of running a real scan.
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Optional, Tuple

from netscan_report.models import Host, Port


class ParseError(Exception):
    """Raised when the nmap output cannot be understood."""


def parse_nmap_xml(xml_text: str) -> Tuple[List[Host], dict]:
    """Parse nmap XML output.

    Args:
        xml_text: The XML produced by `nmap -oX`.

    Returns:
        A tuple of (hosts, metadata). `hosts` only contains hosts that are up.
        `metadata` has the keys "command", "version" and "started_at"
        (an ISO 8601 timestamp, or "" if nmap did not record one).

    Raises:
        ParseError: If the text is not valid nmap XML.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise ParseError(f"Could not parse nmap XML output: {error}") from None

    if root.tag != "nmaprun":
        raise ParseError("This does not look like nmap XML (no <nmaprun> element).")

    # nmap records the start time as a Unix timestamp (seconds since 1970).
    start = root.get("start", "")
    started_at = (
        datetime.fromtimestamp(int(start)).isoformat(timespec="seconds")
        if start.isdigit() else ""
    )
    metadata = {
        "command": root.get("args", ""),
        "version": root.get("version", ""),
        "started_at": started_at,
    }

    hosts = []
    for host_element in root.findall("host"):
        host = _parse_host(host_element)
        if host is not None:
            hosts.append(host)
    return hosts, metadata


def _parse_host(element: ET.Element) -> Optional[Host]:
    """Convert one <host> element into a Host, or None if it is not up."""
    status = element.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"
    if state != "up":
        return None

    # A host can have several addresses (e.g. IPv4 + MAC). Prefer the IP.
    address = ""
    for addr in element.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            address = addr.get("addr", "")
            break
    if not address:
        return None

    hostname_element = element.find("hostnames/hostname")
    hostname = hostname_element.get("name", "") if hostname_element is not None else ""

    ports = [_parse_port(p) for p in element.findall("ports/port")]
    # Only keep open ports, sorted by number for tidy reports.
    open_ports = sorted((p for p in ports if p.state == "open"), key=lambda p: p.number)

    return Host(address=address, hostname=hostname, state=state, ports=open_ports)


def _parse_port(element: ET.Element) -> Port:
    """Convert one <port> element into a Port."""
    state_element = element.find("state")
    service = element.find("service")

    # Service info is optional, so fall back to empty strings when missing.
    def service_attr(name: str) -> str:
        return service.get(name, "") if service is not None else ""

    # nmap reports HTTPS as name="http" tunnel="ssl". Show it as "ssl/http"
    # (like nmap's normal output does) so it is not mistaken for plain HTTP.
    service_name = service_attr("name")
    if service_name and service_attr("tunnel") == "ssl":
        service_name = f"ssl/{service_name}"

    return Port(
        number=int(element.get("portid", "0")),
        protocol=element.get("protocol", "tcp"),
        state=state_element.get("state", "unknown") if state_element is not None else "unknown",
        service=service_name,
        product=service_attr("product"),
        version=service_attr("version"),
        extra_info=service_attr("extrainfo"),
    )
