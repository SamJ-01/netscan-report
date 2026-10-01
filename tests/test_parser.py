"""Tests for turning nmap XML into Host/Port objects."""

import pytest

from netscan_report.parser import ParseError, parse_nmap_xml


def host_by_address(hosts, address):
    """Small helper to pick one host out of the list."""
    return next(h for h in hosts if h.address == address)


def test_only_hosts_that_are_up_are_returned(sample_hosts):
    addresses = {h.address for h in sample_hosts}
    assert addresses == {"192.168.56.5", "192.168.56.20", "192.168.56.101"}
    assert "192.168.56.200" not in addresses  # marked "down" in the XML


def test_metadata_is_read(sample_xml):
    _hosts, metadata = parse_nmap_xml(sample_xml)
    assert metadata["version"] == "7.94"
    assert metadata["command"].endswith("192.168.56.0/24")
    assert metadata["started_at"]  # converted from the Unix timestamp


def test_hostname_and_ip_are_read(sample_hosts):
    host = host_by_address(sample_hosts, "192.168.56.101")
    assert host.hostname == "metasploitable.lab"
    assert host.display_name == "192.168.56.101 (metasploitable.lab)"


def test_ports_and_service_details_are_read(sample_hosts):
    host = host_by_address(sample_hosts, "192.168.56.101")
    assert [p.number for p in host.ports] == [21, 22, 23, 80, 139, 445, 3306]
    ftp = host.ports[0]
    assert (ftp.service, ftp.product, ftp.version) == ("ftp", "vsftpd", "2.3.4")


def test_filtered_ports_are_ignored(sample_hosts):
    host = host_by_address(sample_hosts, "192.168.56.5")
    assert 8443 not in [p.number for p in host.ports]


def test_ssl_services_are_labelled(sample_hosts):
    host = host_by_address(sample_hosts, "192.168.56.5")
    https = next(p for p in host.ports if p.number == 443)
    assert https.service == "ssl/http"


def test_missing_service_details_do_not_crash(sample_hosts):
    host = host_by_address(sample_hosts, "192.168.56.20")
    smb = next(p for p in host.ports if p.number == 445)
    assert smb.product == "" and smb.version == ""
    assert smb.service_label == "microsoft-ds"


def test_scan_with_no_hosts():
    hosts, _ = parse_nmap_xml('<nmaprun args="nmap 10.0.0.1"></nmaprun>')
    assert hosts == []


@pytest.mark.parametrize("bad_xml", ["", "not xml at all", "<other></other>"])
def test_invalid_xml_raises_parse_error(bad_xml):
    with pytest.raises(ParseError):
        parse_nmap_xml(bad_xml)
