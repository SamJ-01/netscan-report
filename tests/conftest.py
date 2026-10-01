"""Shared pytest fixtures.

The tests use the saved nmap XML in examples/sample_scan.xml, so they never
need nmap installed and never scan anything.
"""

from pathlib import Path

import pytest

from netscan_report.parser import parse_nmap_xml

SAMPLE_XML = Path(__file__).resolve().parent.parent / "examples" / "sample_scan.xml"


@pytest.fixture
def sample_xml() -> str:
    """The raw text of the sample nmap XML file."""
    return SAMPLE_XML.read_text(encoding="utf-8")


@pytest.fixture
def sample_hosts(sample_xml):
    """The sample XML parsed into a list of Host objects."""
    hosts, _metadata = parse_nmap_xml(sample_xml)
    return hosts
