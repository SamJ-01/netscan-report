"""Allows the tool to be run with `python -m netscan_report`."""

import sys

from netscan_report.cli import main

if __name__ == "__main__":
    sys.exit(main())
