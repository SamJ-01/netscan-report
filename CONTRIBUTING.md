# Contributing

Thanks for your interest in improving netscan-report! This is a small learning
project, so contributions of any size are welcome, including typo fixes.

## Ground rules

- **Never include real scan data from networks you don't own** in issues, pull
  requests or test files. Use private lab addresses (e.g. `192.168.56.x`) or
  made-up data.
- Keep the code beginner-readable: clear names, docstrings, and comments that
  explain *why*, not just *what*.
- The tool should keep working with only the Python standard library (plus nmap).

## Getting set up

```bash
git clone https://github.com/SamJ-01/netscan-report.git
cd netscan-report
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt
pytest
```

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on
   the approach.
2. Create a branch: `git checkout -b my-change`.
3. Add or update tests in `tests/`. Tests must **not** run real scans; use
   sample XML or monkeypatching (see `tests/test_scanner.py`).
4. Run `pytest` and make sure everything passes.
5. Open a pull request describing what you changed and why.

## Adding a risk rule

Risk rules live in `netscan_report/risk.py`:

- add a `ServiceRule` to `SERVICE_RULES` for a service that is risky to expose, or
- add a `VersionRule` to `VERSION_RULES` for an outdated product version
  (list rules for the same product **most severe first**).

Please include a short, factual description, a practical recommendation and,
where possible, a reference (e.g. a CVE number), plus a test in
`tests/test_risk.py`.

## Reporting security issues

If you find a security problem in this tool itself, please open an issue
without exploit details, or contact the maintainer via GitHub.
