# Lab Write-up: Scanning and Hardening a Linux Server

<!--
  HOW TO USE THIS TEMPLATE
  ------------------------
  1. Replace every "TODO" with your own words. Write it as YOU: what you did,
     what you saw and what you learned. Short and honest beats long and vague.
  2. Save screenshots into docs/images/ using the file names below.
  3. Each image line is hidden inside a comment like this one. Once the image
     file exists, delete the comment markers around it so it shows up.
  4. Delete this instructions block when you are finished.
  5. Add a link to this page from the main README (see the checklist at the end).

  Only ever include results from your isolated lab network.
  Never publish scans of your home or work network.
-->

> **Scope and authorisation:** every system scanned in this write-up is a
> virtual machine I own, running on an isolated VirtualBox network on my own
> computer. No other networks or systems were scanned.

**Date:** TODO (e.g. October 2026)
**Tool:** [netscan-report](../README.md) (Python + nmap)
**Skills shown:** network scanning, service enumeration, risk assessment,
remediation, verification

---

## 1. Summary

TODO: two or three sentences. For example: "I built a small virtual lab and
deliberately ran insecure services on a Linux server. netscan-report found
N High, N Medium and N Low findings. After hardening the server, a re-scan
showed N High, N Medium and N Low."

| | High | Medium | Low |
| --- | --- | --- | --- |
| Before hardening | TODO | TODO | TODO |
| After hardening | TODO | TODO | TODO |

## 2. Lab setup

| Role | Machine | OS | IP address |
| --- | --- | --- | --- |
| Attacker / scanner | `kali` | Kali Linux (ARM64) | TODO (e.g. 10.0.2.4) |
| Target | `linux-test` | TODO (e.g. Debian 13 ARM64) | TODO (e.g. 10.0.2.5) |

- **Hypervisor:** VirtualBox on macOS (Apple Silicon)
- **Network:** a VirtualBox **NAT Network** called `LabNet` (`10.0.2.0/24`).
  The VMs can reach each other and the internet, but nothing on my home
  network can reach them.

TODO: one sentence on why the lab is isolated.

<!-- ![VirtualBox showing the Kali and target VMs](images/lab-setup.png) -->

<!-- ![The LabNet NAT Network settings](images/network-settings.png) -->

## 3. Preparing the target

To have something realistic to find, I installed services on the target that
are commonly found on poorly configured servers:

| Service | Package | Why it's risky |
| --- | --- | --- |
| Telnet | `telnetd` | TODO |
| FTP | `vsftpd` | TODO |
| SMB file sharing | `samba` | TODO |
| Web server (HTTP) | `apache2` | TODO |

<!-- ![Listening services on the target (ss -tlnp)](images/target-services.png) -->

## 4. Scan: before hardening

Command run from Kali:

```bash
netscan-report TODO-TARGET-IP
```

<!-- ![Console output of the first scan](images/scan-before.png) -->

Full report: [HTML](lab-reports/before.html) · [JSON](lab-reports/before.json)

<!-- ![HTML report from the first scan](images/report-before.png) -->

## 5. Analysis of the top findings

Explain each finding in your own words. This section matters most to an
employer.

### Finding 1: TODO (e.g. Telnet exposed, High)

- **What it is:** TODO
- **Why it matters:** TODO (what could an attacker actually do?)
- **How to fix it:** TODO

### Finding 2: TODO (e.g. SMB exposed, High)

- **What it is:** TODO
- **Why it matters:** TODO
- **How to fix it:** TODO

### Finding 3: TODO (e.g. FTP exposed, Medium)

- **What it is:** TODO
- **Why it matters:** TODO
- **How to fix it:** TODO

## 6. Remediation

Commands I ran on the target to fix the findings:

```bash
TODO: paste the commands you actually ran, e.g.
sudo apt remove --purge -y telnetd
```

TODO: anything you decided NOT to fix, and why (e.g. "Kept Apache because the
server needs to host a website. In a real environment I would add HTTPS.").

## 7. Verification: after hardening

```bash
netscan-report TODO-TARGET-IP
```

<!-- ![Console output of the second scan](images/scan-after.png) -->

Full report: [HTML](lab-reports/after.html) · [JSON](lab-reports/after.json)

<!-- ![HTML report from the second scan](images/report-after.png) -->

TODO: what changed between the two scans? Did anything surprise you?

## 8. Limitations

TODO, in your own words. Points worth mentioning:

- A port scan only shows what is *exposed*, not whether it can actually be
  exploited.
- Version checks can be wrong, because Linux distributions backport security
  fixes without changing version numbers.
- Only TCP was scanned, so UDP services (e.g. SNMP) were not checked.

## 9. What I learned

- TODO
- TODO
- TODO

## 10. Next steps

- TODO (e.g. "Add HTTPS to the web server", "Try UDP scanning",
  "Add a --compare option to netscan-report to diff two scans")

---

<!--
  FINISHING CHECKLIST
  [ ] All TODOs replaced
  [ ] Screenshots in docs/images/ and their comment markers removed
  [ ] Reports copied into docs/lab-reports/ (before.html, before.json, after.html, after.json)
  [ ] Screenshots checked for personal info (home IPs, other windows, notifications)
  [ ] Link added to README.md, e.g. under "Sample output":
        ### Lab write-up
        See my [lab write-up](docs/lab-writeup.md) for a real before-and-after assessment.
  [ ] This comment and the instructions comment at the top deleted
-->
