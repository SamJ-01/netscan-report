# Lab Write-up: Scanning and Hardening a Linux Server

<!--
  DRAFT: rewrite this in your own words before sharing it, so you can talk
  about every part of it confidently. Check that the image file names in
  docs/images/ match the ones used below exactly (they are case-sensitive).
  Delete this comment when you are happy with the page.
-->

> **Scope and authorisation:** every system scanned in this write-up is a
> virtual machine I own, running on an isolated VirtualBox network on my own
> computer. No other networks or systems were scanned.

**Date:** October 2026
**Tool:** [netscan-report](../README.md) (Python + nmap)
**Skills shown:** lab building, network scanning, service enumeration, risk
assessment, remediation, verification, troubleshooting

---

## 1. Summary

I built a two-machine virtual lab, deliberately ran insecure services on a
Linux server, and scanned it with netscan-report. The first scan found
**1 High, 3 Medium and 1 Low** findings. I then hardened the server and
re-scanned it: only **1 Low** finding remained (plain HTTP on a web server I
chose to keep).

Testing against a real server also exposed a bug in the tool's risk rules:
SMB on port 445 was rated Medium instead of High. The rule has since been
fixed and covered by a regression test (see [section 8](#8-a-bug-found-by-real-world-testing)).

| | High | Medium | Low | Open ports |
| --- | --- | --- | --- | --- |
| Before hardening | 1 | 3 | 1 | 6 |
| Before hardening (re-rated with the fixed tool) | 2 | 2 | 1 | 6 |
| After hardening | **0** | **0** | 1 | 2 |

## 2. Lab setup

| Role | Machine | OS | IP address |
| --- | --- | --- | --- |
| Scanner | `kali` | Kali Linux (ARM64) | `10.0.2.15` |
| Target | `target` | Kali Linux (ARM64), linked clone of the scanner | `10.0.2.20` |

- **Host:** MacBook (Apple Silicon) running VirtualBox.
- **Network:** a VirtualBox **NAT Network** called `LabNet` (`10.0.2.0/24`).
  The VMs can reach each other and the internet (for installing packages),
  but nothing on my home network can reach them.
- **Remote access:** SSH from macOS into the VMs through port forwards bound
  to `127.0.0.1` only, so only my Mac can use them.

The lab is isolated so that deliberately vulnerable services are never
exposed to my home network, and so that every scan stays within systems I own.

The network was created from the command line:

```bash
VBoxManage natnetwork add --netname LabNet --network "10.0.2.0/24" --enable --dhcp on
```

![The LabNet NAT Network](images/network-settings.png)

![VirtualBox showing the Kali and target VMs](images/lab-setup.png)

## 3. Preparing the target

To have something realistic to find, I installed services that are commonly
found on poorly configured servers. Kali does not start network services
automatically, so each one also had to be enabled:

```bash
sudo apt install -y vsftpd samba apache2 inetutils-telnetd inetutils-inetd
sudo systemctl enable --now vsftpd smbd nmbd apache2 inetutils-inetd
```

| Service | Port | Why it's risky |
| --- | --- | --- |
| Telnet | 23 | Sends usernames, passwords and all data in plain text |
| FTP | 21 | Sends credentials and files in plain text, may allow anonymous login |
| SMB / NetBIOS (Samba) | 445 / 139 | Long history of remote exploits (e.g. EternalBlue), common ransomware entry point |
| Web server (Apache) | 80 | Plain HTTP: traffic can be read or changed in transit |
| SSH | 22 | Enabled on purpose for remote administration (not a finding) |

`ss -tlnp` on the target confirmed all six services were listening:

![Listening services on the target](images/target-services.png)

## 4. Scan: before hardening

Command run from the scanner:

```bash
netscan-report 10.0.2.20
```

![Console output of the first scan](images/scan-before.png)

Full report: [HTML](lab-reports/before.html) · [JSON](lab-reports/before.json)

![HTML report from the first scan](images/report-before.png)

![HTML report from the first scan (continued)](images/report-before-2.png)

## 5. Analysis of the top findings

### Finding 1: Telnet exposed (High)

- **What it is:** a remote login service from the 1960s–70s that has no
  encryption.
- **Why it matters:** anyone who can see the network traffic (for example on
  shared Wi-Fi, or after compromising another machine on the network) can read
  the username and password as plain text and log in as that user.
- **How to fix it:** remove Telnet and use SSH, which encrypts the whole
  session.

### Finding 2: SMB exposed (High)

- **What it is:** Windows-style file sharing, provided on Linux by Samba.
- **Why it matters:** SMB has had some of the most damaging vulnerabilities in
  recent history (EternalBlue was used by the WannaCry ransomware), and exposed
  shares can leak data or be targeted by password guessing.
- **How to fix it:** stop the service if it isn't needed; otherwise firewall
  it to trusted hosts only, disable SMBv1 and keep it patched.

### Finding 3: FTP exposed (Medium)

- **What it is:** an old file-transfer protocol.
- **Why it matters:** like Telnet, it sends credentials and files unencrypted,
  and misconfigured servers may allow anonymous access.
- **How to fix it:** replace it with SFTP (which runs over SSH) or FTPS, and
  disable anonymous login.

## 6. Remediation

Commands run on the target:

```bash
sudo apt remove --purge -y inetutils-telnetd
sudo systemctl disable --now vsftpd smbd nmbd
```

`disable --now` stops each service immediately **and** stops it starting
again at boot, so the fix survives a reboot.

I deliberately kept two services:

- **SSH (22):** needed to administer the server remotely. A current OpenSSH
  version is not flagged by the tool.
- **Apache (80):** the server is meant to host a website. In a real
  environment the next step would be to add HTTPS and redirect HTTP to it,
  which would clear the remaining Low finding.

## 7. Verification: after hardening

```bash
netscan-report 10.0.2.20
```

![Console output of the second scan](images/scan-after.png)

Full report: [HTML](lab-reports/after.html) · [JSON](lab-reports/after.json)

![HTML report from the second scan](images/report-after.png)

![HTML report from the second scan (continued)](images/report-after-2.png)

The open ports dropped from six to two, and every High and Medium finding
disappeared. Re-scanning matters: it proves the fix worked from an
attacker's point of view, rather than assuming it did.

## 8. A bug found by real-world testing

The first scan reported **1 High**, but I expected 2. Looking at the output,
nmap had labelled port 445 as `netbios-ssn`, the same label as port 139:

```text
139/tcp  netbios-ssn (Samba smbd 4)
445/tcp  netbios-ssn (Samba smbd 4)
[MEDIUM] port 445: NetBIOS session service exposed
```

Samba answers on both ports, so nmap's version detection gives them the same
name. The tool's rules trust nmap's service name over the port number (so
that, for example, Telnet on a non-standard port is still caught), which meant
SMB on 445 was never matched by the "SMB exposed" rule and was under-rated as
Medium.

**Fix:** the risk rules now treat `netbios-ssn` **on port 445** as SMB, and
two regression tests use the exact data from this lab: 445 must be rated High,
and 139 must stay Medium. With the fix, the "before" scan rates as
**2 High, 2 Medium, 1 Low**.

**Lesson:** unit tests with sample data only prove the code does what I
*expected* the scanner to output. Testing against a real system showed what
it *actually* outputs.

## 9. Challenges and how I solved them

| Problem | Cause | Solution |
| --- | --- | --- |
| Planned target (Metasploitable 2) wouldn't run | It is built for Intel PCs, and my Mac is Apple Silicon (ARM) | Cloned my Kali VM as the target and installed insecure services on it |
| Kali VM failed to start (`VERR_SSM_LOAD_CONFIG_MISMATCH`) | Its saved state no longer matched the VM's configuration | Discarded the saved state; now I always shut VMs down instead of saving them |
| Network settings missing from VirtualBox | VirtualBox's Basic mode hides advanced tools | Created the network with `VBoxManage` from the command line |
| Cloned VM had no IP address | The clone got a new MAC address, and the copied network profile didn't pick it up | Created a fresh NetworkManager profile with a fixed address (`10.0.2.20`) |
| Services installed but not listening | Kali disables network services by default | Enabled them with `systemctl enable --now` |
| Telnet (port 23) not listening | Telnet runs through `inetd`, and its entry was disabled | `update-inetd --enable telnet` and restarted `inetd` |
| Copy-paste into the VMs didn't work | Shared clipboard needs Guest Additions, which are awkward on ARM | Used SSH from the Mac Terminal instead, which is also how real servers are managed |

## 10. Limitations

- A port scan shows what is **exposed**, not whether it can actually be
  exploited.
- Version checks rely on what services report. Linux distributions often
  backport security fixes without changing version numbers, so "outdated"
  results need checking against vendor advisories.
- Only TCP was scanned, so UDP services (such as SNMP) were not checked.
- I scanned over the network rather than from the target itself, on purpose:
  a local scan can report services bound only to `127.0.0.1`, or blocked by a
  firewall, as if they were exposed.

## 11. What I learned

- How to build an isolated lab network and manage VMs from the command line.
- What makes Telnet, FTP and SMB risky, and how to remove or restrict them.
- Why every fix should be verified with a second scan.
- That real-world testing finds problems that unit tests with sample data miss.
- How to troubleshoot networking problems step by step (`ip a`, `ping`,
  `ss -tlnp`, `nmcli`).

## 12. Next steps

- Add HTTPS to the web server to clear the last Low finding.
- Add UDP scanning for services such as SNMP and DNS.
- Add a `--compare` option to netscan-report to show what changed between two
  scans automatically.
