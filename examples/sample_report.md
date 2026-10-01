# Network Scan Report: `192.168.56.0/24`

> This report was produced by an automated scan. Findings are indicators for a human to verify, not confirmed vulnerabilities. Only scan systems you own or have explicit written permission to test.

## Summary

| Item | Value |
| --- | --- |
| Target | `192.168.56.0/24` |
| Scan started | 2026-01-01T12:00:00 |
| nmap version | 7.94 |
| Live hosts | 3 |
| Open ports | 12 |
| High / Medium / Low | 7 / 4 / 1 |

## Findings

| Severity | Host | Port | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| **High** | 192.168.56.20 | 445 | **SMB exposed**: SMB file sharing has a long history of serious remote exploits (e.g. EternalBlue / WannaCry) and is a common ransomware entry point. | Block port 445 at the firewall except for trusted internal hosts; disable SMBv1 and keep the system patched. |
| **High** | 192.168.56.20 | 3389 | **RDP exposed**: Remote Desktop is heavily targeted by password-guessing attacks and has had critical vulnerabilities (e.g. BlueKeep). | Do not expose RDP directly. Put it behind a VPN or gateway, enforce Network Level Authentication, strong passwords and MFA. |
| **High** | 192.168.56.101 | 21 | **Backdoored vsftpd version**: Detected vsftpd 2.3.4. vsftpd 2.3.4 was distributed with a known backdoor (CVE-2011-2523) that gives an attacker a root shell. | Upgrade vsftpd immediately and investigate the host for compromise. |
| **High** | 192.168.56.101 | 22 | **Very old OpenSSH**: Detected OpenSSH 4.7p1 Debian 8ubuntu1. OpenSSH versions before 7.0 are many years old and affected by multiple known vulnerabilities. | Check the vendor's security advisories (distributions may backport fixes without changing the version number) and upgrade if affected. |
| **High** | 192.168.56.101 | 23 | **Telnet exposed**: Telnet sends usernames, passwords and all data in plain text, so anyone on the network path can read them. | Disable Telnet and use SSH instead. |
| **High** | 192.168.56.101 | 80 | **End-of-life Apache httpd**: Detected Apache httpd 2.2.8. Apache httpd versions before 2.4 are end-of-life and no longer receive security fixes. | Upgrade to a supported Apache 2.4 release. |
| **High** | 192.168.56.101 | 445 | **SMB exposed**: SMB file sharing has a long history of serious remote exploits (e.g. EternalBlue / WannaCry) and is a common ransomware entry point. | Block port 445 at the firewall except for trusted internal hosts; disable SMBv1 and keep the system patched. |
| **Medium** | 192.168.56.101 | 21 | **FTP exposed**: FTP sends credentials and files in plain text and may allow anonymous login. | Replace with SFTP or FTPS, and disable anonymous access. |
| **Medium** | 192.168.56.101 | 139 | **NetBIOS session service exposed**: NetBIOS can leak information about the host, users and shares, and is an older way of reaching SMB. | Disable NetBIOS over TCP/IP if it is not needed, or firewall it. |
| **Medium** | 192.168.56.101 | 3306 | **Database port exposed**: Database servers should rarely be reachable directly from other networks; exposure invites password guessing and exploits. | Firewall the database so only the application servers that need it can connect. |
| **Medium** | 192.168.56.101 | 3306 | **Outdated MySQL**: Detected MySQL 5.0.51a-3ubuntu5. MySQL versions before 8.0 are end-of-life. | Upgrade to a supported MySQL release. |
| **Low** | 192.168.56.101 | 80 | **Unencrypted HTTP**: The web service is served over plain HTTP, so traffic (including any logins) can be read or modified in transit. | Serve the site over HTTPS and redirect HTTP to HTTPS. |

## Hosts

### 192.168.56.5

| Port | Service | Product | Version | Extra info |
| --- | --- | --- | --- | --- |
| 22/tcp | ssh | OpenSSH | 9.9p1 | protocol 2.0 |
| 443/tcp | ssl/http | nginx | 1.26.2 |  |

### 192.168.56.20 (win-desktop.lab)

| Port | Service | Product | Version | Extra info |
| --- | --- | --- | --- | --- |
| 135/tcp | msrpc | Microsoft Windows RPC |  |  |
| 445/tcp | microsoft-ds |  |  |  |
| 3389/tcp | ms-wbt-server | Microsoft Terminal Services |  |  |

### 192.168.56.101 (metasploitable.lab)

| Port | Service | Product | Version | Extra info |
| --- | --- | --- | --- | --- |
| 21/tcp | ftp | vsftpd | 2.3.4 |  |
| 22/tcp | ssh | OpenSSH | 4.7p1 Debian 8ubuntu1 | protocol 2.0 |
| 23/tcp | telnet | Linux telnetd |  |  |
| 80/tcp | http | Apache httpd | 2.2.8 | (Ubuntu) DAV/2 |
| 139/tcp | netbios-ssn | Samba smbd | 3.X - 4.X | workgroup: WORKGROUP |
| 445/tcp | microsoft-ds | Samba smbd | 3.0.20-Debian | workgroup: WORKGROUP |
| 3306/tcp | mysql | MySQL | 5.0.51a-3ubuntu5 |  |

## Scan details

nmap command: `nmap -sV -T4 --open -oX - 192.168.56.0/24`
