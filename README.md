# Lazy Tool

Automates repetitive tasks during internal network penetration tests and Active Directory security assessments. Operates through SSH jumphosts using Paramiko (and your `~/.ssh/config`) to remotely execute tools on attack infrastructure.

## Features

| Mode | Description |
|---|---|
| `network-scans` | Launch nmap TCP/UDP scans on remote jumpboxes via SSH, orchestrated through a YAML config file. Supports live-host filtering via `arp-scan`. |
| `monitor-scans` | Monitor running scans on jumpboxes (probably broken). |
| `scan-results` | Download scan results from jumpboxes (probably broken). |
| `parse` | Parse nmap XML output, categorize services, and generate ready-to-run shell scripts (`parsed-nmap-checks/*.sh`) for service-specific enumeration (web, ssh, smb, ftp, dns, snmp, ldap, rpc, nfs, db, redis, smtp, mongodb, elasticsearch, rdp, winrm). |
| `users` | Dump enabled users and high-privilege users (Domain Admins, Enterprise Admins, etc.) from AD via LDAP through a jumpbox. |
| `roasting` | Perform Kerberoasting and ASREPRoasting attacks over SSH using `netexec` on a remote jumpbox. |
| `responder` | Start Responder on a jumpbox. With a config file, checks hosts for SMB signing and starts Responder + ntlmrelayx in socks mode. |
| `pass-audit` | Remote NTDS.dit extraction via WinRM + `smbclient` + `diskshadow`, then local secretsdump to dump NTLM hashes filtered to enabled users. |

## Prerequisites

### Python packages

```
paramiko       # SSH/SFTP connections
pyyaml          # YAML config parsing
```

Install with: `pip install -r requirements.txt` (if one exists) or `pip install paramiko pyyaml`.

### System tools expected on remote jumpboxes

`nmap`, `tmux`, `sudo` (passwordless), `arp-scan`, `ldapsearch`, `netexec`/`nxc`, `responder`, `impacket-ntlmrelayx`, `smbclient`

### System tools expected locally (for `parse` and `pass-audit` modes)

`httpx`, `nuclei`, `gobuster`, `nikto`, `testssl`, `ssh-audit`, `smbclient`, `netexec`, `smbmap`, `enum4linux`, `curl`, `dig`, `dnsrecon`, `snmpwalk`, `snmpcheck`, `ldapsearch`, `rpcclient`, `showmount`, `mysql`, `psql`, `redis-cli`, `smtp-user-enum`, `mongosh`, `gowitness`, `impacket-secretsdump`

## Usage

Run `python lazy-tool.py -h` for top-level help, or `python lazy-tool.py <mode> -h` for mode-specific help.

### Network scans (YAML-driven)

```bash
python lazy-tool.py network-scans example-config.yaml
python lazy-tool.py network-scans example-config.yaml -live       # scan only live hosts via arp-scan
python lazy-tool.py network-scans example-config.yaml -printonly  # just print what would run
```

### Parse nmap results and generate enumeration scripts

```bash
python lazy-tool.py parse -n /path/to/nmap-output.xml
python lazy-tool.py parse -n /path/to/nmap-output.xml -nhc       # skip httpx probing
python lazy-tool.py parse -n /path/to/nmap-output.xml -sp /path/to/SecLists
python lazy-tool.py parse -n /path/to/nmap-output.xml -ct        # check which local tools exist
```

### Active Directory

```bash
python lazy-tool.py users    -jh jumpbox -dc 10.0.0.1 -u admin@marvel.local -p Passw0rd -d marvel.local
python lazy-tool.py roasting -jh jumpbox -dc 10.0.0.1 -u admin@marvel.local -p Passw0rd -d marvel.local
python lazy-tool.py responder -jh jumpbox
python lazy-tool.py responder -jh jumpbox -c example-config.yaml
python lazy-tool.py pass-audit -dc 10.0.0.1 -u admin@marvel.local -p Passw0rd -d marvel.local
python lazy-tool.py pass-audit -dc 10.0.0.1 -u admin@marvel.local -p Passw0rd -d marvel.local -jh jumpbox -v
```
