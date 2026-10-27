# AEGISLOG
![Logo](assets/Logo_Aeigis.jpg)
**Network & Log Defense Toolkit for Kali Linux**

AEGISLOG is a single-file, dependency-free Python tool for defensive security. It inspects your system, scans ports, analyzes SSH and web server logs for attack patterns, and correlates exposure with log activity to produce a security score.

> ⚠️ **For authorized use only.** Scan and analyze only systems you own or have explicit permission to test.

---

## Features

| Module | Description |
|---|---|
| **System & network info** | Hostname, user, root status, OS, kernel, architecture, local IP and network interfaces (state, MAC, addresses) |
| **Connectivity test** | Ping with packet loss and average latency, plus DNS failure detection |
| **Port scanner** | Multithreaded TCP connect scan, service name lookup, warnings for risky services |
| **Listening services** | Parses `ss` to show what is listening, on which address, by which process, and whether it is exposed or local-only |
| **Log analyzer** | Detects brute force, web attacks and scanners in SSH and web logs |
| **Full security audit** | Correlates exposed ports with log findings, then gives a score (0–100), a grade (A–F) and recommendations |

---

## Requirements

- Linux (developed and tested on Kali)
- Python 3.8+
- **No external packages**: standard library only

System tools used when available (the tool degrades gracefully without them): `ss`, `ip`, `ping`, `journalctl`.

---

## Installation

```bash
git clone https://github.com/<your-username>/aegislog.git
cd aegislog
python3 aegislog.py
```

Run with `sudo` to read protected logs (e.g. `/var/log/auth.log`) and to see process names for every listening socket.

---

## Usage

### Interactive menu

```bash
python3 aegislog.py
```

### Direct commands

```bash
python3 aegislog.py info
python3 aegislog.py ping 1.1.1.1
python3 aegislog.py ports --target 127.0.0.1 --ports top
python3 aegislog.py logs /var/log/auth.log access.log
python3 aegislog.py logs journal
python3 aegislog.py audit --json report.json
```

### Global options

| Option | Description |
|---|---|
| `--no-color` | Disable colored output (must come **before** the subcommand). The `NO_COLOR` environment variable is also respected. |

### Commands

#### `info`
Shows system and network information.

#### `ping [host]`
Connectivity test. Default host: `8.8.8.8`.

#### `ports`
| Option | Default | Description |
|---|---|---|
| `--target` | `127.0.0.1` | Host to scan |
| `--ports` | `common` | `common`, `top` (ports 1–1024), a list like `22,80,443`, or a range like `1-1000` |
| `--timeout` | `0.5` | Connection timeout in seconds |
| `--json FILE` | – | Save the result as JSON |

When the target is the local machine, the scan is followed by the list of listening services from `ss`.

#### `logs [files...]`
Analyzes log files (`.gz` supported) or the keyword `journal` to read SSH logs from journald. With no arguments, sources are auto-detected.

| Option | Default | Description |
|---|---|---|
| `--window` | `300` | Sliding time window in seconds |
| `--threshold` | `5` | Minimum number of attempts to flag |
| `--year` | current year | Year to assume for syslog lines that don't include one |
| `--json FILE` | – | Save the result as JSON |

#### `audit`
Runs the full audit in four steps (system, exposure, logs, verdict).

| Option | Description |
|---|---|
| `--json FILE` | Save the full report as JSON |

---

## Detections

### SSH

| Severity | Finding | Logic |
|---|---|---|
| 🔴 CRITICAL | Login succeeded after brute force | A successful login from an IP that previously had ≥ `threshold` failed attempts |
| 🟠 HIGH | SSH brute force | ≥ `threshold` failed logins from one IP within `window` seconds |
| 🟡 MEDIUM | User enumeration / password spraying | One IP trying many different usernames |

### Web (Apache / Nginx / httpd)

| Severity | Finding | Logic |
|---|---|---|
| 🟠 HIGH | SQL injection | Patterns such as `UNION SELECT`, `OR 1=1`, `sleep()`, `information_schema` |
| 🟠 HIGH | Path traversal | `../`, `/etc/passwd`, `/etc/shadow`, `/proc/self` |
| 🟠 HIGH | XSS | `<script`, `onerror=`, `onload=`, `javascript:` |
| 🟠 HIGH | Command injection | Shell operators followed by commands, `/bin/sh` |
| 🟠 HIGH | Web login brute force | Burst of POST requests to login-like paths |
| 🟡 MEDIUM | Offensive tool / scanner | User-Agent of tools like sqlmap, nikto, gobuster, ffuf, nmap, hydra, nuclei, wpscan… |
| 🟡 MEDIUM | Directory enumeration | Burst of 403/404 responses from one IP |

Request paths are URL-decoded **twice**, so single and double encoding (`%2e%2e`, `%252e%252e`) are caught.

### Log sources (auto-detected)

- SSH: `/var/log/auth.log`, `/var/log/secure`, or journald (`journal`) when no auth log exists
- Web: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/httpd/access_log`

---

## Security score

The audit starts from 100 points and subtracts penalties:

- **Findings**, capped per severity: CRITICAL 30 each (max 60), HIGH 8 (max 40), MEDIUM 3 (max 15), LOW 1 (max 5)
- **Exposed risky services**: e.g. Telnet −15, Redis / MongoDB −12, databases −10, FTP / SMB / RDP / VNC −8

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 55–74 | C |
| 35–54 | D |
| 0–34 | F |

Risky services flagged: FTP, Telnet, SMB, RDP, VNC, MySQL, PostgreSQL, Redis, MongoDB.

---

## JSON output

Reports can be exported with `--json FILE` (or from the interactive menu), for example:

```json
{
  "timestamp": "2026-10-27T10:30:00",
  "system": { "...": "..." },
  "services": [ { "proto": "tcp", "port": 22, "addr": "0.0.0.0", "process": "sshd", "exposed": true } ],
  "findings": [ { "severity": "HIGH", "type": "SSH brute force", "ip": "203.0.113.5", "count": 42 } ],
  "score": 62,
  "grade": "C",
  "recommendations": [ "..." ]
}
```

---

## Limitations

- Linux only: relies on `ss`, `ip`, `/sys/class/net` and `journalctl`.
- The port scanner is a plain **TCP connect scan over IPv4**; no UDP, no stealth scanning, no service fingerprinting.
- `--ports top` scans ports 1–1024, not a statistical "top ports" list.
- Syslog lines have no year; the tool assumes the current year (or `--year`) and corrects logs from the previous December.
- Web log parsing expects the standard Apache/Nginx *combined* format.
- Detection is regex- and threshold-based: expect some false positives and false negatives. Tune `--window` and `--threshold` to your environment.

---

## Project structure

```
aegislog/
├── aegislog.py   # entire tool (menu, CLI, scanners, analyzers)
└── README.md
```

---

## Disclaimer

This tool is provided for educational and defensive purposes. The author is not responsible for misuse. Always obtain proper authorization before scanning or analyzing systems you do not own.

## License

Add your license here (e.g. MIT).