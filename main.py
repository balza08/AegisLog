#!/usr/bin/env python3
"""
AEGISLOG - Network & Log Defense Toolkit (Kali Linux)

Interactive menu:      python3 aegislog.py
Direct commands:       python3 aegislog.py info
                       python3 aegislog.py ping 1.1.1.1
                       python3 aegislog.py ports --target 127.0.0.1 --ports top
                       python3 aegislog.py logs /var/log/auth.log access.log
                       python3 aegislog.py logs journal          (read SSH logs from journald)
                       python3 aegislog.py audit --json report.json

Only scan and analyze systems you own or are authorized to test.
"""
#import per colori da terminal
import sys                           # sys.stdout.isatty(): decide se usare i colori

#Interfaccia da riga di comando 
import argparse                      # info, ping, ports, logs, audit
import shlex                         # lexical analysis

#Sistema operativo e processi 
import os                            # clear schermo, variabili d'ambiente, file, geteuid (root?)
import platform                      # nome OS, kernel, architettura, versione Python
import shutil                        # shutil.which(): controlla se un comando esiste (ss, ip, ...)
import subprocess                    # esegue comandi esterni (ping, ss, ip, journalctl)
import sys                           # sys.stdout.isatty(): decide se usare i colori
from getpass import getuser          # nome dell'utente corrente

#Rete e parallelismo 
import socket                        # IP locale, connect_ex (scan porte), DNS, nomi dei servizi
from concurrent.futures import ThreadPoolExecutor   # sonde sulle porte in parallelo

#Lettura e parsing dei log 
import gzip                          # legge i log compressi (.gz)
import re                            # regex: estrae IP, utenti, date e riconosce gli attacchi
from urllib.parse import unquote     # decodifica gli URL (%2e%2e -> ..), anche il double encoding

#Tempo e date
import time                          # time.time() per misurare la scansione, sleep() nel menu
from datetime import datetime, timedelta   # date dei log, finestra scorrevole, correzione anno

#Strutture dati e salvataggio risultati
import json                          # esporta i report in JSON
from collections import defaultdict  # dizionario che crea da solo i valori mancanti
from dataclasses import asdict, dataclass   # classe Finding e conversione in dizionario

VERSION = "1.0"

BANNER = r"""
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░░░░█░░░░░▌▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌▐░▌          ▐░▌          ▐█████░█████▌▐░▌          
▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌ ▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌▐░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌ ▀▀▀▀▀█░▌      ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌
▐░▌       ▐░▌▐░▌          ▐░▌      ▐░▌      ▐░▌               ▐░▌
▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄█░▌ ▄▄▄▄▄█░█▄▄▄▄ ▄▄▄▄▄▄▄▄▄█░▌
▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
"""


class C:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    # Colori standard (30-37) invece dei "brillanti" (90-97):
    # più scuri, meno aggressivi, e rispettano il tema del terminale
    CODES = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "cyan": "36",
        "grey": "90",
        "bold": "1",
        "dim": "2",
    }

    @classmethod
    def c(cls, code, text):
        """Colora un testo con un codice ANSI (es. "31" o "38;5;245")."""
        return f"\033[{code}m{text}\033[0m" if cls.on else str(text)

    @classmethod
    def disable(cls):
        """Disattiva i colori (usato da --no-color)."""
        cls.on = False

    @classmethod
    def red(cls, t):
        return cls.c(cls.CODES["red"], t)

    @classmethod
    def green(cls, t):
        return cls.c(cls.CODES["green"], t)

    @classmethod
    def yellow(cls, t):
        return cls.c(cls.CODES["yellow"], t)

    @classmethod
    def blue(cls, t):
        return cls.c(cls.CODES["blue"], t)

    @classmethod
    def cyan(cls, t):
        return cls.c(cls.CODES["cyan"], t)

    @classmethod
    def grey(cls, t):
        return cls.c(cls.CODES["grey"], t)

    @classmethod
    def bold(cls, t):
        return cls.c(cls.CODES["bold"], t)

    @classmethod
    def dim(cls, t):
        return cls.c(cls.CODES["dim"], t)

    @classmethod
    def severity(cls, level, text):
        """Colore per livello di gravità: il colore comunica, non decora."""
        colors = {
            "critical": "1;31",   # rosso bold
            "high": "31",         # rosso
            "medium": "33",       # giallo
            "low": "36",          # ciano
            "info": "90",         # grigio
        }
        return cls.c(colors.get(level.lower(), "0"), text)


# Banner monocromatico: sfumature di grigio (scala 232-255 di xterm-256)
# al posto del gradiente ciano -> viola
GRADIENT = ["38;5;240", "38;5;243", "38;5;245", "38;5;247",
            "38;5;249", "38;5;251", "38;5;253", "38;5;255"]
WIDTH = 64


def clear_screen():
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")

def banner():
    lines = [ln for ln in BANNER.splitlines() if ln.strip()]
    for i, ln in enumerate(lines):
        idx = i * len(GRADIENT) // len(lines)
        print(C.c(GRADIENT[idx], ln))
    print(C.bold(C.cyan("   AEGISLOG")) + C.dim(f"  ·  Network & Log Defense Toolkit  ·  v{VERSION}"))
    print(C.dim("   For authorized use only"))

def section(title):
    print("\n" + C.cyan("┌─[ ") + C.bold(title) + C.cyan(" ]" + "─" * max(2, WIDTH - len(title) - 6)))


def kv(label, value):
    print(f"  {C.dim(label.ljust(20))} {value}")


def ok(msg):
    print(C.green("[+] ") + msg)


def bad(msg):
    print(C.red("[-] ") + msg)


def note(msg):
    print(C.cyan("[*] ") + msg)


def warn(msg):
    print(C.yellow("[!] ") + msg)


def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(C.cyan("  ? ") + prompt + C.dim(suffix) + ": ").strip()
    return value or default


def pause():
    input(C.dim("\nPress ENTER to return to the menu..."))

# Helpers
def run(cmd, timeout=5):
    """Run a command, return (returncode, stdout). (-1, '') if unavailable."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.returncode, r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return -1, ""


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0)
            s.connect(("8.8.8.8", 80))  # UDP connect: no packet is actually sent
            return s.getsockname()[0]
    except Exception:
        return None


def save_json(data, path):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
    ok(f"Report saved to {C.bold(path)}")


def offer_save(data):
    if ask("Save JSON report? (y/N)", "n").lower().startswith("y"):
        default = f"aegislog_report_{datetime.now():%Y%m%d_%H%M%S}.json"
        save_json(data, ask("File name", default))

# 1. SYSTEM & NETWORK INFO --> per ora solo locale --> prende dal tuo OS
def get_interfaces():
    ifaces = []
    base = "/sys/class/net"

    def rd(name, f):
        try:
            with open(f"{base}/{name}/{f}") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            ifaces.append({"name": name, "state": rd(name, "operstate") or "?", "mac": rd(name, "address"), "addrs": []})

    if shutil.which("ip"):
        _, out = run(["ip", "-br", "addr"])
        addrs = {}
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 3:
                addrs[p[0].split("@")[0]] = p[2:]
        for i in ifaces:
            i["addrs"] = addrs.get(i["name"], [])
    return ifaces


def show_system_info(header=True):
    if header:
        section("System & Network Information")
    ip = get_local_ip()
    info = {
        "hostname": socket.gethostname(),
        "user": getuser(),
        "root": is_root(),
        "os": f"{platform.system()} {platform.release()}",
        "kernel": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "local_ip": ip,
        "interfaces": get_interfaces(),
    }
    kv("Hostname", C.bold(info["hostname"]))
    kv("User", info["user"] + (C.green("  (root)") if info["root"] else C.dim("  (not root: some logs may be unreadable)")))
    kv("Operating system", info["os"])
    kv("Kernel", info["kernel"][:44])
    kv("Architecture", info["arch"])
    kv("Python", info["python"])
    kv("Local IP", C.cyan(ip) if ip else C.red("not available (no active interface?)"))

    if info["interfaces"]:
        print("\n  " + C.dim("INTERFACE".ljust(14) + "STATE".ljust(10) + "MAC".ljust(20) + "ADDRESSES"))
        for i in info["interfaces"]:
            state = C.green(i["state"].ljust(10)) if i["state"] == "up" else C.dim(i["state"].ljust(10))
            print(f"  {i['name'].ljust(14)}{state}{(i['mac'] or '-').ljust(20)}{', '.join(i['addrs']) or '-'}")
    return info

# 2. CONNECTIVITY TEST
def ping_test(host="8.8.8.8", count=3):
    section(f"Connectivity test -> {host}")
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", flag, str(count)] + ([] if flag == "-n" else ["-W", "2"]) + [host]
    result = {"host": host, "reachable": False, "loss": None, "rtt_avg_ms": None}

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 3 + 4, errors="replace")
    except subprocess.TimeoutExpired:
        bad("Timeout: no response from the host.")
        return result
    except FileNotFoundError:
        bad("'ping' command not found on this system.")
        return result

    out = r.stdout + r.stderr
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    rtt = re.search(r"= [\d.]+/([\d.]+)/[\d.]+", out)
    if loss:
        result["loss"] = float(loss.group(1))
    if rtt:
        result["rtt_avg_ms"] = float(rtt.group(1))

    if r.returncode == 0:
        result["reachable"] = True
        ok(f"{host} is reachable")
        kv("Packet loss", f"{result['loss']}%" if loss else "?")
        kv("Average latency", f"{result['rtt_avg_ms']} ms" if rtt else "?")
    elif "not known" in out.lower() or "resolution" in out.lower():
        bad(f"Cannot resolve '{host}' (DNS problem?)")
    else:
        bad(f"{host} is unreachable")
    return result

# 3. PORT SCANNER + LISTENING SERVICES
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# port -> (reason, score penalty when exposed)
RISKY_PORTS = {
    21: ("FTP sends credentials in clear text", 8),
    23: ("Telnet sends everything in clear text", 15),
    445: ("SMB is a frequent attack target", 8),
    3389: ("RDP exposed to brute force", 8),
    5900: ("VNC often weakly protected", 8),
    3306: ("database should not be public", 10),
    5432: ("database should not be public", 10),
    6379: ("Redis is often unauthenticated", 12),
    27017: ("MongoDB is often unauthenticated", 12),
}


def parse_ports(spec):
    spec = spec.strip().lower()
    if spec in ("common", ""):
        return sorted(COMMON_PORTS)
    if spec == "top":
        return list(range(1, 1025))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def service_name(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "unknown"


def _probe(ip, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return port if s.connect_ex((ip, port)) == 0 else None


def scan_ports(host, ports, timeout=0.5, workers=150):
    ip = socket.gethostbyname(host)
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        found = [p for p in ex.map(lambda p: _probe(ip, p, timeout), ports) if p]
    return ip, [{"port": p, "service": service_name(p)} for p in found]


def is_exposed(addr):
    return not (addr.startswith("127.") or addr in ("::1", "localhost"))


def listening_services():
    """Parse `ss`. Returns None if ss is unavailable."""
    if not shutil.which("ss"):
        return None
    rc, out = run(["ss", "-H", "-tulnp"])
    if rc != 0:
        return None
    seen, svcs = set(), []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        addr, _, port = p[4].rpartition(":")
        if not port.isdigit():
            continue
        addr = addr.strip("[]") or "*"
        key = (p[0], int(port), addr)
        if key in seen:
            continue
        seen.add(key)
        proc = re.search(r'\("([^"]+)"', line)
        svcs.append({"proto": p[0], "port": int(port), "addr": addr,
                     "process": proc.group(1) if proc else "-", "exposed": is_exposed(addr)})
    return sorted(svcs, key=lambda s: (s["port"], s["proto"]))


def show_listening(svcs):
    print("\n  " + C.dim("PROTO".ljust(7) + "PORT".ljust(8) + "BIND ADDRESS".ljust(22) + "PROCESS".ljust(18) + "EXPOSURE"))
    for s in svcs:
        expo = C.yellow("EXPOSED") if s["exposed"] else C.green("local only")
        risky = RISKY_PORTS.get(s["port"])
        extra = C.red(f"  ⚠ {risky[0]}") if (risky and s["exposed"]) else ""
        print(f"  {s['proto'].ljust(7)}{str(s['port']).ljust(8)}{s['addr'].ljust(22)}{s['process'].ljust(18)}{expo}{extra}")


def cmd_ports(target="127.0.0.1", spec="common", timeout=0.5):
    section(f"Port scanner -> {target}")
    try:
        ports = parse_ports(spec)
        ip = socket.gethostbyname(target)
    except ValueError as e:
        bad(f"Invalid port specification: {e}")
        return {}
    except socket.gaierror:
        bad(f"Cannot resolve '{target}'")
        return {}

    local = ip.startswith("127.") or ip == get_local_ip()
    if not local:
        warn("Target is not this machine. Only scan hosts you are authorized to test.")

    note(f"Scanning {len(ports)} port(s) on {ip} ...")
    t0 = time.time()
    _, open_ports = scan_ports(ip, ports, timeout)
    elapsed = time.time() - t0

    print()
    for p in open_ports:
        risky = RISKY_PORTS.get(p["port"])
        flag = C.red(f"  ⚠ {risky[0]}") if risky else ""
        print(f"  {C.green('[OPEN]')}  {str(p['port']).ljust(6)} {p['service']}{flag}")
    print()
    if open_ports:
        ok(f"{len(open_ports)} open port(s) found in {elapsed:.1f}s")
    else:
        bad(f"No open ports found ({elapsed:.1f}s)")

    result = {"target": ip, "open_ports": open_ports, "listening": None}
    if local:
        svcs = listening_services()
        if svcs:
            section("Listening services (ss)")
            show_listening(svcs)
            result["listening"] = svcs
            if not is_root():
                print(C.dim("\n  Tip: run with sudo to see the process name of every socket."))
    return result

# 4. LOG  --> percorso file / journal SSH  
SSH_FAIL = re.compile(r"Failed \w+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")
SSH_OK = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")

SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)")
ISO_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)")

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

ATTACK_PATTERNS = {
    "SQL injection": re.compile(
        r"(union(\s|\+|/\*.*?\*/)+select|\bor\s+1=1|'\s*or\s*'|sleep\(\d+\)|information_schema|benchmark\()", re.I),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self)", re.I),
    "XSS": re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:)", re.I),
    "Command injection": re.compile(r"((;|\|\||&&|\|)\s*(cat|ls|id|whoami|wget|curl|nc|bash)\b|/bin/(ba)?sh)", re.I),
}

#Riconosce il tool con il quale è stato fatto l'attacco
SCANNER_UA = re.compile(
    r"sqlmap|nikto|gobuster|dirbuster|wfuzz|ffuf|nmap|masscan|hydra|zgrab|nuclei|wpscan|acunetix|nessus", re.I)
LOGIN_PATH = re.compile(r"(login|signin|wp-login|xmlrpc|admin|auth)", re.I)

SSH_LOG_FILES = ["/var/log/auth.log", "/var/log/secure"]
WEB_LOG_FILES = ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/httpd/access_log"]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_STYLE = {"CRITICAL": "1;97;41", "HIGH": "1;91", "MEDIUM": "93", "LOW": "96"}


@dataclass
class Finding:
    severity: str
    type: str
    ip: str
    count: int
    first_seen: str
    last_seen: str
    detail: str
    source: str
    category: str  # "ssh" or "web"


def default_log_sources():
    sources = [p for p in SSH_LOG_FILES + WEB_LOG_FILES if os.path.isfile(p)]
    if not any(p in SSH_LOG_FILES for p in sources) and shutil.which("journalctl"):
        sources.append("journal")  # modern Kali: no auth.log, SSH logs live in journald
    return sources


def read_lines(src):
    if src == "journal":
        rc, out = run(["journalctl", "-t", "sshd", "-t", "sshd-session", "--no-pager", "-o", "short-iso"], timeout=60)
        if rc != 0 and not out:
            raise OSError("journalctl unavailable or access denied")
        yield from out.splitlines()
        return
    opener = gzip.open(src, "rt", errors="replace") if src.endswith(".gz") else open(src, "r", errors="replace")
    with opener as fh:
        yield from fh


def parse_syslog_ts(line, year):
    m = ISO_TS.match(line)
    if m:
        return datetime.fromisoformat(m.group(1))
    m = SYSLOG_TS.match(line)
    if m:
        try:
            ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        if ts > datetime.now() + timedelta(days=1):  # log from last December read in January
            ts = ts.replace(year=ts.year - 1)
        return ts
    return None


def parse_web_ts(ts):
    try:
        return datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def find_burst(times, window, threshold):
    """Sliding window: return (n, start, end) of the biggest burst if n >= threshold."""
    times = sorted(times)
    j, best = 0, (0, None, None)
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > window:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, times[j], t)
    return best if best[0] >= threshold else None


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "?"


def analyze_logs(sources, window=300, threshold=5, year=None):
    year = year or datetime.now().year
    ssh_fails, ssh_oks, web = defaultdict(list), defaultdict(list), defaultdict(list)
    origin = {}
    stats = {"read": [], "skipped": [], "lines": 0}

    for src in sources:
        try:
            for line in read_lines(src):
                stats["lines"] += 1
                line = line.rstrip("\n")

                if "sshd" in line:
                    ts = parse_syslog_ts(line, year)
                    m = SSH_FAIL.search(line)
                    if m and ts:
                        ssh_fails[m["ip"]].append((ts, m["user"]))
                        origin[("ssh", m["ip"])] = src
                        continue
                    m = SSH_OK.search(line)
                    if m and ts:
                        ssh_oks[m["ip"]].append((ts, m["user"]))
                        continue

                m = WEB_LINE.match(line)
                if m:
                    ts = parse_web_ts(m["ts"])
                    if ts:
                        web[m["ip"]].append({"ts": ts, "method": m["method"],
                                             "path": unquote(unquote(m["path"])),
                                             "status": int(m["status"]), "ua": m["ua"] or ""})
                        origin[("web", m["ip"])] = src
            stats["read"].append(src)
        except OSError as e:
            stats["skipped"].append((src, e.strerror or str(e)))

    findings = _analyze_ssh(ssh_fails, ssh_oks, origin, window, threshold)
    findings += _analyze_web(web, origin, window, threshold)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))
    return findings, stats


def _analyze_ssh(fails, oks, origin, window, threshold):
    out = []
    for ip, events in fails.items():
        times = [t for t, _ in events]
        users = {u for _, u in events}
        src = origin.get(("ssh", ip), "")

        burst = find_burst(times, window, threshold)
        if burst:
            n, start, end = burst
            out.append(Finding("HIGH", "SSH brute force", ip, n, fmt(start), fmt(end),
                               f"{n} failed logins within {window}s ({len(events)} total, {len(users)} usernames tried)",
                               src, "ssh"))

        if len(users) >= max(5, threshold):
            out.append(Finding("MEDIUM", "SSH user enumeration / password spraying", ip, len(events),
                               fmt(min(times)), fmt(max(times)),
                               f"{len(users)} different usernames: {', '.join(sorted(users)[:6])}...", src, "ssh"))

        for ts_ok, user_ok in oks.get(ip, []):
            before = [t for t in times if t <= ts_ok]
            if len(before) >= threshold:
                out.append(Finding("CRITICAL", "SSH login succeeded after brute force", ip, len(before),
                                   fmt(min(before)), fmt(ts_ok),
                                   f"Logged in as '{user_ok}' after {len(before)} failed attempts: POSSIBLE COMPROMISE",
                                   src, "ssh"))
                break
    return out


def _analyze_web(web, origin, window, threshold):
    out = []
    for ip, events in web.items():
        src = origin.get(("web", ip), "")
        first, last = fmt(min(e["ts"] for e in events)), fmt(max(e["ts"] for e in events))

        hits = defaultdict(list)
        for e in events:
            for name, rx in ATTACK_PATTERNS.items():
                if rx.search(e["path"]):
                    hits[name].append(e)
        for name, evs in hits.items():
            out.append(Finding("HIGH", f"Web attack: {name}", ip, len(evs),
                               fmt(min(e["ts"] for e in evs)), fmt(max(e["ts"] for e in evs)),
                               f"Example: {evs[0]['path'][:80]}", src, "web"))

        scanners = {e["ua"] for e in events if SCANNER_UA.search(e["ua"])}
        if scanners:
            n = sum(1 for e in events if SCANNER_UA.search(e["ua"]))
            out.append(Finding("MEDIUM", "Offensive tool / scanner", ip, n, first, last,
                               f"User-Agent: {', '.join(sorted(scanners))[:80]}", src, "web"))

        errs = [e["ts"] for e in events if e["status"] in (403, 404)]
        burst = find_burst(errs, window, threshold * 4)
        if burst:
            n, start, end = burst
            out.append(Finding("MEDIUM", "Directory enumeration / scan", ip, n, fmt(start), fmt(end),
                               f"{n} 403/404 responses within {window}s", src, "web"))

        logins = [e["ts"] for e in events
                  if e["method"] == "POST" and LOGIN_PATH.search(e["path"]) and e["status"] in (200, 401, 403)]
        burst = find_burst(logins, window, threshold)
        if burst:
            n, start, end = burst
            out.append(Finding("HIGH", "Web login brute force", ip, n, fmt(start), fmt(end),
                               f"{n} POST requests to login pages within {window}s", src, "web"))
    return out


def render_findings(findings):
    if not findings:
        ok("No suspicious activity detected.")
        return
    for f in findings:
        badge = C.c(SEVERITY_STYLE[f.severity], f" {f.severity} ")
        print(f"\n  {badge} {C.bold(f.type)}")
        print(f"     {C.dim('source')} {C.cyan(f.ip)}   {C.dim('hits')} {f.count}   "
              f"{C.dim('when')} {f.first_seen} → {f.last_seen}")
        print(f"     {f.detail}")

    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    summary = "  ".join(C.c(SEVERITY_STYLE[s], f" {s} ") + f" {n}" for s, n in
                        sorted(counts.items(), key=lambda x: SEVERITY_ORDER[x[0]]))
    print("\n  " + summary)

    offenders = defaultdict(int)
    for f in findings:
        offenders[f.ip] += 1
    top = sorted(offenders.items(), key=lambda x: -x[1])[:5]
    print("  " + C.dim("Top offenders: ") + ", ".join(f"{C.cyan(ip)} ({n})" for ip, n in top))


def cmd_logs(sources=None, window=300, threshold=5, year=None):
    section("Log analyzer")
    if not sources:
        sources = default_log_sources()
        if not sources:
            bad("No log files found. Pass a path, or use 'journal' to read SSH logs from journald.")
            return {"findings": [], "stats": {}}
        note("Auto-detected sources: " + ", ".join(sources))

    findings, stats = analyze_logs(sources, window, threshold, year)
    for src, reason in stats["skipped"]:
        warn(f"Skipped {src}: {reason}" + ("  (try sudo)" if "denied" in reason.lower() else ""))
    note(f"Parsed {stats['lines']:,} lines from {len(stats['read'])} source(s)  ·  window {window}s  ·  threshold {threshold}")
    render_findings(findings)
    return {"findings": [asdict(f) for f in findings], "stats": stats}

# 5. FULL SECURITY AUDIT (ports x logs correlation)
def security_score(findings, services):
    penalty_by_sev = {"CRITICAL": (30, 60), "HIGH": (8, 40), "MEDIUM": (3, 15), "LOW": (1, 5)}
    score = 100
    for sev, (per, cap) in penalty_by_sev.items():
        n = sum(1 for f in findings if f.severity == sev)
        score -= min(cap, n * per)
    for s in services:
        if s["exposed"] and s["port"] in RISKY_PORTS:
            score -= RISKY_PORTS[s["port"]][1]
    return max(0, score)


def grade(score):
    for threshold, letter, color in ((90, "A", C.green), (75, "B", C.green), (55, "C", C.yellow),
                                     (35, "D", C.red), (0, "F", C.red)):
        if score >= threshold:
            return letter, color


def cmd_audit():
    report = {"timestamp": datetime.now().isoformat(timespec="seconds")}

    section("Audit 1/4 · System")
    info = show_system_info(header=False)
    report["system"] = info

    section("Audit 2/4 · Exposure")
    svcs = listening_services()
    if svcs is None:
        note("'ss' not available: falling back to a localhost connect scan.")
        _, found = scan_ports("127.0.0.1", sorted(COMMON_PORTS))
        svcs = [{"proto": "tcp", "port": p["port"], "addr": "?", "process": "-", "exposed": True} for p in found]
    show_listening(svcs) if svcs else ok("No listening services found.")
    report["services"] = svcs

    section("Audit 3/4 · Logs")
    sources = default_log_sources()
    if sources:
        findings, stats = analyze_logs(sources)
        for src, reason in stats["skipped"]:
            warn(f"Skipped {src}: {reason}" + ("  (try sudo)" if "denied" in reason.lower() else ""))
        note(f"Parsed {stats['lines']:,} lines from {len(stats['read'])} source(s)")
        render_findings(findings)
    else:
        findings, stats = [], {}
        warn("No log sources available.")
    report["findings"] = [asdict(f) for f in findings]

    # ---- correlation ----
    section("Audit 4/4 · Verdict")
    exposed_ports = {s["port"] for s in svcs if s["exposed"]}
    recs = []

    for p in sorted(exposed_ports & set(RISKY_PORTS)):
        recs.append((("RISK", C.red), f"Port {p} ({service_name(p)}) is exposed: {RISKY_PORTS[p][0]}. "
                                    f"Disable it, bind to localhost, or firewall it."))

    ssh_f = [f for f in findings if f.category == "ssh"]
    web_f = [f for f in findings if f.category == "web"]
    if any(f.severity == "CRITICAL" for f in findings):
        recs.append((("URGENT", C.red), "A login succeeded after brute force: treat the host as compromised. "
                                      "Rotate credentials, review `last`, `lastb`, ~/.ssh/authorized_keys and cron jobs."))
    if ssh_f:
        where = "SSH is exposed AND under attack" if 22 in exposed_ports else "SSH attacks found in logs"
        recs.append((("WARN", C.yellow), f"{where}: install fail2ban, set PasswordAuthentication no, use key-based auth."))
    if web_f:
        where = "The web server is exposed AND being probed" if exposed_ports & {80, 443, 8080, 8443} else "Web attacks found in logs"
        recs.append((("WARN", C.yellow), f"{where}: add rate limiting / a WAF and review the app for injection flaws."))
    if not findings and not (exposed_ports & set(RISKY_PORTS)):
        recs.append((("GOOD", C.green), "No attacks detected and no risky services exposed."))

    score = security_score(findings, svcs)
    letter, color = grade(score)
    filled = score // 5
    bar = color("█" * filled) + C.dim("░" * (20 - filled))
    print(f"\n  Security score   {bar}  {C.bold(color(str(score)))}/100   Grade {C.bold(color(letter))}\n")
    for (tag, tint), text in recs:
        print(f"  {C.bold(tint(tag.ljust(7)))} {text}")

    report["score"], report["grade"], report["recommendations"] = score, letter, [t for _, t in recs]
    return report

# MENU + CLI
def menu():
    while True:
        clear_screen()
        banner()
        print("\n" + C.dim("─" * WIDTH))
        print(f"  {C.dim('host')} {socket.gethostname()}   {C.dim('ip')} {get_local_ip() or '-'}   "
              f"{C.dim('root')} {C.green('yes') if is_root() else C.yellow('no')}")
        print(C.dim("─" * WIDTH))
        print(f"  {C.cyan('[1]')} System & network info")
        print(f"  {C.cyan('[2]')} Connectivity test (ping)")
        print(f"  {C.cyan('[3]')} Port scanner & listening services")
        print(f"  {C.cyan('[4]')} Log analyzer  {C.dim('(brute force, web attacks)')}")
        print(f"  {C.cyan('[5]')} {C.bold('Full security audit')}  {C.yellow('★')}")
        print(f"  {C.cyan('[0]')} Exit")
        print(C.dim("─" * WIDTH))

        choice = input(C.bold(C.cyan("\n aegis")) + C.dim(" › ")).strip()

        if choice == "1":
            show_system_info()
            pause()
        elif choice == "2":
            ping_test(ask("Host", "8.8.8.8"))
            pause()
        elif choice == "3":
            cmd_ports(ask("Target", "127.0.0.1"), ask("Ports (common / top / 22,80,1-1000)", "common"))
            pause()
        elif choice == "4":
            raw = ask("Log file(s), or 'journal' (ENTER = auto-detect)", "")
            try:
                sources = shlex.split(raw)
            except ValueError:
                sources = []
            data = cmd_logs(sources or None)
            offer_save(data)
            pause()
        elif choice == "5":
            data = cmd_audit()
            offer_save(data)
            pause()
        elif choice == "0":
            print("\n" + C.cyan("[*]") + " Stay safe. Goodbye!\n")
            break
        else:
            bad("Invalid option.")
            time.sleep(0.8)


def build_parser():
    ap = argparse.ArgumentParser(prog="aegislog", description="AEGISLOG - Network & Log Defense Toolkit.")
    ap.add_argument("--no-color", action="store_true", help="disable colors")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("info", help="system & network information")

    p = sub.add_parser("ping", help="connectivity test")
    p.add_argument("host", nargs="?", default="8.8.8.8")

    p = sub.add_parser("ports", help="port scan + listening services")
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--ports", default="common", help="common | top | 22,80,443 | 1-1000")
    p.add_argument("--timeout", type=float, default=0.5)
    p.add_argument("--json", metavar="FILE")

    p = sub.add_parser("logs", help="analyze logs for brute force and web attacks")
    p.add_argument("files", nargs="*", help="log files (.gz ok) or 'journal'; default: auto-detect")
    p.add_argument("--window", type=int, default=300, help="time window in seconds (default 300)")
    p.add_argument("--threshold", type=int, default=5, help="min. attempts to flag (default 5)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog lines without one")
    p.add_argument("--json", metavar="FILE")

    p = sub.add_parser("audit", help="full audit: exposure x logs, with score")
    p.add_argument("--json", metavar="FILE")
    return ap


def main():
    args = build_parser().parse_args()
    if args.no_color:
        C.on = False
    try:
        if not args.cmd:
            menu()
            return
        data = None
        if args.cmd == "info":
            data = show_system_info()
        elif args.cmd == "ping":
            data = ping_test(args.host)
        elif args.cmd == "ports":
            data = cmd_ports(args.target, args.ports, args.timeout)
        elif args.cmd == "logs":
            data = cmd_logs(args.files or None, args.window, args.threshold, args.year)
        elif args.cmd == "audit":
            data = cmd_audit()
        if getattr(args, "json", None) and data is not None:
            print()
            save_json(data, args.json)
    except KeyboardInterrupt:
        print("\n\n" + C.cyan("[*]") + " Interrupted by user. Exiting.")
    except EOFError:
        print()


if __name__ == "__main__":
    main()
