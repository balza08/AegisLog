#!/usr/bin/env python3
"""
SHIELD NET-INSPECTOR
Network and system diagnostic tool, CLI style for Kali Linux.
"""

import os
import socket
import platform
import subprocess

BANNER = r"""
________  _______   ___  ________  ___  ________      
|\   __  \|\  ___ \ |\  \|\   ____\|\  \|\   ____\     
\ \  \|\  \ \   __/|\ \  \ \  \___|\ \  \ \  \___|_    
 \ \   __  \ \  \_|/_\ \  \ \  \  __\ \  \ \_____  \   
  \ \  \ \  \ \  \_|\ \ \  \ \  \|\  \ \  \|____|\  \  
   \ \__\ \__\ \_______\ \__\ \_______\ \__\____\_\  \ 
    \|__|\|__|\|_______|\|__|\|_______|\|__|\_________\
                                           \|_________|
"""

# Common ports to check
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def pause():
    input("\nPress ENTER to return to the menu...")


def show_header():
    clear_screen()
    print(BANNER)
    print("=" * 60)
    print("                  [ SHIELD NET-INSPECTOR ]")
    print("=" * 60)


# ------------------------------------------------------------------
# 1. NETWORK AND SYSTEM INFORMATION
# ------------------------------------------------------------------
def show_network_info():
    print("\n[*] Retrieving system information...\n")

    hostname = socket.gethostname()

    # Local IP: reliable method that doesn't require an actual connection
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "Not available (no active network interface?)"

    system_name = platform.system()
    release = platform.release()
    version = platform.version()
    architecture = platform.machine()

    print(f"  Hostname          : {hostname}")
    print(f"  Local IP Address  : {local_ip}")
    print(f"  Operating System  : {system_name} {release}")
    print(f"  Kernel Version    : {version}")
    print(f"  Architecture      : {architecture}")

    # MAC address (best effort, via uuid.getnode)
    try:
        import uuid
        mac_num = uuid.getnode()
        mac = ':'.join(f"{(mac_num >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
        print(f"  MAC Address       : {mac}")
    except Exception:
        print("  MAC Address       : Not available")


# ------------------------------------------------------------------
# 2. CONNECTION TEST (PING)
# ------------------------------------------------------------------
def ping_test(host="8.8.8.8"):
    print(f"\n[*] Pinging {host} ...\n")

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        command = ["ping", "-n", "1", host]
    else:
        command = ["ping", "-c", "1", "-W", "2", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        print(result.stdout.decode(errors="ignore"))

        if result.returncode == 0:
            print(f"[+] Connection OK -> {host} is reachable.")
        else:
            print(f"[-] No connection -> {host} is unreachable.")

    except subprocess.TimeoutExpired:
        print("[-] Timeout: no response from the server.")
    except FileNotFoundError:
        print("[-] Error: 'ping' command not found on this system.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


# ------------------------------------------------------------------
# 3. LOCAL PORT SCANNER
# ------------------------------------------------------------------
def scan_local_ports():
    target = "127.0.0.1"
    print(f"\n[*] Scanning common ports on {target} (localhost)...\n")

    open_ports = []

    for port, service_name in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append((port, service_name))
            print(f"  [OPEN]   Port {port:<6} ({service_name})")
        sock.close()

    print()
    if open_ports:
        print(f"[+] Scan complete: {len(open_ports)} open port(s) found.")
    else:
        print("[-] Scan complete: no common open ports found on localhost.")


# ------------------------------------------------------------------
# MAIN MENU
# ------------------------------------------------------------------
def menu():
    while True:
        show_header()
        print("  1. Show Network Info (Local IP, Hostname, MAC)")
        print("  2. Check Internet Connection (Ping Test)")
        print("  3. Scan Localhost Ports (Local Security Test)")
        print("  4. Exit")
        print("=" * 60)

        choice = input("Select an option [1-4]: ").strip()

        if choice == "1":
            show_network_info()
            pause()
        elif choice == "2":
            ping_test()
            pause()
        elif choice == "3":
            scan_local_ports()
            pause()
        elif choice == "4":
            print("\n[*] Exiting... See you next time!\n")
            break
        else:
            print("\n[-] Invalid option, please try again.")
            pause()


def main():
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user. Exiting.")


if __name__ == "__main__":
    main()