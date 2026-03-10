#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           🌐 PYTHON PORT SCANNER v1.0                    ║
║     Scan common ports (1–1024) on a target IP            ║
╚══════════════════════════════════════════════════════════╝

Definition:
    A Port Scanner is a network tool that probes a target IP address
    to discover which TCP/UDP ports are open and what services may be
    running behind them.

Learning Procedure:
    1. Socket creation  → Python opens a TCP socket
    2. Connection test  → Attempts connect() to each port
    3. Result capture   → Records open/closed state
    4. Service mapping  → Matches port numbers to known services
    5. Report output    → Displays results in a structured table

Usage:
    python port_scanner.py
    python port_scanner.py --target 192.168.1.1 --start 1 --end 1024
    python port_scanner.py --target scanme.nmap.org --threads 200
"""

import socket
import argparse
import threading
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
#  DEFINITION: Common Port → Service Mapping
#  Maps well-known port numbers to their
#  corresponding service/protocol names.
# ─────────────────────────────────────────────
COMMON_SERVICES = {
    20:   "FTP-Data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP-Server",
    68:   "DHCP-Client",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    119:  "NNTP",
    123:  "NTP",
    135:  "MS-RPC",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    500:  "IKE/IPSec",
    514:  "Syslog",
    515:  "LPD/LPR",
    587:  "SMTP-Submission",
    631:  "IPP/CUPS",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS Proxy",
}


def banner():
    """
    DEFINITION: Banner Function
    Displays an ASCII art header with tool info and timestamp.
    Purpose: Provide clear visual identification of the tool.
    """
    print("\n" + "═" * 60)
    print("  🌐  PYTHON PORT SCANNER  |  Ports 1–1024")
    print("═" * 60)
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 60 + "\n")


def resolve_target(target: str) -> str:
    """
    DEFINITION: Target Resolution
    Converts a hostname (e.g. 'scanme.nmap.org') to an IP address
    using DNS lookup via socket.gethostbyname().

    Parameters:
        target (str): Hostname or IP address string.

    Returns:
        str: Resolved IPv4 address.

    Learning Step:
        DNS Resolution → socket.gethostbyname(host)
    """
    try:
        ip = socket.gethostbyname(target)
        print(f"  [✔] Target   : {target}")
        if ip != target:
            print(f"  [✔] Resolved : {ip}")
        return ip
    except socket.gaierror:
        print(f"  [✘] ERROR: Cannot resolve hostname '{target}'")
        sys.exit(1)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    DEFINITION: Port Scanning Function (Core Logic)
    Attempts a TCP connection to a specific port on the target IP.

    Algorithm:
        1. Create a TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        2. Set a timeout to avoid hanging on filtered ports
        3. Call connect_ex() — returns 0 if port is OPEN
        4. Grab the banner (if any) for service fingerprinting
        5. Close the socket and return the result

    Parameters:
        ip      (str)   : Target IPv4 address
        port    (int)   : Port number to probe (1–65535)
        timeout (float) : Seconds to wait per connection attempt

    Returns:
        dict: {'port': int, 'open': bool, 'service': str, 'banner': str}

    TCP States:
        OPEN     → connect_ex() returns 0
        CLOSED   → connect_ex() returns non-zero (e.g. ECONNREFUSED)
        FILTERED → Connection times out (firewall drops packets)
    """
    result = {
        "port":    port,
        "open":    False,
        "service": COMMON_SERVICES.get(port, "Unknown"),
        "banner":  ""
    }

    try:
        # Step 1: Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Step 2: Attempt connection
        # connect_ex() returns 0 on success (port OPEN)
        code = sock.connect_ex((ip, port))

        if code == 0:
            result["open"] = True

            # Step 3: Try to grab service banner
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_data = sock.recv(128).decode(errors="ignore").strip()
                result["banner"] = banner_data.split("\n")[0][:60] if banner_data else ""
            except Exception:
                pass  # Banner grab is optional

        sock.close()

    except socket.error:
        pass  # Port is closed or unreachable

    return result


def display_result(res: dict):
    """
    DEFINITION: Result Display Function
    Formats and prints a single open-port result to stdout.

    Output Format:
        [OPEN]  Port 22   | SSH        | Banner (if any)
    """
    port    = res["port"]
    service = res["service"]
    banner  = res.get("banner", "")
    banner_str = f"  ← {banner}" if banner else ""
    print(f"  [OPEN]  Port {port:<6} | {service:<20}{banner_str}")


def run_scan(ip: str, start: int, end: int, threads: int, timeout: float) -> list:
    """
    DEFINITION: Threaded Scan Engine
    Manages concurrent port scanning using Python's ThreadPoolExecutor.

    Why Threading?
        Sequential scanning of 1024 ports at 1s timeout = ~17 minutes.
        With 200 threads it completes in seconds.

    Learning Procedure:
        1. ThreadPoolExecutor creates a pool of worker threads
        2. Each thread calls scan_port() for one port
        3. as_completed() yields results as they finish (non-blocking)
        4. Progress is tracked with a counter

    Parameters:
        ip      (str) : Target IP
        start   (int) : First port to scan
        end     (int) : Last port to scan (inclusive)
        threads (int) : Max concurrent threads
        timeout (float): Per-port timeout in seconds

    Returns:
        list[dict]: Sorted list of open port result dicts
    """
    open_ports = []
    total      = end - start + 1
    scanned    = 0
    lock       = threading.Lock()

    print(f"  [*] Scanning ports {start}–{end}  ({total} ports)  "
          f"threads={threads}  timeout={timeout}s\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in range(start, end + 1)
        }

        for future in as_completed(futures):
            res = future.result()
            with lock:
                scanned += 1
                if res["open"]:
                    open_ports.append(res)
                    display_result(res)

                # Live progress bar every 50 ports
                if scanned % 50 == 0 or scanned == total:
                    pct = int((scanned / total) * 40)
                    bar = "█" * pct + "░" * (40 - pct)
                    print(f"\r  Progress: [{bar}] {scanned}/{total}", end="", flush=True)

    print()  # newline after progress bar
    return sorted(open_ports, key=lambda x: x["port"])


def print_summary(open_ports: list, elapsed: float, target: str):
    """
    DEFINITION: Summary Report Generator
    Produces a final tabular summary of all discovered open ports.

    Output:
        ┌──────────────────────────────────┐
        │  PORT  │  SERVICE   │  STATUS   │
        ├──────────────────────────────────┤
        │  22    │  SSH       │  OPEN ✔  │
        └──────────────────────────────────╝
    """
    print("\n" + "═" * 60)
    print("  📋  SCAN SUMMARY")
    print("═" * 60)
    print(f"  Target   : {target}")
    print(f"  Duration : {elapsed:.2f} seconds")
    print(f"  Open Ports Found: {len(open_ports)}")
    print("─" * 60)

    if open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<22} {'STATUS'}")
        print("  " + "─" * 40)
        for p in open_ports:
            status = "OPEN ✔"
            print(f"  {p['port']:<8} {p['service']:<22} {status}")
    else:
        print("  No open ports detected in the scanned range.")

    print("═" * 60 + "\n")


def parse_args():
    """
    DEFINITION: Argument Parser
    Handles command-line arguments using Python's argparse module.
    Provides defaults for easy interactive use.
    """
    parser = argparse.ArgumentParser(
        description="🌐 Python Port Scanner — Scan TCP ports on a target IP",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--target",  "-t", default=None,
                        help="Target IP address or hostname (prompted if omitted)")
    parser.add_argument("--start",   "-s", type=int, default=1,
                        help="Start port (default: 1)")
    parser.add_argument("--end",     "-e", type=int, default=1024,
                        help="End port (default: 1024)")
    parser.add_argument("--threads", "-n", type=int, default=200,
                        help="Number of threads (default: 200)")
    parser.add_argument("--timeout", "-o", type=float, default=0.5,
                        help="Timeout per port in seconds (default: 0.5)")
    return parser.parse_args()


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────
def main():
    """
    DEFINITION: Main Execution Flow

    Full Program Flow:
        1. Print banner
        2. Parse CLI arguments
        3. Prompt for target if not provided
        4. Resolve hostname → IP
        5. Run threaded port scan
        6. Print summary report
        7. Exit
    """
    banner()
    args = parse_args()

    # Step 1: Get target
    target = args.target
    if not target:
        target = input("  Enter target IP or hostname: ").strip()
        if not target:
            print("  [✘] No target specified. Exiting.")
            sys.exit(1)

    # Step 2: Validate port range
    if not (1 <= args.start <= 65535) or not (1 <= args.end <= 65535):
        print("  [✘] Port range must be between 1 and 65535.")
        sys.exit(1)
    if args.start > args.end:
        print("  [✘] Start port must be <= end port.")
        sys.exit(1)

    # Step 3: Resolve target
    ip = resolve_target(target)
    print()

    # Step 4: Scan
    t0 = time.time()
    open_ports = run_scan(ip, args.start, args.end, args.threads, args.timeout)
    elapsed = time.time() - t0

    # Step 5: Summary
    print_summary(open_ports, elapsed, target)


if __name__ == "__main__":
    main()
