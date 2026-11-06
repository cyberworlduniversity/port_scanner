# 🌐 Python Port Scanner


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/port_scanner.git
cd port_scanner
```

> **Definition:** A Port Scanner is a network reconnaissance tool that probes a target IP address or hostname to discover which TCP ports are **open** and what **services** may be running behind them. It is a foundational tool in network security, system administration, and ethical hacking.

---
\n## 📚 Table of Contents

1. [What is a Port Scanner?](#-what-is-a-port-scanner)
2. [Key Definitions](#-key-definitions)
3. [How It Works — Full Program Flow](#-how-it-works--full-program-flow)
4. [Learning Procedure](#-learning-procedure)
5. [Installation & Requirements](#-installation--requirements)
6. [Usage](#-usage)
7. [Output Examples](#-output-examples)
8. [All Definitions (Glossary)](#-all-definitions-glossary)
9. [Ethical Notice](#-ethical-notice)

---

## 🔍 What is a Port Scanner?

A **port** is a logical communication endpoint on a networked device. Every service (web server, SSH, FTP, etc.) listens on a specific port number. A port scanner works by:

- Sending a **TCP connection request** to each port
- Checking whether the target **accepts** (open) or **refuses** (closed) the connection
- Reporting which ports are **open** and mapping them to known services

Port scanning is used by:
- **Network administrators** → auditing firewall rules and open services
- **Security researchers** → finding vulnerable services
- **Ethical hackers (pentesters)** → reconnaissance in authorized assessments

---

## 📖 Key Definitions

| Term | Definition |
|---|---|
| **Port** | A 16-bit number (0–65535) identifying a specific process or service on a host |
| **TCP** | Transmission Control Protocol — connection-oriented, reliable transport layer protocol |
| **Socket** | A software endpoint combining an IP address + port number for communication |
| **Open Port** | A port where a service is actively listening and accepting connections |
| **Closed Port** | A port with no service listening; connection refused immediately |
| **Filtered Port** | A port blocked by a firewall; connection attempts time out with no response |
| **Banner Grabbing** | Reading the first bytes a service sends upon connection to identify it |
| **Threading** | Running multiple port scans simultaneously to drastically reduce scan time |
| **DNS Resolution** | Translating a hostname (e.g. `example.com`) to its IP address |
| **Timeout** | Maximum time to wait for a port response before marking it as closed/filtered |

---

## 🔄 How It Works — Full Program Flow

```
┌─────────────────────────────────────────────────────────┐
│                   PORT SCANNER FLOW                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. START                                               │
│     └─► Print banner + parse CLI arguments              │
│                                                         │
│  2. INPUT VALIDATION                                    │
│     └─► Get target (IP or hostname from user/args)      │
│     └─► Validate port range (start ≤ end, 1–65535)      │
│                                                         │
│  3. DNS RESOLUTION                                      │
│     └─► socket.gethostbyname(target)                    │
│     └─► Convert hostname → IPv4 address                 │
│                                                         │
│  4. THREADED SCAN ENGINE                                │
│     └─► ThreadPoolExecutor(max_workers=N)               │
│     └─► For each port in [start..end]:                  │
│           ├─► Create TCP socket (AF_INET, SOCK_STREAM)  │
│           ├─► Set timeout                               │
│           ├─► sock.connect_ex(ip, port)                 │
│           │     ├─► Returns 0   → PORT IS OPEN ✔       │
│           │     └─► Returns >0  → PORT IS CLOSED ✗     │
│           ├─► If open → attempt banner grab             │
│           └─► Close socket                             │
│                                                         │
│  5. RESULT COLLECTION                                   │
│     └─► Aggregate all open ports                        │
│     └─► Map port numbers → service names               │
│     └─► Display live progress bar                       │
│                                                         │
│  6. SUMMARY REPORT                                      │
│     └─► Tabular output of all open ports               │
│     └─► Show scan duration + port count                │
│                                                         │
│  7. END                                                 │
└─────────────────────────────────────────────────────────┘
```

---

## 🧠 Learning Procedure

Follow these steps to understand how port scanning works from the ground up:

### Step 1 — Understand Sockets
```python
import socket
sock = socket.socket(socket.AF_INET,   # IPv4
                     socket.SOCK_STREAM)  # TCP
```
A **socket** is Python's interface to the OS networking stack. `AF_INET` means IPv4, `SOCK_STREAM` means TCP (reliable, connection-based).

---

### Step 2 — Set a Timeout
```python
sock.settimeout(0.5)  # Wait max 0.5 seconds
```
Without a timeout, a **filtered** port (firewalled) would cause the scanner to hang indefinitely.

---

### Step 3 — Attempt Connection
```python
result = sock.connect_ex(("192.168.1.1", 80))
# result == 0  → Port 80 is OPEN
# result != 0  → Port 80 is CLOSED or FILTERED
```
`connect_ex()` is the core of the scanner. Unlike `connect()`, it returns an error code instead of raising an exception.

---

### Step 4 — Banner Grabbing (Optional)
```python
sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
data = sock.recv(128)
print(data)  # e.g., "HTTP/1.1 200 OK" → identifies web server
```
Reading the first response bytes can reveal the **service version** running on a port.

---

### Step 5 — Threading for Speed
```python
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=200) as executor:
    futures = [executor.submit(scan_port, ip, port) for port in range(1, 1025)]
```
Sequential scanning of 1024 ports at 1s timeout = **~17 minutes**.
With 200 threads it completes in **~5 seconds**.

---

### Step 6 — Service Mapping
```python
SERVICES = {22: "SSH", 80: "HTTP", 443: "HTTPS", ...}
service = SERVICES.get(port, "Unknown")
```
A dictionary maps well-known port numbers to their standard service names.

---

## ⚙️ Installation & Requirements

### Requirements
- **Python 3.7+** (uses `concurrent.futures`, f-strings)
- No external libraries needed — uses Python standard library only:
  - `socket` — TCP connections
  - `threading` — Thread lock for safe concurrent writes
  - `concurrent.futures` — ThreadPoolExecutor
  - `argparse` — CLI argument parsing
  - `datetime` — Timestamp display

### Installation
```bash
# No pip install needed! Clone and run:
git clone https://github.com/cyberworlduniversity/port_scanner.git
cd port_scanner
python port_scanner.py
```

---

## 🚀 Usage

### Interactive Mode (no arguments)
```bash
python port_scanner.py
# Prompts: Enter target IP or hostname:
```

### Command-Line Mode
```bash
# Scan localhost ports 1–1024
python port_scanner.py --target 127.0.0.1

# Scan a hostname with custom range
python port_scanner.py --target scanme.nmap.org --start 1 --end 1024

# Fast scan with more threads
python port_scanner.py --target 192.168.1.1 --threads 500 --timeout 0.3

# Scan only web ports
python port_scanner.py --target example.com --start 80 --end 443
```

### All Arguments

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | *(prompted)* | Target IP or hostname |
| `--start` | `-s` | `1` | First port to scan |
| `--end` | `-e` | `1024` | Last port to scan |
| `--threads` | `-n` | `200` | Concurrent threads |
| `--timeout` | `-o` | `0.5` | Seconds per port |

---

## 📊 Output Examples

### Scan in Progress
```
════════════════════════════════════════════════════════════
  🌐  PYTHON PORT SCANNER  |  Ports 1–1024
════════════════════════════════════════════════════════════
  Started : 2026-03-10 14:22:01
════════════════════════════════════════════════════════════

  [✔] Target   : scanme.nmap.org
  [✔] Resolved : 45.33.32.156

  [*] Scanning ports 1–1024  (1024 ports)  threads=200  timeout=0.5s

  [OPEN]  Port 22     | SSH
  [OPEN]  Port 80     | HTTP
  [OPEN]  Port 9929   | Unknown
  Progress: [████████████████████████████████████████] 1024/1024
```

### Summary Report
```
════════════════════════════════════════════════════════════
  📋  SCAN SUMMARY
════════════════════════════════════════════════════════════
  Target   : scanme.nmap.org
  Duration : 4.83 seconds
  Open Ports Found: 2
────────────────────────────────────────────────────────────
  PORT     SERVICE                STATUS
  ────────────────────────────────────────
  22       SSH                    OPEN ✔
  80       HTTP                   OPEN ✔
════════════════════════════════════════════════════════════
```

---

## 📋 All Definitions (Glossary)

### Network Concepts
| Term | Full Definition |
|---|---|
| **IP Address** | A unique numerical label (e.g. 192.168.1.1) assigned to each device on a network |
| **Port Number** | A 16-bit integer (0–65535) that identifies a specific application/service endpoint |
| **Well-Known Ports** | Ports 0–1023 reserved for standard services (HTTP=80, SSH=22, FTP=21) |
| **Registered Ports** | Ports 1024–49151 used by applications (registered with IANA) |
| **Dynamic/Private Ports** | Ports 49152–65535 used for temporary/ephemeral connections |
| **TCP Handshake** | 3-step process: SYN → SYN-ACK → ACK to establish a TCP connection |
| **SYN Scan** | Sends only SYN packets (half-open scan) — stealthier, used by nmap -sS |
| **Full Connect Scan** | Completes the full TCP handshake — what this scanner uses |
| **Firewall** | Network security device that filters traffic based on rules; can BLOCK ports |
| **NAT** | Network Address Translation — maps private IPs to a public IP |

### Python/Programming Concepts
| Term | Full Definition |
|---|---|
| **socket.AF_INET** | Address Family Internet — specifies IPv4 protocol family |
| **socket.SOCK_STREAM** | Socket type for TCP (stream-based, reliable, ordered) |
| **socket.SOCK_DGRAM** | Socket type for UDP (datagram, unreliable, faster) |
| **connect_ex()** | Socket method that returns error code (0=success) instead of raising exception |
| **settimeout(n)** | Configures socket to raise timeout error after n seconds of no response |
| **ThreadPoolExecutor** | Python class managing a pool of worker threads for concurrent execution |
| **as_completed()** | Iterator yielding futures as they complete (non-blocking) |
| **threading.Lock()** | Mutex ensuring only one thread writes shared data at a time (thread-safe) |
| **argparse** | Python standard library for parsing command-line arguments |
| **gethostbyname()** | Resolves a hostname to its IPv4 address via DNS |

### Security Concepts
| Term | Full Definition |
|---|---|
| **Attack Surface** | All ports/services exposed on a host that could be attacked |
| **Reconnaissance** | Phase 1 of ethical hacking — information gathering about a target |
| **Service Fingerprinting** | Identifying what software/version runs on an open port |
| **Banner Grabbing** | Reading service banners to identify software name and version |
| **Vulnerability Scanning** | Finding known weaknesses in discovered services (step after port scanning) |
| **CVE** | Common Vulnerabilities and Exposures — database of known security flaws |
| **Penetration Testing** | Authorized simulation of cyberattacks to find weaknesses |

---

## ⚠️ Ethical Notice

> **Only scan systems you own or have explicit written permission to scan.**
>
> Unauthorized port scanning may be:
> - Illegal under the Computer Fraud and Abuse Act (CFAA) in the US
> - Illegal under the Computer Misuse Act in the UK
> - Against terms of service of cloud providers
>
> **Authorized use cases:**
> - Your own local network (192.168.x.x)
> - Your own VPS/server
> - Deliberately vulnerable VMs: HackTheBox, TryHackMe, DVWA
> - Test targets like `scanme.nmap.org` (explicitly permitted by nmap.org)

---

## 📁 Project Structure

```
port_scanner/
├── port_scanner.py     ← Main scanner script (fully commented)
└── README.md           ← This file — definitions, flow, usage
```

---

*Built with Python standard library only. No external dependencies.*
