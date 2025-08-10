# EnumTool

Enumeration and scanning tool for internal pentesting.

## Usage

python main.py -m <mode> -tc <technique> [options]

## Modes and Techniques

- discovery: arp, tcp, udp, icmp
- scan: connect, syn

## Optional Flags

- -s, --soft: Evaluate HTTP headers (only with scan mode)
- -o, --system: OS detection (works with both modes)

## 🎛️ Flags Overview: EnumTool

### 1. 🔹 Mutually Exclusive Action Flags

| Flag |  Category      |   Technique        |          Module                     |
|------|----------------|--------------------|-------------------------------------|
| `-dA`|  Discovery     |   `arp_ping`       |   `discovery/arp_ping.py`           |
| `-dI`|  Discovery     |   `icmp_ping`      |   `discovery/icmp_ping.py`          |
| `-dT`|  Discovery     |   `tcp_ping`       |   `discovery/tcp_ping.py`           |
| `-dU`|  Discovery     |   `udp_ping`       |   `discovery/udp_ping.py`           |
| `-sT`|  Scan          |   `tcp_connect`    |   `scan/tcp_connect.py`             |
| `-sS`|  Scan          |   `syn_scan`       |   `scan/syn_scan.py`                |
| `-sA`|  Scan          |   `ack_scan`       |   `scan/ack_scan.py`                |
| `-B` |  Fingerprint   |   `banner_grab`    |   `fingerprint/banner_grab.py`      |
| `-O` |  Fingerprint   |   `os_detection`   |   `fingerprint/os_detection.py`     |
| `-V` |  Fingerprint   |   `os_detection`   |   `fingerprint/os_detection_plus.py`|
| `-H` |  Fingerprint   |   `http_headers`   |   `fingerprint/http_headers.py`     |

---

### 2. 🟩 Common Parameters

| Flag               | Description                                            |
|--------------------|--------------------------------------------------------|
| `-i`, `--interface`| Network interface (required for `-dA`)                 |
| `-t`, `--target`   | Target IP or CIDR range                                |
| `-p`, `--port`     | Target ports (e.g. `22,80`, `20-25`)                   |
| `--port-all`       | Scan all TCP ports from 1 to 65535                     |
| `-T`, `--timeout`  | Timeout in seconds (default: `0.5`)                    |
| `--threads`        | Number of concurrent threads (default: 10)            |

---

### 3. 🟨 Special flags for `-H` (HTTP Header Analysis)

| Flag       | Description                                                    |
|------------|----------------------------------------------------------------|
| `--http`   | Force HTTP (no TLS) for all scanned ports                      |
| `--https`  | Force HTTPS (TLS) for all scanned ports                        |
| *(none)*   | Auto-detect protocol based on port number (80 → HTTP, 443 → HTTPS) |

---

### ⚠️ Important Notes

- `--interface` is **required only for `-dA`**.
- `--target` is required for **all techniques**.
- Action flags (e.g. `-sT`, `-B`) are **mutually exclusive**.
- Recommended `--threads ≤ 10` to avoid concurrency issues in Scapy.