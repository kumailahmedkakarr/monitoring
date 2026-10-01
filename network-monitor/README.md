# Network Attack and Monitoring Framework (Version 1.0)
### Defensive Linux Network Monitoring &amp; Heuristic Intrusion Detection System
*BS Information Technology Semester Project • Authorized Lab Security Testing Tool*

---

## 1. Project Description

**Network Attack and Monitoring Framework** is an educational, defensive network monitoring application built for Linux and Kali Linux environments. The tool captures live network traffic on selected network interfaces (e.g., `eth0`, `ens33`, `wlan0`, `lo`), extracts packet metadata (timestamps, IP addresses, protocols, source/destination ports, payload length), updates host activity metrics, logs security alerts via heuristic defensive rules, and displays the telemetry on an asynchronous web dashboard.

This tool is strictly designed for defensive security analysis, network observability, and traffic auditing in an authorized private virtual machine laboratory (VMware / VirtualBox).

---

## 2. Key Features

- **Automated Interface Discovery:** Detects available physical, virtual, and loopback interfaces dynamically (`psutil` and `scapy`).
- **Live Packet Capture:** Non-blocking multithreaded capture engine running Scapy inside a background daemon thread.
- **Protocol Inspection:** Extracts IPv4 metadata for **TCP**, **UDP**, **ICMP**, and other standard IP protocols.
- **Defensive Heuristic Detection Rules:**
  1. *Possible Port Scan*: Triggers when a source IP contacts 15+ distinct ports on a single target within 10 seconds.
  2. *High Packet Rate*: Triggers when a source IP generates 60+ packets within 5 seconds.
  3. *Repeated Connection Attempts*: Triggers when a source IP initiates repeated TCP connection attempts to the same destination and port within 5 seconds.
  4. *High ICMP Activity*: Triggers when a source IP sends 12+ ICMP packets within 5 seconds (ping flood / discovery).
- **Anti-Spam Alert Cooldown:** Automatically suppresses repetitive alerts for the same source/destination pairs within a 30-second cooldown window to prevent database flooding.
- **Persistent Local Database:** Stores all captured packets, active hosts, and generated alerts in SQLite (`data/network_monitor.db`) using parameterized SQL queries.
- **Real-Time Asynchronous Web Dashboard:** Clean, dark cybersecurity web UI polling Flask JSON APIs (`/api/status`, `/api/stats`, `/api/packets`, `/api/alerts`, `/api/hosts`) every 2.5 seconds without full page refreshes.
- **Interface Selection & Start/Stop Controls:** Start and stop packet sniffing on demand directly from the web interface.
- **Comprehensive Audit Logging:** Tracks startup, shutdown, interface switches, packet errors, and security events in `logs/network_monitor.log`.

---

## 3. Architecture

```text
       ┌────────────────────────────────────────────────────────┐
       │             Web Browser (Client Dashboard)             │
       │  HTML5 + CSS3 + Vanilla JavaScript + Fetch Polling     │
       └───────────────────────────┬────────────────────────────┘
                                   │ HTTP GET / POST (JSON API)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                Flask Web Server (app.py)               │
       │       Routes • REST API Endpoints • Jinja2 Pages       │
       └──────────────┬──────────────────────────┬──────────────┘
                      │                          │
                      ▼                          ▼
       ┌───────────────────────────┐  ┌─────────────────────────┐
       │ NetworkMonitor(monitor.py)│  │ SQLite Database         │
       │ Background Sniffing Thread│  │ (database.py)           │
       └──────────────┬────────────┘  │  - packets table        │
                      │               │  - hosts table          │
                      ▼               │  - alerts table         │
       ┌───────────────────────────┐  └──────────▲──────────────┘
       │   Scapy Packet Capture    │             │
       │   (Raw Sockets / AF_PACKET)             │
       └──────────────┬────────────┘             │
                      │ Parsed IPv4 Metadata     │
                      ▼                          │
       ┌─────────────────────────────────────────┴──────────────┐
       │       Defensive Detection Engine (detector.py)         │
       │   Rule 1: Port Scan | Rule 2: High Packet Rate         │
       │   Rule 3: Repeated TCP | Rule 4: High ICMP Activity    │
       │   Alert Cooldown Cache (30s anti-flood)                │
       └────────────────────────────────────────────────────────┘
```

---

## 4. System Requirements

- **Operating System:** Linux (Kali Linux, Ubuntu 22.04+, Debian, Fedora, or Linux Mint inside VMware/VirtualBox)
- **Python:** Python 3.8, 3.9, 3.10, 3.11, or 3.12
- **Package Manager:** `pip` (Python package manager)
- **Dependencies:** `Flask`, `scapy`, `psutil`
- **Privileges:** `sudo` / root capabilities for raw socket packet sniffing (`CAP_NET_RAW` / `CAP_NET_ADMIN`)

---

## 5. Installation Instructions

Execute these commands in your Linux / Kali Linux terminal:

### Step 1: Clone or Navigate to the Project Folder
```bash
cd /path/to/network-monitor
```

### Step 2: Create a Python Virtual Environment
```bash
python3 -m venv venv
```

### Step 3: Activate the Virtual Environment
```bash
source venv/bin/activate
```

### Step 4: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 6. How to Run the Application

Because packet capture with Scapy requires binding to raw network sockets, the monitoring process requires root privileges on Linux.

### Method A: Running with `sudo` in Virtual Environment (Recommended for Kali Linux)
```bash
sudo ./venv/bin/python app.py
```

### Method B: Granting Linux Capabilities (No Sudo Needed for Normal Python)
If you prefer running without root directly:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python3 app.py
```

When started, the terminal displays:
```text
[INFO] Initializing Network Attack & Monitoring Framework...
[INFO] Database initialized successfully at /path/to/data/network_monitor.db
[INFO] Starting Flask Web Server on http://127.0.0.1:5000
 * Running on http://127.0.0.1:5000
```

---

## 7. Accessing the Dashboard

Open your web browser inside your VM (e.g., Firefox in Kali Linux) and navigate to:
```text
http://127.0.0.1:5000
```

---

## 8. Identifying the Correct Network Interface

In Linux, network interface naming depends on whether you use VMware NAT, Bridged, or Host-Only:
- `eth0`: Traditional Ethernet adapter
- `ens33`: Standard VMware Workstation / Player virtual NIC
- `enp0s3`: Standard VirtualBox NIC
- `wlan0`: Wireless Wi-Fi adapter
- `lo`: Local loopback interface (`127.0.0.1`)

To verify your interface in the terminal:
```bash
ip addr show
```
Look for the interface holding your lab IP (e.g., `192.168.x.x` or `10.x.x.x`). Select this interface in the dashboard topbar dropdown.

---

## 9. Operating the Tool

### Starting Monitoring:
1. Select your target network interface from the dropdown (e.g., `ens33` or `eth0`).
2. Click the green **START MONITORING** button.
3. The status indicator will turn green and display **RUNNING**.

### Stopping Monitoring:
1. Click the red **STOP MONITORING** button.
2. The capture thread safely terminates and the status changes to **STOPPED**.

---

## 10. Safe Lab Testing Guide

Test the defensive detection engine inside your authorized VMware virtual machine lab:

### Test 1: Generate Normal Traffic
In a separate terminal on the same VM:
```bash
ping -c 4 8.8.8.8
curl http://example.com
```
*Observe:* Packets table instantly populates with ICMP and TCP traffic; protocol bars update.

### Test 2: Trigger "High ICMP Activity" Rule
Send 15 fast ICMP echo requests (threshold is 12 within 5 seconds):
```bash
ping -c 15 -i 0.2 127.0.0.1
```
*Observe:* Alert generated in the Alerts table: **High ICMP Activity (Severity: LOW)**.

### Test 3: Trigger "Possible Port Scan" Rule
Run an authorized probe across local ports using Nmap or a simple bash loop:
```bash
# Using Nmap on local interface:
nmap -p 20-40 127.0.0.1
```
*Observe:* Alert generated: **Possible Port Scan (Severity: MEDIUM)**.

### Test 4: Trigger "High Packet Rate" Rule
Send a short burst of packets using ping or curl in a loop:
```bash
for i in {1..70}; do ping -c 1 -W 1 127.0.0.1 > /dev/null & done
```
*Observe:* Alert generated: **High Packet Rate (Severity: MEDIUM)**.

---

## 11. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Permission denied (Scapy)** | Raw socket capture requires elevated privileges. | Run with `sudo ./venv/bin/python app.py` |
| **Interface not found** | Interface name changed or disconnected. | Run `ip link show` to verify active interface name, and refresh the dashboard. |
| **Address already in use (5000)** | Another service is using port 5000. | Change `FLASK_PORT = 5005` in `config.py` or terminate the existing process with `sudo lsof -i :5000`. |
| **Database is locked** | Multiple processes writing simultaneously. | SQLite WAL mode is enabled; ensure only one instance of `app.py` is running. |
| **Scapy not capturing packets** | Wrong interface selected or monitor is STOPPED. | Click START MONITORING and select `lo` for localhost testing, or `ens33`/`eth0` for external traffic. |

---

## 12. Security & Ethical Disclaimer

This application is developed strictly for academic, defensive, and authorized lab evaluation. It does not perform offensive exploitation, evasion, or malicious activities. Never monitor or inspect network traffic on networks where you do not have explicit written authorization.
