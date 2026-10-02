import os

# Base Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# On Vercel serverless, root filesystem is read-only; use /tmp for SQLite and logs
if os.environ.get("VERCEL"):
    DATA_DIR = os.environ.get("DATA_DIR", "/tmp/data")
    LOGS_DIR = os.environ.get("LOGS_DIR", "/tmp/logs")
else:
    DATA_DIR = os.path.join(BASE_DIR, "data")
    LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Ensure required directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Database & Logging paths
DB_PATH = os.path.join(DATA_DIR, "network_monitor.db")
LOG_FILE = os.path.join(LOGS_DIR, "network_monitor.log")

# Web Server Settings
FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))
DEBUG_MODE = False

# Detection Engine Thresholds (Configurable)
# Detection 1: Port Scan Pattern
PORT_SCAN_THRESHOLD = 15       # Number of unique destination ports targeted
PORT_SCAN_WINDOW = 10          # Time window in seconds

# Detection 2: High Packet Rate
HIGH_PACKET_RATE_THRESHOLD = 60  # Number of packets from a single source
HIGH_PACKET_RATE_WINDOW = 5      # Time window in seconds

# Detection 3: Repeated Connection Attempts (Same destination IP & Port)
REPEATED_CONN_THRESHOLD = 12   # Number of repeat attempts to same target:port
REPEATED_CONN_WINDOW = 5       # Time window in seconds

# Detection 4: Suspicious ICMP Rate
ICMP_THRESHOLD = 12            # Number of ICMP echo/packets from a single source
ICMP_WINDOW = 5                # Time window in seconds

# Alert Cooldown (Prevents flooding database with duplicate alerts)
ALERT_COOLDOWN = 30            # Seconds before the same alert can be re-triggered for a host

# Packet Processing Limits
MAX_MEMORY_PACKETS = 200       # Keep recent packets in-memory for instant UI polling
MAX_DB_RECORDS_DEFAULT = 100   # Default query limit for UI tables
