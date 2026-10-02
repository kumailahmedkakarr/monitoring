import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  Shield,
  Activity,
  Play,
  Square,
  AlertTriangle,
  Server,
  Terminal,
  Settings,
  Database,
  FileCode,
  Download,
  Copy,
  Check,
  Search,
  Filter,
  RefreshCw,
  BookOpen,
  Radio,
  Globe,
  Sliders,
  HelpCircle,
  ExternalLink,
  Wifi,
  WifiOff
} from "lucide-react";

// Types
interface Packet {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  protocol: "TCP" | "UDP" | "ICMP" | "OTHER";
  source_port: number | null;
  destination_port: number | null;
  packet_length: number;
}

interface Alert {
  id: number;
  timestamp: string;
  alert_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  source_ip: string;
  destination_ip: string;
  description: string;
  status: string;
}

interface Host {
  id: number;
  ip_address: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
  role: "local" | "gateway" | "external";
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "packets" | "alerts" | "hosts" | "settings" | "codebase" | "guide" | "theory">("dashboard");
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [selectedInterface, setSelectedInterface] = useState<string>("ens33");
  const [availableInterfaces, setAvailableInterfaces] = useState<string[]>(["ens33", "eth0", "wlan0", "lo"]);

  // Backend Engine connection state (Kali Linux VM / Local Linux)
  const [engineUrl, setEngineUrl] = useState<string>(() => {
    return localStorage.getItem("netmonitor_engine_url") || "http://127.0.0.1:5000";
  });
  const [tempEngineUrl, setTempEngineUrl] = useState<string>(() => {
    return localStorage.getItem("netmonitor_engine_url") || "http://127.0.0.1:5000";
  });
  const [isEngineOnline, setIsEngineOnline] = useState<boolean>(false);
  const [isCheckingEngine, setIsCheckingEngine] = useState<boolean>(false);
  const [engineError, setEngineError] = useState<string | null>("Monitoring engine offline. Start the Python/Scapy backend on Kali Linux.");
  const [lastCheckTime, setLastCheckTime] = useState<string>("");
  const [pingLatency, setPingLatency] = useState<number | null>(null);

  // Real packet stream & records (populated strictly from real backend)
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [hosts, setHosts] = useState<Map<string, Host>>(new Map());
  const [backendStats, setBackendStats] = useState<{
    total_packets: number;
    tcp_packets: number;
    udp_packets: number;
    icmp_packets: number;
    other_packets: number;
    total_hosts: number;
    total_alerts: number;
  }>({
    total_packets: 0,
    tcp_packets: 0,
    udp_packets: 0,
    icmp_packets: 0,
    other_packets: 0,
    total_hosts: 0,
    total_alerts: 0
  });

  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  // Filters for Packets Tab
  const [packetSearchIp, setPacketSearchIp] = useState<string>("");
  const [packetProtocolFilter, setPacketProtocolFilter] = useState<string>("ALL");
  const [packetLimit, setPacketLimit] = useState<number>(100);

  // Filters for Alerts Tab
  const [alertSeverityFilter, setAlertSeverityFilter] = useState<string>("ALL");
  const [alertTypeFilter, setAlertTypeFilter] = useState<string>("ALL");
  const [alertSearchIp, setAlertSearchIp] = useState<string>("");

  // Codebase selected file
  const [selectedCodeFile, setSelectedCodeFile] = useState<string>("app.py");

  // Thresholds (configurable display from config.py)
  const [thresholds, setThresholds] = useState({
    portScanLimit: 15,
    portScanWindow: 10,
    packetRateLimit: 60,
    packetRateWindow: 5,
    repeatedConnLimit: 12,
    repeatedConnWindow: 5,
    icmpLimit: 12,
    icmpWindow: 5,
    alertCooldown: 30
  });

  // Query Real Backend Engine
  const fetchEngineData = async (targetUrl = engineUrl) => {
    setIsCheckingEngine(true);
    const startTime = performance.now();
    try {
      const statusRes = await fetch(`${targetUrl}/api/status`, {
        signal: AbortSignal.timeout(2500)
      });
      if (!statusRes.ok) throw new Error(`HTTP ${statusRes.status}`);
      const statusData = await statusRes.json();

      const elapsed = Math.round(performance.now() - startTime);
      setPingLatency(elapsed);
      setIsEngineOnline(true);
      setEngineError(null);
      setLastCheckTime(new Date().toLocaleTimeString());
      setIsRunning(statusData.status === "RUNNING");
      if (statusData.interface) setSelectedInterface(statusData.interface);

      // Fetch stats, interfaces, packets, alerts, hosts
      const [ifacesRes, statsRes, pktsRes, alertsRes, hostsRes, settingsRes] = await Promise.allSettled([
        fetch(`${targetUrl}/api/interfaces`),
        fetch(`${targetUrl}/api/stats`),
        fetch(`${targetUrl}/api/packets?limit=100`),
        fetch(`${targetUrl}/api/alerts?limit=100`),
        fetch(`${targetUrl}/api/hosts?limit=100`),
        fetch(`${targetUrl}/api/settings`)
      ]);

      if (ifacesRes.status === "fulfilled" && ifacesRes.value.ok) {
        const ifacesData = await ifacesRes.value.json();
        if (ifacesData.interfaces && ifacesData.interfaces.length > 0) {
          setAvailableInterfaces(ifacesData.interfaces);
        }
      }

      if (statsRes.status === "fulfilled" && statsRes.value.ok) {
        const statsData = await statsRes.value.json();
        setBackendStats(statsData);
      }

      if (pktsRes.status === "fulfilled" && pktsRes.value.ok) {
        const pktsData = await pktsRes.value.json();
        setPackets(pktsData.packets || []);
      }

      if (alertsRes.status === "fulfilled" && alertsRes.value.ok) {
        const alertsData = await alertsRes.value.json();
        setAlerts(alertsData.alerts || []);
      }

      if (hostsRes.status === "fulfilled" && hostsRes.value.ok) {
        const hostsData = await hostsRes.value.json();
        const hostMap = new Map<string, Host>();
        (hostsData.hosts || []).forEach((item: any) => {
          hostMap.set(item.ip_address, {
            id: item.id,
            ip_address: item.ip_address,
            first_seen: item.first_seen,
            last_seen: item.last_seen,
            packet_count: item.packet_count,
            role: item.ip_address.startsWith("192.168.") || item.ip_address.startsWith("10.") || item.ip_address === "127.0.0.1" ? "local" : "external"
          });
        });
        setHosts(hostMap);
      }

      if (settingsRes.status === "fulfilled" && settingsRes.value.ok) {
        const settData = await settingsRes.value.json();
        if (settData.thresholds) {
          setThresholds({
            portScanLimit: settData.thresholds.port_scan_threshold,
            portScanWindow: settData.thresholds.port_scan_window_sec,
            packetRateLimit: settData.thresholds.high_packet_rate_threshold,
            packetRateWindow: settData.thresholds.high_packet_rate_window_sec,
            repeatedConnLimit: settData.thresholds.repeated_conn_threshold,
            repeatedConnWindow: settData.thresholds.repeated_conn_window_sec,
            icmpLimit: settData.thresholds.icmp_threshold,
            icmpWindow: settData.thresholds.icmp_window_sec,
            alertCooldown: settData.thresholds.alert_cooldown_sec
          });
        }
      }
    } catch (err: any) {
      setIsEngineOnline(false);
      setPingLatency(null);
      setEngineError(err.message || "Failed to reach monitoring engine");
      setIsRunning(false);
      // Clean slate - DO NOT fabricate fake data when offline
      setPackets([]);
      setAlerts([]);
      setHosts(new Map());
    } finally {
      setIsCheckingEngine(false);
    }
  };

  // Background polling every 3.5s
  useEffect(() => {
    fetchEngineData();
    const interval = setInterval(() => {
      fetchEngineData();
    }, 3500);
    return () => clearInterval(interval);
  }, [engineUrl]);

  // Real Start Monitoring call to Python backend
  const handleStartMonitoring = async () => {
    try {
      const res = await fetch(`${engineUrl}/api/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: selectedInterface })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setIsRunning(true);
        fetchEngineData();
      } else {
        alert(data.message || "Failed to start monitoring");
      }
    } catch (err: any) {
      alert(`Cannot connect to monitoring engine at ${engineUrl}.\nPlease ensure the Python/Scapy backend is running on Kali Linux with:\nsudo python3 app.py`);
    }
  };

  // Real Stop Monitoring call to Python backend
  const handleStopMonitoring = async () => {
    try {
      const res = await fetch(`${engineUrl}/api/stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setIsRunning(false);
        fetchEngineData();
      } else {
        alert(data.message || "Failed to stop monitoring");
      }
    } catch (err: any) {
      alert(`Cannot connect to monitoring engine at ${engineUrl}.`);
    }
  };

  const handleSaveEngineUrl = (newUrl: string) => {
    let formatted = newUrl.trim();
    if (formatted.endsWith("/")) formatted = formatted.slice(0, -1);
    setEngineUrl(formatted);
    localStorage.setItem("netmonitor_engine_url", formatted);
    fetchEngineData(formatted);
  };

  // Statistics calculation from real data
  const stats = useMemo(() => {
    if (isEngineOnline && backendStats.total_packets > 0) {
      return {
        total: backendStats.total_packets,
        tcp: backendStats.tcp_packets,
        udp: backendStats.udp_packets,
        icmp: backendStats.icmp_packets,
        other: backendStats.other_packets,
        hostsCount: backendStats.total_hosts || hosts.size,
        alertsCount: backendStats.total_alerts || alerts.length
      };
    }
    let tcp = 0, udp = 0, icmp = 0, other = 0;
    packets.forEach(p => {
      if (p.protocol === "TCP") tcp++;
      else if (p.protocol === "UDP") udp++;
      else if (p.protocol === "ICMP") icmp++;
      else other++;
    });
    return {
      total: packets.length,
      tcp,
      udp,
      icmp,
      other,
      hostsCount: hosts.size,
      alertsCount: alerts.length
    };
  }, [isEngineOnline, backendStats, packets, hosts, alerts]);

  // Filtered Packets
  const filteredPackets = useMemo(() => {
    return packets.filter(p => {
      if (packetProtocolFilter !== "ALL" && p.protocol !== packetProtocolFilter) return false;
      if (packetSearchIp) {
        const query = packetSearchIp.toLowerCase();
        return p.source_ip.toLowerCase().includes(query) || p.destination_ip.toLowerCase().includes(query);
      }
      return true;
    }).slice(0, packetLimit);
  }, [packets, packetProtocolFilter, packetSearchIp, packetLimit]);

  // Filtered Alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      if (alertSeverityFilter !== "ALL" && a.severity !== alertSeverityFilter) return false;
      if (alertTypeFilter !== "ALL" && a.alert_type !== alertTypeFilter) return false;
      if (alertSearchIp) {
        const query = alertSearchIp.toLowerCase();
        return a.source_ip.toLowerCase().includes(query) || a.destination_ip.toLowerCase().includes(query);
      }
      return true;
    });
  }, [alerts, alertSeverityFilter, alertTypeFilter, alertSearchIp]);

  // Code repository files for the "Codebase" tab
  const codeFiles: Record<string, string> = {
    "app.py": `"""
app.py - Main Flask Application & Web API
Serves web dashboard templates and provides JSON REST endpoints
for real-time packet telemetry, alert auditing, host tracking, and monitor control.
"""
import sys
import logging
from flask import Flask, render_template, jsonify, request
import config
import database
from monitor import monitor_instance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("network_monitor")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "cybersecurity-lab-monitor-secret-v1"
database.init_db()

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/")
def dashboard_page():
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/api/status", methods=["GET"])
def api_status():
    status = monitor_instance.get_status()
    return jsonify(status), 200

@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(silent=True) or {}
    result = monitor_instance.start_monitoring(data.get("interface"))
    return jsonify(result), 200 if result["success"] else 400

@app.route("/api/stop", methods=["POST"])
def api_stop():
    result = monitor_instance.stop_monitoring()
    return jsonify(result), 200 if result["success"] else 400

if __name__ == "__main__":
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.DEBUG_MODE, threaded=True)`,

    "monitor.py": `"""
monitor.py - Network Packet Capture & Monitoring Engine
Captures live network packets using Scapy in a background thread.
"""
import threading
import logging
from collections import deque
from datetime import datetime
import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP
import config, database
from detector import DetectionEngine

logger = logging.getLogger("network_monitor")

class NetworkMonitor:
    def __init__(self):
        self.is_running = False
        self.selected_interface = "eth0"
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.detector = DetectionEngine()
        self.lock = threading.Lock()
        self.recent_packets = deque(maxlen=config.MAX_MEMORY_PACKETS)

    def start_monitoring(self, iface_name=None):
        with self.lock:
            if self.is_running:
                return {"success": False, "message": "Already running"}
            self.stop_event.clear()
            self.is_running = True
            self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
            self.capture_thread.start()
            return {"success": True, "message": f"Started on {self.selected_interface}"}

    def _capture_worker(self):
        while not self.stop_event.is_set():
            sniff(
                iface=self.selected_interface,
                prn=self._process_scapy_packet,
                store=False,
                timeout=1.0,
                stop_filter=lambda _: self.stop_event.is_set()
            )`,

    "detector.py": `"""
detector.py - Defensive Intrusion Detection Engine
Analyzes packet streams in real-time using rule-based behavioral checks:
1. Port Scan Detection (distinct ports on same target)
2. High Packet Rate Detection (packet flood)
3. Repeated Connection Attempts (SYN/TCP bursts)
4. High ICMP Activity Detection (ping bursts)
"""
import time, threading, logging
from collections import defaultdict, deque
import config

class DetectionEngine:
    def __init__(self):
        self.lock = threading.Lock()
        self.cooldown_tracker = {}
        self.port_scan_history = defaultdict(deque)
        self.packet_rate_history = defaultdict(deque)
        self.repeated_conn_history = defaultdict(deque)
        self.icmp_history = defaultdict(deque)

    def is_in_cooldown(self, alert_type, src_ip, dst_ip, now):
        key = (alert_type, src_ip, dst_ip)
        last_time = self.cooldown_tracker.get(key)
        if last_time and (now - last_time) < config.ALERT_COOLDOWN:
            return True
        self.cooldown_tracker[key] = now
        return False`,

    "database.py": `"""
database.py - SQLite Database Management Module
Handles table creation and parameterized queries for packets, hosts, and alerts.
"""
import sqlite3
import config

def get_connection():
    conn = sqlite3.connect(config.DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_length INTEGER NOT NULL
            )
        """)
        conn.commit()`,

    "config.py": `import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

DB_PATH = os.path.join(DATA_DIR, "network_monitor.db")
LOG_FILE = os.path.join(LOGS_DIR, "network_monitor.log")

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
DEBUG_MODE = False

# Detection Heuristics
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10
HIGH_PACKET_RATE_THRESHOLD = 60
HIGH_PACKET_RATE_WINDOW = 5
REPEATED_CONN_THRESHOLD = 12
REPEATED_CONN_WINDOW = 5
ICMP_THRESHOLD = 12
ICMP_WINDOW = 5
ALERT_COOLDOWN = 30
MAX_MEMORY_PACKETS = 200`,

    "requirements.txt": `Flask>=2.3.0\nscapy>=2.5.0\npsutil>=5.9.0`
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFile(label);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  return (
    <div className="flex h-screen w-full bg-[#0b0f14] text-[#e6edf3] font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-[#121820] border-r border-[#222d3a] flex flex-col shrink-0 select-none">
        {/* Brand */}
        <div className="p-4 border-b border-[#222d3a] flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-sm tracking-wide text-white leading-tight">NetMonitor</h1>
            <p className="text-[11px] text-gray-400">v1.0 • Linux Security Lab</p>
          </div>
        </div>

        {/* Engine Status Pill */}
        <div className="m-3 p-2.5 bg-[#1a222c] border border-[#222d3a] rounded-md flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${isEngineOnline ? (isRunning ? "bg-emerald-400 shadow-[0_0_8px_#34d399]" : "bg-blue-400") : "bg-rose-500"}`} />
            <span className={`text-[11px] font-bold tracking-wider ${isEngineOnline ? (isRunning ? "text-emerald-400" : "text-blue-400") : "text-rose-400"}`}>
              {isEngineOnline ? (isRunning ? "ENGINE RUNNING" : "ENGINE IDLE") : "ENGINE OFFLINE"}
            </span>
          </div>
          <span className="text-[11px] font-mono bg-[#0b0f14] text-gray-300 px-2 py-0.5 rounded border border-[#222d3a]">
            {isEngineOnline ? selectedInterface : "offline"}
          </span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-2.5 py-2 space-y-1 overflow-y-auto">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "dashboard" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Dashboard</span>
          </button>

          <button
            onClick={() => setActiveTab("packets")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "packets" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Radio className="w-4 h-4" />
              <span>Live Packets</span>
            </div>
            <span className="text-[10px] font-mono bg-[#0b0f14] text-gray-400 px-1.5 py-0.5 rounded">
              {stats.total}
            </span>
          </button>

          <button
            onClick={() => setActiveTab("alerts")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "alerts" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4" />
              <span>Alerts</span>
            </div>
            {stats.alertsCount > 0 && (
              <span className="text-[10px] font-bold bg-rose-500 text-white px-1.5 py-0.5 rounded-full">
                {stats.alertsCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("hosts")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "hosts" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Server className="w-4 h-4" />
              <span>Active Hosts</span>
            </div>
            <span className="text-[10px] font-mono bg-[#0b0f14] text-gray-400 px-1.5 py-0.5 rounded">
              {stats.hostsCount}
            </span>
          </button>

          <button
            onClick={() => setActiveTab("settings")}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "settings" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <Settings className="w-4 h-4" />
            <span>Settings &amp; Engine</span>
          </button>

          <div className="pt-3 pb-1 px-2 text-[10px] font-bold uppercase tracking-wider text-gray-500">
            Project &amp; VM Lab
          </div>

          <button
            onClick={() => setActiveTab("codebase")}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "codebase" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <FileCode className="w-4 h-4 text-emerald-400" />
            <span>Python Source Files</span>
          </button>

          <button
            onClick={() => setActiveTab("guide")}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "guide" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <Terminal className="w-4 h-4 text-amber-400" />
            <span>VMware Lab Guide</span>
          </button>

          <button
            onClick={() => setActiveTab("theory")}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition ${
              activeTab === "theory" ? "bg-blue-600/20 text-blue-400 border-l-2 border-blue-500" : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
            }`}
          >
            <BookOpen className="w-4 h-4 text-purple-400" />
            <span>Educational Concepts</span>
          </button>
        </nav>

        {/* Engine Connection Card in Sidebar */}
        <div className="p-3 m-2.5 bg-[#161f2b] border border-[#222d3a] rounded-lg text-xs space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-semibold text-gray-200 text-[11px]">
              {isEngineOnline ? <Wifi className="w-3.5 h-3.5 text-emerald-400" /> : <WifiOff className="w-3.5 h-3.5 text-rose-400" />}
              <span>Backend Engine</span>
            </div>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${isEngineOnline ? "bg-emerald-500/20 text-emerald-400" : "bg-rose-500/20 text-rose-400"}`}>
              {isEngineOnline ? "ONLINE" : "OFFLINE"}
            </span>
          </div>

          <div className="text-[11px] text-gray-400 truncate font-mono bg-[#0b0f14] p-1.5 rounded border border-[#222d3a]">
            {engineUrl}
          </div>

          {isEngineOnline && pingLatency !== null && (
            <div className="text-[10px] text-gray-400 flex justify-between">
              <span>Latency:</span>
              <span className="font-mono text-emerald-400">{pingLatency} ms</span>
            </div>
          )}

          <button
            onClick={() => fetchEngineData()}
            disabled={isCheckingEngine}
            className="w-full py-1 bg-[#202d3d] hover:bg-[#28384d] text-[11px] text-gray-300 rounded border border-[#2e3f54] flex items-center justify-center gap-1.5 transition"
          >
            <RefreshCw className={`w-3 h-3 ${isCheckingEngine ? "animate-spin" : ""}`} />
            <span>{isCheckingEngine ? "Connecting..." : "Check Engine"}</span>
          </button>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-[#222d3a] text-[11px] text-gray-500 text-center">
          <span>BSIT Cybersecurity Project</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 bg-[#0b0f14] overflow-hidden">
        {/* Top Control Bar */}
        <header className="h-16 px-6 bg-[#121820] border-b border-[#222d3a] flex items-center justify-between shrink-0">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">
              Network Attack &amp; Monitoring Framework
            </h2>
            <p className="text-xs text-gray-400">
              Real-Time Defensive Network Security Monitoring &amp; Telemetry
            </p>
          </div>

          <div className="flex items-center gap-4">
            {/* Interface Dropdown */}
            <div className="flex items-center gap-2">
              <label htmlFor="iface-top" className="text-xs font-semibold text-gray-400">
                Interface:
              </label>
              <select
                id="iface-top"
                value={selectedInterface}
                onChange={e => setSelectedInterface(e.target.value)}
                disabled={isRunning || !isEngineOnline}
                className="bg-[#0f151c] border border-[#222d3a] text-xs text-gray-200 px-2.5 py-1.5 rounded-md focus:border-blue-500 outline-none disabled:opacity-60"
              >
                {availableInterfaces.map(iface => (
                  <option key={iface} value={iface}>
                    {iface}
                  </option>
                ))}
              </select>
            </div>

            {/* Start / Stop Buttons */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleStartMonitoring}
                disabled={isRunning || !isEngineOnline}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:hover:bg-emerald-600 text-white text-xs font-bold rounded-md transition shadow-sm"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                START MONITORING
              </button>
              <button
                onClick={handleStopMonitoring}
                disabled={!isRunning || !isEngineOnline}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:hover:bg-rose-600 text-white text-xs font-bold rounded-md transition shadow-sm"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                STOP MONITORING
              </button>
            </div>
          </div>
        </header>

        {/* Tab Body View */}
        <div className="flex-1 p-6 overflow-y-auto">
          {/* TAB 1: DASHBOARD */}
          {activeTab === "dashboard" && (
            <div className="space-y-6">
              {/* Engine Offline Banner (if not connected) */}
              {!isEngineOnline && (
                <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-md bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0">
                      <AlertTriangle className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-bold text-amber-300">Monitoring Engine Offline</div>
                      <div className="text-gray-400">
                        The Python / Scapy capture engine is currently not detected at <span className="font-mono text-gray-200">{engineUrl}</span>.
                        Run <code className="text-emerald-400 font-mono">sudo python3 app.py</code> in your Kali Linux VM to start capturing live network traffic.
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => fetchEngineData()}
                      disabled={isCheckingEngine}
                      className="px-3 py-1.5 bg-[#1a222c] hover:bg-[#232d3a] border border-[#222d3a] rounded text-gray-300 text-xs font-semibold flex items-center gap-1.5 transition"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isCheckingEngine ? "animate-spin" : ""}`} />
                      <span>{isCheckingEngine ? "Checking..." : "Reconnect"}</span>
                    </button>
                    <button
                      onClick={() => setActiveTab("settings")}
                      className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-xs font-semibold transition"
                    >
                      Configure IP
                    </button>
                  </div>
                </div>
              )}

              {/* Stat Cards */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
                <div className="p-4 bg-[#121820] border border-[#222d3a] rounded-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-md bg-blue-500/10 text-blue-400 flex items-center justify-center shrink-0">
                    <Activity className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Packets</div>
                    <div className="text-xl font-bold font-mono text-white">{stats.total.toLocaleString()}</div>
                  </div>
                </div>

                <div className="p-4 bg-[#121820] border border-[#222d3a] rounded-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-md bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0">
                    <Server className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Hosts</div>
                    <div className="text-xl font-bold font-mono text-white">{stats.hostsCount}</div>
                  </div>
                </div>

                <div className="p-4 bg-[#121820] border border-[#222d3a] rounded-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-md bg-rose-500/10 text-rose-400 flex items-center justify-center shrink-0">
                    <AlertTriangle className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Alerts</div>
                    <div className="text-xl font-bold font-mono text-white">{stats.alertsCount}</div>
                  </div>
                </div>

                <div className="p-4 bg-[#121820] border border-[#222d3a] rounded-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-md bg-sky-500/10 text-sky-400 font-mono font-bold text-xs flex items-center justify-center shrink-0">
                    TCP
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">TCP</div>
                    <div className="text-xl font-bold font-mono text-sky-300">{stats.tcp.toLocaleString()}</div>
                  </div>
                </div>

                <div className="p-4 bg-[#121820] border border-[#222d3a] rounded-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-md bg-purple-500/10 text-purple-400 font-mono font-bold text-xs flex items-center justify-center shrink-0">
                    UDP
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">UDP</div>
                    <div className="text-xl font-bold font-mono text-purple-300">{stats.udp.toLocaleString()}</div>
                  </div>
                </div>

                <div className="p-4 bg-[#121820] border border-[#222d3a] rounded-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-md bg-amber-500/10 text-amber-400 font-mono font-bold text-xs flex items-center justify-center shrink-0">
                    ICMP
                  </div>
                  <div>
                    <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">ICMP</div>
                    <div className="text-xl font-bold font-mono text-amber-300">{stats.icmp.toLocaleString()}</div>
                  </div>
                </div>
              </div>

              {/* Protocol Breakdown & Recent Alerts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Protocol Progress Bars */}
                <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
                  <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222d3a]">
                    <div>
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider">Protocol Breakdown</h3>
                      <p className="text-[11px] text-gray-400">Distribution of analyzed network traffic</p>
                    </div>
                    <span className="text-xs font-mono text-gray-400">{stats.total} total</span>
                  </div>

                  <div className="space-y-3.5">
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-sky-300 font-medium">TCP (Transmission Control Protocol)</span>
                        <span className="font-mono text-gray-300">
                          {stats.total ? ((stats.tcp / stats.total) * 100).toFixed(1) : 0}% ({stats.tcp})
                        </span>
                      </div>
                      <div className="h-2 bg-[#0b0f14] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-sky-500 rounded-full transition-all duration-300"
                          style={{ width: `${stats.total ? (stats.tcp / stats.total) * 100 : 0}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-purple-300 font-medium">UDP (User Datagram Protocol)</span>
                        <span className="font-mono text-gray-300">
                          {stats.total ? ((stats.udp / stats.total) * 100).toFixed(1) : 0}% ({stats.udp})
                        </span>
                      </div>
                      <div className="h-2 bg-[#0b0f14] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-purple-500 rounded-full transition-all duration-300"
                          style={{ width: `${stats.total ? (stats.udp / stats.total) * 100 : 0}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-amber-300 font-medium">ICMP (Internet Control Message Protocol)</span>
                        <span className="font-mono text-gray-300">
                          {stats.total ? ((stats.icmp / stats.total) * 100).toFixed(1) : 0}% ({stats.icmp})
                        </span>
                      </div>
                      <div className="h-2 bg-[#0b0f14] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-amber-500 rounded-full transition-all duration-300"
                          style={{ width: `${stats.total ? (stats.icmp / stats.total) * 100 : 0}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-gray-400 font-medium">Other Protocols</span>
                        <span className="font-mono text-gray-300">
                          {stats.total ? ((stats.other / stats.total) * 100).toFixed(1) : 0}% ({stats.other})
                        </span>
                      </div>
                      <div className="h-2 bg-[#0b0f14] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gray-500 rounded-full transition-all duration-300"
                          style={{ width: `${stats.total ? (stats.other / stats.total) * 100 : 0}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Recent Alerts Mini-Table */}
                <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
                  <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222d3a]">
                    <div>
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider">Recent Defensive Alerts</h3>
                      <p className="text-[11px] text-gray-400">Automated heuristic security detections</p>
                    </div>
                    <button
                      onClick={() => setActiveTab("alerts")}
                      className="text-xs text-blue-400 hover:text-blue-300 font-medium"
                    >
                      View All ({alerts.length}) →
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    {alerts.length === 0 ? (
                      <div className="py-8 text-center text-xs text-gray-500 italic">
                        {isEngineOnline ? "No security alerts generated yet. Heuristic rules are monitoring traffic." : "Monitoring engine offline - Start Kali VM backend to view alerts."}
                      </div>
                    ) : (
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="text-gray-400 border-b border-[#222d3a]">
                            <th className="pb-2">Time</th>
                            <th className="pb-2">Alert Type</th>
                            <th className="pb-2">Severity</th>
                            <th className="pb-2">Source IP</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#222d3a]">
                          {alerts.slice(0, 4).map(alert => (
                            <tr key={alert.id} className="hover:bg-white/[0.02]">
                              <td className="py-2 font-mono text-[11px] text-gray-400">{alert.timestamp.substring(11)}</td>
                              <td className="py-2 font-semibold text-gray-200">{alert.alert_type}</td>
                              <td className="py-2">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    alert.severity === "HIGH"
                                      ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                                      : alert.severity === "MEDIUM"
                                      ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                                      : "bg-blue-500/20 text-blue-400 border border-blue-500/40"
                                  }`}
                                >
                                  {alert.severity}
                                </span>
                              </td>
                              <td className="py-2 font-mono text-blue-300">{alert.source_ip}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </div>

              {/* Live Network Activity Table */}
              <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
                <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222d3a]">
                  <div className="flex items-center gap-2.5">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">Live Network Activity</h3>
                    <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono">
                      <span className={`w-1.5 h-1.5 rounded-full ${isEngineOnline && isRunning ? "bg-emerald-400 animate-pulse" : "bg-rose-500"}`} />
                      <span>{isEngineOnline && isRunning ? "STREAMING" : (isEngineOnline ? "ENGINE IDLE" : "ENGINE OFFLINE")}</span>
                    </div>
                  </div>
                  <span className="text-xs text-gray-400">Captured on interface: {selectedInterface}</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="text-gray-400 border-b border-[#222d3a] font-semibold">
                        <th className="pb-2.5">Time</th>
                        <th className="pb-2.5">Source IP</th>
                        <th className="pb-2.5">Destination IP</th>
                        <th className="pb-2.5">Protocol</th>
                        <th className="pb-2.5">Src Port</th>
                        <th className="pb-2.5">Dst Port</th>
                        <th className="pb-2.5">Length</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#222d3a]">
                      {packets.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="py-8 text-center text-xs text-gray-500 italic">
                            {isEngineOnline
                              ? isRunning
                                ? `Waiting for incoming traffic on interface ${selectedInterface}...`
                                : 'Monitoring is stopped. Click "START MONITORING" to capture live packets.'
                              : `Monitoring engine offline - No live traffic received. Start the Python/Scapy backend on Kali Linux (sudo python3 app.py).`}
                          </td>
                        </tr>
                      ) : (
                        packets.slice(0, 25).map(pkt => (
                          <tr key={pkt.id} className="hover:bg-white/[0.02]">
                            <td className="py-2 font-mono text-gray-400 text-[11px]">{pkt.timestamp}</td>
                            <td className="py-2 font-mono text-blue-300">{pkt.source_ip}</td>
                            <td className="py-2 font-mono text-blue-300">{pkt.destination_ip}</td>
                            <td className="py-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                  pkt.protocol === "TCP"
                                    ? "bg-sky-500/20 text-sky-400"
                                    : pkt.protocol === "UDP"
                                    ? "bg-purple-500/20 text-purple-400"
                                    : pkt.protocol === "ICMP"
                                    ? "bg-amber-500/20 text-amber-400"
                                    : "bg-gray-500/20 text-gray-400"
                                }`}
                              >
                                {pkt.protocol}
                              </span>
                            </td>
                            <td className="py-2 font-mono text-amber-300/80">{pkt.source_port ?? "-"}</td>
                            <td className="py-2 font-mono text-amber-300/80">{pkt.destination_port ?? "-"}</td>
                            <td className="py-2 font-mono text-gray-300">{pkt.packet_length} B</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: LIVE PACKETS */}
          {activeTab === "packets" && (
            <div className="space-y-4">
              <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-[#222d3a]">
                  <div>
                    <h3 className="text-sm font-bold text-white">Network Packet Inspector</h3>
                    <p className="text-xs text-gray-400">Search and filter frames captured by Scapy</p>
                  </div>
                  <span className="text-xs font-mono text-gray-400">
                    Matching: {filteredPackets.length} of {packets.length}
                  </span>
                </div>

                {/* Filter Controls */}
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-4">
                  <div>
                    <label className="text-[11px] text-gray-400 font-semibold block mb-1">Search IP Address</label>
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-2.5" />
                      <input
                        type="text"
                        placeholder="e.g. 192.168.1.105"
                        value={packetSearchIp}
                        onChange={e => setPacketSearchIp(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 bg-[#0b0f14] border border-[#222d3a] rounded-md text-xs text-gray-200 outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-[11px] text-gray-400 font-semibold block mb-1">Protocol</label>
                    <select
                      value={packetProtocolFilter}
                      onChange={e => setPacketProtocolFilter(e.target.value)}
                      className="w-full px-3 py-1.5 bg-[#0b0f14] border border-[#222d3a] rounded-md text-xs text-gray-200 outline-none focus:border-blue-500"
                    >
                      <option value="ALL">All Protocols</option>
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="ICMP">ICMP</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] text-gray-400 font-semibold block mb-1">Max Display Limit</label>
                    <select
                      value={packetLimit}
                      onChange={e => setPacketLimit(Number(e.target.value))}
                      className="w-full px-3 py-1.5 bg-[#0b0f14] border border-[#222d3a] rounded-md text-xs text-gray-200 outline-none focus:border-blue-500"
                    >
                      <option value={50}>50 packets</option>
                      <option value={100}>100 packets</option>
                      <option value={200}>200 packets</option>
                    </select>
                  </div>

                  <div className="flex items-end">
                    <button
                      onClick={() => { setPacketSearchIp(""); setPacketProtocolFilter("ALL"); }}
                      className="w-full py-1.5 bg-[#1a222c] hover:bg-[#232d3a] text-xs font-semibold text-gray-300 rounded-md border border-[#222d3a]"
                    >
                      Reset Filters
                    </button>
                  </div>
                </div>

                {/* Packets Full Table */}
                <div className="overflow-x-auto max-h-[600px]">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-[#121820]">
                      <tr className="text-gray-400 border-b border-[#222d3a] font-semibold">
                        <th className="pb-2.5">ID</th>
                        <th className="pb-2.5">Time</th>
                        <th className="pb-2.5">Source IP</th>
                        <th className="pb-2.5">Destination IP</th>
                        <th className="pb-2.5">Protocol</th>
                        <th className="pb-2.5">Src Port</th>
                        <th className="pb-2.5">Dst Port</th>
                        <th className="pb-2.5">Length</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#222d3a]">
                      {filteredPackets.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="py-8 text-center text-xs text-gray-500 italic">
                            {isEngineOnline ? "No packets match the filter criteria." : "Monitoring engine offline - No packets to display."}
                          </td>
                        </tr>
                      ) : (
                        filteredPackets.map(pkt => (
                          <tr key={pkt.id} className="hover:bg-white/[0.02]">
                            <td className="py-2 text-gray-500 font-mono text-[11px]">#{pkt.id}</td>
                            <td className="py-2 font-mono text-gray-400 text-[11px]">{pkt.timestamp}</td>
                            <td className="py-2 font-mono text-blue-300">{pkt.source_ip}</td>
                            <td className="py-2 font-mono text-blue-300">{pkt.destination_ip}</td>
                            <td className="py-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                  pkt.protocol === "TCP"
                                    ? "bg-sky-500/20 text-sky-400"
                                    : pkt.protocol === "UDP"
                                    ? "bg-purple-500/20 text-purple-400"
                                    : pkt.protocol === "ICMP"
                                    ? "bg-amber-500/20 text-amber-400"
                                    : "bg-gray-500/20 text-gray-400"
                                }`}
                              >
                                {pkt.protocol}
                              </span>
                            </td>
                            <td className="py-2 font-mono text-amber-300/80">{pkt.source_port ?? "-"}</td>
                            <td className="py-2 font-mono text-amber-300/80">{pkt.destination_port ?? "-"}</td>
                            <td className="py-2 font-mono text-gray-300">{pkt.packet_length} B</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: ALERTS */}
          {activeTab === "alerts" && (
            <div className="space-y-4">
              <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-[#222d3a]">
                  <div>
                    <h3 className="text-sm font-bold text-white">Defensive Intrusion Alerts</h3>
                    <p className="text-xs text-gray-400">Heuristic detections with 30s anti-spam alert cooldown</p>
                  </div>
                  <span className="text-xs font-mono text-gray-400">
                    Total Alerts: {filteredAlerts.length}
                  </span>
                </div>

                {/* Filter Controls */}
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-4">
                  <div>
                    <label className="text-[11px] text-gray-400 font-semibold block mb-1">Severity</label>
                    <select
                      value={alertSeverityFilter}
                      onChange={e => setAlertSeverityFilter(e.target.value)}
                      className="w-full px-3 py-1.5 bg-[#0b0f14] border border-[#222d3a] rounded-md text-xs text-gray-200 outline-none focus:border-blue-500"
                    >
                      <option value="ALL">All Severities</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] text-gray-400 font-semibold block mb-1">Alert Category</label>
                    <select
                      value={alertTypeFilter}
                      onChange={e => setAlertTypeFilter(e.target.value)}
                      className="w-full px-3 py-1.5 bg-[#0b0f14] border border-[#222d3a] rounded-md text-xs text-gray-200 outline-none focus:border-blue-500"
                    >
                      <option value="ALL">All Alert Types</option>
                      <option value="Possible Port Scan">Possible Port Scan</option>
                      <option value="High Packet Rate">High Packet Rate</option>
                      <option value="Repeated Connection Attempts">Repeated Connection Attempts</option>
                      <option value="High ICMP Activity">High ICMP Activity</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] text-gray-400 font-semibold block mb-1">Search IP</label>
                    <input
                      type="text"
                      placeholder="e.g. 192.168.1.189"
                      value={alertSearchIp}
                      onChange={e => setAlertSearchIp(e.target.value)}
                      className="w-full px-3 py-1.5 bg-[#0b0f14] border border-[#222d3a] rounded-md text-xs text-gray-200 outline-none focus:border-blue-500"
                    />
                  </div>

                  <div className="flex items-end">
                    <button
                      onClick={() => { setAlertSeverityFilter("ALL"); setAlertTypeFilter("ALL"); setAlertSearchIp(""); }}
                      className="w-full py-1.5 bg-[#1a222c] hover:bg-[#232d3a] text-xs font-semibold text-gray-300 rounded-md border border-[#222d3a]"
                    >
                      Clear Filters
                    </button>
                  </div>
                </div>

                {/* Alerts Table */}
                <div className="overflow-x-auto">
                  {filteredAlerts.length === 0 ? (
                    <div className="py-12 text-center text-xs text-gray-500 italic">
                      {isEngineOnline ? "No matching security alerts found." : "Monitoring engine offline - No security alerts to display."}
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="text-gray-400 border-b border-[#222d3a] font-semibold">
                          <th className="pb-2.5">ID</th>
                          <th className="pb-2.5">Time</th>
                          <th className="pb-2.5">Alert Type</th>
                          <th className="pb-2.5">Severity</th>
                          <th className="pb-2.5">Source IP</th>
                          <th className="pb-2.5">Target IP</th>
                          <th className="pb-2.5">Description</th>
                          <th className="pb-2.5">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#222d3a]">
                        {filteredAlerts.map(a => (
                          <tr key={a.id} className="hover:bg-white/[0.02]">
                            <td className="py-2.5 text-gray-500 font-mono text-[11px]">#{a.id}</td>
                            <td className="py-2.5 font-mono text-gray-400 text-[11px]">{a.timestamp}</td>
                            <td className="py-2.5 font-bold text-gray-200">{a.alert_type}</td>
                            <td className="py-2.5">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  a.severity === "HIGH"
                                    ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                                    : a.severity === "MEDIUM"
                                    ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                                    : "bg-blue-500/20 text-blue-400 border border-blue-500/40"
                                }`}
                              >
                                {a.severity}
                              </span>
                            </td>
                            <td className="py-2.5 font-mono text-rose-300">{a.source_ip}</td>
                            <td className="py-2.5 font-mono text-blue-300">{a.destination_ip}</td>
                            <td className="py-2.5 text-gray-300 max-w-xs">{a.description}</td>
                            <td className="py-2.5">
                              <span className="px-2 py-0.5 bg-blue-600/20 text-blue-400 rounded text-[10px] font-bold border border-blue-500/30">
                                {a.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: ACTIVE HOSTS */}
          {activeTab === "hosts" && (
            <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#222d3a]">
                <div>
                  <h3 className="text-sm font-bold text-white">Discovered Network Hosts</h3>
                  <p className="text-xs text-gray-400">Endpoints observed communicating across the lab network</p>
                </div>
                <span className="text-xs font-mono text-gray-400">Total: {hosts.size} hosts</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-gray-400 border-b border-[#222d3a] font-semibold">
                      <th className="pb-2.5">Host ID</th>
                      <th className="pb-2.5">IP Address</th>
                      <th className="pb-2.5">Scope</th>
                      <th className="pb-2.5">First Seen</th>
                      <th className="pb-2.5">Last Seen</th>
                      <th className="pb-2.5">Observed Packets</th>
                      <th className="pb-2.5">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#222d3a]">
                    {hosts.size === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-xs text-gray-500 italic">
                          {isEngineOnline ? "No active hosts recorded yet. Waiting for traffic..." : "Monitoring engine offline - No hosts detected."}
                        </td>
                      </tr>
                    ) : (
                      Array.from(hosts.values()).map(h => (
                        <tr key={h.ip_address} className="hover:bg-white/[0.02]">
                          <td className="py-2.5 text-gray-500 font-mono">#{h.id}</td>
                          <td className="py-2.5 font-mono font-bold text-blue-300">{h.ip_address}</td>
                          <td className="py-2.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              h.role === "local" ? "bg-emerald-500/20 text-emerald-400" : "bg-purple-500/20 text-purple-400"
                            }`}>
                              {h.role === "local" ? "Local Subnet" : "External IP"}
                            </span>
                          </td>
                          <td className="py-2.5 font-mono text-gray-400 text-[11px]">{h.first_seen}</td>
                          <td className="py-2.5 font-mono text-gray-400 text-[11px]">{h.last_seen}</td>
                          <td className="py-2.5 font-mono text-gray-200">{h.packet_count.toLocaleString()}</td>
                          <td className="py-2.5">
                            <button
                              onClick={() => {
                                setPacketSearchIp(h.ip_address);
                                setActiveTab("packets");
                              }}
                              className="px-2 py-1 bg-[#1a222c] hover:bg-[#232d3a] text-blue-400 text-[11px] rounded border border-[#222d3a]"
                            >
                              Inspect Traffic
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 5: SETTINGS & RULES */}
          {activeTab === "settings" && (
            <div className="space-y-5">
              {/* Kali VM Connection Card */}
              <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5">
                <div className="flex items-center justify-between border-b border-[#222d3a] pb-3 mb-4">
                  <div className="flex items-center gap-2.5">
                    <Wifi className="w-5 h-5 text-blue-400" />
                    <div>
                      <h3 className="text-sm font-bold text-white">Monitoring Engine Connection (Kali Linux VM)</h3>
                      <p className="text-xs text-gray-400">Configure connection to your Python/Scapy backend running on Linux</p>
                    </div>
                  </div>
                  <span className={`text-xs px-2.5 py-1 rounded font-bold ${isEngineOnline ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-rose-500/20 text-rose-400 border border-rose-500/30"}`}>
                    {isEngineOnline ? "CONNECTED" : "DISCONNECTED"}
                  </span>
                </div>

                <div className="space-y-4 text-xs">
                  <div>
                    <label className="text-gray-300 font-semibold block mb-1.5">Engine API Base URL:</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={tempEngineUrl}
                        onChange={e => setTempEngineUrl(e.target.value)}
                        placeholder="http://127.0.0.1:5000 or http://192.168.1.150:5000"
                        className="flex-1 px-3 py-2 bg-[#0b0f14] border border-[#222d3a] rounded-md font-mono text-gray-200 outline-none focus:border-blue-500"
                      />
                      <button
                        onClick={() => handleSaveEngineUrl(tempEngineUrl)}
                        disabled={isCheckingEngine}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-md transition"
                      >
                        {isCheckingEngine ? "Connecting..." : "Save & Connect"}
                      </button>
                      <button
                        onClick={() => handleSaveEngineUrl("http://127.0.0.1:5000")}
                        className="px-3 py-2 bg-[#1a222c] hover:bg-[#232d3a] border border-[#222d3a] text-gray-300 rounded-md"
                      >
                        Default (localhost)
                      </button>
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1.5">
                      • When running browser and Kali in the same VM: use <code className="text-blue-400">http://127.0.0.1:5000</code><br />
                      • When accessing from Windows host or Vercel: use your Kali VM's IP, e.g. <code className="text-blue-400">http://192.168.x.x:5000</code> (check with <code className="text-emerald-400">ip addr</code> on Kali).
                    </p>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                    <div className="p-3 bg-[#1a222c] rounded border border-[#222d3a]">
                      <span className="text-gray-400 block mb-1">Connection State:</span>
                      <span className={`font-bold ${isEngineOnline ? "text-emerald-400" : "text-rose-400"}`}>
                        {isEngineOnline ? "Online & Responding" : "Offline / Unreachable"}
                      </span>
                    </div>

                    <div className="p-3 bg-[#1a222c] rounded border border-[#222d3a]">
                      <span className="text-gray-400 block mb-1">Ping Latency:</span>
                      <span className="font-mono text-gray-200">
                        {pingLatency !== null ? `${pingLatency} ms` : "N/A"}
                      </span>
                    </div>

                    <div className="p-3 bg-[#1a222c] rounded border border-[#222d3a]">
                      <span className="text-gray-400 block mb-1">Last Status Check:</span>
                      <span className="font-mono text-gray-200">
                        {lastCheckTime || "Never"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Interface & Heuristic Rules */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5 space-y-4">
                  <h3 className="text-sm font-bold text-white border-b border-[#222d3a] pb-2">
                    Network Interface Configuration
                  </h3>

                  <div className="flex justify-between items-center text-xs py-1 border-b border-[#222d3a]/60">
                    <span className="text-gray-400">Active Capture Interface:</span>
                    <span className="font-mono bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded border border-blue-500/30">
                      {selectedInterface}
                    </span>
                  </div>

                  <div className="flex justify-between items-center text-xs py-1 border-b border-[#222d3a]/60">
                    <span className="text-gray-400">Capture Engine Status:</span>
                    <span className={`font-bold ${isRunning ? "text-emerald-400" : "text-rose-400"}`}>
                      {isRunning ? "RUNNING" : "STOPPED"}
                    </span>
                  </div>

                  <div className="flex justify-between items-center text-xs py-1 border-b border-[#222d3a]/60">
                    <span className="text-gray-400">SQLite Storage File:</span>
                    <span className="font-mono text-gray-300 text-[11px]">data/network_monitor.db</span>
                  </div>

                  <div className="flex justify-between items-center text-xs py-1 border-b border-[#222d3a]/60">
                    <span className="text-gray-400">Audit Log File:</span>
                    <span className="font-mono text-gray-300 text-[11px]">logs/network_monitor.log</span>
                  </div>

                  <div className="pt-2">
                    <h4 className="text-xs font-semibold text-gray-300 mb-2">Detected Interface Adapters:</h4>
                    <div className="flex flex-wrap gap-2">
                      {availableInterfaces.map(iface => (
                        <span key={iface} className="font-mono text-xs bg-[#1a222c] border border-[#222d3a] px-2.5 py-1 rounded text-gray-300">
                          {iface}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-5 space-y-3.5">
                  <h3 className="text-sm font-bold text-white border-b border-[#222d3a] pb-2">
                    Heuristic Detection Thresholds (config.py)
                  </h3>

                  <div className="p-3 bg-[#1a222c] border border-[#222d3a] rounded-md text-xs">
                    <div className="flex justify-between items-center font-semibold mb-1">
                      <span className="text-white">Rule 1 — Possible Port Scan</span>
                      <span className="text-amber-400 text-[10px] bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/30">MEDIUM</span>
                    </div>
                    <p className="text-gray-400 text-[11px] mb-1.5">Triggers on unique ports contacted on a single target IP.</p>
                    <div className="font-mono text-[11px] text-gray-300 flex justify-between">
                      <span>Threshold: {thresholds.portScanLimit} ports</span>
                      <span>Window: {thresholds.portScanWindow}s</span>
                    </div>
                  </div>

                  <div className="p-3 bg-[#1a222c] border border-[#222d3a] rounded-md text-xs">
                    <div className="flex justify-between items-center font-semibold mb-1">
                      <span className="text-white">Rule 2 — High Packet Rate</span>
                      <span className="text-amber-400 text-[10px] bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/30">MEDIUM</span>
                    </div>
                    <p className="text-gray-400 text-[11px] mb-1.5">Triggers when single host emits rapid packet bursts.</p>
                    <div className="font-mono text-[11px] text-gray-300 flex justify-between">
                      <span>Threshold: {thresholds.packetRateLimit} pkts</span>
                      <span>Window: {thresholds.packetRateWindow}s</span>
                    </div>
                  </div>

                  <div className="p-3 bg-[#1a222c] border border-[#222d3a] rounded-md text-xs">
                    <div className="flex justify-between items-center font-semibold mb-1">
                      <span className="text-white">Rule 3 — Repeated Connection Attempts</span>
                      <span className="text-blue-400 text-[10px] bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/30">LOW</span>
                    </div>
                    <p className="text-gray-400 text-[11px] mb-1.5">Triggers on repeated TCP attempts to same service port.</p>
                    <div className="font-mono text-[11px] text-gray-300 flex justify-between">
                      <span>Threshold: {thresholds.repeatedConnLimit} conns</span>
                      <span>Window: {thresholds.repeatedConnWindow}s</span>
                    </div>
                  </div>

                  <div className="p-3 bg-[#1a222c] border border-[#222d3a] rounded-md text-xs">
                    <div className="flex justify-between items-center font-semibold mb-1">
                      <span className="text-white">Rule 4 — High ICMP Activity</span>
                      <span className="text-blue-400 text-[10px] bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/30">LOW</span>
                    </div>
                    <p className="text-gray-400 text-[11px] mb-1.5">Triggers on ping floods or ICMP reconnaissance bursts.</p>
                    <div className="font-mono text-[11px] text-gray-300 flex justify-between">
                      <span>Threshold: {thresholds.icmpLimit} echo pkts</span>
                      <span>Window: {thresholds.icmpWindow}s</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: PYTHON SOURCE FILES */}
          {activeTab === "codebase" && (
            <div className="bg-[#121820] border border-[#222d3a] rounded-lg overflow-hidden flex flex-col h-[750px]">
              <div className="p-4 bg-[#161f2b] border-b border-[#222d3a] flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-emerald-400" />
                  <div>
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      network-monitor/{selectedCodeFile}
                    </h3>
                    <p className="text-[11px] text-gray-400">Complete, production-ready Python 3 source code</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copyToClipboard(codeFiles[selectedCodeFile] || "", selectedCodeFile)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#202d3d] hover:bg-[#28384d] text-xs font-semibold text-gray-200 rounded-md border border-[#2e3f54] transition"
                  >
                    {copiedFile === selectedCodeFile ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy File</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* File selector pill bar */}
              <div className="flex border-b border-[#222d3a] bg-[#0f151c] px-3 py-2 gap-2 overflow-x-auto text-xs">
                {Object.keys(codeFiles).map(file => (
                  <button
                    key={file}
                    onClick={() => setSelectedCodeFile(file)}
                    className={`px-3 py-1 rounded font-mono text-xs transition ${
                      selectedCodeFile === file
                        ? "bg-blue-600 text-white font-bold"
                        : "text-gray-400 hover:bg-[#1a222c] hover:text-gray-200"
                    }`}
                  >
                    {file}
                  </button>
                ))}
              </div>

              {/* Code viewer */}
              <div className="flex-1 p-4 bg-[#090d12] overflow-auto">
                <pre className="font-mono text-xs text-gray-300 leading-relaxed whitespace-pre">
                  <code>{codeFiles[selectedCodeFile]}</code>
                </pre>
              </div>
            </div>
          )}

          {/* TAB 7: VMWARE LAB GUIDE */}
          {activeTab === "guide" && (
            <div className="space-y-5 max-w-4xl mx-auto">
              <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-6 space-y-4">
                <div className="flex items-center gap-3 pb-3 border-b border-[#222d3a]">
                  <Terminal className="w-6 h-6 text-amber-400" />
                  <div>
                    <h3 className="text-base font-bold text-white">VMware &amp; Kali Linux Deployment Guide</h3>
                    <p className="text-xs text-gray-400">Step-by-step instructions to run this project in your VM lab</p>
                  </div>
                </div>

                <div className="space-y-4 text-xs">
                  <div>
                    <h4 className="font-bold text-white text-sm mb-1.5 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">1</span>
                      Create Directory &amp; Virtual Environment
                    </h4>
                    <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a] font-mono text-gray-300">
                      mkdir -p ~/network-monitor/data ~/network-monitor/logs<br />
                      cd ~/network-monitor<br />
                      python3 -m venv venv<br />
                      source venv/bin/activate
                    </div>
                  </div>

                  <div>
                    <h4 className="font-bold text-white text-sm mb-1.5 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">2</span>
                      Install Python Dependencies
                    </h4>
                    <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a] font-mono text-gray-300">
                      pip install --upgrade pip<br />
                      pip install -r requirements.txt
                    </div>
                  </div>

                  <div>
                    <h4 className="font-bold text-white text-sm mb-1.5 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">3</span>
                      Run Application with Raw Socket Privileges
                    </h4>
                    <p className="text-gray-400 mb-2 leading-relaxed">
                      Scapy packet capture requires Linux root privileges to attach to raw network sockets:
                    </p>
                    <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a] font-mono text-emerald-400">
                      sudo ./venv/bin/python app.py
                    </div>
                  </div>

                  <div>
                    <h4 className="font-bold text-white text-sm mb-1.5 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">4</span>
                      Access Local Web Dashboard
                    </h4>
                    <p className="text-gray-400 mb-2">
                      Open Firefox inside Kali Linux and browse to:
                    </p>
                    <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a] font-mono text-blue-400">
                      http://127.0.0.1:5000
                    </div>
                  </div>

                  <div>
                    <h4 className="font-bold text-white text-sm mb-1.5 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-amber-600 text-white flex items-center justify-center text-xs">5</span>
                      Safe Lab Detection Testing (Separate Terminal)
                    </h4>
                    <div className="space-y-2">
                      <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a]">
                        <span className="text-amber-400 font-bold block mb-1">Test 1: Ping Flood (triggers High ICMP Activity)</span>
                        <code className="font-mono text-gray-300 text-xs">ping -c 15 -i 0.2 127.0.0.1</code>
                      </div>

                      <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a]">
                        <span className="text-amber-400 font-bold block mb-1">Test 2: Local Port Scan (triggers Possible Port Scan)</span>
                        <code className="font-mono text-gray-300 text-xs">nmap -p 20-40 127.0.0.1</code>
                      </div>

                      <div className="bg-[#0b0f14] p-3 rounded border border-[#222d3a]">
                        <span className="text-amber-400 font-bold block mb-1">Test 3: Normal Web Traffic</span>
                        <code className="font-mono text-gray-300 text-xs">curl https://example.com</code>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: EDUCATIONAL CONCEPTS */}
          {activeTab === "theory" && (
            <div className="space-y-4 max-w-4xl mx-auto text-xs">
              <div className="bg-[#121820] border border-[#222d3a] rounded-lg p-6 space-y-4">
                <div className="flex items-center gap-3 pb-3 border-b border-[#222d3a]">
                  <BookOpen className="w-6 h-6 text-purple-400" />
                  <div>
                    <h3 className="text-base font-bold text-white">Educational Cybersecurity Study Guide</h3>
                    <p className="text-xs text-gray-400">Core networking &amp; defensive monitoring concepts for BSIT students</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-[#1a222c] rounded-lg border border-[#222d3a]">
                    <h4 className="font-bold text-white text-sm mb-1 text-sky-400">What is a Network Packet?</h4>
                    <p className="text-gray-300 leading-relaxed">
                      A discrete unit of binary data formatted with protocol headers (source/dest IP, port, sequence numbers) and a payload, routed across network interfaces according to OSI model layers.
                    </p>
                  </div>

                  <div className="p-4 bg-[#1a222c] rounded-lg border border-[#222d3a]">
                    <h4 className="font-bold text-white text-sm mb-1 text-sky-400">What is an IP Address?</h4>
                    <p className="text-gray-300 leading-relaxed">
                      A logical 32-bit (IPv4) or 128-bit (IPv6) numerical label assigned to each network interface connected to an IP network, enabling routing and addressing between hosts.
                    </p>
                  </div>

                  <div className="p-4 bg-[#1a222c] rounded-lg border border-[#222d3a]">
                    <h4 className="font-bold text-white text-sm mb-1 text-sky-400">TCP vs. UDP vs. ICMP</h4>
                    <p className="text-gray-300 leading-relaxed">
                      <strong>TCP:</strong> Connection-oriented, reliable 3-way handshake (SYN, SYN-ACK, ACK).<br />
                      <strong>UDP:</strong> Connectionless, low-overhead datagrams without retransmission.<br />
                      <strong>ICMP:</strong> Operational diagnostics and error messaging (e.g., Echo Request / Echo Reply).
                    </p>
                  </div>

                  <div className="p-4 bg-[#1a222c] rounded-lg border border-[#222d3a]">
                    <h4 className="font-bold text-white text-sm mb-1 text-sky-400">What is an IDS?</h4>
                    <p className="text-gray-300 leading-relaxed">
                      An Intrusion Detection System (IDS) inspects network traffic patterns against signatures or heuristic rules to detect anomalies, unauthorized scans, and policy violations without interrupting normal flows.
                    </p>
                  </div>

                  <div className="p-4 bg-[#1a222c] rounded-lg border border-[#222d3a]">
                    <h4 className="font-bold text-white text-sm mb-1 text-sky-400">How Scapy Sniffing Works</h4>
                    <p className="text-gray-300 leading-relaxed">
                      Scapy binds directly to Linux raw AF_PACKET sockets in promiscuous mode, bypassing the standard kernel TCP/IP stack to inspect full frame bytes as they arrive at the network card.
                    </p>
                  </div>

                  <div className="p-4 bg-[#1a222c] rounded-lg border border-[#222d3a]">
                    <h4 className="font-bold text-white text-sm mb-1 text-sky-400">Why Heuristic Cooldowns Matter</h4>
                    <p className="text-gray-300 leading-relaxed">
                      Without an alert cooldown cache, an ongoing port scan or packet flood would generate thousands of identical database rows in seconds, overwhelming storage and human analysts (alert fatigue).
                    </p>
                  </div>
                </div>

                {/* Future Roadmap */}
                <div className="pt-4 border-t border-[#222d3a]">
                  <h4 className="font-bold text-white text-sm mb-3">Future Version Roadmap</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="p-3 bg-[#0b0f14] rounded border border-[#222d3a]">
                      <span className="text-blue-400 font-bold block mb-1">Version 2</span>
                      <p className="text-gray-400 text-[11px]">PostgreSQL migration, RBAC authentication, enhanced host profiling.</p>
                    </div>
                    <div className="p-3 bg-[#0b0f14] rounded border border-[#222d3a]">
                      <span className="text-blue-400 font-bold block mb-1">Version 3</span>
                      <p className="text-gray-400 text-[11px]">Nmap integration for authorized vulnerability audits, Snort rule parsing.</p>
                    </div>
                    <div className="p-3 bg-[#0b0f14] rounded border border-[#222d3a]">
                      <span className="text-blue-400 font-bold block mb-1">Version 4</span>
                      <p className="text-gray-400 text-[11px]">Machine learning anomaly detection (Isolation Forests / Autoencoders).</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
