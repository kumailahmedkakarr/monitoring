"""
monitor.py - Network Packet Capture & Monitoring Engine
Captures live network packets using Scapy in a dedicated background thread,
extracts protocol headers, updates database records, checks defensive rules,
and manages monitor lifecycle (Start/Stop).
"""

import time
import threading
import logging
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional

import psutil
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import config
import database
from detector import DetectionEngine

logger = logging.getLogger("network_monitor")


class NetworkMonitor:
    """
    Manages packet sniffing, interface discovery, and packet pipeline dispatch.
    """

    def __init__(self):
        self.is_running = False
        self.selected_interface: Optional[str] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.detector = DetectionEngine()

        # Thread lock for monitor state & memory buffer
        self.lock = threading.Lock()

        # In-memory recent packet buffer for ultra-fast UI rendering
        self.recent_packets = deque(maxlen=config.MAX_MEMORY_PACKETS)

        # In-memory real-time counters
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "active_hosts": set(),
            "total_alerts": 0
        }

        # Auto-select initial interface
        available = self.get_available_interfaces()
        if available:
            # Prefer physical/virtual non-loopback interface if available
            non_lo = [i for i in available if i != "lo" and not i.startswith("127.")]
            self.selected_interface = non_lo[0] if non_lo else available[0]
        else:
            self.selected_interface = "lo"

    @staticmethod
    def get_available_interfaces() -> List[str]:
        """
        Discovers active network interfaces on the host system using psutil and Scapy.
        Returns a sorted list of interface names (e.g., ['eth0', 'ens33', 'wlan0', 'lo']).
        """
        interfaces = set()

        # Method 1: psutil interface discovery
        try:
            net_if_addrs = psutil.net_if_addrs()
            for iface_name in net_if_addrs.keys():
                interfaces.add(iface_name)
        except Exception as e:
            logger.warning("Could not list interfaces via psutil: %s", e)

        # Method 2: Scapy interface discovery
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import get_if_list
                for iface_name in get_if_list():
                    interfaces.add(iface_name)
            except Exception as e:
                logger.warning("Could not list interfaces via Scapy: %s", e)

        if not interfaces:
            interfaces.add("lo")

        # Sort with physical/ethernet interfaces first, loopback last
        sorted_ifaces = sorted(
            list(interfaces),
            key=lambda x: (1 if x == "lo" else 0, x)
        )
        return sorted_ifaces

    def set_interface(self, iface_name: str) -> bool:
        """
        Sets the active interface for packet sniffing.
        Cannot change interface while monitoring is active.
        """
        with self.lock:
            if self.is_running:
                logger.warning("Cannot change interface while monitor is running.")
                return False

            available = self.get_available_interfaces()
            if iface_name not in available:
                logger.error("Interface '%s' not found on system.", iface_name)
                return False

            self.selected_interface = iface_name
            logger.info("Selected network interface: %s", iface_name)
            return True

    def start_monitoring(self, iface_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Starts the packet capture engine on the selected interface in a background daemon thread.
        """
        with self.lock:
            if self.is_running:
                return {
                    "success": False,
                    "message": "Monitoring is already running.",
                    "interface": self.selected_interface
                }

            if iface_name:
                self.selected_interface = iface_name

            if not self.selected_interface:
                return {
                    "success": False,
                    "message": "No valid network interface selected.",
                    "interface": None
                }

            self.stop_event.clear()
            self.is_running = True

            self.capture_thread = threading.Thread(
                target=self._capture_worker,
                name="PacketCaptureWorker",
                daemon=True
            )
            self.capture_thread.start()

            logger.info("Packet monitor started on interface '%s'", self.selected_interface)
            return {
                "success": True,
                "message": f"Monitoring started on {self.selected_interface}",
                "interface": self.selected_interface
            }

    def stop_monitoring(self) -> Dict[str, Any]:
        """
        Signals the background capture thread to stop safely.
        """
        with self.lock:
            if not self.is_running:
                return {
                    "success": False,
                    "message": "Monitoring is already stopped.",
                    "interface": self.selected_interface
                }

            self.is_running = False
            self.stop_event.set()

        logger.info("Packet monitor stop signaled.")
        return {
            "success": True,
            "message": "Monitoring stopped successfully.",
            "interface": self.selected_interface
        }

    def _capture_worker(self) -> None:
        """
        Worker function executing inside the dedicated capture thread.
        Uses Scapy's sniff with a stop_filter lambda check.
        """
        logger.info("Worker thread starting packet capture on %s", self.selected_interface)

        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not installed. Packet capture cannot run.")
            self.is_running = False
            return

        try:
            # We use a short timeout in a loop so the thread checks stop_event regularly
            while not self.stop_event.is_set():
                sniff(
                    iface=self.selected_interface,
                    prn=self._process_scapy_packet,
                    store=False,
                    timeout=1.0,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
        except PermissionError:
            logger.error("Permission denied during packet capture. Run with sudo/root privileges.")
        except Exception as e:
            logger.error("Unhandled error in capture worker: %s", e)
        finally:
            with self.lock:
                self.is_running = False
            logger.info("Worker thread exited.")

    def _process_scapy_packet(self, packet: Any) -> None:
        """
        Parses a single captured Scapy packet, updates DB, passes to detector.
        Safe against malformed packets.
        """
        try:
            # Check IPv4 layer
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            pkt_len = len(packet)
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            proto_str = "OTHER"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None

            if packet.haslayer(TCP):
                proto_str = "TCP"
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
            elif packet.haslayer(UDP):
                proto_str = "UDP"
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
            elif packet.haslayer(ICMP):
                proto_str = "ICMP"
                src_port = None
                dst_port = None
            else:
                proto_str = f"IP-{ip_layer.proto}"

            packet_data = {
                "timestamp": now_str,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": proto_str,
                "source_port": src_port,
                "destination_port": dst_port,
                "packet_length": pkt_len
            }

            # 1. Update in-memory state
            with self.lock:
                self.recent_packets.appendleft(packet_data)
                self.stats["total_packets"] += 1
                if proto_str == "TCP":
                    self.stats["tcp_packets"] += 1
                elif proto_str == "UDP":
                    self.stats["udp_packets"] += 1
                elif proto_str == "ICMP":
                    self.stats["icmp_packets"] += 1
                else:
                    self.stats["other_packets"] += 1

                self.stats["active_hosts"].add(src_ip)
                self.stats["active_hosts"].add(dst_ip)

            # 2. Persist to SQLite Database
            database.insert_packet(
                timestamp=now_str,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto_str,
                source_port=src_port,
                destination_port=dst_port,
                packet_length=pkt_len
            )
            database.upsert_host(src_ip, now_str)
            database.upsert_host(dst_ip, now_str)

            # 3. Defensive Intrusion Detection Engine check
            detected_alerts = self.detector.process_packet(packet_data)
            if detected_alerts:
                with self.lock:
                    self.stats["total_alerts"] += len(detected_alerts)

                for alert in detected_alerts:
                    database.insert_alert(
                        timestamp=alert["timestamp"],
                        alert_type=alert["alert_type"],
                        severity=alert["severity"],
                        source_ip=alert["source_ip"],
                        destination_ip=alert["destination_ip"],
                        description=alert["description"],
                        status=alert.get("status", "New")
                    )

        except Exception as e:
            # Defensive logging: do not crash on strange or malformed packets
            logger.debug("Error parsing packet: %s", e)

    def get_live_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Returns recent in-memory packets for low-latency dashboard polling.
        Falls back to database if memory buffer has fewer records.
        """
        with self.lock:
            mem_pkts = list(self.recent_packets)[:limit]

        if len(mem_pkts) >= limit:
            return mem_pkts

        # Fallback to database
        db_pkts = database.get_recent_packets(limit=limit)
        return db_pkts

    def get_status(self) -> Dict[str, Any]:
        """
        Returns the operational status of the network monitor.
        """
        with self.lock:
            return {
                "status": "RUNNING" if self.is_running else "STOPPED",
                "interface": self.selected_interface,
                "total_captured": self.stats["total_packets"],
                "active_hosts_count": len(self.stats["active_hosts"])
            }


# Singleton monitor instance for application-wide access
monitor_instance = NetworkMonitor()
