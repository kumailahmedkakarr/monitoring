"""
detector.py - Defensive Intrusion Detection Engine
Analyzes packet streams in real-time using rule-based behavioral checks:
1. Port Scan Detection (multiple distinct ports on same target)
2. High Packet Rate Detection (flood of packets from single source)
3. Repeated Connection Attempts (repeated TCP connections to same service)
4. High ICMP Activity Detection (potential ping flood / reconnaissance)

Includes an alert cooldown system to prevent flooding database with duplicates.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
import config

logger = logging.getLogger("network_monitor")


class DetectionEngine:
    """
    Lightweight rule-based detection engine for defensive network monitoring.
    Maintains sliding time windows of recent packet metadata per host.
    """

    def __init__(self):
        self.lock = threading.Lock()

        # Cooldown tracker: (alert_type, src_ip, dst_ip) -> last_alert_timestamp
        self.cooldown_tracker: Dict[tuple, float] = {}

        # 1. Port scan tracker: (src_ip, dst_ip) -> deque of (timestamp, dst_port)
        self.port_scan_history: Dict[tuple, deque] = defaultdict(deque)

        # 2. Packet rate tracker: src_ip -> deque of timestamps
        self.packet_rate_history: Dict[str, deque] = defaultdict(deque)

        # 3. Repeated connection tracker: (src_ip, dst_ip, dst_port) -> deque of timestamps
        self.repeated_conn_history: Dict[tuple, deque] = defaultdict(deque)

        # 4. ICMP activity tracker: src_ip -> deque of timestamps
        self.icmp_history: Dict[str, deque] = defaultdict(deque)

    def is_in_cooldown(self, alert_type: str, src_ip: str, dst_ip: str, now: float) -> bool:
        """
        Checks whether an alert of the same type for this source/destination is currently in cooldown.
        Returns True if suppressed, False if allowed to fire.
        """
        key = (alert_type, src_ip, dst_ip)
        last_time = self.cooldown_tracker.get(key)
        if last_time is not None:
            if (now - last_time) < config.ALERT_COOLDOWN:
                return True
        self.cooldown_tracker[key] = now
        return False

    def process_packet(self, pkt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes a single packet against all defensive rules.
        Returns a list of generated alert dictionaries (if any threshold is breached).
        """
        alerts: List[Dict[str, Any]] = []
        src_ip = pkt.get("source_ip")
        dst_ip = pkt.get("destination_ip")
        proto = (pkt.get("protocol") or "").upper()
        dst_port = pkt.get("destination_port")

        # Ignore invalid or loopback empty addresses if present
        if not src_ip or not dst_ip or src_ip == "-" or dst_ip == "-":
            return alerts

        now = time.time()
        time_str = pkt.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")

        with self.lock:
            # -----------------------------------------------------------------
            # Rule 1: Possible Port Scan Detection
            # -----------------------------------------------------------------
            if dst_port is not None and dst_port > 0:
                scan_key = (src_ip, dst_ip)
                scan_q = self.port_scan_history[scan_key]
                scan_q.append((now, dst_port))

                # Purge entries older than the time window
                while scan_q and (now - scan_q[0][0]) > config.PORT_SCAN_WINDOW:
                    scan_q.popleft()

                # Count unique destination ports contacted
                unique_ports = {port for _, port in scan_q}
                if len(unique_ports) >= config.PORT_SCAN_THRESHOLD:
                    if not self.is_in_cooldown("Possible Port Scan", src_ip, dst_ip, now):
                        alert = {
                            "timestamp": time_str,
                            "alert_type": "Possible Port Scan",
                            "severity": "Medium",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "description": (
                                f"Host {src_ip} scanned {len(unique_ports)} distinct ports "
                                f"on target {dst_ip} within {config.PORT_SCAN_WINDOW}s window."
                            ),
                            "status": "New"
                        }
                        alerts.append(alert)
                        logger.warning("ALERT: %s from %s -> %s", alert["alert_type"], src_ip, dst_ip)

            # -----------------------------------------------------------------
            # Rule 2: High Packet Rate Detection
            # -----------------------------------------------------------------
            rate_q = self.packet_rate_history[src_ip]
            rate_q.append(now)

            while rate_q and (now - rate_q[0]) > config.HIGH_PACKET_RATE_WINDOW:
                rate_q.popleft()

            if len(rate_q) >= config.HIGH_PACKET_RATE_THRESHOLD:
                if not self.is_in_cooldown("High Packet Rate", src_ip, dst_ip, now):
                    alert = {
                        "timestamp": time_str,
                        "alert_type": "High Packet Rate",
                        "severity": "Medium",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "description": (
                            f"Host {src_ip} generated {len(rate_q)} packets "
                            f"within {config.HIGH_PACKET_RATE_WINDOW}s window."
                        ),
                        "status": "New"
                    }
                    alerts.append(alert)
                    logger.warning("ALERT: %s from %s", alert["alert_type"], src_ip)

            # -----------------------------------------------------------------
            # Rule 3: Repeated Connection Attempts (TCP)
            # -----------------------------------------------------------------
            if proto == "TCP" and dst_port is not None:
                rep_key = (src_ip, dst_ip, dst_port)
                rep_q = self.repeated_conn_history[rep_key]
                rep_q.append(now)

                while rep_q and (now - rep_q[0]) > config.REPEATED_CONN_WINDOW:
                    rep_q.popleft()

                if len(rep_q) >= config.REPEATED_CONN_THRESHOLD:
                    if not self.is_in_cooldown("Repeated Connection Attempts", src_ip, dst_ip, now):
                        alert = {
                            "timestamp": time_str,
                            "alert_type": "Repeated Connection Attempts",
                            "severity": "Low",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "description": (
                                f"Repeated TCP connection burst: {src_ip} initiated {len(rep_q)} "
                                f"attempts to {dst_ip}:{dst_port} within {config.REPEATED_CONN_WINDOW}s."
                            ),
                            "status": "New"
                        }
                        alerts.append(alert)
                        logger.warning("ALERT: %s from %s -> %s:%s", alert["alert_type"], src_ip, dst_ip, dst_port)

            # -----------------------------------------------------------------
            # Rule 4: Suspicious ICMP Activity (Ping Flood / Recon)
            # -----------------------------------------------------------------
            if proto == "ICMP":
                icmp_q = self.icmp_history[src_ip]
                icmp_q.append(now)

                while icmp_q and (now - icmp_q[0]) > config.ICMP_WINDOW:
                    icmp_q.popleft()

                if len(icmp_q) >= config.ICMP_THRESHOLD:
                    if not self.is_in_cooldown("High ICMP Activity", src_ip, dst_ip, now):
                        alert = {
                            "timestamp": time_str,
                            "alert_type": "High ICMP Activity",
                            "severity": "Low",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "description": (
                                f"Host {src_ip} sent {len(icmp_q)} ICMP packets "
                                f"within {config.ICMP_WINDOW}s window."
                            ),
                            "status": "New"
                        }
                        alerts.append(alert)
                        logger.warning("ALERT: %s from %s", alert["alert_type"], src_ip)

            # -----------------------------------------------------------------
            # Periodic cleanup of expired cooldown keys
            # -----------------------------------------------------------------
            if len(self.cooldown_tracker) > 500:
                expired = [k for k, v in self.cooldown_tracker.items() if (now - v) > (config.ALERT_COOLDOWN * 2)]
                for k in expired:
                    del self.cooldown_tracker[k]

        return alerts
