"""
database.py - SQLite Database Management Module
Handles table creation, packet storage, host tracking, alert logging,
and data queries with safe parameterized statements.
"""

import sqlite3
import logging
from typing import List, Dict, Any, Optional
import config

logger = logging.getLogger("network_monitor")


def get_connection() -> sqlite3.Connection:
    """
    Creates and returns a connection to the SQLite database.
    Enables dictionary-like row access.
    """
    conn = sqlite3.connect(config.DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initializes the SQLite database tables if they do not exist:
    1. packets - Stores recorded network packets
    2. hosts   - Tracks seen IP addresses and packet counts
    3. alerts  - Stores defensive intrusion alerts
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # 1. Packets Table
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

            # 2. Hosts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 1
                )
            """)

            # 3. Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'New'
                )
            """)

            # Helpful indexes for query speed
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(destination_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC)")

            conn.commit()
            logger.info("Database initialized successfully at %s", config.DB_PATH)
    except Exception as e:
        logger.error("Failed to initialize database: %s", e)
        raise


def insert_packet(
    timestamp: str,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    source_port: Optional[int],
    destination_port: Optional[int],
    packet_length: int
) -> Optional[int]:
    """
    Inserts a single network packet into the database using parameterized queries.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO packets (
                    timestamp, source_ip, destination_ip, protocol,
                    source_port, destination_port, packet_length
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, source_ip, destination_ip, protocol, source_port, destination_port, packet_length)
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        logger.error("Error inserting packet into database: %s", e)
        return None


def upsert_host(ip_address: str, timestamp: str) -> None:
    """
    Registers a host if new, or updates last_seen timestamp and increments packet count.
    """
    if not ip_address or ip_address == "-":
        return

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO hosts (ip_address, first_seen, last_seen, packet_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    packet_count = hosts.packet_count + 1
                """,
                (ip_address, timestamp, timestamp)
            )
            conn.commit()
    except Exception as e:
        logger.error("Error upserting host %s: %s", ip_address, e)


def insert_alert(
    timestamp: str,
    alert_type: str,
    severity: str,
    source_ip: str,
    destination_ip: str,
    description: str,
    status: str = "New"
) -> Optional[int]:
    """
    Inserts a security alert into the database using parameterized queries.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (
                    timestamp, alert_type, severity, source_ip,
                    destination_ip, description, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, alert_type, severity, source_ip, destination_ip, description, status)
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        logger.error("Error inserting alert into database: %s", e)
        return None


def get_recent_packets(
    limit: int = 100,
    ip_filter: Optional[str] = None,
    protocol_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent packets with optional IP and protocol filtering.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM packets WHERE 1=1"
            params: List[Any] = []

            if ip_filter:
                query += " AND (source_ip LIKE ? OR destination_ip LIKE ?)"
                params.extend([f"%{ip_filter}%", f"%{ip_filter}%"])

            if protocol_filter and protocol_filter.upper() != "ALL":
                query += " AND protocol = ?"
                params.append(protocol_filter.upper())

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Error querying packets: %s", e)
        return []


def get_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    ip_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves generated security alerts with optional filters.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts WHERE 1=1"
            params: List[Any] = []

            if severity and severity.upper() != "ALL":
                query += " AND severity = ?"
                params.append(severity.upper())

            if alert_type and alert_type != "ALL":
                query += " AND alert_type = ?"
                params.append(alert_type)

            if ip_filter:
                query += " AND (source_ip LIKE ? OR destination_ip LIKE ?)"
                params.extend([f"%{ip_filter}%", f"%{ip_filter}%"])

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Error querying alerts: %s", e)
        return []


def get_hosts(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Retrieves active tracked hosts sorted by latest activity.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM hosts ORDER BY last_seen DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Error querying hosts: %s", e)
        return []


def get_stats_summary() -> Dict[str, Any]:
    """
    Calculates summary metrics: total packets, protocol breakdown, host count, total alerts.
    """
    stats = {
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "other_packets": 0,
        "total_hosts": 0,
        "total_alerts": 0,
        "high_alerts": 0,
        "medium_alerts": 0,
        "low_alerts": 0
    }

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Protocol counts
            cursor.execute("""
                SELECT protocol, COUNT(*) as cnt
                FROM packets
                GROUP BY protocol
            """)
            for row in cursor.fetchall():
                proto = (row["protocol"] or "").upper()
                count = row["cnt"]
                stats["total_packets"] += count
                if proto == "TCP":
                    stats["tcp_packets"] = count
                elif proto == "UDP":
                    stats["udp_packets"] = count
                elif proto == "ICMP":
                    stats["icmp_packets"] = count
                else:
                    stats["other_packets"] += count

            # Host count
            cursor.execute("SELECT COUNT(*) as total FROM hosts")
            row = cursor.fetchone()
            if row:
                stats["total_hosts"] = row["total"]

            # Alert counts
            cursor.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM alerts
                GROUP BY severity
            """)
            for row in cursor.fetchall():
                sev = (row["severity"] or "").upper()
                count = row["cnt"]
                stats["total_alerts"] += count
                if sev == "HIGH":
                    stats["high_alerts"] = count
                elif sev == "MEDIUM":
                    stats["medium_alerts"] = count
                elif sev == "LOW":
                    stats["low_alerts"] = count

    except Exception as e:
        logger.error("Error calculating summary stats: %s", e)

    return stats
