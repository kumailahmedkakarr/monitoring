"""
app.py - Main Flask Application & Web API
Serves web dashboard templates and provides JSON REST endpoints
for real-time packet telemetry, alert auditing, host tracking, and monitor control.
"""

import os
import sys
import logging
from flask import Flask, render_template, jsonify, request

import config
import database
from monitor import monitor_instance

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("network_monitor")
logger.info("Initializing Network Attack & Monitoring Framework...")

# -----------------------------------------------------------------------------
# Flask Application Setup
# -----------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)
app.config["SECRET_KEY"] = "cybersecurity-lab-monitor-secret-v1"

# Initialize SQLite database schema
database.init_db()


@app.after_request
def add_cors_headers(response):
    """Enable CORS so the Vercel or local React dashboard can communicate with the engine."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response



# -----------------------------------------------------------------------------
# Frontend Template Routes
# -----------------------------------------------------------------------------
@app.route("/")
def dashboard_page():
    """Renders the main command dashboard."""
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/packets")
def packets_page():
    """Renders the dedicated live packet analyzer view."""
    return render_template("packets.html", active_page="packets")


@app.route("/alerts")
def alerts_page():
    """Renders the defensive security alerts auditing view."""
    return render_template("alerts.html", active_page="alerts")


@app.route("/hosts")
def hosts_page():
    """Renders the network host discovery and tracking view."""
    return render_template("hosts.html", active_page="hosts")


@app.route("/settings")
def settings_page():
    """Renders the configuration and interface settings view."""
    return render_template("settings.html", active_page="settings")


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------
@app.route("/api/status", methods=["GET"])
def api_status():
    """
    Returns the current operational status of the packet monitor:
    - Running/Stopped state
    - Active network interface
    - Memory packet count
    """
    status = monitor_instance.get_status()
    return jsonify({
        "status": status["status"],
        "interface": status["interface"],
        "total_captured": status["total_captured"],
        "active_hosts_count": status["active_hosts_count"]
    }), 200


@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """
    Returns the list of available network interfaces detected on the host system.
    """
    interfaces = monitor_instance.get_available_interfaces()
    return jsonify({
        "current": monitor_instance.selected_interface,
        "interfaces": interfaces
    }), 200


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """
    Returns aggregated metrics:
    - Total packets captured
    - Protocol counts (TCP, UDP, ICMP, OTHER)
    - Active host counts
    - Alerts breakdown by severity (HIGH, MEDIUM, LOW)
    """
    # Fetch persistent stats from SQLite
    db_stats = database.get_stats_summary()

    # Blend with in-memory active counters for immediate responsiveness
    with monitor_instance.lock:
        mem_stats = monitor_instance.stats.copy()

    total_pkts = max(db_stats["total_packets"], mem_stats["total_packets"])
    tcp_pkts = max(db_stats["tcp_packets"], mem_stats["tcp_packets"])
    udp_pkts = max(db_stats["udp_packets"], mem_stats["udp_packets"])
    icmp_pkts = max(db_stats["icmp_packets"], mem_stats["icmp_packets"])
    other_pkts = max(db_stats["other_packets"], mem_stats["other_packets"])
    total_hosts = max(db_stats["total_hosts"], len(mem_stats["active_hosts"]))
    total_alerts = max(db_stats["total_alerts"], mem_stats["total_alerts"])

    return jsonify({
        "total_packets": total_pkts,
        "tcp_packets": tcp_pkts,
        "udp_packets": udp_pkts,
        "icmp_packets": icmp_pkts,
        "other_packets": other_pkts,
        "total_hosts": total_hosts,
        "total_alerts": total_alerts,
        "high_alerts": db_stats["high_alerts"],
        "medium_alerts": db_stats["medium_alerts"],
        "low_alerts": db_stats["low_alerts"]
    }), 200


@app.route("/api/packets", methods=["GET"])
def api_packets():
    """
    Returns recent captured packets with optional filtering:
    - limit: maximum rows to return (default 100, max 500)
    - ip: filter by source or destination IP
    - protocol: filter by protocol (TCP, UDP, ICMP, OTHER)
    """
    limit = min(request.args.get("limit", default=100, type=int), 500)
    ip_filter = request.args.get("ip", default=None, type=str)
    protocol_filter = request.args.get("protocol", default=None, type=str)

    # If no filters applied and monitor has recent memory packets, return them quickly
    if not ip_filter and not protocol_filter:
        packets = monitor_instance.get_live_packets(limit=limit)
    else:
        packets = database.get_recent_packets(
            limit=limit,
            ip_filter=ip_filter,
            protocol_filter=protocol_filter
        )

    return jsonify({
        "count": len(packets),
        "packets": packets
    }), 200


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    Returns defensive intrusion alerts with optional filtering:
    - limit: maximum rows (default 50)
    - severity: HIGH, MEDIUM, LOW
    - type: alert category (e.g., 'Possible Port Scan')
    - ip: source or destination IP
    """
    limit = min(request.args.get("limit", default=50, type=int), 500)
    severity = request.args.get("severity", default=None, type=str)
    alert_type = request.args.get("type", default=None, type=str)
    ip_filter = request.args.get("ip", default=None, type=str)

    alerts = database.get_alerts(
        limit=limit,
        severity=severity,
        alert_type=alert_type,
        ip_filter=ip_filter
    )

    return jsonify({
        "count": len(alerts),
        "alerts": alerts
    }), 200


@app.route("/api/hosts", methods=["GET"])
def api_hosts():
    """
    Returns active hosts recorded in the network, sorted by last seen timestamp.
    """
    limit = min(request.args.get("limit", default=100, type=int), 500)
    hosts = database.get_hosts(limit=limit)

    return jsonify({
        "count": len(hosts),
        "hosts": hosts
    }), 200


@app.route("/api/start", methods=["POST"])
def api_start():
    """
    Starts packet capture on the designated interface.
    Optional JSON payload: { "interface": "eth0" }
    """
    data = request.get_json(silent=True) or {}
    requested_iface = data.get("interface")

    if requested_iface:
        success = monitor_instance.set_interface(requested_iface)
        if not success and monitor_instance.is_running:
            return jsonify({
                "success": False,
                "message": "Cannot change interface while monitor is actively running. Stop monitoring first."
            }), 400

    result = monitor_instance.start_monitoring(requested_iface)
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """
    Stops packet capture safely.
    """
    result = monitor_instance.stop_monitoring()
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/settings", methods=["GET"])
def api_settings():
    """
    Returns the current detection configuration and runtime environment parameters.
    """
    return jsonify({
        "current_interface": monitor_instance.selected_interface,
        "available_interfaces": monitor_instance.get_available_interfaces(),
        "is_running": monitor_instance.is_running,
        "database_path": config.DB_PATH,
        "log_path": config.LOG_FILE,
        "thresholds": {
            "port_scan_threshold": config.PORT_SCAN_THRESHOLD,
            "port_scan_window_sec": config.PORT_SCAN_WINDOW,
            "high_packet_rate_threshold": config.HIGH_PACKET_RATE_THRESHOLD,
            "high_packet_rate_window_sec": config.HIGH_PACKET_RATE_WINDOW,
            "repeated_conn_threshold": config.REPEATED_CONN_THRESHOLD,
            "repeated_conn_window_sec": config.REPEATED_CONN_WINDOW,
            "icmp_threshold": config.ICMP_THRESHOLD,
            "icmp_window_sec": config.ICMP_WINDOW,
            "alert_cooldown_sec": config.ALERT_COOLDOWN
        }
    }), 200


# -----------------------------------------------------------------------------
# Application Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting Flask Web Server on http://%s:%s", config.FLASK_HOST, config.FLASK_PORT)
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.DEBUG_MODE,
        threaded=True
    )
