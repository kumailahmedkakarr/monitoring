/**
 * dashboard.js - Frontend Asynchronous Polling & Interface Control
 * Periodically queries REST endpoints:
 *   - /api/status
 *   - /api/stats
 *   - /api/packets
 *   - /api/alerts
 *   - /api/hosts
 * Manages monitor start/stop state, real-time UI updates, and filter controls.
 */

let pollingInterval = null;
let protocolChartInstance = null;

// Determine current active page view
const currentPath = window.location.pathname;
const isDashboard = currentPath === "/" || currentPath.endsWith("/dashboard");
const isPacketsPage = currentPath.includes("/packets");
const isAlertsPage = currentPath.includes("/alerts");
const isHostsPage = currentPath.includes("/hosts");
const isSettingsPage = currentPath.includes("/settings");

document.addEventListener("DOMContentLoaded", () => {
    // 1. Initial configuration and interface discovery
    fetchInterfaces();
    fetchStatus();
    fetchStats();

    // 2. Page-specific initial loads
    if (isDashboard) {
        fetchPackets();
        fetchRecentAlerts();
    } else if (isPacketsPage) {
        loadPacketsPageData();
    } else if (isAlertsPage) {
        loadAlertsPageData();
    } else if (isHostsPage) {
        loadHostsPageData();
    } else if (isSettingsPage) {
        loadSettingsPageData();
    }

    // 3. Start background polling (every 2.5 seconds)
    startPolling();

    // 4. Pause polling if user minimizes or switches browser tabs
    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopPolling();
        } else {
            startPolling();
            fetchStatus();
            fetchStats();
        }
    });
});

/* -----------------------------------------------------------------------------
   Polling Loop
   ----------------------------------------------------------------------------- */
function startPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(() => {
        fetchStatus();
        fetchStats();

        if (isDashboard) {
            fetchPackets();
            fetchRecentAlerts();
        } else if (isPacketsPage) {
            const autoRefresh = document.getElementById("packets-auto-refresh");
            if (autoRefresh && autoRefresh.checked) {
                loadPacketsPageData();
            }
        }
    }, 2500);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

/* -----------------------------------------------------------------------------
   Toast Notification Helper
   ----------------------------------------------------------------------------- */
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

/* -----------------------------------------------------------------------------
   API Calls: Status & Interfaces
   ----------------------------------------------------------------------------- */
async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        if (!res.ok) throw new Error("Status endpoint error");
        const data = await res.json();

        const isRunning = data.status === "RUNNING";
        updateStatusUI(isRunning, data.interface);
    } catch (err) {
        console.warn("Could not fetch status:", err);
    }
}

function updateStatusUI(isRunning, currentIface) {
    const dot = document.getElementById("sidebar-status-dot");
    const label = document.getElementById("sidebar-status-text");
    const ifaceText = document.getElementById("sidebar-iface-text");
    const btnStart = document.getElementById("btn-start-monitor");
    const btnStop = document.getElementById("btn-stop-monitor");
    const ifaceSelect = document.getElementById("iface-select");

    if (dot) {
        dot.className = `status-dot ${isRunning ? "running" : "stopped"}`;
    }
    if (label) {
        label.textContent = isRunning ? "RUNNING" : "STOPPED";
        label.style.color = isRunning ? "#2ea043" : "#f85149";
    }
    if (ifaceText && currentIface) {
        ifaceText.textContent = currentIface;
    }

    if (btnStart) btnStart.disabled = isRunning;
    if (btnStop) btnStop.disabled = !isRunning;
    if (ifaceSelect) ifaceSelect.disabled = isRunning;

    // Settings page mirrors
    const settingsState = document.getElementById("settings-monitor-state");
    const settingsIface = document.getElementById("settings-current-iface");
    if (settingsState) {
        settingsState.textContent = isRunning ? "RUNNING" : "STOPPED";
        settingsState.className = `badge ${isRunning ? "badge-primary" : "badge-low"}`;
    }
    if (settingsIface && currentIface) {
        settingsIface.textContent = currentIface;
    }
}

async function fetchInterfaces() {
    try {
        const res = await fetch("/api/interfaces");
        if (!res.ok) return;
        const data = await res.json();

        const select = document.getElementById("iface-select");
        if (!select) return;

        select.innerHTML = "";
        data.interfaces.forEach(iface => {
            const opt = document.createElement("option");
            opt.value = iface;
            opt.textContent = iface;
            if (iface === data.current) {
                opt.selected = true;
            }
            select.appendChild(opt);
        });
    } catch (err) {
        console.warn("Could not fetch interfaces:", err);
    }
}

/* -----------------------------------------------------------------------------
   Monitor Start / Stop Controls
   ----------------------------------------------------------------------------- */
async function startMonitoring() {
    const select = document.getElementById("iface-select");
    const selectedIface = select ? select.value : "";

    try {
        const res = await fetch("/api/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: selectedIface })
        });
        const data = await res.json();

        if (res.ok && data.success) {
            showToast(data.message, "success");
            fetchStatus();
        } else {
            showToast(data.message || "Failed to start monitoring", "danger");
        }
    } catch (err) {
        showToast("Error communicating with monitor server", "danger");
    }
}

async function stopMonitoring() {
    try {
        const res = await fetch("/api/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();

        if (res.ok && data.success) {
            showToast(data.message, "info");
            fetchStatus();
        } else {
            showToast(data.message || "Failed to stop monitoring", "danger");
        }
    } catch (err) {
        showToast("Error stopping monitor", "danger");
    }
}

/* -----------------------------------------------------------------------------
   API Calls: Statistics & Protocol Breakdown
   ----------------------------------------------------------------------------- */
async function fetchStats() {
    try {
        const res = await fetch("/api/stats");
        if (!res.ok) return;
        const data = await res.json();

        // Update Stat Cards
        updateCardValue("stat-total-packets", data.total_packets);
        updateCardValue("stat-total-hosts", data.total_hosts);
        updateCardValue("stat-total-alerts", data.total_alerts);
        updateCardValue("stat-tcp-packets", data.tcp_packets);
        updateCardValue("stat-udp-packets", data.udp_packets);
        updateCardValue("stat-icmp-packets", data.icmp_packets);

        // Sidebar alert count badge
        const alertBadge = document.getElementById("sidebar-alert-badge");
        if (alertBadge) {
            if (data.total_alerts > 0) {
                alertBadge.style.display = "inline-block";
                alertBadge.textContent = data.total_alerts;
            } else {
                alertBadge.style.display = "none";
            }
        }

        // Protocol breakdown percentages
        const total = data.total_packets || 0;
        const tcpPct = total ? ((data.tcp_packets / total) * 100).toFixed(1) : 0;
        const udpPct = total ? ((data.udp_packets / total) * 100).toFixed(1) : 0;
        const icmpPct = total ? ((data.icmp_packets / total) * 100).toFixed(1) : 0;
        const otherPct = total ? ((data.other_packets / total) * 100).toFixed(1) : 0;

        setProgressBar("tcp", tcpPct);
        setProgressBar("udp", udpPct);
        setProgressBar("icmp", icmpPct);
        setProgressBar("other", otherPct);

        // Update optional Doughnut chart
        updateDoughnutChart(data);
    } catch (err) {
        console.warn("Could not fetch stats:", err);
    }
}

function updateCardValue(elementId, value) {
    const el = document.getElementById(elementId);
    if (el) {
        el.textContent = Number(value || 0).toLocaleString();
    }
}

function setProgressBar(protocol, pct) {
    const textEl = document.getElementById(`pct-${protocol}`);
    const barEl = document.getElementById(`bar-${protocol}`);
    if (textEl) textEl.textContent = `${pct}%`;
    if (barEl) barEl.style.width = `${pct}%`;
}

function updateDoughnutChart(data) {
    const canvas = document.getElementById("protocolDoughnutChart");
    if (!canvas || typeof Chart === "undefined") return;

    const values = [
        data.tcp_packets || 0,
        data.udp_packets || 0,
        data.icmp_packets || 0,
        data.other_packets || 0
    ];

    if (!protocolChartInstance) {
        const ctx = canvas.getContext("2d");
        protocolChartInstance = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "ICMP", "Other"],
                datasets: [{
                    data: values,
                    backgroundColor: ["#388bfd", "#a371f7", "#d29922", "#7d8590"],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: true }
                },
                cutout: "68%"
            }
        });
    } else {
        protocolChartInstance.data.datasets[0].data = values;
        protocolChartInstance.update("none");
    }
}

/* -----------------------------------------------------------------------------
   Dashboard Packets & Alerts Stream
   ----------------------------------------------------------------------------- */
async function fetchPackets() {
    const tbody = document.getElementById("dashboard-packets-body");
    if (!tbody) return;

    try {
        const res = await fetch("/api/packets?limit=100");
        if (!res.ok) return;
        const data = await res.json();

        if (!data.packets || data.packets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="table-empty-msg">No packets recorded yet. Ensure monitoring is RUNNING.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.packets.map(p => `
            <tr>
                <td class="time-cell">${escapeHtml(p.timestamp)}</td>
                <td class="ip-cell">${escapeHtml(p.source_ip)}</td>
                <td class="ip-cell">${escapeHtml(p.destination_ip)}</td>
                <td><span class="proto-badge ${getProtoClass(p.protocol)}">${escapeHtml(p.protocol)}</span></td>
                <td class="port-cell">${p.source_port !== null ? p.source_port : "-"}</td>
                <td class="port-cell">${p.destination_port !== null ? p.destination_port : "-"}</td>
                <td>${p.packet_length} B</td>
            </tr>
        `).join("");
    } catch (err) {
        console.warn("Error fetching dashboard packets:", err);
    }
}

async function fetchRecentAlerts() {
    const tbody = document.getElementById("dashboard-alerts-body");
    if (!tbody) return;

    try {
        const res = await fetch("/api/alerts?limit=5");
        if (!res.ok) return;
        const data = await res.json();

        if (!data.alerts || data.alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="table-empty-msg">No alerts generated yet. Heuristics are nominal.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.alerts.map(a => `
            <tr>
                <td class="time-cell">${escapeHtml(a.timestamp)}</td>
                <td><strong>${escapeHtml(a.alert_type)}</strong></td>
                <td><span class="badge ${getSeverityBadgeClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td class="ip-cell">${escapeHtml(a.source_ip)}</td>
                <td class="ip-cell">${escapeHtml(a.destination_ip)}</td>
            </tr>
        `).join("");
    } catch (err) {
        console.warn("Error fetching dashboard alerts:", err);
    }
}

/* -----------------------------------------------------------------------------
   Dedicated Packets Page Logic
   ----------------------------------------------------------------------------- */
async function loadPacketsPageData() {
    const tbody = document.getElementById("packets-table-body");
    if (!tbody) return;

    const ip = document.getElementById("filter-ip")?.value.trim() || "";
    const protocol = document.getElementById("filter-protocol")?.value || "ALL";
    const limit = document.getElementById("filter-limit")?.value || "100";

    const params = new URLSearchParams();
    if (limit) params.set("limit", limit);
    if (ip) params.set("ip", ip);
    if (protocol && protocol !== "ALL") params.set("protocol", protocol);

    try {
        const res = await fetch(`/api/packets?${params.toString()}`);
        if (!res.ok) return;
        const data = await res.json();

        const countDisplay = document.getElementById("packets-count-display");
        if (countDisplay) {
            countDisplay.textContent = `Showing ${data.packets ? data.packets.length : 0} packets`;
        }

        if (!data.packets || data.packets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="table-empty-msg">No matching packets found.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.packets.map(p => `
            <tr>
                <td>${p.id || "-"}</td>
                <td class="time-cell">${escapeHtml(p.timestamp)}</td>
                <td class="ip-cell">${escapeHtml(p.source_ip)}</td>
                <td class="ip-cell">${escapeHtml(p.destination_ip)}</td>
                <td><span class="proto-badge ${getProtoClass(p.protocol)}">${escapeHtml(p.protocol)}</span></td>
                <td class="port-cell">${p.source_port !== null ? p.source_port : "-"}</td>
                <td class="port-cell">${p.destination_port !== null ? p.destination_port : "-"}</td>
                <td>${p.packet_length} B</td>
            </tr>
        `).join("");
    } catch (err) {
        console.warn("Error loading packets page data:", err);
    }
}

function resetPacketFilters() {
    const ipInput = document.getElementById("filter-ip");
    const protoSelect = document.getElementById("filter-protocol");
    const limitSelect = document.getElementById("filter-limit");

    if (ipInput) ipInput.value = "";
    if (protoSelect) protoSelect.value = "ALL";
    if (limitSelect) limitSelect.value = "100";

    loadPacketsPageData();
}

/* -----------------------------------------------------------------------------
   Dedicated Alerts Page Logic
   ----------------------------------------------------------------------------- */
async function loadAlertsPageData() {
    const tbody = document.getElementById("alerts-table-body");
    if (!tbody) return;

    const severity = document.getElementById("alert-filter-severity")?.value || "ALL";
    const alertType = document.getElementById("alert-filter-type")?.value || "ALL";
    const ip = document.getElementById("alert-filter-ip")?.value.trim() || "";

    const params = new URLSearchParams();
    if (severity && severity !== "ALL") params.set("severity", severity);
    if (alertType && alertType !== "ALL") params.set("type", alertType);
    if (ip) params.set("ip", ip);
    params.set("limit", "100");

    try {
        const res = await fetch(`/api/alerts?${params.toString()}`);
        if (!res.ok) return;
        const data = await res.json();

        const countDisplay = document.getElementById("alerts-count-display");
        if (countDisplay) {
            countDisplay.textContent = `Showing ${data.alerts ? data.alerts.length : 0} alerts`;
        }

        if (!data.alerts || data.alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="table-empty-msg">No alerts match the criteria.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.alerts.map(a => `
            <tr>
                <td>${a.id || "-"}</td>
                <td class="time-cell">${escapeHtml(a.timestamp)}</td>
                <td><strong>${escapeHtml(a.alert_type)}</strong></td>
                <td><span class="badge ${getSeverityBadgeClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td class="ip-cell">${escapeHtml(a.source_ip)}</td>
                <td class="ip-cell">${escapeHtml(a.destination_ip)}</td>
                <td>${escapeHtml(a.description)}</td>
                <td><span class="badge badge-primary">${escapeHtml(a.status || "New")}</span></td>
            </tr>
        `).join("");
    } catch (err) {
        console.warn("Error loading alerts page data:", err);
    }
}

function resetAlertFilters() {
    const sev = document.getElementById("alert-filter-severity");
    const typ = document.getElementById("alert-filter-type");
    const ip = document.getElementById("alert-filter-ip");

    if (sev) sev.value = "ALL";
    if (typ) typ.value = "ALL";
    if (ip) ip.value = "";

    loadAlertsPageData();
}

/* -----------------------------------------------------------------------------
   Dedicated Hosts Page Logic
   ----------------------------------------------------------------------------- */
async function loadHostsPageData() {
    const tbody = document.getElementById("hosts-table-body");
    if (!tbody) return;

    try {
        const res = await fetch("/api/hosts?limit=100");
        if (!res.ok) return;
        const data = await res.json();

        const countDisplay = document.getElementById("hosts-count-display");
        if (countDisplay) {
            countDisplay.textContent = `Tracking ${data.hosts ? data.hosts.length : 0} unique hosts`;
        }

        if (!data.hosts || data.hosts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="table-empty-msg">No network hosts tracked yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.hosts.map(h => `
            <tr>
                <td>${h.id}</td>
                <td class="ip-cell"><strong>${escapeHtml(h.ip_address)}</strong></td>
                <td class="time-cell">${escapeHtml(h.first_seen)}</td>
                <td class="time-cell">${escapeHtml(h.last_seen)}</td>
                <td>${h.packet_count.toLocaleString()} packets</td>
                <td>
                    <a href="/packets?ip=${encodeURIComponent(h.ip_address)}" class="btn btn-outline btn-sm">
                        Inspect Packets
                    </a>
                </td>
            </tr>
        `).join("");
    } catch (err) {
        console.warn("Error loading hosts page data:", err);
    }
}

/* -----------------------------------------------------------------------------
   Dedicated Settings Page Logic
   ----------------------------------------------------------------------------- */
async function loadSettingsPageData() {
    try {
        const res = await fetch("/api/settings");
        if (!res.ok) return;
        const data = await res.json();

        setText("settings-current-iface", data.current_interface);
        setText("settings-db-path", data.database_path);
        setText("settings-log-path", data.log_path);

        if (data.thresholds) {
            setText("thresh-portscan", `${data.thresholds.port_scan_threshold} ports`);
            setText("thresh-portscan-win", `${data.thresholds.port_scan_window_sec} sec`);
            setText("thresh-pkts", `${data.thresholds.high_packet_rate_threshold} pkts`);
            setText("thresh-pkts-win", `${data.thresholds.high_packet_rate_window_sec} sec`);
            setText("thresh-repeat", `${data.thresholds.repeated_conn_threshold} attempts`);
            setText("thresh-repeat-win", `${data.thresholds.repeated_conn_window_sec} sec`);
            setText("thresh-icmp", `${data.thresholds.icmp_threshold} pkts`);
            setText("thresh-icmp-win", `${data.thresholds.icmp_window_sec} sec`);
            setText("thresh-cooldown", `${data.thresholds.alert_cooldown_sec} sec`);
        }

        const ifaceList = document.getElementById("settings-available-ifaces");
        if (ifaceList && data.available_interfaces) {
            ifaceList.innerHTML = data.available_interfaces
                .map(iface => `<li>${escapeHtml(iface)}</li>`)
                .join("");
        }
    } catch (err) {
        console.warn("Error loading settings:", err);
    }
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el && text) el.textContent = text;
}

/* -----------------------------------------------------------------------------
   Formatting Utilities
   ----------------------------------------------------------------------------- */
function getProtoClass(protocol) {
    if (!protocol) return "other";
    const p = protocol.toUpperCase();
    if (p === "TCP") return "tcp";
    if (p === "UDP") return "udp";
    if (p === "ICMP") return "icmp";
    return "other";
}

function getSeverityBadgeClass(sev) {
    if (!sev) return "badge-low";
    const s = sev.toUpperCase();
    if (s === "HIGH") return "badge-high";
    if (s === "MEDIUM") return "badge-medium";
    return "badge-low";
}

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
