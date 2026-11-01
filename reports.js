
"use strict";

const API_URL = "/api/threats";

let allRecords = [];
let severityChart = null;
let toastTimer = null;

const $ = (id) => document.getElementById(id);

function safeText(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

function firstValue(record, keys, fallback = "") {
    for (const key of keys) {
        const value = record?.[key];
        if (value !== undefined && value !== null && String(value).trim() !== "") {
            return value;
        }
    }
    return fallback;
}

function normalizeSeverity(value) {
    const severity = String(value || "").trim().toLowerCase();

    if (severity.includes("high") || severity.includes("critical")) return "high";
    if (severity.includes("medium") || severity.includes("moderate")) return "medium";
    if (severity.includes("low") || severity.includes("info") || severity.includes("minor")) return "low";

    return "unknown";
}

function normalizeRecord(record, index) {
    const timestamp = firstValue(record, [
        "timestamp", "time", "datetime", "date", "created_at"
    ], "");

    const threat = firstValue(record, [
        "threat", "threat_type", "attack_type", "event",
        "type", "description", "alert", "name"
    ], "Security event");

    const source = firstValue(record, [
        "source_ip", "src_ip", "src", "source", "ip_src"
    ], "—");

    const destination = firstValue(record, [
        "destination_ip", "dest_ip", "dst_ip", "dst",
        "destination", "ip_dst"
    ], "—");

    const rawSeverity = firstValue(record, [
        "severity", "level", "risk", "priority"
    ], "");

    return {
        original: record,
        index,
        timestamp: formatTimestamp(timestamp),
        rawTimestamp: timestamp,
        threat: String(threat),
        source: String(source),
        destination: String(destination),
        severity: normalizeSeverity(rawSeverity),
        severityLabel: rawSeverity ? String(rawSeverity) : "Unknown"
    };
}

function formatTimestamp(value) {
    if (value === "" || value === null || value === undefined) {
        return "—";
    }

    // Numeric timestamps can be seconds or milliseconds.
    if (typeof value === "number" || /^\d{10,13}$/.test(String(value).trim())) {
        const numeric = Number(value);
        const date = new Date(String(numeric).length <= 10 ? numeric * 1000 : numeric);
        if (!Number.isNaN(date.getTime())) return date.toLocaleString();
    }

    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toLocaleString();

    return String(value);
}

function showToast(message, isError = false) {
    const toast = $("toast");
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.classList.add("show");

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function setApiStatus(message, isError = false) {
    const status = $("apiStatus");
    status.textContent = message;
    status.style.color = isError ? "#d83f51" : "#168d64";
}

function countSeverities(records) {
    return records.reduce((counts, record) => {
        if (record.severity === "high") counts.high++;
        else if (record.severity === "medium") counts.medium++;
        else counts.low++;
        return counts;
    }, { high: 0, medium: 0, low: 0 });
}

function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = value;
}

function updateOverview() {
    const counts = countSeverities(allRecords);
    const total = allRecords.length;

    setText("totalCount", total);
    setText("highCount", counts.high);
    setText("mediumCount", counts.medium);
    setText("lowCount", counts.low);
    setText("loadedRecords", total);

    const percent = (count) => total ? `${Math.round(count / total * 100)}%` : "0%";
    setText("highPercent", percent(counts.high));
    setText("mediumPercent", percent(counts.medium));
    setText("lowPercent", percent(counts.low));

    setText("lastUpdated", new Date().toLocaleTimeString());

    const emptyChart = $("chartEmpty");
if (emptyChart) {
    emptyChart.hidden = total > 0;
    emptyChart.style.display = total > 0 ? "none" : "grid";
}

    const canvas = $("severityChart");
    if (!canvas || typeof Chart === "undefined") return;

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: ["High", "Medium", "Low / Other"],
            datasets: [{
                data: [counts.high, counts.medium, counts.low],
                backgroundColor: ["#ef5262", "#f5a623", "#21b981"],
                borderColor: "#ffffff",
                borderWidth: 4,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "69%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (context) => {
                            const value = context.raw || 0;
                            const share = total ? Math.round(value / total * 100) : 0;
                            return ` ${context.label}: ${value} (${share}%)`;
                        }
                    }
                }
            }
        }
    });
}

function getFilteredRecords() {
    const query = ($("searchInput")?.value || "").trim().toLowerCase();
    const severity = $("severityFilter")?.value || "all";

    return allRecords.filter((record) => {
        const searchable = [
            record.timestamp,
            record.threat,
            record.source,
            record.destination,
            record.severityLabel
        ].join(" ").toLowerCase();

        const matchesSearch = !query || searchable.includes(query);
        const matchesSeverity =
            severity === "all" ||
            (severity === "low" ? record.severity === "low" || record.severity === "unknown"
                                : record.severity === severity);

        return matchesSearch && matchesSeverity;
    });
}

function severityBadge(record) {
    const severity = record.severity;
    const label = severity === "unknown"
        ? record.severityLabel
        : severity.charAt(0).toUpperCase() + severity.slice(1);

    const className = severity === "unknown" ? "severity-unknown" : `severity-${severity}`;
    return `<span class="severity-badge ${className}">${safeText(label)}</span>`;
}

function renderTable() {
    const body = $("reportTableBody");
    if (!body) return;

    const filtered = getFilteredRecords();
    const total = allRecords.length;

    setText("recordCount", `${filtered.length} record${filtered.length === 1 ? "" : "s"}`);
    setText("tableSummary", `Showing ${filtered.length} of ${total} records`);

    if (filtered.length === 0) {
        const message = total === 0
            ? "No threat records available. Generate network traffic and check the detection logs."
            : "No records match your search or severity filter.";

        body.innerHTML = `<tr><td colspan="6" class="empty-cell">${safeText(message)}</td></tr>`;
        return;
    }

    body.innerHTML = filtered.map((record, position) => `
        <tr>
            <td>${position + 1}</td>
            <td>${safeText(record.timestamp)}</td>
            <td class="threat-name">${safeText(record.threat)}</td>
            <td class="ip-address">${safeText(record.source)}</td>
            <td class="ip-address">${safeText(record.destination)}</td>
            <td>${severityBadge(record)}</td>
        </tr>
    `).join("");
}

async function loadReports(showMessage = false) {
    const refreshButton = $("refreshBtn");
    if (refreshButton) refreshButton.disabled = true;

    setApiStatus("Connecting...");

    try {
        const response = await fetch(API_URL, {
            method: "GET",
            headers: { "Accept": "application/json" },
            credentials: "same-origin",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`API returned HTTP ${response.status}`);
        }

        const payload = await response.json();

        let records;
        if (Array.isArray(payload)) {
            records = payload;
        } else if (Array.isArray(payload.threats)) {
            records = payload.threats;
        } else if (Array.isArray(payload.records)) {
            records = payload.records;
        } else if (Array.isArray(payload.logs)) {
            records = payload.logs;
        } else {
            throw new Error("Unexpected API response format");
        }

        allRecords = records.map(normalizeRecord);
        updateOverview();
        renderTable();
        setApiStatus("Connected");

        if (showMessage) showToast("Report records refreshed.");
    } catch (error) {
        console.error("Reports loading error:", error);
        setApiStatus("API error", true);

        if (allRecords.length === 0) {
            setText("totalCount", "—");
            setText("highCount", "—");
            setText("mediumCount", "—");
            setText("lowCount", "—");

            const body = $("reportTableBody");
            if (body) {
                body.innerHTML = `
                    <tr><td colspan="6" class="empty-cell">
                        Unable to load records. Check that Flask is running and
                        <code>/api/threats</code> is available.
                    </td></tr>`;
            }
        }

        if (showMessage) showToast("Could not refresh reports. Check the Flask API.", true);
    } finally {
        if (refreshButton) refreshButton.disabled = false;
    }
}

function csvCell(value) {
    let text = String(value ?? "");

    // Prevent spreadsheet formulas from executing when opened in Excel.
    if (/^[\s]*[=+\-@]/.test(text)) text = "'" + text;

    return `"${text.replace(/"/g, '""')}"`;
}

function exportCsv() {
    const records = getFilteredRecords();

    if (!records.length) {
        showToast("There are no records to export.", true);
        return;
    }

    const rows = [
        ["Timestamp", "Threat / Event", "Source IP", "Destination IP", "Severity"],
        ...records.map((record) => [
            record.timestamp,
            record.threat,
            record.source,
            record.destination,
            record.severityLabel
        ])
    ];

    const csv = "\uFEFF" + rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `network-forensics-report-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    showToast(`Exported ${records.length} records to CSV.`);
}

function clearFilters() {
    $("searchInput").value = "";
    $("severityFilter").value = "all";
    renderTable();
}

document.addEventListener("DOMContentLoaded", () => {
    $("refreshBtn")?.addEventListener("click", () => loadReports(true));
    $("printBtn")?.addEventListener("click", () => window.print());
    $("csvBtn")?.addEventListener("click", exportCsv);
    $("searchInput")?.addEventListener("input", renderTable);
    $("severityFilter")?.addEventListener("change", renderTable);
    $("clearFiltersBtn")?.addEventListener("click", clearFilters);

    loadReports();

    // Refresh the report view periodically while this page is open.
    window.setInterval(() => loadReports(false), 15000);
});
