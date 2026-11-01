/* =========================================================
   NFA ANALYSIS PAGE
   LIVE PACKET DATA
========================================================= */

const tableBody =
    document.getElementById("packetTableBody");

const updateText =
    document.getElementById("packetUpdate");



/* =========================================================
   CLOCK
========================================================= */

function updateClock() {

    const clock =
        document.getElementById("topClock");

    if (!clock) return;

    const now = new Date();

    const hours =
        String(now.getHours()).padStart(2, "0");

    const minutes =
        String(now.getMinutes()).padStart(2, "0");

    const seconds =
        String(now.getSeconds()).padStart(2, "0");

    clock.textContent =
        `${hours}:${minutes}:${seconds}`;
}

setInterval(updateClock, 1000);

updateClock();



/* =========================================================
   ESCAPE HTML
========================================================= */

function escapeHTML(value) {

    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}



/* =========================================================
   PROTOCOL BADGE
========================================================= */

function protocolBadge(protocol) {

    const value =
        String(protocol || "OTHER").toUpperCase();

    let className =
        "protocol-badge";

    if (value === "TCP") {
        className += " protocol-tcp";
    }

    if (value === "ICMP") {
        className += " protocol-icmp";
    }

    return `
        <span class="${className}">
            ${escapeHTML(value)}
        </span>
    `;
}



/* =========================================================
   STATUS BADGE
========================================================= */

function statusBadge(status) {

    const value =
        String(status || "Allowed");

    const isMonitor =
        value.toLowerCase() === "monitor";

    if (isMonitor) {

        return `
            <span class="status-badge status-monitor">

                <span class="status-dot-small"></span>

                Monitor

            </span>
        `;
    }

    return `
        <span class="status-badge status-allowed">

            <span class="status-dot-small"></span>

            Allowed

        </span>
    `;
}



/* =========================================================
   RENDER PACKETS
========================================================= */

function renderPackets(logs) {

    if (!tableBody) return;


    if (!Array.isArray(logs) || logs.length === 0) {

        tableBody.innerHTML = `
            <tr class="loading-row">

                <td colspan="6">

                    <div class="loading-container">

                        <div class="loader"></div>

                        <span>
                            Waiting for live packet data...
                        </span>

                    </div>

                </td>

            </tr>
        `;

        return;
    }


    tableBody.innerHTML = "";


    logs.slice(0, 20).forEach(packet => {

        const row =
            document.createElement("tr");


        const time =
            escapeHTML(packet.time || "--:--:--");

        const protocol =
            packet.protocol || "OTHER";

        const source =
            escapeHTML(packet.source || "-");

        const destination =
            escapeHTML(packet.destination || "-");

        const size =
            escapeHTML(packet.size ?? 0);

        const status =
            packet.status || "Allowed";


        row.innerHTML = `

            <td>
                ${time}
            </td>

            <td>
                ${protocolBadge(protocol)}
            </td>

            <td>
                ${source}
            </td>

            <td>
                ${destination}
            </td>

            <td>
                ${size} B
            </td>

            <td>
                ${statusBadge(status)}
            </td>

        `;


        tableBody.appendChild(row);

    });


    if (updateText) {

        const now =
            new Date();

        updateText.textContent =
            "Last updated " +
            now.toLocaleTimeString();

    }
}



/* =========================================================
   FETCH LIVE DATA
========================================================= */

async function fetchLiveData() {

    try {

        const response =
            await fetch(
                "/api/live",
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );

        }


        const data =
            await response.json();


        /*
         * Flask /api/live returns:
         *
         * {
         *    stats: {...},
         *    statistics: {...},
         *    logs: [...]
         * }
         */


        renderPackets(
            data.logs || []
        );


    } catch (error) {

        console.error(
            "Analysis live-data error:",
            error
        );

        if (tableBody) {

            tableBody.innerHTML = `
                <tr class="loading-row">

                    <td colspan="6">

                        <div class="loading-container">

                            <span>
                                Unable to fetch live packet data
                            </span>

                        </div>

                    </td>

                </tr>
            `;
        }

    }
}



/* =========================================================
   START LIVE UPDATES
========================================================= */

fetchLiveData();


setInterval(
    fetchLiveData,
    1000
);