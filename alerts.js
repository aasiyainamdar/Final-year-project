/* =========================================================
   NFA SENTINEL
   THREAT ALERTS
========================================================= */


const alertsTable =
    document.getElementById("alertsTable");

const totalAlerts =
    document.getElementById("totalAlerts");

const highAlerts =
    document.getElementById("highAlerts");

const mediumAlerts =
    document.getElementById("mediumAlerts");

const lowAlerts =
    document.getElementById("lowAlerts");

const sidebarAlertCount =
    document.getElementById("sidebarAlertCount");

const lastUpdate =
    document.getElementById("lastUpdate");

const refreshButton =
    document.getElementById("refreshAlerts");


/* =========================================================
   HTML ESCAPE
========================================================= */

function escapeHTML(value) {

    if (value === null || value === undefined) {
        return "-";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* =========================================================
   SEVERITY CLASS
========================================================= */

function severityClass(severity) {

    const value =
        String(severity || "Low").toLowerCase();

    if (value === "high") {
        return "severity-high";
    }

    if (value === "medium") {
        return "severity-medium";
    }

    return "severity-low";
}


/* =========================================================
   LOAD ALERTS
========================================================= */

async function loadAlerts() {

    try {

        const response =
            await fetch("/api/threats", {
                cache: "no-store"
            });


        if (!response.ok) {

            throw new Error(
                "Threat API returned " +
                response.status
            );
        }


        const data =
            await response.json();


        let threats = [];


        if (Array.isArray(data)) {

            threats = data;

        } else if (
            data &&
            Array.isArray(data.threats)
        ) {

            threats = data.threats;

        }


        updateMetrics(threats);

        renderThreats(threats);

        updateTime();


    } catch (error) {

        console.error(
            "ALERT API ERROR:",
            error
        );

        alertsTable.innerHTML = `
            <tr>
                <td colspan="6"
                    class="no-data">

                    Unable to load threat data.

                </td>
            </tr>
        `;
    }
}


/* =========================================================
   METRICS
========================================================= */

function updateMetrics(threats) {

    let high = 0;
    let medium = 0;
    let low = 0;


    threats.forEach(threat => {

        const severity =
            String(
                threat.severity || "Low"
            ).toLowerCase();


        if (severity === "high") {

            high++;

        } else if (severity === "medium") {

            medium++;

        } else {

            low++;

        }

    });


    totalAlerts.textContent =
        threats.length;

    highAlerts.textContent =
        high;

    mediumAlerts.textContent =
        medium;

    lowAlerts.textContent =
        low;


    sidebarAlertCount.textContent =
        threats.length;
}


/* =========================================================
   TABLE
========================================================= */

function renderThreats(threats) {

    if (!threats.length) {

        alertsTable.innerHTML = `
            <tr>

                <td colspan="6"
                    class="no-data">

                    No suspicious activity detected.

                </td>

            </tr>
        `;

        return;
    }


    alertsTable.innerHTML =
        threats.map(threat => {

            const time =
                escapeHTML(
                    threat.time || "-"
                );

            const threatName =
                escapeHTML(
                    threat.threat ||
                    "Suspicious Activity"
                );

            const source =
                escapeHTML(
                    threat.source ||
                    "-"
                );

            const destination =
                escapeHTML(
                    threat.destination ||
                    "-"
                );

            const protocol =
                escapeHTML(
                    threat.protocol ||
                    "OTHER"
                );

            const severity =
                escapeHTML(
                    threat.severity ||
                    "Low"
                );


            return `
                <tr>

                    <td>
                        ${time}
                    </td>

                    <td>
                        ${threatName}
                    </td>

                    <td>
                        ${source}
                    </td>

                    <td>
                        ${destination}
                    </td>

                    <td>

                        <span class="protocol-badge">

                            ${protocol}

                        </span>

                    </td>

                    <td>

                        <span class="
                            severity-badge
                            ${severityClass(severity)}
                        ">

                            ${severity.toUpperCase()}

                        </span>

                    </td>

                </tr>
            `;

        }).join("");
}


/* =========================================================
   LAST UPDATE
========================================================= */

function updateTime() {

    const now =
        new Date();


    const time =
        now.toLocaleTimeString(
            "en-IN",
            {
                hour12: false
            }
        );


    lastUpdate.textContent =
        "LAST UPDATE: " + time;
}


/* =========================================================
   MANUAL REFRESH
========================================================= */

if (refreshButton) {

    refreshButton.addEventListener(
        "click",
        loadAlerts
    );

}


/* =========================================================
   INITIAL LOAD
========================================================= */

loadAlerts();


/* =========================================================
   AUTO REFRESH
========================================================= */

setInterval(
    loadAlerts,
    3000
);