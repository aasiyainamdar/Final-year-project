/* =========================================================
   NFA - LIVE DASHBOARD CONTROLLER
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    console.log("NFA Dashboard JS Loaded");

    /* =====================================================
       ELEMENTS - MAIN DASHBOARD
       ===================================================== */

    const totalPackets =
        document.getElementById("totalPackets");

    const packetsSec =
        document.getElementById("packetsSec");

    const suspiciousPackets =
        document.getElementById("suspiciousPackets");


    /* =====================================================
       PROTOCOL ELEMENTS
       ===================================================== */

    const tcpPackets =
        document.getElementById("tcpPackets");

    const udpPackets =
        document.getElementById("udpPackets");

    const icmpPackets =
        document.getElementById("icmpPackets");


    const tcpProgress =
        document.getElementById("tcpProgress");

    const udpProgress =
        document.getElementById("udpProgress");

    const icmpProgress =
        document.getElementById("icmpProgress");


    /* =====================================================
       TRAFFIC / SUMMARY
       ===================================================== */

    const trafficRate =
        document.getElementById("trafficRate");

    const tcpSummary =
        document.getElementById("tcpSummary");

    const udpSummary =
        document.getElementById("udpSummary");

    const icmpSummary =
        document.getElementById("icmpSummary");

    const otherSummary =
        document.getElementById("otherSummary");


    /* =====================================================
       PACKET TABLE
       ===================================================== */

    const packetTableBody =
        document.getElementById("packetTableBody");


    /* =====================================================
       THREAT DETECTION CENTER
       ===================================================== */

    const threatTableBody =
        document.getElementById("threatTableBody");

    const threatTotal =
        document.getElementById("threatTotal");

    const highThreats =
        document.getElementById("highThreats");

    const mediumThreats =
        document.getElementById("mediumThreats");

    const threatCount =
        document.getElementById("threatCount");


    /* =====================================================
       CLOCK
       ===================================================== */

    const currentTime =
        document.getElementById("currentTime");


    /* =====================================================
       NUMBER FORMAT
       ===================================================== */

    function formatNumber(value) {

        return Number(value || 0)
            .toLocaleString();

    }


    function updateNumber(element, value) {

        if (!element) return;

        element.textContent =
            formatNumber(value);

    }


    /* =====================================================
       CLOCK
       ===================================================== */

    function updateClock() {

        if (!currentTime) return;

        const now = new Date();

        const hours =
            String(now.getHours())
                .padStart(2, "0");

        const minutes =
            String(now.getMinutes())
                .padStart(2, "0");

        const seconds =
            String(now.getSeconds())
                .padStart(2, "0");

        currentTime.textContent =
            `${hours}:${minutes}:${seconds}`;
    }


    updateClock();

    setInterval(
        updateClock,
        1000
    );


    /* =====================================================
       STATUS CLASS
       ===================================================== */

    function getStatusClass(status) {

        if (!status) {
            return "";
        }

        const value =
            String(status).toLowerCase();

        if (
            value.includes("suspicious") ||
            value.includes("monitor") ||
            value.includes("danger")
        ) {
            return "packet-danger";
        }

        return "packet-normal";
    }


    /* =====================================================
       PROTOCOL CLASS
       ===================================================== */

    function getProtocolClass(protocol) {

        if (!protocol) {
            return "";
        }

        return (
            "protocol-" +
            String(protocol).toLowerCase()
        );
    }


    /* =====================================================
       RENDER LIVE PACKETS
       ===================================================== */

    function renderPacketTable(logs) {

        if (!packetTableBody) {
            return;
        }

        packetTableBody.innerHTML = "";


        if (
            !Array.isArray(logs) ||
            logs.length === 0
        ) {

            packetTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="no-data">
                        WAITING FOR LIVE PACKETS...
                    </td>
                </tr>
            `;

            return;
        }


        logs
            .slice(0, 20)
            .forEach(packet => {

                const row =
                    document.createElement("tr");


                const statusClass =
                    getStatusClass(
                        packet.status
                    );


                const protocolClass =
                    getProtocolClass(
                        packet.protocol
                    );


                row.innerHTML = `

                    <td>
                        ${packet.time || "--"}
                    </td>

                    <td>
                        <span class="protocol-tag ${protocolClass}">
                            ${packet.protocol || "OTHER"}
                        </span>
                    </td>

                    <td>
                        ${packet.source || "-"}
                    </td>

                    <td>
                        ${packet.destination || "-"}
                    </td>

                    <td>
                        ${(packet.size || 0)} B
                    </td>

                    <td>
                        <span class="status-tag ${statusClass}">
                            <i></i>
                            ${packet.status || "Allowed"}
                        </span>
                    </td>

                `;


                packetTableBody.appendChild(row);

            });

    }


    /* =====================================================
       UPDATE MAIN DASHBOARD
       ===================================================== */

    function updateDashboard(data) {

        if (!data) {
            return;
        }


        const stats =
            data.stats || {};


        /* -----------------------------------------------
           MAIN STATISTICS
        ----------------------------------------------- */

        updateNumber(
            totalPackets,
            stats.total_packets
        );


        updateNumber(
            packetsSec,
            stats.packets_sec
        );


        updateNumber(
            suspiciousPackets,
            stats.suspicious
        );


        /* -----------------------------------------------
           PROTOCOL COUNTS
        ----------------------------------------------- */

        updateNumber(
            tcpPackets,
            stats.tcp
        );


        updateNumber(
            udpPackets,
            stats.udp
        );


        updateNumber(
            icmpPackets,
            stats.icmp
        );


        /* -----------------------------------------------
           PROTOCOL PROGRESS
        ----------------------------------------------- */

        const total =
            Number(stats.total_packets || 0);


        if (total > 0) {

            if (tcpProgress) {

                tcpProgress.style.width =
                    `${((stats.tcp || 0) / total) * 100}%`;

            }


            if (udpProgress) {

                udpProgress.style.width =
                    `${((stats.udp || 0) / total) * 100}%`;

            }


            if (icmpProgress) {

                icmpProgress.style.width =
                    `${((stats.icmp || 0) / total) * 100}%`;

            }

        }


        /* -----------------------------------------------
           TRAFFIC RATE
        ----------------------------------------------- */

        updateNumber(
            trafficRate,
            stats.packets_sec
        );


        /* -----------------------------------------------
           PROTOCOL SUMMARY
        ----------------------------------------------- */

        updateNumber(
            tcpSummary,
            stats.tcp
        );


        updateNumber(
            udpSummary,
            stats.udp
        );


        updateNumber(
            icmpSummary,
            stats.icmp
        );


        updateNumber(
            otherSummary,
            stats.other
        );


        /* -----------------------------------------------
           PACKET TABLE
        ----------------------------------------------- */

        renderPacketTable(
            data.logs || []
        );

    }


    /* =====================================================
       RENDER THREATS
       ===================================================== */

    function renderThreats(threats) {

        if (!threatTableBody) {
            return;
        }


        const threatList =
            Array.isArray(threats)
                ? threats
                : [];


        /* -----------------------------------------------
           NO THREATS
        ----------------------------------------------- */

        if (threatList.length === 0) {

            threatTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="threat-empty">
                        <span class="empty-icon">◉</span>
                        NO ACTIVE THREATS DETECTED
                    </td>
                </tr>
            `;


            if (threatTotal) {
                threatTotal.textContent = "0";
            }

            if (highThreats) {
                highThreats.textContent = "0";
            }

            if (mediumThreats) {
                mediumThreats.textContent = "0";
            }

            if (threatCount) {
                threatCount.textContent = "0";
            }

            return;
        }


        /* -----------------------------------------------
           COUNTS
        ----------------------------------------------- */

        const highCount =
            threatList.filter(threat =>
                String(
                    threat.severity || ""
                ).toLowerCase() === "high"
            ).length;


        const mediumCount =
            threatList.filter(threat =>
                String(
                    threat.severity || ""
                ).toLowerCase() === "medium"
            ).length;


        if (threatTotal) {

            threatTotal.textContent =
                threatList.length;

        }


        if (highThreats) {

            highThreats.textContent =
                highCount;

        }


        if (mediumThreats) {

            mediumThreats.textContent =
                mediumCount;

        }


        if (threatCount) {

            threatCount.textContent =
                threatList.length;

        }


        /* -----------------------------------------------
           THREAT TABLE
        ----------------------------------------------- */

        threatTableBody.innerHTML = "";


        threatList
            .slice(0, 20)
            .forEach(threat => {

                const row =
                    document.createElement("tr");


                const severity =
                    String(
                        threat.severity || "Low"
                    ).toLowerCase();


                row.innerHTML = `

                    <td>
                        ${threat.time || "--"}
                    </td>

                    <td class="threat-name">
                        ${threat.threat || "Unknown Threat"}
                    </td>

                    <td class="threat-ip">
                        ${threat.source || "-"}
                    </td>

                    <td class="threat-ip">
                        ${threat.destination || "-"}
                    </td>

                    <td>
                        <span class="threat-protocol">
                            ${threat.protocol || "OTHER"}
                        </span>
                    </td>

                    <td>
                        <span class="severity severity-${severity}">
                            ${severity.toUpperCase()}
                        </span>
                    </td>

                `;


                threatTableBody.appendChild(row);

            });

    }


    /* =====================================================
       FETCH LIVE PACKET DATA
       ===================================================== */

    async function fetchLiveData() {

        try {

            const response =
                await fetch(
                    "/api/live",
                    {
                        method: "GET",
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


            updateDashboard(data);


        } catch (error) {

            console.error(
                "NFA LIVE API ERROR:",
                error
            );

        }

    }


    /* =====================================================
       FETCH REAL THREATS
       ===================================================== */

    async function fetchThreats() {

        try {

            const response =
                await fetch(
                    "/api/threats",
                    {
                        method: "GET",
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


            if (data.success) {

                renderThreats(
                    data.threats || []
                );

            } else {

                renderThreats([]);

            }


        } catch (error) {

            console.error(
                "NFA THREAT API ERROR:",
                error
            );

        }

    }


    /* =====================================================
       INITIAL LOAD
       ===================================================== */

    fetchLiveData();

    fetchThreats();


    /* =====================================================
       LIVE UPDATE LOOPS
       ===================================================== */

    setInterval(
        fetchLiveData,
        1000
    );


    setInterval(
        fetchThreats,
        1000
    );


});