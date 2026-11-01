# ============================================================
# NFA - THREAT DETECTION MODULE
# ============================================================

from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
import time


# ============================================================
# DETECTION STORAGE
# ============================================================

connection_tracker = defaultdict(list)

threat_logs = []

MAX_THREATS = 100

# Same threat ko kitne seconds tak duplicate nahi karna
DUPLICATE_WINDOW = 5


# ============================================================
# THREAT DETECTION
# ============================================================

def analyze_packet(packet):

    # --------------------------------------------------------
    # Default result
    # --------------------------------------------------------

    result = {
        "suspicious": False,
        "threat": "Normal Traffic",
        "severity": "Low",
        "source": "-",
        "destination": "-",
        "protocol": "OTHER",
        "time": time.strftime("%H:%M:%S")
    }

    # --------------------------------------------------------
    # Ignore non-IP packets
    # --------------------------------------------------------

    if not packet.haslayer(IP):
        return result

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    result["source"] = src_ip
    result["destination"] = dst_ip


    # ========================================================
    # TCP
    # ========================================================

    if packet.haslayer(TCP):

        result["protocol"] = "TCP"

        tcp = packet[TCP]

        flags = int(tcp.flags)

        destination_port = int(tcp.dport)

        # ----------------------------------------------------
        # TCP SYN DETECTION
        # ----------------------------------------------------

        syn_flag = bool(flags & 0x02)
        ack_flag = bool(flags & 0x10)

        if syn_flag and not ack_flag:

            result["suspicious"] = True

            result["threat"] = "TCP SYN Connection Attempt"

            result["severity"] = "Medium"


            # ------------------------------------------------
            # Track connection attempt
            # ------------------------------------------------

            current_time = time.time()

            connection_tracker[src_ip].append(
                (
                    current_time,
                    destination_port
                )
            )


            # ------------------------------------------------
            # Remove old attempts
            # ------------------------------------------------

            connection_tracker[src_ip] = [

                item

                for item in connection_tracker[src_ip]

                if current_time - item[0] <= 10

            ]


            # ------------------------------------------------
            # Detect possible port scan
            # ------------------------------------------------

            unique_ports = set(

                port

                for timestamp, port
                in connection_tracker[src_ip]

            )


            if len(unique_ports) >= 5:

                result["suspicious"] = True

                result["threat"] = "Possible Port Scan"

                result["severity"] = "High"


    # ========================================================
    # UDP
    # ========================================================

    elif packet.haslayer(UDP):

        result["protocol"] = "UDP"

        packet_size = len(packet)

        # ----------------------------------------------------
        # Large UDP Traffic
        # ----------------------------------------------------

        if packet_size > 1200:

            result["suspicious"] = True

            result["threat"] = "Large UDP Traffic"

            result["severity"] = "Medium"


    # ========================================================
    # ICMP
    # ========================================================

    elif packet.haslayer(ICMP):

        result["protocol"] = "ICMP"

        packet_size = len(packet)

        # ----------------------------------------------------
        # Large ICMP Traffic
        # ----------------------------------------------------

        if packet_size > 1000:

            result["suspicious"] = True

            result["threat"] = "Abnormal ICMP Traffic"

            result["severity"] = "Medium"


    # ========================================================
    # STORE THREAT
    # ========================================================

    if result["suspicious"]:

        current_time = time.time()

        duplicate_found = False


        # ----------------------------------------------------
        # CHECK RECENT DUPLICATE
        # ----------------------------------------------------

        for old_threat in threat_logs:

            same_threat = (

                old_threat.get("threat")
                == result.get("threat")

                and

                old_threat.get("source")
                == result.get("source")

                and

                old_threat.get("destination")
                == result.get("destination")

                and

                old_threat.get("protocol")
                == result.get("protocol")

            )


            if same_threat:

                old_timestamp = old_threat.get(
                    "_timestamp",
                    0
                )

                if (
                    current_time - old_timestamp
                    < DUPLICATE_WINDOW
                ):

                    duplicate_found = True

                    break


        # ----------------------------------------------------
        # STORE ONLY IF NOT DUPLICATE
        # ----------------------------------------------------

        if not duplicate_found:

            threat_entry = result.copy()

            # Internal timestamp
            # API me nahi bhejna
            threat_entry["_timestamp"] = current_time


            threat_logs.insert(
                0,
                threat_entry
            )


            # Keep only latest 100 threat events

            if len(threat_logs) > MAX_THREATS:

                del threat_logs[MAX_THREATS:]


            print(
                f"[THREAT] "
                f"{result['threat']} | "
                f"{result['source']} -> "
                f"{result['destination']} | "
                f"Severity: "
                f"{result['severity']}"
            )


    return result


# ============================================================
# GET THREAT LOGS
# ============================================================

def get_threat_logs():

    # ---------------------------------------------
    # Remove internal timestamp before returning
    # ---------------------------------------------

    clean_logs = []

    for threat in threat_logs:

        item = threat.copy()

        item.pop("_timestamp", None)

        clean_logs.append(item)

    return clean_logs


# ============================================================
# CLEAR THREAT LOGS
# ============================================================

def clear_threat_logs():

    threat_logs.clear()


# ============================================================
# RESET DETECTION TRACKER
# ============================================================

def reset_detection():

    connection_tracker.clear()

    threat_logs.clear()