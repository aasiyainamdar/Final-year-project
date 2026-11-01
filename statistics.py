# ============================================================
# NFA - STATISTICS MODULE
# ============================================================

from collections import Counter
from statistics import mean, median


# ============================================================
# STATISTICS STORAGE
# ============================================================

packet_sizes = []
response_times = []

protocol_counter = Counter()

threat_counter = Counter()


# ============================================================
# RECORD PACKET
# ============================================================

def record_packet(packet_size, protocol, suspicious=False, threat=None):
    """
    Store information about a processed packet.
    """

    # --------------------------------------------------------
    # Packet size
    # --------------------------------------------------------

    if packet_size is not None:

        packet_sizes.append(
            int(packet_size)
        )


    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    if protocol:

        protocol_counter[
            protocol.upper()
        ] += 1


    # --------------------------------------------------------
    # Threat
    # --------------------------------------------------------

    if suspicious:

        threat_name = (
            threat
            if threat
            else "Unknown Threat"
        )

        threat_counter[
            threat_name
        ] += 1


# ============================================================
# RECORD RESPONSE TIME
# ============================================================

def record_response_time(response_time):
    """
    Store packet processing / response time in milliseconds.
    """

    if response_time is None:
        return

    try:

        response_times.append(
            float(response_time)
        )

    except (TypeError, ValueError):

        pass


# ============================================================
# GET PACKET STATISTICS
# ============================================================

def get_packet_statistics():
    # Take a safe snapshot so live capture does not modify
    # the list while statistics are being calculated.
    packet_snapshot = list(packet_sizes)

    if not packet_snapshot:
        return {
            "count": 0,
            "mean": 0,
            "median": 0,
            "minimum": 0,
            "maximum": 0,
            "range": 0
        }

    # Convert values safely to float
    valid_sizes = []

    for value in packet_snapshot:
        try:
            valid_sizes.append(float(value))
        except (TypeError, ValueError):
            continue

    if not valid_sizes:
        return {
            "count": 0,
            "mean": 0,
            "median": 0,
            "minimum": 0,
            "maximum": 0,
            "range": 0
        }

    minimum = min(valid_sizes)
    maximum = max(valid_sizes)

    return {
        "count": len(valid_sizes),
        "mean": round(mean(valid_sizes), 2),
        "median": round(median(valid_sizes), 2),
        "minimum": round(minimum, 2),
        "maximum": round(maximum, 2),
        "range": round(maximum - minimum, 2)
    }


# ============================================================
# GET PROTOCOL STATISTICS
# ============================================================

def get_protocol_statistics():
    """
    Return packet count for each protocol.
    """

    return {

        "TCP":
            protocol_counter.get(
                "TCP",
                0
            ),

        "UDP":
            protocol_counter.get(
                "UDP",
                0
            ),

        "ICMP":
            protocol_counter.get(
                "ICMP",
                0
            ),

        "OTHER":
            protocol_counter.get(
                "OTHER",
                0
            )

    }


# ============================================================
# GET THREAT STATISTICS
# ============================================================

def get_threat_statistics():
    """
    Return number of detected threats
    grouped by threat type.
    """

    return dict(
        threat_counter
    )


# ============================================================
# THREAT PERCENTAGE
# ============================================================

def calculate_threat_percentage(
    total_packets,
    suspicious_packets
):
    """
    Calculate percentage of suspicious packets.
    """

    if not total_packets:

        return 0


    percentage = (
        suspicious_packets
        / total_packets
    ) * 100


    return round(
        percentage,
        2
    )


# ============================================================
# RESPONSE TIME STATISTICS
# ============================================================

# ============================================================
# RESPONSE TIME STATISTICS
# ============================================================

def get_response_statistics():
    """
    Return basic response-time statistics safely.
    """

    # Make a snapshot so live packet capture does not
    # modify the list while statistics are being calculated.
    response_snapshot = list(response_times)

    if not response_snapshot:

        return {
            "count": 0,
            "mean": 0,
            "median": 0,
            "minimum": 0,
            "maximum": 0,
            "range": 0
        }

    # Keep only valid numeric response times
    valid_times = []

    for value in response_snapshot:

        try:
            valid_times.append(float(value))

        except (TypeError, ValueError):
            continue

    if not valid_times:

        return {
            "count": 0,
            "mean": 0,
            "median": 0,
            "minimum": 0,
            "maximum": 0,
            "range": 0
        }

    minimum = min(valid_times)
    maximum = max(valid_times)

    return {
        "count": len(valid_times),

        "mean": round(
            mean(valid_times),
            2
        ),

        "median": round(
            median(valid_times),
            2
        ),

        "minimum": round(
            minimum,
            2
        ),

        "maximum": round(
            maximum,
            2
        ),

        "range": round(
            maximum - minimum,
            2
        )
    }


# ============================================================
# COMPLETE STATISTICS
# ============================================================

def get_all_statistics(
    total_packets=0,
    suspicious_packets=0
):
    """
    Return all available project statistics.
    """

    return {

        "packet_statistics":
            get_packet_statistics(),

        "protocol_statistics":
            get_protocol_statistics(),

        "threat_statistics":
            get_threat_statistics(),

        "response_statistics":
            get_response_statistics(),

        "threat_percentage":
            calculate_threat_percentage(
                total_packets,
                suspicious_packets
            )

    }


# ============================================================
# RESET STATISTICS
# ============================================================

def reset_statistics():
    """
    Clear all stored statistics.
    """

    packet_sizes.clear()

    response_times.clear()

    protocol_counter.clear()

    threat_counter.clear()