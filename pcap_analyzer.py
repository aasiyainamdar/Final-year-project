
from collections import Counter, defaultdict
from datetime import datetime
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP


def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    rows = []
    protocols = Counter()
    source_ips = set()
    destination_ips = set()
    threats = []
    syn_ports_by_ip = defaultdict(set)

    for index, packet in enumerate(packets, start=1):
        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%Y-%m-%d %H:%M:%S")

        source = "Unknown"
        destination = "Unknown"
        protocol = "Other"
        severity = "Low"
        threat = "Normal"

        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
        elif IPv6 in packet:
            source = packet[IPv6].src
            destination = packet[IPv6].dst

        size = len(packet)

        if TCP in packet:
            protocol = "TCP"
            flags = int(packet[TCP].flags)

            # SYN set, ACK not set: connection attempt indicator.
            if flags & 0x02 and not flags & 0x10:
                severity = "Medium"
                threat = "TCP SYN Connection Attempt"
                syn_ports_by_ip[source].add(int(packet[TCP].dport))

        elif UDP in packet:
            protocol = "UDP"

            if size > 1200:
                severity = "Medium"
                threat = "Large UDP Traffic"

        elif ICMP in packet:
            protocol = "ICMP"

            if size > 1000:
                severity = "Medium"
                threat = "Abnormal ICMP Traffic"

        elif IPv6 in packet:
            protocol = "IPv6"

        else:
            protocol = "Other"

        protocols[protocol] += 1
        source_ips.add(source)
        destination_ips.add(destination)

        row = {
            "number": index,
            "timestamp": timestamp,
            "protocol": protocol,
            "source": source,
            "destination": destination,
            "size": size,
            "severity": severity,
            "threat": threat
        }

        rows.append(row)

        if threat != "Normal":
            threats.append(row.copy())

    # Identify possible port scans across the entire capture.
    for source, ports in syn_ports_by_ip.items():
        if len(ports) >= 5:
            threats.append({
                "number": "-",
                "timestamp": "-",
                "protocol": "TCP",
                "source": source,
                "destination": "Multiple",
                "size": 0,
                "severity": "High",
                "threat": (
                    f"Possible Port Scan "
                    f"({len(ports)} unique destination ports)"
                )
            })

    return {
        "filename": file_path.split("/")[-1].split("\\")[-1],
        "total_packets": len(packets),
        "unique_ips": len(source_ips | destination_ips),
        "protocol_counts": dict(protocols),
        "suspicious_count": len(threats),
        "threats": threats,
        "packets": rows
    }
