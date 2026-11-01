from scapy.all import IP, TCP, UDP, ICMP
from modules.detection import analyze_packet

print("=" * 60)
print("NFA - DIRECT THREAT DETECTION TEST")
print("=" * 60)

print("\n[1] TCP SYN TEST")

ports = [80, 443, 8080, 8000, 5000]

for port in ports:

    packet = IP(
        src="192.168.1.100",
        dst="192.168.1.1"
    ) / TCP(
        sport=45000,
        dport=port,
        flags="S"
    )

    result = analyze_packet(packet)

    print(
        f"Port {port} -> "
        f"Suspicious: {result['suspicious']} | "
        f"Threat: {result['threat']} | "
        f"Severity: {result['severity']}"
    )


print("\n[2] LARGE UDP TEST")

packet = IP(
    src="192.168.1.100",
    dst="192.168.1.1"
) / UDP(
    sport=5000,
    dport=5001
) / ("X" * 1300)

result = analyze_packet(packet)

print(
    f"UDP -> "
    f"Suspicious: {result['suspicious']} | "
    f"Threat: {result['threat']} | "
    f"Severity: {result['severity']}"
)


print("\n[3] LARGE ICMP TEST")

packet = IP(
    src="192.168.1.100",
    dst="192.168.1.1"
) / ICMP() / ("X" * 1100)

result = analyze_packet(packet)

print(
    f"ICMP -> "
    f"Suspicious: {result['suspicious']} | "
    f"Threat: {result['threat']} | "
    f"Severity: {result['severity']}"
)


print("\n" + "=" * 60)
print("TEST COMPLETED")
print("=" * 60)