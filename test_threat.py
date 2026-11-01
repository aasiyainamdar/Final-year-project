from scapy.all import IP, TCP, send
import time

print("=" * 50)
print("NFA - LOCAL THREAT DETECTION TEST")
print("=" * 50)

print("\nSending controlled TCP SYN test packets...")
print("Target: 127.0.0.1")

for port in [80, 443, 8080, 8000, 5000]:

    packet = IP(
        src="127.0.0.1",
        dst="127.0.0.1"
    ) / TCP(
        sport=12345,
        dport=port,
        flags="S"
    )

    send(
        packet,
        verbose=False
    )

    print(
        f"[TEST] TCP SYN sent to port {port}"
    )

    time.sleep(0.5)


print("\nTest packets sent.")
print("Check your NFA dashboard.")
