# ============================================================
# NFA - LIVE PACKET CAPTURE MODULE
# ============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


# ============================================================
# START LIVE CAPTURE
# ============================================================

def start_capture(packet_callback):

    print("\n" + "=" * 60)
    print(" NETWORK FORENSICS - LIVE PACKET CAPTURE")
    print("=" * 60)
    print("Starting real packet capture...")
    print("Press CTRL+C to stop.\n")


    def handle_packet(packet):

        try:

            # Only IPv4 packets are useful for our system
            if not packet.haslayer(IP):

                return


            # Send packet to app.py
            packet_callback(packet)


        except Exception as e:

            print(
                "[PACKET PROCESSING ERROR]",
                e
            )


    # ========================================================
    # SCAPY CAPTURE
    # ========================================================

    sniff(

        prn=handle_packet,

        store=False

    )


# ============================================================
# OPTIONAL PACKET DISPLAY
# ============================================================

def print_packet(packet):

    if not packet.haslayer(IP):

        return


    src_ip = packet[IP].src

    dst_ip = packet[IP].dst

    protocol = "OTHER"


    if packet.haslayer(TCP):

        protocol = "TCP"


    elif packet.haslayer(UDP):

        protocol = "UDP"


    elif packet.haslayer(ICMP):

        protocol = "ICMP"


    print(

        f"[{datetime.now().strftime('%H:%M:%S')}] "

        f"{protocol:<5} "

        f"{src_ip} -> {dst_ip} "

        f"Size: {len(packet)} bytes"

    )