from scapy.all import rdpcap, TCP, UDP, ICMP
from collections import Counter

pcap_file = "sample.pcap"

packets = rdpcap(pcap_file)

print(f"Total packets: {len(packets)}")

protocol_counts = Counter()

for packet in packets:
    if packet.haslayer(TCP):
        protocol_counts["TCP"] += 1
    elif packet.haslayer(UDP):
        protocol_counts["UDP"] += 1
    elif packet.haslayer(ICMP):
        protocol_counts["ICMP"] += 1
    else:
        protocol_counts["Other"] += 1

print("\nProtocol summary:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")