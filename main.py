from scapy.all import rdpcap, TCP, UDP, ICMP, IP
from collections import Counter

pcap_file = "sample.pcap"

packets = rdpcap(pcap_file)

print(f"Total packets: {len(packets)}")

protocol_counts = Counter()
source_ips = Counter()
destination_ips = Counter()

for packet in packets:
    if packet.haslayer(TCP):
        protocol_counts["TCP"] += 1
    elif packet.haslayer(UDP):
        protocol_counts["UDP"] += 1
    elif packet.haslayer(ICMP):
        protocol_counts["ICMP"] += 1
    else:
        protocol_counts["Other"] += 1

    if packet.haslayer(IP):
        source_ips[packet[IP].src] += 1
        destination_ips[packet[IP].dst] += 1

print("\nProtocol summary:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")

print("\nTop source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"{ip}: {count}")

print("\nTop destination IPs:")
for ip, count in destination_ips.most_common(5):
    print(f"{ip}: {count}")