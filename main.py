from scapy.all import rdpcap, TCP, UDP, ICMP, IP
from collections import Counter

pcap_file = "sample.pcap"

packets = rdpcap(pcap_file)

protocol_counts = Counter()
source_ips = Counter()
destination_ips = Counter()
source_ports = Counter()
destination_ports = Counter()

for packet in packets:
    if packet.haslayer(TCP):
        protocol_counts["TCP"] += 1
        source_ports[packet[TCP].sport] += 1
        destination_ports[packet[TCP].dport] += 1
    elif packet.haslayer(UDP):
        protocol_counts["UDP"] += 1
        source_ports[packet[UDP].sport] += 1
        destination_ports[packet[UDP].dport] += 1
    elif packet.haslayer(ICMP):
        protocol_counts["ICMP"] += 1
    else:
        protocol_counts["Other"] += 1

    if packet.haslayer(IP):
        source_ips[packet[IP].src] += 1
        destination_ips[packet[IP].dst] += 1

print("=== Network Traffic Report ===")
print(f"Total packets: {len(packets)}")

print("\nProtocol summary:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")

print("\nTop source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"{ip}: {count}")

print("\nTop destination IPs:")
for ip, count in destination_ips.most_common(5):
    print(f"{ip}: {count}")

print("\nTop source ports:")
for port, count in source_ports.most_common(5):
    print(f"{port}: {count}")

print("\nTop destination ports:")
for port, count in destination_ports.most_common(5):
    print(f"{port}: {count}")

print("\nSample packet summaries:")
for packet in packets[:5]:
    print(packet.summary())