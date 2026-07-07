from scapy.all import rdpcap

pcap_file = "sample.pcap"

packets = rdpcap(pcap_file)

print(f"Total packets: {len(packets)}")