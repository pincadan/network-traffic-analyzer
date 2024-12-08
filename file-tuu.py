from scapy.all import *

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_proto = packet[IP].proto
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {ip_proto}")

    if TCP in packet:
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        print(f"Source Port: {tcp_sport}")
        print(f"Destination Port: {tcp_dport}")
        print(f"TCP Flags: {tcp_flags}")

    if UDP in packet:
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport
        print(f"Source Port: {udp_sport}")
        print(f"Destination Port: {udp_dport}")

    if Raw in packet:
        raw_load = packet[Raw].load
        print(f"Raw Data: {raw_load}")

    print("=" * 50)

def main():
    sniff(prn=analyze_packet)

if __name__ == "__main__":
    main()