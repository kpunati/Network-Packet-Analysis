# Programmed in 2024 by Karthik P.
from scapy.all import rdpcap, TCP

def analyze_packets(pcap_file):
    try:
        # Read the captured packets from the pcap file
        packets = rdpcap(pcap_file)

        # Initialize counters and lists to store packet properties
        total_packets = len(packets)
        tcp_packets = 0
        udp_packets = 0
        packet_lengths = []
        tcp_flags = []

        # Analyze each packet
        for packet in packets:
            # Count packet types
            if packet.haslayer(TCP):
                tcp_packets += 1
            elif packet.haslayer("UDP"):
                udp_packets += 1

            # Collect packet properties
            packet_lengths.append(len(packet))
            if packet.haslayer(TCP):
                tcp_flags.extend(list(packet[TCP].flags))

        # Compute statistical measures for packet lengths
        mean_length = sum(packet_lengths) / total_packets
        max_length = max(packet_lengths)
        min_length = min(packet_lengths)
        std_dev_length = (sum((x - mean_length) ** 2 for x in packet_lengths) / total_packets) ** 0.5

        # Compute statistical measures for TCP flags
        tcp_flag_counts = {flag: tcp_flags.count(flag) for flag in set(tcp_flags)}

        # Print packet type counts
        print("Packet Type Counts:")
        print(f"Total Packets: {total_packets}")
        print(f"TCP Packets: {tcp_packets}")
        print(f"UDP Packets: {udp_packets}")

        # Print statistical analysis results for packet lengths
        print("\nPacket Length Analysis:")
        print(f"Mean Length: {mean_length}")
        print(f"Maximum Length: {max_length}")
        print(f"Minimum Length: {min_length}")
        print(f"Standard Deviation: {std_dev_length}")

        # Print statistical analysis results for TCP flags
        print("\nTCP Flag Analysis:")
        for flag, count in tcp_flag_counts.items():
            print(f"{flag}: {count} occurrences")

    except Exception as e:
        print(f"An error occurred during packet analysis: {e}")

if __name__ == "__main__":
    pcap_file = "captured_packets.pcap"
    print(f"Analyzing packets from file: {pcap_file}")
    analyze_packets(pcap_file)
