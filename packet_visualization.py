# Programmed in 2024 by Karthik P.
import matplotlib.pyplot as plt
from scapy.all import rdpcap

def load_packets(pcap_file):
    # Load the captured packets from the pcap file
    try:
        packets = rdpcap(pcap_file)
        return packets
    except Exception as e:
        print(f"Error loading pcap file: {e}")
        return None

def plot_packet_counts(packets):
    # Count the number of TCP and UDP packets
    tcp_count = sum(1 for pkt in packets if pkt.haslayer('TCP'))
    udp_count = sum(1 for pkt in packets if pkt.haslayer('UDP'))

    # Plot the packet counts for TCP and UDP
    labels = ['TCP', 'UDP']
    counts = [tcp_count, udp_count]

    plt.bar(labels, counts, color=['blue', 'green'])
    plt.xlabel('Packet Type')
    plt.ylabel('Packet Count')
    plt.title('Packet Counts for TCP and UDP')
    plt.show()

def plot_packet_lengths(packets):
    # Extract packet lengths
    lengths = [len(pkt) for pkt in packets]

    # Plot the distribution of packet lengths
    plt.hist(lengths, bins=20, color='orange', edgecolor='black')
    plt.xlabel('Packet Length')
    plt.ylabel('Frequency')
    plt.title('Distribution of Packet Lengths')
    plt.show()

def plot_tcp_flags(packets):
    # Count occurrences of TCP flags
    tcp_flags = {}
    for pkt in packets:
        if pkt.haslayer('TCP'):
            flags = pkt['TCP'].flags
            for flag in flags:
                if flag in tcp_flags:
                    tcp_flags[flag] += 1
                else:
                    tcp_flags[flag] = 1

    # Plot the occurrences of TCP flags
    labels = list(tcp_flags.keys())
    counts = list(tcp_flags.values())

    plt.bar(labels, counts, color='red')
    plt.xlabel('TCP Flags')
    plt.ylabel('Occurrence Count')
    plt.title('Occurrences of TCP Flags')
    plt.show()

if __name__ == "__main__":
    pcap_file = "captured_packets.pcap"  # Assuming pcap file is saved in the same folder as this script
    packets = load_packets(pcap_file)

    if packets:
        plot_packet_counts(packets)
        plot_packet_lengths(packets)
        plot_tcp_flags(packets)
