# Programmed in 2024 by Karthik P.
import json
import re

from scapy.all import sniff, TCP, wrpcap
from scapy.layers.inet import IP

# Regular expression pattern for detecting common file signatures
FILE_SIGNATURES = {
    "JPEG": rb"\xFF\xD8\xFF",
    "PNG": rb"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
    "GIF": rb"\x47\x49\x46\x38",
    "PDF": rb"\x25\x50\x44\x46",
    "ZIP": rb"\x50\x4B\x03\x04",
}

def detect_file_type(payload):
    for file_type, signature in FILE_SIGNATURES.items():
        if re.search(signature, payload):
            return file_type
    return "Unknown"

def basic_data_validation(payload):
    # Validate that the payload length is within a certain range
    if not payload:
        print("Payload is empty")
    if len(payload) > 1000:
        print("Payload length exceeds maximum limit (1000 bytes)")
    elif len(payload) < 10:
        print("Payload length is too short (less than 10 bytes)")
    if payload[:4] != payload[-4:]:
        print("Payload start and end do not match")
    try:
        json.loads(payload)
    except ValueError:
        print("Payload is not in valid JSON format")

def packet_handler(packet):
    try:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = packet[TCP].sport if TCP in packet else "N/A"
        destination_port = packet[TCP].dport if TCP in packet else "N/A"
        protocol = packet[IP].proto
        timestamp = packet.time
        payload = packet[TCP].payload

        # Perform basic data validation on the payload
        basic_data_validation(payload)

        # Print packet summary and payload
        print(f"Source IP: {source_ip}, Destination IP: {destination_ip}, "
              f"Source Port: {source_port}, Destination Port: {destination_port}, "
              f"Protocol: {protocol}, Timestamp: {timestamp}")
        print("Payload:", payload)

    except Exception as e:
        print(f"Error processing packet: {e}")

    # Append packet to pcap file
    wrpcap("captured_packets.pcap", packet, append=True)


def capture_packets():
    try:
        # Sniff packets on the default network interface (change iface parameter as needed)
        sniff(prn=packet_handler, count=10)  # Capture 10 packets and call packet_handler for each
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    print("Starting packet capture...")
    capture_packets()
    print("Packet capture complete.")
