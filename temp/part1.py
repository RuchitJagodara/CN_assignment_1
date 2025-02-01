import socket
import struct
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import os
import threading

# Global variables for metrics
total_bytes = 0
packet_sizes = []
unique_pairs = set()
source_flow_count = defaultdict(int)
destination_flow_count = defaultdict(int)
data_transfer = defaultdict(int)  # Mapping of (src_mac, dst_mac) to data transferred
capture_duration = 0

def parse_ethernet_header(packet):
    """Parses the Ethernet header for MAC addresses."""
    eth_header = struct.unpack("!6s6sH", packet[:14])
    src_mac = ':'.join('%02x' % b for b in eth_header[1])
    dst_mac = ':'.join('%02x' % b for b in eth_header[0])
    return src_mac, dst_mac

def process_packet(packet):
    """Processes any captured raw packet and updates metrics."""
    global total_bytes, packet_sizes, unique_pairs, source_flow_count, destination_flow_count, data_transfer

    total_bytes += len(packet)
    packet_sizes.append(len(packet))

    # Parse only Ethernet MACs
    src_mac, dst_mac = parse_ethernet_header(packet)
    pair = (src_mac, dst_mac)

    unique_pairs.add(pair)
    source_flow_count[src_mac] += 1
    destination_flow_count[dst_mac] += 1
    data_transfer[pair] += len(packet)

def display_metrics():
    """Displays packet metrics and generates a histogram of packet sizes."""
    global total_bytes, packet_sizes, capture_duration
    total_packets = len(packet_sizes)
    min_size = min(packet_sizes) if packet_sizes else 0
    max_size = max(packet_sizes) if packet_sizes else 0
    avg_size = np.mean(packet_sizes) if packet_sizes else 0
    duration = capture_duration if capture_duration > 0 else 1
    pps = total_packets / duration
    mbps = (total_bytes * 8 / (1024 * 1024)) / duration

    print("\n=== Packet Metrics ===")
    print(f"Total data transferred: {total_bytes} bytes")
    print(f"Total packets transferred: {total_packets}")
    print(f"Minimum packet size: {min_size} bytes")
    print(f"Maximum packet size: {max_size} bytes")
    print(f"Average packet size: {avg_size:.2f} bytes")
    print(f"Capture speed: {pps:.2f} pps, {mbps:.2f} Mbps")

    plt.hist(packet_sizes, bins=20, edgecolor='k', alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid(True)
    plt.show()

def display_unique_pairs():
    """Displays unique source-destination pairs (MAC-based)."""
    print("\n=== Unique Source-Destination Pairs ===")
    cnt = 0
    for pair in unique_pairs:
        if cnt == 10:
            break
        print(f"Source MAC: {pair[0]} -> Destination MAC: {pair[1]}")
        cnt += 1
    print(f"Total unique pairs: {len(unique_pairs)}")

def display_flows():
    """Displays source and destination flow counts (MAC-based)."""
    print("\n=== Flows by Source MAC ===")
    cnt = 0
    for src, count in source_flow_count.items():
        if cnt == 10:
            break
        print(f"{src}: {count} flows")
        cnt += 1
    print(f"Total unique source MACs: {len(source_flow_count)}")

    print("\n=== Flows by Destination MAC ===")
    cnt = 0
    for dst, count in destination_flow_count.items():
        if cnt == 10:
            break
        print(f"{dst}: {count} flows")
        cnt += 1
    print(f"Total unique destination MACs: {len(destination_flow_count)}")

def find_top_transfer():
    """Finds the (src_mac, dst_mac) pair that transferred the most data."""
    if not data_transfer:
        print("\nNo data transfer detected.")
        return

    top_pair = max(data_transfer, key=data_transfer.get)
    print("\n=== Top Source-Destination Pair by Data Transferred ===")
    print(f"Source MAC: {top_pair[0]} -> Destination MAC: {top_pair[1]}: {data_transfer[top_pair]} bytes")

def main():
    interface = input("Enter the interface to listen on (e.g., eth0, wlan0): ")
    duration = int(input("Enter the capture duration (in seconds): "))
    pcap_file = input("Enter the path to the .pcap file for replay (e.g., X.pcap): ")

    def replay_pcap():
        replay_command = f"sudo tcpreplay --pps=100000  -i {interface} {pcap_file}"
        print(f"\nStarting packet replay with the following command:\n{replay_command}")
        os.system(replay_command)

    def sniff_packets():
        print(f"\nListening for packets on interface {interface} for {duration} seconds...")
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        raw_socket.bind((interface, 0))
        capture_start_time = time.time()
        start_time = time.time()
        while time.time() - start_time < duration:
            raw_packet = raw_socket.recvfrom(65565)[0]
            process_packet(raw_packet)
        capture_end_time = time.time()
        global capture_duration
        capture_duration = capture_end_time - capture_start_time

    replay_thread = threading.Thread(target=replay_pcap)
    sniff_thread = threading.Thread(target=sniff_packets)

    replay_thread.start()
    sniff_thread.start()

    replay_thread.join()
    sniff_thread.join()

    display_metrics()
    display_unique_pairs()
    display_flows()
    find_top_transfer()

if __name__ == "__main__":
    main()
