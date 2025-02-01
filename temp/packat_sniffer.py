import socket
from matplotlib import pyplot as plt
import time

total_data_transferred = 0  # bytes
total_packets_transferred = 0
packet_sizes = []
unique_pairs = set()
source_flow_count = {}
destination_flow_count = {}
data_transfer = {}
capture_duration = 0

# Part 1
def packets_metrics():
    min_size = min(packet_sizes) if packet_sizes else 0
    max_size = max(packet_sizes) if packet_sizes else 0
    avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

    print("\n=== Packet Metrics ===")
    print(f"Total data transferred: {total_data_transferred} bytes")
    print(f"Total packets transferred: {total_packets_transferred}")
    print(f"Minimum packet size: {min_size} bytes")
    print(f"Maximum packet size: {max_size} bytes")
    print(f"Average packet size: {avg_size:.2f} bytes")

    duration = capture_duration if capture_duration > 0 else 1
    pps = total_packets_transferred / duration
    mbps = (total_data_transferred * 8 / (1024 * 1024)) / duration
    print(f"Capture speed: {pps:.2f} pps, {mbps:.2f} Mbps")

    # Plotting the histogram of packet sizes in the main thread
    plt.figure()  # Ensure a new figure is created
    plt.hist(packet_sizes, bins=20, edgecolor='k', alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid(True)
    plt.savefig("packet_sizes.png")
    plt.close()

# Part 2 and part 3
def process_ip(raw_packet):
    ip_header = raw_packet[14:34]  # Extract the IP header
    source_ip = ".".join(map(str, ip_header[12:16]))
    destination_ip = ".".join(map(str, ip_header[16:20]))

    unique_pairs.add((source_ip, destination_ip))

    # Count the number of flows for each source and destination IP
    source_flow_count[source_ip] = source_flow_count.get(source_ip, 0) + 1
    destination_flow_count[destination_ip] = destination_flow_count.get(destination_ip, 0) + 1

    # Calculate the data transferred for each flow
    data_transfer[(source_ip, destination_ip)] = data_transfer.get((source_ip, destination_ip), 0) + len(raw_packet)

# part 2 and part 3
def print_ip_metrics():
    print("\n=== IP Metrics ===")

    # printing few of the unique pairs
    print(f"Below are few of the unique pairs: ")
    for i, pair in enumerate(list(unique_pairs)[:5]):
        print(f"{i+1}. {pair}")
    
    print(f"Total unique IP pairs: {len(unique_pairs)}")

    print("\n\nBelow are the source and destination IP flows: ")
    for source_ip, count in source_flow_count.items():
        print(f"Source IP: {source_ip}, Flows: {count}")
    print("Total source IP flows: ", len(source_flow_count))

    for destination_ip, count in destination_flow_count.items():
        print(f"Destination IP: {destination_ip}, Flows: {count}")
    print("Total destination IP flows: ", len(destination_flow_count))

    print("\n\nBelow are the data transfer per flow: ")
    for pair, data in data_transfer.items():
        print(f"Source IP: {pair[0]}, Destination IP: {pair[1]}, Data transfer: {data}")

    print("Total data transfer: ", sum(data_transfer.values()))


    print("\n\nThe source-destination pair with the maximum data transfer: ")
    max_data_transfer = max(data_transfer, key=data_transfer.get)
    print(f"Source IP: {max_data_transfer[0]}, Destination IP: {max_data_transfer[1]}, Data transfer: {data_transfer[max_data_transfer]}")

# Part 3


def process_packet(raw_packet):
    global total_data_transferred, total_packets_transferred, packet_sizes, unique_pairs, source_flow_count, destination_flow_count, data_transfer

    total_data_transferred += len(raw_packet)
    total_packets_transferred += 1
    packet_sizes.append(len(raw_packet))

def raw_packet_sniffer(interface, duration=10):
    global capture_duration
    start_time = time.time()
    # Requires running as root on most systems
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer_socket.bind((interface, 0))  # Bind to the specified interface and port
    sniffer_socket.settimeout(0.5)  # Set timeout to avoid waiting indefinitely

    print(f"Sniffing started on interface {interface}.")

    while True:
        try:
            raw_packet, _ = sniffer_socket.recvfrom(65535)
            process_packet(raw_packet)
        except socket.timeout:
            pass

        if time.time() - start_time > duration:
            break

    capture_duration = time.time() - start_time
    print("Sniffing finished. Duration: {} seconds".format(capture_duration))
    sniffer_socket.close()

if __name__ == "__main__":
    interface = input("Enter the interface to listen on (e.g., eth0, wlan0): ")
    duration = int(input("Enter the capture duration (in seconds): "))


    raw_packet_sniffer(interface, duration)

    # Display packet metrics
    packets_metrics()