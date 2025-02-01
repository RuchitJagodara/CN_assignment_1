from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import matplotlib.pyplot as plt

total_bytes = 0
sizes = []
flows_data = defaultdict(int)  # (srcIP:port, dstIP:port) -> total bytes
src_dict = defaultdict(int)    # srcIP -> number of flows initiated
dst_dict = defaultdict(int)    # dstIP -> number of flows received
start_time = None
end_time = None
packet_count = 0

def handle_packet(pkt):
    global total_bytes, sizes, flows_data, src_dict, dst_dict
    global start_time, end_time, packet_count

    if start_time is None:
        start_time = pkt.time

    length = len(pkt)
    total_bytes += length
    sizes.append(length)

    ip_layer = pkt.getlayer(IP)
    if ip_layer:
        protocol_layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        src_port = protocol_layer.sport if protocol_layer else 0
        dst_port = protocol_layer.dport if protocol_layer else 0
        src_key = f"{ip_layer.src}:{src_port}"
        dst_key = f"{ip_layer.dst}:{dst_port}"
        flows_data[(src_key, dst_key)] += length

        src_dict[ip_layer.src] += 1
        dst_dict[ip_layer.dst] += 1

    packet_count += 1
    end_time = pkt.time

def analyze_results():
    if packet_count == 0:
        print("No packets captured.")
        return

    duration = end_time - start_time if end_time and start_time else 0
    total_pkts = packet_count
    min_size = min(sizes)
    max_size = max(sizes)
    avg_size = sum(sizes) / total_pkts

    print("Total data (bytes):", total_bytes)
    print("Total packets:", total_pkts)
    print(f"Packet size -> min: {min_size}, max: {max_size}, avg: {avg_size:.2f}")

    print("-"*50)
    print(f"Unique (src:port -> dst:port) pairs: {len(flows_data.keys())}")
    print("\nBelow are some of the Unique (src:port -> dst:port) pairs:")
    for key, value in list(flows_data.items())[:5]:
        print(f"Flow data (src:port {key[0]} -> dst:port {key[1]}))")

    print("-"*50)
    print(f"Below are some of the source IP address and flows for that IP address:")
    for key, value in list(src_dict.items())[:5]:
        print(f"Source dictionary (IP -> #flows): {key} -> {value}")

    print("-"*50)
    print(f"Below are some of the destination IP address and flows for that IP address:")
    for key, value in list(dst_dict.items())[:5]:
        print(f"Destination dictionary (IP -> #flows): {key} -> {value}")
    top_flow = max(flows_data, key=flows_data.get)

    print("-"*50)
    print("Flow with most data:", top_flow, "->", flows_data[top_flow], "bytes")

    print("-"*50)
    pps = total_pkts / duration if duration > 0 else 0
    mbps = (total_bytes * 8 / 1_000_000) / duration if duration > 0 else 0
    print(f"Approx. speed: {pps:.2f} pps, {mbps:.2f} Mbps")


    # Also, show the distribution of packet sizes (e.g., by plotting a histogram of packet sizes).
    plt.hist(sizes, bins=range(0, 2000, 100))
    plt.xlabel("Packet size")
    plt.ylabel("Frequency")
    plt.title("Packet size distribution")
    plt.savefig("packet_size_distribution.png")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: sudo python sniffer.py <interface>")
        sys.exit(1)
    iface = sys.argv[1]
    print(f"Listening on interface: {iface}")
    try:
        # filter out DHCP, MDNS, ICMPv6
        sniff(iface=iface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        pass
    analyze_results()