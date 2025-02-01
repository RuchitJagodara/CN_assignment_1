from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import matplotlib.pyplot as plt

total_bytes = 0
sizes = []
flows_data = defaultdict(int)
src_dict = defaultdict(int)
dst_dict = defaultdict(int)
start_time = None
end_time = None
packet_count = 0

file_name = None
file_name_ip = None
file_name_tcp_checksum = None

local_host_port = None
company_name_found = False
local_host_ip = None

def handle_packet(pkt):
    global total_bytes, sizes, flows_data, src_dict, dst_dict
    global start_time, end_time, packet_count
    global file_name, file_name_ip, file_name_tcp_checksum
    global local_host_port, local_host_ip, company_name_found

    if start_time is None:
        start_time = pkt.time

    length = len(pkt)
    total_bytes += length
    sizes.append(length)

    ip_layer = pkt.getlayer(IP)
    tcp_layer = pkt.getlayer(TCP)
    udp_layer = pkt.getlayer(UDP)

    if ip_layer:
        protocol_layer = tcp_layer or udp_layer
        src_port = protocol_layer.sport if protocol_layer else 0
        dst_port = protocol_layer.dport if protocol_layer else 0
        src_key = f"{ip_layer.src}:{src_port}"
        dst_key = f"{ip_layer.dst}:{dst_port}"
        flows_data[(src_key, dst_key)] += length

        src_dict[ip_layer.src] += 1
        dst_dict[ip_layer.dst] += 1

        # Check for special data in Raw payload
        if tcp_layer and pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            # Q1 - search for file name
            if b"The name of file is = " in raw_data and file_name is None:
                file_name = ((raw_data.split(b"The name of file is = ")[1]).split()[0]).strip().decode(errors='ignore')
                file_name_ip = ip_layer.src
                file_name_tcp_checksum = tcp_layer.chksum
            # Q3 - search for company of phone request from localhost
            if b"Company of phone is = " in raw_data and not company_name_found:
                local_host_port = tcp_layer.sport
                company_name_found = True
                local_host_ip = ip_layer.src


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

    if file_name:
        print("-"*50)
        print("Q1) Found file name:", file_name)
        print("    TCP checksum of that packet:", file_name_tcp_checksum)
        print("    Source IP of that packet:", file_name_ip)
        print("Q2) Number of packets with that IP:", src_dict[file_name_ip])

    if company_name_found:
        print("-"*50)
        print("Q3) Port used by localhost:", local_host_port)
        print("    Number of packets from localhost:", src_dict[local_host_ip])



if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: sudo python sniffer.py <interface>")
        sys.exit(1)
    iface = sys.argv[1]
    print(f"Listening on interface: {iface}")
    try:
        sniff(iface=iface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        pass
    analyze_results()