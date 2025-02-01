sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo python packet_sniffer.py
sudo tcpreplay -i veth0 --pps 40000 5.pcap

# deleting the virtual interface
sudo ip link delete veth0
