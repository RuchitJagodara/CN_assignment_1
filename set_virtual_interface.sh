sudo ip link add veth0 type veth peer name veth1
sudo nmcli dev set veth0 managed no
sudo nmcli dev set veth1 managed no
sudo ip link set veth0 up
sudo ip link set veth1 up
# sudo ip netns add ns1
# sudo ip link set veth0 netns ns1
# sudo ip netns exec ns1 ip link set veth0 up
# sudo ip link set veth1 netns ns1
# sudo ip netns exec ns1 ip link set veth1 up