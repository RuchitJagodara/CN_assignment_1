sudo ip link add veth0 type veth peer name veth1
sudo nmcli dev set veth0 managed no
sudo nmcli dev set veth1 managed no
sudo ip link set veth0 up
sudo ip link set veth1 up