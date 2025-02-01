# Packet Sniffer Instructions

1. Install dependencies.
   ```
   sudo apt update
   sudo apt upgrade
   sudo apt install python3-scapy
   sudo apt install python3-matplotlib
   ```  
2. First, we need a virtual interface to work on so that our code does not capture any extra pcap packets so the script set_virtual_interface.sh includes that script so first of run that and give it the root user permissions, so run below commands on a terminal
   ```
   chmod +x set_virtual_interface.sh
   sudo ./set_virtual_interface.sh
   ```
3. In a terminal, run the sniffer: (here, note that while running on a different machine you have to connect two machines using ethernet cable and then in the interface you have to specify the interface which is related to ethernet port of your machine),
   ```
   chmod +x test_sniffer.sh
   sudo ./test_sniffer.sh veth1
   ```
4. In a separate terminal, Run tcpreplay on the same machine (or another machine) to replay the chosen pcap:
   ```
   sudo tcpreplay --pps 1900 --intf1=veth0 5.pcap
   ```
5. Press Ctrl+C when done(when the terminal on which tcpreplay is running shows any output). The console output will show total bytes, packet counts, packet sizes, 
   flow dictionaries, and approximate capture speed based on replay traffic.

Similarly run the same commands for the part 2 just change the file name in the test_sniffer.sh script and it will work similarly for part 2 (i.e. replace the name sniffer.py with question_2.py).

6. Now, for the 3rd questions' first part, first start capturing packets using wireshark on the wifi, to open the wireshark you can run below command,
   ```
   sudo apt install wireshark
   sudo wireshark
   ```
7. After visiting few websites, first stop the capturing packets from wireshark and save the packets in a pcap file, save the file using the name `question3.pcapng`.
8. Now, run the script question3_1.py using below command (please change the file path if required):
   ```
   python3 question3_1.py
   ```
