# Packet Sniffer Instructions

1. Install dependencies (e.g., `pip install scapy`).  
2. Run tcpreplay on the same machine (or another machine) to replay the chosen pcap:
   ```
   sudo tcpreplay --intf1=<interface> X.pcap
   ```
3. In a separate terminal, run the sniffer:
   ```
   chmod +x test_sniffer.sh
   sudo ./test_sniffer.sh <interface>
   ```
4. Press Ctrl+C when done. The console output will show total bytes, packet counts, packet sizes, 
   flow dictionaries, and approximate capture speed based on replay traffic.