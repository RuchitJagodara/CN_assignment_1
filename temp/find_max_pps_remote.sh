
#!/usr/bin/env bash

PCAP_FILE="5.pcap"
INTERFACE_VETH0="veth0"
INTERFACE_VETH1="veth1"
SNIFFER_DURATION=30
LOW=1000
HIGH=600000
BEST=0

REMOTE_USER="student"
REMOTE_HOST="192.168.1.10"
SNIFFER_SCRIPT="/home/ruchitjagodara/Education/computer_networks/packat_sniffer.py"

while [ $LOW -le $HIGH ]
do
  MID=$(( (LOW + HIGH) / 2 ))
  echo "Testing pps=$MID"

  # Remove old log if any
  rm -f /tmp/sniffer_log.txt

  # Start the sniffer (packat_sniffer.py) on the remote machine
  ssh -T ${REMOTE_USER}@${REMOTE_HOST} "sudo python ${SNIFFER_SCRIPT}" <<EOF > /tmp/sniffer_log.txt 2>&1 &
$INTERFACE_VETH1
$SNIFFER_DURATION
EOF

  # Allow sniffer startup
  sleep 2

  # Run tcpreplay at $MID pps
  REPLAY_LOG=$(sudo tcpreplay -q -i "$INTERFACE_VETH0" --pps "$MID" "$PCAP_FILE" 2>&1)

  # Wait for sniffer to exit
  wait

  # Extract sent packets from tcpreplay logs
  # Usually found in a line like "Actual: 12345 packets ( ... ) sent ..."
  SENT=$(echo "$REPLAY_LOG" | grep -oP "(?<=Actual:\s)\d+")
  if [ -z "$SENT" ]; then SENT=0; fi

  # Extract captured packets from sniffer logs
  # Usually found in "Total packets transferred: 12345"
  CAPTURED=$(grep "Total packets transferred:" /tmp/sniffer_log.txt | awk '{print $5}')
  if [ -z "$CAPTURED" ]; then CAPTURED=0; fi

  echo "Packets sent: $SENT, captured: $CAPTURED"

  # Extract sent bytes from tcpreplay logs (e.g., "... (364640870 bytes) sent ...")
  SENT_BYTES=$(echo "$REPLAY_LOG" | grep -oP "(?<=\()\d+(?=\sbytes\))")
  if [ -z "$SENT_BYTES" ]; then SENT_BYTES=0; fi

  # Extract captured bytes from sniffer logs
  # The line looks like: "Total data transferred: 364640870 bytes"
  CAPTURED_BYTES=$(grep "Total data transferred:" /tmp/sniffer_log.txt | awk '{print $4}')
  if [ -z "$CAPTURED_BYTES" ]; then CAPTURED_BYTES=0; fi

  # Allow a small epsilon for minor discrepancies
  EPSILON=0
  DIFF=$(( SENT_BYTES - CAPTURED_BYTES ))
  ABS_DIFF=${DIFF#-}  # absolute value

  CAPTURED_PACKETS=$(grep "Total packets transferred:" /tmp/sniffer_log.txt | awk '{print $4}')

  echo "Bytes sent: $SENT_BYTES, captured: $CAPTURED_BYTES"
  echo "Packets sent: $SENT, captured: $CAPTURED_PACKETS"

  # If difference is within epsilon => no data loss => search higher
  if [ "$ABS_DIFF" -le "$EPSILON" ]; then
    BEST=$MID
    LOW=$((MID+1))
  else
    HIGH=$((MID-1))
  fi

  echo "----------------------------------"
done

echo "Best pps with no data loss: $BEST"
echo "Done."