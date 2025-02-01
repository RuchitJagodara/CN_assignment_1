#!/usr/bin/env bash

if [ $# -lt 1 ]; then
  echo "Usage: sudo ./test_sniffer.sh <interface>"
  exit 1
fi

sudo python3 sniffer.py "$1"