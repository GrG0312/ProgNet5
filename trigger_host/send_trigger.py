#!/usr/bin/env python3
from scapy.all import Ether, sendp

IFACE      = "eth0"
CLIENT_MAC = "00:00:00:00:00:01"

print("Sending TCP handshake trigger (EtherType=0xFFFE)...")
sendp(Ether(src=CLIENT_MAC, dst=CLIENT_MAC, type=0xFFFE), iface=IFACE, verbose=False)
print("Trigger sent. Check shared/client.log and shared/server.log for the handshake trace.")
