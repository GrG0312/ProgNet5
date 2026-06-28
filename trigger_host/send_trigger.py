#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, sendp, sniff

IFACE      = "eth0"
CLIENT_MAC = "00:00:00:00:00:01"

FLAG_NAMES = {0x02: "SYN", 0x12: "SYN-ACK", 0x10: "ACK", 0x11: "FIN+ACK", 0x01: "FIN"}

def flag_name(f):
    return FLAG_NAMES.get(f, f"0x{f:02X}")

print("=== TCP Handshake Trigger ===")
print("Sending trigger packet (EtherType=0xFFFE) on eth0...")
sendp(Ether(src=CLIENT_MAC, dst=CLIENT_MAC, type=0xFFFE), iface=IFACE, verbose=False)
print("Trigger sent. Sniffing for TCP packets (5 seconds)...")
print()

packets = sniff(iface=IFACE, filter="tcp", timeout=5)

if packets:
    print(f"Captured {len(packets)} TCP packet(s):")
    for p in packets:
        if p.haslayer(TCP):
            t = p[TCP]
            i = p["IP"] if p.haslayer(IP) else None
            src = i.src if i else "?"
            dst = i.dst if i else "?"
            print(f"  [{src}:{t.sport} -> {dst}:{t.dport}]  flags={flag_name(t.flags)}  seq={t.seq}  ack={t.ack}")
else:
    print("No TCP packets captured.")
