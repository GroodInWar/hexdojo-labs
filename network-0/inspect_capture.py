#!/usr/bin/env python3
"""Inspect the bounded workshop PCAP. No packets are transmitted."""
import sys
import os
from scapy.all import IP, ICMP, rdpcap

def main():
    path = sys.argv[1] if len(sys.argv) == 2 else "/work/icmp.pcap"
    requests, replies = set(), set()
    client = os.environ.get("CLIENT_IP", "10.10.0.10")
    server = os.environ.get("SERVER_IP", "10.20.0.10")
    for packet in rdpcap(path):
        if IP not in packet or ICMP not in packet:
            continue
        ip, icmp = packet[IP], packet[ICMP]
        print(f"{ip.src} -> {ip.dst} ICMP type={icmp.type} TTL={ip.ttl}")
        if icmp.type == 8 and ip.src == client and ip.dst == server:
            requests.add((icmp.id, icmp.seq, bytes(icmp.payload)))
        if icmp.type == 0 and ip.src == server and ip.dst == client:
            replies.add((icmp.id, icmp.seq, bytes(icmp.payload)))
    matched = requests & replies
    print(f"Matching request/reply pairs: {len(matched)}")
    if not matched:
        raise SystemExit("No complete assigned echo exchange found. Inspect routing and retry.")

if __name__ == "__main__":
    main()
