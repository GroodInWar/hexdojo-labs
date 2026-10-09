#!/usr/bin/env python3
"""Bounded fresh ICMP probe, run only in the assigned workshop client."""
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
from scapy.all import AsyncSniffer, ICMP, IP, Raw, conf, sr, wrpcap


def exchange(nonce):
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ValueError("Expected a 32-byte hexadecimal probe nonce.")
    client = os.environ.get("CLIENT_IP", "10.10.0.10")
    server = os.environ.get("SERVER_IP", "10.20.0.10")
    for address in (client, server):
        if ipaddress.ip_address(address) not in ipaddress.ip_network("10.0.0.0/8"):
            raise ValueError("Probe endpoints must belong to the assigned private lab.")
    payload = ("hexdojo-module0:" + nonce).encode("ascii")
    identifier = secrets.randbelow(65536)
    ready = threading.Event()
    complete = threading.Event()
    captured = []

    def assigned(packet):
        return (IP in packet and ICMP in packet
                and (packet[IP].src, packet[IP].dst) in {(client, server), (server, client)}
                and packet[ICMP].type in (0, 8)
                and packet[ICMP].id == identifier and packet[ICMP].seq in (1, 2, 3)
                and bytes(packet[ICMP].payload) == payload)

    def collect(packet):
        if len(captured) < 24:
            captured.append(packet)
        if {p[ICMP].seq for p in captured if p[ICMP].type == 0} == {1, 2, 3}:
            complete.set()

    sniffer = AsyncSniffer(iface=conf.route.route(server)[0], store=False,
                           lfilter=assigned, prn=collect, timeout=8,
                           started_callback=ready.set)
    sniffer.start()
    try:
        if not ready.wait(2):
            raise RuntimeError("Packet capture could not start.")
        requests = [IP(src=client, dst=server, ttl=64)
                    / ICMP(type=8, id=identifier, seq=sequence) / Raw(payload)
                    for sequence in (1, 2, 3)]
        sr(requests, timeout=3, retry=0, verbose=0)
        complete.wait(0.75)
    finally:
        if sniffer.running:
            sniffer.stop()
        sniffer.join()
    wrpcap("/work/assessment.pcap", captured)
    sent = {p[ICMP].seq for p in captured if p[ICMP].type == 8 and p[IP].src == client}
    received = {p[ICMP].seq for p in captured if p[ICMP].type == 0 and p[IP].src == server}
    return {"probeNonce": nonce, "requestSequences": sorted(sent),
            "replySequences": sorted(received), "matchedPairs": len(sent & received),
            "capturePath": "/work/assessment.pcap"}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Usage: probe_exchange.py NONCE")
        print(json.dumps(exchange(sys.argv[1])))
    except Exception as error:
        print(json.dumps({"error": str(error)}))
        sys.exit(2)
