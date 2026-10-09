#!/bin/sh
set -eu
client_ip=${CLIENT_IP:-10.10.0.10}
iface=$(ip -o -4 addr show | awk -v address="$client_ip" 'split($4, parts, "/") && parts[1] == address {print $2}')
test -n "$iface" || { printf '%s\n' 'Client address not found.' >&2; exit 1; }
printf '%s\n' 'Capturing ICMP for up to 15 seconds. Run ping in a second VM console.'
# -Z root avoids tcpdump's default user transition, which needs extra capabilities.
# The process is already inside the restricted, disposable lab guest.
set +e
timeout 15 tcpdump -Z root -U -ni "$iface" -c 6 -w /work/icmp.pcap icmp
result=$?
set -e
case "$result" in 0|124) printf '%s\n' 'Capture saved at /work/icmp.pcap.' ;; *) exit "$result" ;; esac
