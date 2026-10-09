#!/bin/sh
set -eu
CLIENT_LAN=${CLIENT_LAN:-10.10.0.0/24}
SERVER_LAN=${SERVER_LAN:-10.20.0.0/24}
SERVER_IP=${SERVER_IP:-10.20.0.10}
CLIENT_GATEWAY=${CLIENT_GATEWAY:-10.10.0.1}
SERVER_GATEWAY=${SERVER_GATEWAY:-10.20.0.1}
# No external default route is needed. NET_ADMIN applies to this guest namespace.
while ip route del default 2>/dev/null; do :; done
case "${1:-}" in
  client)
    ip route replace "$SERVER_LAN" via "$CLIENT_GATEWAY"
    exec sleep infinity
    ;;
  router)
    iptables -P FORWARD DROP
    iptables -F FORWARD
    iptables -A FORWARD -s "$CLIENT_LAN" -d "$SERVER_LAN" -j ACCEPT
    iptables -A FORWARD -s "$SERVER_LAN" -d "$CLIENT_LAN" -j ACCEPT
    exec sleep infinity
    ;;
  server)
    ip route replace "$CLIENT_LAN" via "$SERVER_GATEWAY"
    exec python3 -m http.server 8000 --bind "$SERVER_IP" --directory /srv
    ;;
  *) printf '%s\n' 'Expected client, router, or server.' >&2; exit 2 ;;
esac
