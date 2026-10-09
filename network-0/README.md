# HexDojo Module 0 — disposable-VM workshop

This original exercise is for a dedicated Linux VM operated through its hypervisor console. Containers share the VM's kernel. Do not run it on a production host or treat it as a hosted multi-tenant sandbox. Source/configuration checks have been performed; live VM execution and escape-resistance testing have not yet been performed.

## Setup

1. Create a fresh, supported Linux VM. Suggested starting allocation: 2 vCPUs, 2 GB RAM, 12 GB disk. Do not attach shared folders, clipboard integration, personal credentials, or a bridged LAN adapter.
2. With temporary NAT connectivity, install Docker Engine and the Compose plugin from https://docs.docker.com/engine/install/ and install Python 3.
3. Unpack this kit inside the VM. Run `docker compose build`. Rebuild if you used an earlier kit: the fresh challenge needs the new packet-probe script in the image. Base images and packages need download access at build time. The workshop image uses a mutable base tag; hosted releases require immutable digests and review.
4. Snapshot the prepared VM. Disconnect its external network adapter. Use the hypervisor console for the remaining steps. The lab must not reach your physical LAN or Internet.
5. Run `docker compose up -d`, then `docker compose ps` and `python3 verify_lab.py`.

## Topology

| Machine | Address | Route |
| --- | --- | --- |
| client | 10.10.0.10/24 | 10.20.0.0/24 via 10.10.0.1 |
| router | 10.10.0.1/24 and 10.20.0.1/24 | Connected routes; forwarding enabled |
| server | 10.20.0.10/24 | 10.10.0.0/24 via 10.20.0.1 |

Docker's guest bridge addresses are .254, not the router's .1 addresses. Internal networks do not prove isolation from the guest host. No ports or host directories are published. NET_ADMIN and NET_RAW are enabled only in the workshop containers. Read-only root filesystems, no-new-privileges, bounded tmpfs, PID/memory/CPU controls, and disabled IPv6 are defense in depth; they are not VM isolation.

Reverse-path filtering is explicitly disabled in the workshop network namespaces so the broken-route exercise is about routing rather than an inherited reverse-path filter. This is a teaching configuration inside the disconnected VM, not a recommended production router policy.

## Observe

Run `docker compose exec client ip -br addr` and `docker compose exec client ip route`. Repeat on the router and server. Check the router with `docker compose exec router cat /proc/sys/net/ipv4/ip_forward` and `docker compose exec router iptables -S FORWARD`.

Run `docker compose exec client ping -c 3 -W 2 10.20.0.10` and `docker compose exec client curl --fail --max-time 3 http://10.20.0.10:8000/`.

Capture in console one with `docker compose exec client /opt/lab/capture.sh`. While it runs, issue the ping in a second VM console. Then run `docker compose exec client python3 /opt/lab/inspect_capture.py /work/icmp.pcap`. Copy evidence with `docker compose cp client:/work/icmp.pcap ./icmp.pcap`. The capture stops after six ICMP packets or 15 seconds; packet loss may leave a partial capture.

## Diagnose and repair

Delete the return route: `docker compose exec server ip route del 10.10.0.0/24`. Repeat ping; inspect the route tables and capture before repairing it. Restore with `docker compose exec server ip route replace 10.10.0.0/24 via 10.20.0.1`. Repeat ping and `python3 verify_lab.py`.

Explain why the original request can arrive but its reply fails. Preserve matching ICMP request/reply evidence after repair. Do not claim the local verifier proves hypervisor or cross-tenant security.

## Reset

Copy evidence first: `/work` is temporary. `docker compose down` destroys the containers and their temporary data. `docker compose up -d` recreates the initial topology. Reset the whole VM using your prepared snapshot, or delete it when finished.


## Release scope

This public package contains the guided workshop only. Randomized challenges, attestation, and hidden grading material are excluded. The local verifier reports practice evidence and cannot award account mastery.
