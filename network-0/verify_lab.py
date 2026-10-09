#!/usr/bin/env python3
"""Structured local diagnostics. This student-owned report cannot award mastery."""
import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULTS = {
    "CLIENT_LAN": "10.10.0.0/24", "SERVER_LAN": "10.20.0.0/24",
    "CLIENT_IP": "10.10.0.10", "SERVER_IP": "10.20.0.10",
    "CLIENT_GATEWAY": "10.10.0.1", "SERVER_GATEWAY": "10.20.0.1",
    "CLIENT_BRIDGE": "10.10.0.254", "SERVER_BRIDGE": "10.20.0.254",
}


def validate_config(config):
    if set(config) != set(DEFAULTS):
        raise ValueError("Invalid lab configuration keys.")
    networks = []
    for prefix in ("CLIENT", "SERVER"):
        network = ipaddress.ip_network(config[prefix + "_LAN"])
        if network.version != 4 or network.prefixlen != 24 or not network.subnet_of(ipaddress.ip_network("10.0.0.0/8")):
            raise ValueError("Expected an assigned 10.x.x.0/24 network.")
        addresses = [ipaddress.ip_address(config[prefix + suffix]) for suffix in ("_IP", "_GATEWAY", "_BRIDGE")]
        if len(set(addresses)) != 3 or any(a not in network or a in (network.network_address, network.broadcast_address) for a in addresses):
            raise ValueError("Lab hosts, router, and bridge must have different usable addresses.")
        networks.append(network)
    if networks[0].overlaps(networks[1]):
        raise ValueError("The assigned LANs must be separate.")
    return config


class ComposeRuntime:
    def __init__(self, config=None, project="hexdojo-network-0", env_file=None):
        self.config = validate_config(dict(config or DEFAULTS))
        self.command = ["docker", "compose", "-f", str(ROOT / "compose.yaml"), "-p", project]
        if env_file is not None:
            self.command += ["--env-file", str(env_file)]
        # Shell variables otherwise override --env-file. Make the chosen case explicit.
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
        self.environment.update(self.config)

    def run(self, *args, timeout=15):
        return subprocess.run([*self.command, *args], cwd=ROOT, env=self.environment,
                              text=True, capture_output=True, timeout=timeout, check=True).stdout

    def exec(self, machine, *args):
        return self.run("exec", "-T", "--interactive=false", machine, *args)

    def inspect(self, machine):
        identifier = self.run("ps", "-q", machine).strip()
        if not identifier:
            raise ValueError("Container is missing.")
        return json.loads(subprocess.run(["docker", "inspect", identifier], cwd=ROOT,
                          env=self.environment, text=True, capture_output=True,
                          timeout=15, check=True).stdout)[0]

    def network(self, name):
        return json.loads(subprocess.run(["docker", "network", "inspect", name], cwd=ROOT,
                          env=self.environment, text=True, capture_output=True,
                          timeout=15, check=True).stdout)[0]


def tmpfs_options_safe(value, maximum):
    options = value.split(",")
    sizes = [option for option in options if option.startswith("size=")]
    if len(sizes) != 1 or not {"noexec", "nosuid", "nodev"}.issubset(options) or {"exec", "suid", "dev"}.intersection(options):
        return False
    match = re.fullmatch(r"size=(\d+)([kmg]?)", sizes[0], re.IGNORECASE)
    return bool(match and 0 < int(match[1]) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[match[2].lower()] <= maximum)


def restriction_check(runtime, machine):
    data = runtime.inspect(machine)
    host = data["HostConfig"]
    caps = {s.upper().removeprefix("CAP_") for s in host.get("CapAdd") or []}
    mounts = data.get("Mounts", [])
    tmpfs = host.get("Tmpfs") or {}
    expected_tmpfs = {"/tmp": 32 * 1024**2, "/run": 8 * 1024**2, "/work": 64 * 1024**2}
    return (data["State"]["Running"] and not host["Privileged"] and host["ReadonlyRootfs"]
            and host["NetworkMode"] != "host" and not host.get("PortBindings")
            and all(m["Type"] == "tmpfs" and m["Destination"] in expected_tmpfs for m in mounts)
            and set(tmpfs) == set(expected_tmpfs)
            and all(tmpfs_options_safe(tmpfs[path], size) for path, size in expected_tmpfs.items())
            and "ALL" in {c.upper() for c in host.get("CapDrop") or []}
            and caps == {"NET_ADMIN", "NET_RAW"}
            and "no-new-privileges:true" in (host.get("SecurityOpt") or [])
            and 0 < host["Memory"] <= 268435456 and 0 < host["PidsLimit"] <= 64
            and 0 < host["NanoCpus"] <= 500000000
            and runtime.exec(machine, "cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6").strip() == "1"
            and not runtime.exec(machine, "ip", "route", "show", "default").strip())


def network_check(runtime, machine):
    c = runtime.config
    expected = {"client": {c["CLIENT_IP"]}, "router": {c["CLIENT_GATEWAY"], c["SERVER_GATEWAY"]}, "server": {c["SERVER_IP"]}}[machine]
    networks = runtime.inspect(machine)["NetworkSettings"]["Networks"]
    if {n["IPAddress"] for n in networks.values()} != expected or len(networks) != len(expected):
        return False
    for name, interface in networks.items():
        network = runtime.network(name)
        prefix = "CLIENT" if ipaddress.ip_address(interface["IPAddress"]) in ipaddress.ip_network(c["CLIENT_LAN"]) else "SERVER"
        if not (network["Internal"] and network["Driver"] == "bridge"
                and network["IPAM"]["Config"] == [{"Subnet": c[prefix + "_LAN"], "Gateway": c[prefix + "_BRIDGE"]}]):
            return False
    return True


def route_check(runtime, machine, destination, gateway):
    return any(r.get("dst") == destination and r.get("gateway") == gateway
               for r in json.loads(runtime.exec(machine, "ip", "-j", "route")))


def firewall_check(runtime):
    c = runtime.config
    rules = runtime.exec("router", "iptables", "-S", "FORWARD").splitlines()
    return set(rules) == {"-P FORWARD DROP",
                         f'-A FORWARD -s {c["CLIENT_LAN"]} -d {c["SERVER_LAN"]} -j ACCEPT',
                         f'-A FORWARD -s {c["SERVER_LAN"]} -d {c["CLIENT_LAN"]} -j ACCEPT'} and len(rules) == 3


def probe(runtime, nonce):
    result = json.loads(runtime.exec("client", "python3", "/opt/lab/probe_exchange.py", nonce))
    if result.get("probeNonce") != nonce or "error" in result:
        raise ValueError("The fresh packet probe did not complete.")
    return result


def diagnostics(runtime, nonce=None):
    c = runtime.config
    checks = []

    def check(identifier, label, action, feedback):
        try:
            passed = bool(action())
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError):
            passed = False
        checks.append({"id": identifier, "label": label, "passed": passed,
                       "feedback": "Expected behavior observed." if passed else feedback})

    for machine in ("client", "router", "server"):
        check(machine + "-restrictions", machine + " runtime restrictions",
              lambda m=machine: restriction_check(runtime, m), "Inspect capabilities, mounts, port publishing, resource limits, IPv6, and external default routes.")
        check(machine + "-networks", machine + " assigned internal LANs",
              lambda m=machine: network_check(runtime, m), "Compare the assigned addresses and internal bridge configuration with this challenge.")
    check("client-route", "Client route to server LAN", lambda: route_check(runtime, "client", c["SERVER_LAN"], c["CLIENT_GATEWAY"]), "The client needs a path through the router to the server LAN.")
    check("server-route", "Server route to client LAN", lambda: route_check(runtime, "server", c["CLIENT_LAN"], c["SERVER_GATEWAY"]), "Inspect the reply path. A request arriving does not establish a route back.")
    check("forwarding", "Router IPv4 forwarding", lambda: runtime.exec("router", "cat", "/proc/sys/net/ipv4/ip_forward").strip() == "1", "The router must forward IPv4 packets between its interfaces.")
    check("firewall", "Assigned forwarding policy", lambda: firewall_check(runtime), "Keep default-deny forwarding and allow only traffic between the two assigned LANs.")
    check("icmp", "Client-server ICMP", lambda: bool(runtime.exec("client", "ping", "-c", "3", "-W", "2", c["SERVER_IP"])), "Echo requests or replies failed. Check both routes and the router before retrying.")
    check("http", "Routed HTTP service", lambda: "HexDojo Module 0 target" in runtime.exec("client", "curl", "--fail", "--max-time", "3", f'http://{c["SERVER_IP"]}:8000/'), "The HTTP target is not reachable with the expected response. Inspect routing and the server process.")
    packet_evidence = None
    if nonce is not None:
        def packet_check():
            nonlocal packet_evidence
            packet_evidence = probe(runtime, nonce)
            return (packet_evidence.get("requestSequences") == [1, 2, 3]
                    and packet_evidence.get("replySequences") == [1, 2, 3]
                    and packet_evidence.get("matchedPairs") == 3)
        check("capture", "Three fresh captured echo exchanges", packet_check, "Capture did not contain all three fresh matching requests and replies. Diagnose the path, then check again.")
    return {"schemaVersion": 1, "module": "network-0", "source": "student-owned-vm",
            "masteryVerified": False, "passed": all(item["passed"] for item in checks),
            "checks": checks, "packetEvidence": packet_evidence,
            "untested": ["hypervisor escape resistance", "host-side egress", "cross-tenant isolation", "cloud metadata access", "orchestrator authorization", "resource exhaustion"]}


def print_report(report):
    print("Local practice report. Does not earn a badge or establish VM isolation.")
    for item in report["checks"]:
        print(("PASS" if item["passed"] else "FAIL") + " " + item["label"])
        if not item["passed"]:
            print("  " + item["feedback"])
    print("UNTESTED: " + ", ".join(report["untested"]) + ".")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = diagnostics(ComposeRuntime())
    print(json.dumps(result, indent=2)) if args.json else print_report(result)
    raise SystemExit(0 if result["passed"] else 1)
