#!/usr/bin/env python3
"""Restricted Domains, canonical aliases and NAT Access over real WG Links.

p1 takes a-b-e-d; a-c-d is shorter but c belongs only to p2. Both Plans
announce the same defaults. Clients and the external service are independent
namespaces, so each probe exercises actual forwarding and return delivery.
"""

import argparse
from collections import deque
import copy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess as sp
import tempfile
import time
import uuid


def run(*args, check=True, input=None):
    result = sp.run(list(map(str, args)), input=input, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {' '.join(map(str,args))}\n{result.stdout}{result.stderr}")
    return result


def wait_for(check, message, seconds=75):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.5)
    raise AssertionError(message)


class Network:
    nodes = "abcde"
    edges = [("a", "b"), ("b", "e"), ("e", "d"), ("a", "c"), ("c", "d")]
    members = {"p1": set("abed"), "p2": set("acd")}
    sources = {
        "p1": ["10.100.1.0/24", "10.100.3.0/24", "fd10:100:1::/64", "fd10:100:3::/64"],
        "p2": ["10.100.2.0/24", "fd10:100:2::/64"],
    }
    tables = {"p1": 20001, "p2": 20002}

    def __init__(self, args):
        self.args = args
        self.token = uuid.uuid4().hex[:6]
        self.bridge = "vdb" + self.token
        self.root = Path(tempfile.mkdtemp(prefix="velvet-domains-"))
        self.namespaces = []
        self.links = []
        self.processes = []
        self.logs = []
        self.uuids = {n: str(uuid.uuid4()) for n in self.nodes}
        self.state_paths = []
        self.configs = {}

    def ns(self, node):
        return f"vd-{self.token}-{node}"

    def inside(self, node, *args, **kwargs):
        return run("ip", "netns", "exec", self.ns(node), *args, **kwargs)

    def ip(self, node, *args, **kwargs):
        return run("ip", "-n", self.ns(node), *args, **kwargs)

    def create_ns(self, node):
        run("ip", "netns", "add", self.ns(node))
        self.namespaces.append(node)
        self.ip(node, "link", "set", "lo", "up")
        for setting in ("net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.default.accept_dad=0"):
            self.inside(node, "sysctl", "-qw", setting)

    def veth(self, left, right, left_name, right_name):
        index = len(self.links)
        a, b = f"v{self.token}{index}a", f"v{self.token}{index}b"
        run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
        self.links += [a, b]
        for node, old, new in ((left, a, left_name), (right, b, right_name)):
            run("ip", "link", "set", old, "netns", self.ns(node), "name", new)
            self.ip(node, "link", "set", new, "up")

    def address(self, node, interface, address):
        self.ip(node, "address", "add", address, "dev", interface)

    def path(self, source, target, members):
        graph = {n: [] for n in members}
        for a, b in self.edges:
            if a in members and b in members:
                graph[a].append(b)
                graph[b].append(a)
        queue = deque([(source, [])])
        seen = set()
        while queue:
            node, path = queue.popleft()
            if node == target:
                return path[0]
            if node in seen:
                continue
            seen.add(node)
            queue.extend((peer, path + [peer]) for peer in graph[node])
        raise AssertionError("disconnected test Domain")

    def create(self):
        for node in self.nodes + "123s":
            self.create_ns(node)
        run("ip", "link", "add", self.bridge, "type", "bridge")
        self.links.append(self.bridge)
        run("ip", "link", "set", self.bridge, "up")
        for index, node in enumerate(self.nodes, 1):
            outer, inner = f"vu{self.token}{node}", f"vi{self.token}{node}"
            run("ip", "link", "add", outer, "type", "veth", "peer", "name", inner)
            self.links.extend([outer, inner])
            run("ip", "link", "set", outer, "master", self.bridge)
            run("ip", "link", "set", outer, "up")
            run("ip", "link", "set", inner, "netns", self.ns(node), "name", "underlay0")
            self.address(node, "underlay0", f"192.0.2.{index}/24")
            self.ip(node, "link", "set", "underlay0", "up")
        for client, subnet in (("1", "10.100.1"), ("2", "10.100.2"), ("3", "10.200.3")):
            self.veth("a", client, "access" + client, "client0")
            v6 = ("fd20:200:3" if client == "3" else "fd10:100:" + client)
            self.address("a", "access" + client, subnet + ".1/24")
            self.address(client, "client0", subnet + ".2/24")
            self.address("a", "access" + client, v6 + "::1/64")
            self.address(client, "client0", v6 + "::2/64")
            self.ip(client, "route", "add", "default", "via", subnet + ".1")
            self.ip(client, "-6", "route", "add", "default", "via", v6 + "::1")
        self.veth("d", "s", "service0", "server0")
        for node, interface, host in (("d", "service0", 1), ("s", "server0", 2)):
            self.address(node, interface, f"203.0.113.{host}/24")
            self.address(node, interface, f"fd20:113::{host}/64")
        self.ip("s", "route", "add", "default", "via", "203.0.113.1")
        self.ip("s", "-6", "route", "add", "default", "via", "fd20:113::1")
        self.inside("a", "nft", "-f", "-", input="""table inet access_nat {
 chain access_mark { type filter hook prerouting priority mangle; policy accept;
  iifname "access3" meta mark set 20001
 }
 chain access_postrouting { type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.200.3.0/24 snat ip to 10.100.3.2
  ip6 saddr fd20:200:3::/64 snat ip6 to fd10:100:3::2
 }
}
""")
        for family in ("-4", "-6"):
            self.ip("a", family, "rule", "add", "priority", "19999", "fwmark", "20001", "lookup", "20001")
        psk = run("wg", "genpsk").stdout.strip()
        private = {n: run("wg", "genkey").stdout.strip() for n in self.nodes}
        public = {n: run("wg", "pubkey", input=private[n] + "\n").stdout.strip() for n in self.nodes}
        ports = {}
        for index, (a, b) in enumerate(self.edges):
            ports[a, b], ports[b, a] = 52000 + index * 2, 52001 + index * 2
        for index, node in enumerate(self.nodes, 1):
            for base in ("/run/velvet", "/run/velvet-babel", "/var/lib/velvet"):
                path = Path(base) / self.uuids[node]
                if path.exists():
                    raise AssertionError("test state collision")
                self.state_paths.append(path)
            peers = [b if a == node else a for a, b in self.edges if node in (a, b)]
            spec = {
                "api_version": "velvet.io/v1alpha2", "kind": "NodeSpec",
                "fabric": {"psk": psk, "loopback_prefix_v6": "fd78:5151::/48"},
                "node": {"uid": {"name": node, "uuid": self.uuids[node]}, "private_key": private[node], "loopback_address_v6": f"fd78:5151::{index}"},
                "peers": [{"name": p, "public_key": public[p], "endpoints": [f"192.0.2.{self.nodes.index(p)+1}:{ports[p,node]}"], "listen_ports": ports[node,p], "interface_name": f"vl-{node}-{p}"} for p in peers],
                "domains": {},
            }
            if self.args.mode == "babel":
                spec["babel"] = {"enabled": True, "executable": str(self.args.babel)}
            else:
                for remote in self.nodes:
                    if remote != node:
                        peer = self.path(node, remote, set(self.nodes))
                        spec["fabric"].setdefault("static_routes", {}).setdefault(peer, []).append(f"fd78:5151::{self.nodes.index(remote)+1}/128")
            for plan, members in self.members.items():
                if node not in members:
                    continue
                domain = {"source_table_id": self.tables[plan], "source_prefixes": self.sources[plan], "announcements": []}
                if node == "a":
                    domain["announcements"] += self.sources[plan]
                if node == "d":
                    domain["announcements"] += ["0.0.0.0/0", "::/0"]
                if self.args.mode == "static":
                    for target, prefixes in (("a", self.sources[plan]), ("d", ["0.0.0.0/0", "::/0"])):
                        if target != node:
                            peer = self.path(node, target, members)
                            domain.setdefault("static_routes", {}).setdefault(peer, []).extend(prefixes)
                spec["domains"][plan] = domain
            self.configs[node] = spec
            self.write(node, spec)
            log = (self.root / f"{node}.log").open("w")
            self.logs.append(log)
            self.processes.append(sp.Popen(["ip", "netns", "exec", self.ns(node), str(self.args.velvetd), "--config", str(self.root / f"{node}.json"), "--reconcile-interval", "1s"], stdout=log, stderr=sp.STDOUT))

    def write(self, node, spec):
        path = self.root / f"{node}.json"
        path.write_text(json.dumps(spec))
        path.chmod(0o600)

    def probe(self, client, family):
        target = "203.0.113.2" if family == 4 else "fd20:113::2"
        return self.inside(client, "ping", "-" + str(family), "-c", "1", "-W", "1", target, check=False).returncode == 0

    def routes(self, node, family, table, protocol=None):
        args = ["-" + str(family), "-j", "route", "show", "table", str(table)]
        if protocol:
            args += ["proto", str(protocol)]
        return json.loads(self.ip(node, *args).stdout)

    def check(self):
        for client in "123":
            for family in (4, 6):
                wait_for(lambda: self.probe(client, family), f"client {client}/IPv{family}: no bidirectional delivery")
        protocol = 203 if self.args.mode == "babel" else 201
        for family in (4, 6):
            zero = "default"
            for table, peer in ((20001, "b"), (20002, "c")):
                routes = self.routes("a", family, table, protocol)
                assert any(r.get("dst") == zero and r.get("dev") == f"vl-a-{peer}" for r in routes), routes
            for source_node, foreign_plan in (("b", "p2"), ("c", "p1")):
                foreign = {p for p in self.sources[foreign_plan] if (":" in p) == (family == 6)}
                routes = self.routes(source_node, family, 20000)
                assert not any(r.get("dst") in foreign for r in routes), routes
            # The common table on a multi-Domain node must not be copied whole
            # into both source views, including ordinary return destinations.
            for plan, foreign_plan in (("p1", "p2"), ("p2", "p1")):
                foreign = set(self.sources[foreign_plan])
                assert not any(r.get("dst") in foreign for r in self.routes("d", family, self.tables[plan]))
        print(f"{self.args.mode}: dual-stack native/NAT clients and restricted forward/return paths PASS", flush=True)
        if self.args.mode == "babel":
            removed = copy.deepcopy(self.configs["b"])
            del removed["domains"]["p1"]
            self.write("b", removed)
            self.inside("b", self.args.velvetctl, "reload", "--config", self.root / "b.json")
            def withdrawn():
                return all(not any(r.get("type", "unicast") == "unicast" and r.get("dst") == "default" for r in self.routes("a", family, 20001, 203)) for family in (4, 6))
            wait_for(withdrawn, "p1 route survived after its only member path was withdrawn")
            for family in (4, 6):
                assert not self.probe("1", family) and not self.probe("3", family)
                assert self.probe("2", family), "unrelated p2 stopped forwarding"
                # The fixed fwmark entry keeps its terminal route after Babel
                # withdrawal, including the pre-SNAT source on NAT Access.
                lookup = self.ip("a", "-" + str(family), "route", "get", "203.0.113.2" if family == 4 else "fd20:113::2", "mark", "20001", check=False)
                assert lookup.returncode != 0, lookup.stdout
                # Protocol withdrawal holds may remain as unreachable entries;
                # they must never be mistaken for accepted forwarding routes.
                assert not any(r.get("type", "unicast") == "unicast" and r.get("dst") in self.sources["p1"] for r in self.routes("b", family, 20000, 203))
            self.write("b", self.configs["b"])
            self.inside("b", self.args.velvetctl, "reload", "--config", self.root / "b.json")
            for client in "13":
                for family in (4, 6):
                    wait_for(lambda: self.probe(client, family), "restored p1 did not recover")
            print("babel: Domain removal, no-path termination, p2 continuity and restoration PASS", flush=True)

    def cleanup(self):
        for node in self.namespaces:
            pids = run("ip", "netns", "pids", self.ns(node), check=False).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except sp.TimeoutExpired:
                process.kill()
                process.wait()
        for node in reversed(self.namespaces):
            for pid in run("ip", "netns", "pids", self.ns(node), check=False).stdout.split():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            run("ip", "netns", "delete", self.ns(node), check=False)
        for link in self.links:
            run("ip", "link", "delete", link, check=False)
        for log in self.logs:
            log.close()
        for path in self.state_paths:
            shutil.rmtree(path, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("velvetd", type=Path)
    parser.add_argument("babel", type=Path)
    parser.add_argument("velvetctl", type=Path)
    parser.add_argument("--mode", choices=("static", "babel"), default="babel")
    args = parser.parse_args()
    for name in ("velvetd", "babel", "velvetctl"):
        setattr(args, name, getattr(args, name).resolve())
    if os.geteuid() != 0:
        parser.error("run only in a disposable root test VM")
    os.umask(0o077)
    network = Network(args)
    print("artifacts:", network.root, flush=True)
    try:
        network.create()
        network.check()
    except Exception:
        for path in network.root.glob("*.log"):
            print(path.name, path.read_text()[-6000:], flush=True)
        raise
    finally:
        network.cleanup()


if __name__ == "__main__":
    main()
