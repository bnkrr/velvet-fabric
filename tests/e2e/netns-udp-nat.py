#!/usr/bin/env python3
"""Real Dynamic Links over IPv4/IPv6: public peers, NAT44/NAT66 and fallback."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess as sp
import sys
import tempfile
import time
import uuid

os.umask(0o077)

DAEMON, BABEL = map(os.path.abspath, sys.argv[1:3])
if os.geteuid() != 0:
    raise SystemExit("netns test requires root")
for command in ("ip", "wg", "nft", "ping", "sysctl", "tc", "ss"):
    if not shutil.which(command):
        raise SystemExit(f"missing {command}")


def run(*args, input=None, check=True):
    result = sp.run(args, input=input, text=True, stdout=sp.PIPE, stderr=sp.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr.strip()}")
    return result.stdout.strip()


# Public means directly addressed on the isolated WAN, never the Internet.
CASES = {name: {"mode": name} for name in (
    "preserve", "remap", "delayed-remap", "blocked", "control-loss", "random",
    "observer-fallback", "lifecycle")}
CASES["v6-lifecycle"] = {"family": 6, "mode": "lifecycle"}
for family in (4, 6):
    for allocation in ("preserve", "remap", "random"):
        for origin, initiator in (("public", "a"), ("nat", "b")):
            CASES[f"v{family}-single-{allocation}-{origin}-init"] = {
                "family": family, "mode": allocation, "public": ("a",), "initiator": initiator}
for origin in ("a", "b"):
    CASES[f"v6-native-{origin}-init"] = {
        "family": 6, "mode": "preserve", "public": ("a", "b"), "initiator": origin}
    CASES[f"v6-filtered-{origin}-init"] = {
        "family": 6, "mode": "preserve", "public": ("a", "b"), "initiator": origin,
        "filter_public": True}
for allocation in ("preserve", "remap", "blocked", "random"):
    CASES[f"v6-dual-{allocation}"] = {"family": 6, "mode": allocation}



for family in (4, 6):
    for fault in ("retry-blackout", "policy-wakeup", "policy-restart-query"):
        CASES[f"v{family}-{fault}"] = {
            "family": family, "mode": "preserve", "public": ("a", "b"),
            "initiator": "a", "retry_fault": fault}


def endpoint(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def split_endpoint(value):
    address, port = value.rsplit(":", 1)
    return ipaddress.ip_address(address.split("%", 1)[0].strip("[]")), int(port)


def scenario(case):
    config = CASES[case]
    mode, family = config["mode"], config.get("family", 4)
    public_nodes = config.get("public", ())
    negative = mode in ("blocked", "control-loss") or (mode == "random" and not public_nodes)
    table, address_match = ("ip6", "ip6") if family == 6 else ("ip", "ip")
    wan_prefix = "2001:db8:77::/64" if family == 6 else "192.0.2.0/24"
    wan_addresses = {n: (f"2001:db8:77::{host}" if family == 6 else f"192.0.2.{host}")
                     for n, host in (("c", 1), ("d", 2), ("ra", 11), ("rb", 12), ("a", 11), ("b", 12))}
    def observed_address(node):
        if mode == "observer-fallback":
            return "192.0.2.13" if node == "a" else "192.0.2.14"
        return wan_addresses[node]

    def lan_address(index, host):
        return f"fd42:77:{index}::{host}" if family == 6 else f"10.77.{index}.{host}"

    suffix = str(os.getpid())
    # Keep interface-name prefix 7100 while isolating persistent/control state
    # between independent concurrent test runs.
    uid_group = uuid.uuid4().hex[:4]
    nodes = ("a", "b", "c", "d") if mode == "observer-fallback" else ("a", "b", "c")
    names = {node: f"vun-{node}-{suffix}" for node in (*nodes, *("r" + n for n in ("a", "b") if n not in public_nodes))}
    bridge = f"vunbr{suffix}"
    runtime = Path(tempfile.mkdtemp(prefix="velvet-udp-nat-"))
    runtime.chmod(0o700)
    processes, logs, uuids, root_links = [], [], [], []
    succeeded = False

    def ns(node, *args, **kw):
        return run("ip", "netns", "exec", names[node], *args, **kw)

    def ip(node, *args):
        return run("ip", "-n", names[node], *args)

    def events(node):
        result = []
        for line in (runtime / f"{node}.log").read_text().splitlines():
            try:
                result.append(json.loads(line))
            except ValueError:
                pass
        return result

    def connected(node):
        return any(e.get("event") == "velvet-dynamic-link" and e.get("status") == "up" for e in events(node))

    try:
        run("ip", "link", "add", bridge, "type", "bridge")
        run("ip", "link", "set", bridge, "up")
        for node in names:
            run("ip", "netns", "add", names[node])
            ip(node, "link", "set", "lo", "up")
            # Assign deterministic IPv6 addresses without a DAD startup race.
            ns(node, "sysctl", "-qw", "net.ipv6.conf.default.accept_dad=0")
            ns(node, "sysctl", "-qw", "net.ipv6.conf.default.autoconf=0")
        wan_nodes = ["c", *(n if n in public_nodes else "r" + n for n in ("a", "b"))]
        if mode == "observer-fallback":
            wan_nodes.append("d")
        for idx, node in enumerate(wan_nodes, 1):
            root, other = f"vu{idx}r{suffix}", f"vu{idx}n{suffix}"
            run("ip", "link", "add", root, "type", "veth", "peer", "name", other)
            root_links.append(root)
            run("ip", "link", "set", root, "master", bridge)
            run("ip", "link", "set", root, "up")
            run("ip", "link", "set", other, "netns", names[node])
            ip(node, "link", "set", other, "name", "wan")
            address = wan_addresses[node]
            ip(node, "addr", "add", address + ("/64" if family == 6 else "/24"), "dev", "wan")
            ip(node, "link", "set", "wan", "up")
        for idx, node in enumerate(("a", "b"), 1):
            ns(node, "sysctl", "-qw", "net.ipv4.ip_local_port_range=31000 32000")
            if node in public_nodes:
                if config.get("filter_public"):
                    ns(node, "nft", "-f", "-", input=f"""table ip6 velvet_filter {{
 chain input {{ type filter hook input priority 0; policy accept;
 ct state established,related accept
 udp dport {51000+idx} accept
 iifname "wan" meta l4proto udp drop
 }}
}}""")
                continue
            router = "r" + node
            left, right = f"vul{idx}{suffix}", f"vur{idx}{suffix}"
            run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
            run("ip", "link", "set", left, "netns", names[node])
            run("ip", "link", "set", right, "netns", names[router])
            ip(node, "link", "set", left, "name", "lan")
            ip(router, "link", "set", right, "name", "lan")
            for side, address in ((node, 2), (router, 1)):
                ip(side, "addr", "add", lan_address(idx, address) + ("/64" if family == 6 else "/24"), "dev", "lan")
                ip(side, "link", "set", "lan", "up")
            ip(node, f"-{family}", "route", "add", "default", "via", lan_address(idx, 1))
            ns(router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1" if family == 6 else "net.ipv4.ip_forward=1")
            public = wan_addresses[router]
            translation = endpoint(public, 45000) if mode in ("remap", "delayed-remap", "control-loss") else public
            if mode == "random":
                translation = endpoint(public, "40000-60000") + " random"
            outbound = f'{address_match} daddr {wan_addresses["c"]} udp dport {52000+idx} accept' if mode == "blocked" else 'iifname "lan" accept'
            nat_rules = f'oifname "wan" meta l4proto udp snat to {translation}'
            if mode == "observer-fallback":
                second_public = f"192.0.2.{12+idx}"
                ip(router, "addr", "add", second_public + "/24", "dev", "wan")
                nat_rules = f'oifname "wan" ip daddr 192.0.2.1 ip protocol udp snat to {public}\noifname "wan" ip daddr != 192.0.2.1 ip protocol udp snat to {second_public}'
            rules = f'''table {table} velvet_test {{
 chain input {{ type filter hook input priority 0; policy accept; iifname "wan" meta l4proto udp drop; }}
 chain forward {{ type filter hook forward priority 0; policy drop;
 ct state established,related accept
 {outbound}
 }}
 chain post {{ type nat hook postrouting priority 100; policy accept;
 {nat_rules}
 }}
}}'''
            ns(router, "nft", "-f", "-", input=rules)
        if mode == "delayed-remap":
            for node, delay in (("ra", "150ms"), ("rb", "150ms"), ("c", "200ms")):
                ns(node, "tc", "qdisc", "add", "dev", "wan", "root", "netem", "delay", delay)
        if mode == "observer-fallback":
            ns("c", "nft", "-f", "-", input="""table ip velvet_observer_fault {
 chain input { type filter hook input priority -10; policy accept;
 udp dport != { 52001, 52002, 52003 } drop
 }
}""")
        for node, peer in (("a", "b"), ("b", "a")):
            ns(node, "nft", "-f", "-", input=f"""table inet velvet_trace {{
 counter probes_out {{ }}
 counter probes_in {{ }}
 chain output {{ type filter hook output priority -10; policy accept;
 {address_match} daddr {observed_address(peer)} meta l4proto udp @th,64,32 0x56465000 counter name probes_out
 }}
 chain input {{ type filter hook input priority -10; policy accept;
 {address_match} saddr {observed_address(peer)} meta l4proto udp @th,64,32 0x56465000 counter name probes_in
 }}
}}""")
        keys = {node: run("wg", "genkey") for node in nodes}
        pubs = {node: run("wg", "pubkey", input=key + "\n") for node, key in keys.items()}
        psk = run("wg", "genpsk")
        for index, node in enumerate(nodes, 1):
            uid = f"71000000-{uid_group}-4000-8000-{index:012d}"
            uuids.append(uid)
            peers = []
            for peer in (("a", "b", "d") if node == "c" and mode == "observer-fallback" else ("a", "b") if node == "c" else ("c",)):
                if {node, peer} == {"c", "d"}:
                    peers.append({"name": peer, "public_key": pubs[peer], "interface_name": f"vl-{node}-{peer}", "listen_port": 52003 if node == "c" else 53003, "endpoints": ["192.0.2.2:53003" if node == "c" else "192.0.2.1:52003"], "persistent_keepalive_seconds": 1})
                    continue
                leaf = peer if node == "c" else node
                number = 1 if leaf == "a" else 2
                peers.append({"name": peer, "public_key": pubs[peer], "interface_name": f"vl-{node}-{peer}",
                              "listen_port": 52000+number if node == "c" else 51000+number,
                              "endpoints": [endpoint(wan_addresses[leaf], 51000+number) if node == "c" else endpoint(wan_addresses["c"], 52000+number)],
                              "persistent_keepalive_seconds": 1})
            spec = {"api_version": "velvet.io/v1alpha1", "kind": "NodeSpec",
                    "fabric": {"psk": psk, "loopback_prefix_v6": "fd78:7777::/48", "routing_table_id": 20000},
                    "node": {"uid": {"name": node, "uuid": uid}, "private_key": keys[node], "loopback_address_v6": f"fd78:7777::{index}"},
                    "peers": peers, "babel": {"enabled": True, "executable": BABEL}}
            if node in ("a", "b"):
                spec["dynamic_links"] = {"mode": "active" if config.get("initiator", node) == node else "passive", "allow_candidate_prefixes": [wan_prefix]}
            if node == "b" and config.get("retry_fault", "").startswith("policy-"):
                spec["dynamic_links"]["mode"] = "off"
            if node == "a" and config.get("retry_fault") == "retry-blackout":
                ns("a", "nft", "-f", "-", input=f"""table inet velvet_retry_fault {{
 chain input {{ type filter hook input priority -20; policy accept;
 {address_match} saddr {observed_address("b")} meta l4proto udp @th,64,32 {{ 0x01000000, 0x02000000, 0x04000000 }} counter drop
 }}
}}""")
            (runtime / f"{node}.json").write_text(json.dumps(spec))
            log = (runtime / f"{node}.log").open("w")
            logs.append(log)
            processes.append(sp.Popen(["ip", "netns", "exec", names[node], DAEMON, "--config", str(runtime / f"{node}.json"), "--reconcile-interval", "1s"], stdout=log, stderr=sp.STDOUT))
        def tentative_clean():
            return all(not any(i.startswith("vdl-") for i in ns(n, "wg", "show", "interfaces").split()) for n in ("a", "b"))

        retry_fault = config.get("retry_fault")
        if retry_fault:
            def wait_retry(predicate, description, seconds):
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    if any(p.poll() is not None for p in processes):
                        raise AssertionError("velvetd exited during retry test")
                    if predicate():
                        return
                    time.sleep(0.2)
                raise AssertionError(description)

            def peer_events(kind, status):
                return [e for e in events("a") if e.get("event") == kind and
                        e.get("status") == status and e.get("remote_uid") == uuids[1]]

            if retry_fault == "retry-blackout":
                # Let the complete first attempt fail; a later attempt must use
                # fresh resources, not just resume a successful UDP handoff.
                wait_retry(lambda: bool(peer_events("velvet-dynamic-attempt", "failed")),
                           "WG blackout did not fail first Attempt", 60)
                assert not connected("a"), "blackout allowed false commit"
                ns("a", "ping", "-n", "-6", "-I", "fd78:7777::1", "-c", "2", "-W", "2", "fd78:7777::2")
                ns("a", "nft", "delete", "table", "inet", "velvet_retry_fault")
                print(f"{case}: first Attempt failed, fallback works, WG restored", flush=True)
            else:
                wait_retry(lambda: bool(peer_events("velvet-dynamic-policy", "denied")),
                           "policy Decline did not enter denied state", 45)
                count = len(peer_events("velvet-dynamic-attempt", "proposed"))
                # Longer than the first retry budget: denial must suppress
                # proposals without suppressing the UDP query channel.
                time.sleep(18)
                assert len(peer_events("velvet-dynamic-attempt", "proposed")) == count, "policy refusal caused repeated proposals"
                assert tentative_clean(), "policy refusal retained tentative resources"
                config_path = runtime / "b.json"
                b_config = json.loads(config_path.read_text())
                b_config["dynamic_links"]["mode"] = "passive"
                config_path.write_text(json.dumps(b_config))
                if retry_fault == "policy-wakeup":
                    processes[1].send_signal(signal.SIGHUP)
                    wait_retry(lambda: bool(peer_events("velvet-dynamic-policy", "allowed")),
                               "passive reload failed to push allowance", 45)
                else:
                    # A already consumed its immediate QUERY while B was off.
                    # Restart B without any peer cache. No push is possible;
                    # the normal five-minute QUERY must recover admission.
                    processes[1].terminate()
                    processes[1].wait(timeout=15)
                    processes[1] = sp.Popen(["ip", "netns", "exec", names["b"], DAEMON,
                        "--config", str(config_path), "--reconcile-interval", "1s"],
                        stdout=logs[1], stderr=sp.STDOUT)
                    print(f"{case}: B restarted passive without peer cache; waiting for normal query budget", flush=True)
                    wait_retry(lambda: bool(peer_events("velvet-dynamic-policy", "allowed")),
                               "periodic query did not recover after publisher restart", 400)
                print(f"{case}: received versioned allowance", flush=True)

        fault_at = None
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes):
                raise AssertionError("velvetd exited")
            if mode == "control-loss" and fault_at is None and any(
                    e.get("event") == "velvet-dynamic-attempt" and e.get("status") == "accepted"
                    for node in ("a", "b") for e in events(node)):
                fault_at = {n: len(events(n)) for n in ("a", "b")}
                ns("c", "nft", "-f", "-", input="""table inet velvet_fault {
 chain forward { type filter hook forward priority -10; policy accept;
 tcp dport 58420 reject with tcp reset
 tcp sport 58420 reject with tcp reset
 }
}""")
            if mode == "control-loss":
                if fault_at is not None and all(any(e.get("event") == "velvet-dynamic-link" and e.get("status") == "cleanup" for e in events(n)[fault_at[n]:]) for n in ("a", "b")) and tentative_clean():
                    break
            elif negative:
                if all(any(e.get("event") == "velvet-dynamic-attempt" and e.get("status") == "failed" and "UDP discovery" in e.get("error", "") for e in events(n)) for n in ("a", "b")) and tentative_clean():
                    break
            elif connected("a") and connected("b"):
                break
            time.sleep(0.25)
        else:
            raise AssertionError("dynamic discovery deadline")
        for node, source, target in (("a", 1, 2), ("b", 2, 1)):
            ns(node, "ping", "-n", "-6", "-I", f"fd78:7777::{source}", "-c", "3", "-W", "2", f"fd78:7777::{target}")
        for node in ("a", "b"):
            interfaces = ns(node, "wg", "show", "interfaces").split()
            dynamic = [name for name in interfaces if name.startswith("vdl-")]
            if negative:
                assert not dynamic, (node, "tentative interface leaked")
                assert not connected(node), "blocked probes committed a link"
                bound = {split_endpoint(line.split()[3]) for line in ns(node, "ss", "-H", "-u", "-a", "-n").splitlines() if len(line.split()) >= 5 and "*" not in line.split()[3]}
                allocated = {split_endpoint(e["local_endpoint"]) for e in events(node) if e.get("event") == "velvet-udp-probe" and e.get("status") == "prepared"}
                assert allocated and not allocated.intersection(bound), "cancelled task leaked its UDP listener"
            else:
                assert len(dynamic) == 1, (node, dynamic)
                hs = ns(node, "wg", "show", dynamic[0], "latest-handshakes")
                assert int(hs.split()[1]) > 0, "missing real WG handshake"
                handoff = [e for e in events(node) if e.get("event") == "velvet-udp-probe" and e.get("status") == "handoff"]
                assert handoff, "WG was not preceded by UDP discovery"
                if retry_fault == "retry-blackout":
                    assert len(handoff) >= 2, "failed WG attempt was resumed without new UDP discovery"
                assert ns(node, "wg", "show", dynamic[0], "listen-port") == handoff[-1]["local_endpoint"].rsplit(":", 1)[1], "handoff changed local port"
                peer = "b" if node == "a" else "a"
                local_address, _ = split_endpoint(handoff[-1]["local_endpoint"])
                remote_address, remote_port = split_endpoint(handoff[-1]["remote_ip"])
                expected_local = wan_addresses[node] if node in public_nodes else lan_address(1 if node == "a" else 2, 2)
                assert local_address == ipaddress.ip_address(expected_local), "handoff changed source address/family"
                assert remote_address == ipaddress.ip_address(observed_address(peer)), "handoff did not use expected underlay family/address"
                wg_endpoint = ns(node, "wg", "show", dynamic[0], "endpoints").split()[1]
                assert split_endpoint(wg_endpoint) == (remote_address, remote_port), "WG endpoint differs from verified UDP path"
                for counter in ("probes_out", "probes_in"):
                    values = json.loads(ns(node, "nft", "-j", "list", "counter", "inet", "velvet_trace", counter))
                    assert any(v.get("counter", {}).get("packets", 0) > 0 for v in values["nftables"]), (node, "missing peer-directed VFP UDP", counter)
                if mode in ("remap", "delayed-remap") and peer not in public_nodes:
                    assert remote_port == 45000, handoff
                if mode in ("remap", "delayed-remap") and not public_nodes:
                    assert any(e.get("event") == "velvet-udp-observe" and e.get("status") == "measured" for e in events(node)), "remapping did not exercise active observation"
        if config.get("initiator"):
            initiator = config["initiator"]
            passive = "b" if initiator == "a" else "a"
            assert any(e.get("event") == "velvet-dynamic-attempt" and e.get("status") == "proposed" for e in events(initiator)), "selected initiator did not propose"
            assert not any(e.get("event") == "velvet-dynamic-attempt" and e.get("status") == "proposed" for e in events(passive)), "passive node initiated"
            assert any(e.get("event") == "velvet-dynamic-attempt" and e.get("status") == "accepted" for e in events(passive)), "passive node did not accept"
        if retry_fault:
            assert len(peer_events("velvet-dynamic-attempt", "proposed")) >= 2, "no new budgeted Proposal"
        if mode == "observer-fallback":
            for node in ("a", "b"):
                prepared = [e["remote_uid"] for e in events(node) if e.get("event") == "velvet-udp-observe" and e.get("status") == "prepared"]
                assert prepared.index(uuids[2]) < prepared.index(uuids[3]), "static observer was not first"
                assert any(e.get("event") == "velvet-udp-observe" and e.get("status") == "measured" and e.get("remote_uid") == uuids[3] for e in events(node)), "alternate observer not measured"
        if not negative:
            route = ip("a", "-6", "route", "show", "table", "20000", "exact", "fd78:7777::2/128")
            assert "dev vdl-b-7100" in route, f"traffic did not choose the new direct Link: {route}"
        if mode == "lifecycle":
            started = time.monotonic()
            def stage(name):
                print(f"{case}: {name} at {time.monotonic() - started:.1f}s", flush=True)

            def wait_for(predicate, description, seconds=45):
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    if predicate():
                        return
                    time.sleep(0.1)
                raise AssertionError(description)

            device = "vdl-b-7100"
            original_index = json.loads(ip("a", "-j", "link", "show", device))[0]["ifindex"]
            local = json.loads(ip("a", "-j", "-6", "addr", "show", "dev", device))[0]["addr_info"][0]["local"]
            # Completed Links carry no established link-local TCP. Blocking
            # control TCP must not withdraw a healthy UDP-confirmed adjacency.
            assert not ns("a", "ss", "-H", "-6", "-t", "state", "established", "src", f"[{local}]"), "link-local TCP remained established"
            ns("a", "nft", "-f", "-", input=f"""table inet velvet_tcp_only {{
 chain input {{ type filter hook input priority -20; policy accept;
 iifname "{device}" tcp dport 58420 counter drop
 }}
 chain output {{ type filter hook output priority -20; policy accept;
 oifname "{device}" tcp dport 58420 counter drop
 }}
}}""")
            ns("a", "ss", "-K", "-6", "-t", "src", f"[{local}]")
            # Request a fresh negotiation from the higher-address endpoint.
            # TCP will fail, while the existing Link must remain usable.
            b_device = "vdl-a-7100"
            b_local = next(a["local"] for a in json.loads(ip("b", "-j", "-6", "addr", "show", "dev", b_device))[0]["addr_info"] if a["scope"] == "link")
            if ipaddress.IPv6Address(local) < ipaddress.IPv6Address(b_local):
                sender, source, destination, outgoing = "b", b_local, local, b_device
            else:
                sender, source, destination, outgoing = "a", local, b_local, device
            ns(sender, "python3", "-c", "import socket,sys; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); i=socket.if_nametoindex(sys.argv[3]); s.bind((sys.argv[1],0,0,i)); s.sendto(bytes.fromhex('5646500001090008'),(sys.argv[2],58420,0,i))", source, destination, outgoing)
            until = time.monotonic() + 35
            while time.monotonic() < until:
                ns("a", "ping", "-n", "-6", "-I", "fd78:7777::1", "-c", "1", "-W", "2", "fd78:7777::2")
                assert f"dev {device}" in ip("a", "-6", "route", "show", "table", "20000", "exact", "fd78:7777::2/128")
                assert not any(e.get("event") == "velvet-dynamic-link" and e.get("status") == "recovering" for e in events("a")), "TCP-only loss caused Link recovery"
                time.sleep(1)
            assert any(e.get("event") == "velvet-link-negotiation" and e.get("status") == "failed" for n in ("a", "b") for e in events(n)), "TCP fault did not exercise renegotiation"
            stage("TCP fault tolerated")
            # Now fail only link-local VFP UDP, retaining WG data and TCP block.
            ns("a", "nft", "-f", "-", input=f"""table inet velvet_link_udp_loss {{
 chain input {{ type filter hook input priority -20; policy accept;
 iifname "{device}" udp dport 58420 counter drop
 }}
}}""")
            wait_for(lambda: all(any(e.get("event") == "velvet-dynamic-link" and e.get("status") == "recovering" for e in events(n)) for n in ("a", "b")), "UDP liveness failure did not withdraw both adjacencies")
            stage("UDP adjacency withdrawn")
            # Protocol-202 withdrawal is synchronous; Babel convergence has its
            # own clock. Verify same-WG recovery before its finite window ends.
            # The subsequent shutdown fault separately requires routed fallback.
            for node, target in (("a", 2), ("b", 1)):
                assert "proto 202" not in ip(node, "-6", "route", "show", "table", "20000", "exact", f"fd78:7777::{target}/128"), "expired adjacency route was not withdrawn"
            ns("a", "nft", "delete", "table", "inet", "velvet_link_udp_loss")
            stage("UDP restored after both adjacency withdrawals")
            wait_for(lambda: all(any(e.get("event") == "velvet-dynamic-link" and e.get("status") == "recovered" for e in events(n)) for n in ("a", "b")), "same-WG UDP recovery failed", seconds=25)
            assert json.loads(ip("a", "-j", "link", "show", device))[0]["ifindex"] == original_index, "recovery replaced the Link"
            assert f"dev {device}" in ip("a", "-6", "route", "show", "table", "20000", "exact", "fd78:7777::2/128")
            stage("same-WG recovery confirmed with TCP blocked")
            ns("a", "nft", "delete", "table", "inet", "velvet_tcp_only")
            config_path = runtime / "a.json"
            config = json.loads(config_path.read_text())
            # No TCP close is needed: UDP failure detection (30s) followed
            # by the separate 30s recovery window must reclaim the remote Link.
            ns("a", "nft", "-f", "-", input=f"""table inet velvet_shutdown_loss {{
 chain output {{ type filter hook output priority -20; policy accept;
 {address_match} daddr {observed_address("b")} meta l4proto udp drop
 }}
}}""")
            config["dynamic_links"]["mode"] = "off"
            config_path.write_text(json.dumps(config))
            processes[0].send_signal(signal.SIGHUP)
            wait_for(lambda: all(not any(i.startswith("vdl-") for i in ns(n, "wg", "show", "interfaces").split()) for n in ("a", "b")), "changed configuration left dynamic resources after UDP detection and recovery", seconds=75)
            ns("a", "ping", "-n", "-6", "-I", "fd78:7777::1", "-c", "2", "-W", "2", "fd78:7777::2")
            assert "dev vl-a-c" in ip("a", "-6", "route", "show", "table", "20000", "exact", "fd78:7777::2/128"), "routed fallback did not reconverge"
            counts = {n: sum(e.get("event") == "velvet-dynamic-link" and e.get("status") == "up" for e in events(n)) for n in ("a", "b")}
            ns("a", "nft", "delete", "table", "inet", "velvet_shutdown_loss")
            config["dynamic_links"]["mode"] = "active"
            config_path.write_text(json.dumps(config))
            processes[0].send_signal(signal.SIGHUP)
            wait_for(lambda: all(sum(e.get("event") == "velvet-dynamic-link" and e.get("status") == "up" for e in events(n)) > counts[n] for n in ("a", "b")), "new configuration did not relearn the Link")
            ns("a", "ping", "-n", "-6", "-I", "fd78:7777::1", "-c", "2", "-W", "2", "fd78:7777::2")
        print(f"velvet real UDP / IPv{family} / WG handoff ({case}): PASS", flush=True)
        succeeded = True
    except BaseException:
        for node in nodes:
            path = runtime / f"{node}.log"
            if path.exists():
                print(f"--- {node} ---\n{path.read_text()}", file=sys.stderr)
            print(ns(node, "wg", "show", check=False), file=sys.stderr)
            print(ns(node, "ip", "-6", "route", "show", "table", "20000", check=False), file=sys.stderr)
        raise
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            try:
                p.wait(timeout=10)
            except sp.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs:
            log.close()
        for name in names.values():
            for pid in run("ip", "netns", "pids", name, check=False).split():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            run("ip", "netns", "del", name, check=False)
        for device in root_links:
            run("ip", "link", "del", device, check=False)
        run("ip", "link", "del", bridge, check=False)
        for uid in uuids:
            for root in ("/run/velvet", "/var/lib/velvet"):
                shutil.rmtree(Path(root) / uid, ignore_errors=True)
        if succeeded:
            shutil.rmtree(runtime)
        else:
            print(f"failure evidence retained in {runtime}", file=sys.stderr)


selected = sys.argv[3:] or CASES
unknown = set(selected) - CASES.keys()
if unknown:
    raise SystemExit(f"unknown cases: {sorted(unknown)}; choose from {list(CASES)}")
for case in selected:
    scenario(case)
