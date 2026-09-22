#!/usr/bin/env python3
"""Run the shipped three-node examples with an external client and NAT exit."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


def scenario(example, velvetd, babel, velvetctl):
    prefix = f"vex{os.getpid()}{example[0]}"
    namespaces = {node: f"{prefix}-{node}" for node in ("a", "b", "c", "client", "wan")}
    bridge = prefix + "br"
    processes, logs, configs = {}, {}, {}

    def ip(node, *args):
        return run("ip", "-n", namespaces[node], *args)

    def execute(node, *args, **kwargs):
        return run("ip", "netns", "exec", namespaces[node], *args, **kwargs)

    def connect(left, left_if, left_addr, right, right_if, right_addr):
        ip(left, "link", "add", left_if, "type", "veth", "peer", "name", "mate0")
        ip(left, "link", "set", "mate0", "netns", namespaces[right])
        ip(right, "link", "set", "mate0", "name", right_if)
        for node, interface, address in ((left, left_if, left_addr), (right, right_if, right_addr)):
            ip(node, "address", "add", address, "dev", interface)
            ip(node, "link", "set", interface, "up")

    with tempfile.TemporaryDirectory(prefix="velvet-examples-") as temporary:
        runtime = Path(temporary)
        try:
            run("python3", ROOT / "examples/prepare.py", example, runtime / "configs", "--babel", babel)
            configs = {node: json.loads((runtime / "configs" / f"{node}.json").read_text()) for node in "abc"}
            for node in namespaces:
                run("ip", "netns", "add", namespaces[node])
                ip(node, "link", "set", "lo", "up")
            run("ip", "link", "add", bridge, "type", "bridge")
            run("ip", "link", "set", bridge, "up")
            for index, node in enumerate("abc", 1):
                host_if = prefix + node
                run("ip", "link", "add", host_if, "type", "veth", "peer", "name", "mate0",
                    "netns", namespaces[node])
                run("ip", "link", "set", host_if, "master", bridge)
                run("ip", "link", "set", host_if, "up")
                ip(node, "link", "set", "mate0", "name", "underlay0")
                ip(node, "address", "add", f"192.0.2.{index}/24", "dev", "underlay0")
                ip(node, "link", "set", "underlay0", "up")

            connect("a", "access0", "10.100.20.1/24", "client", "eth0", "10.100.20.2/24")
            connect("c", "uplink0", "198.51.100.1/30", "wan", "eth0", "198.51.100.2/30")
            ip("client", "route", "add", "default", "via", "10.100.20.1")
            ip("c", "route", "add", "default", "via", "198.51.100.2", "dev", "uplink0")
            ip("wan", "address", "add", "203.0.113.10/32", "dev", "lo")
            execute("c", "nft", "-f", "-", input='''table ip velvet_example_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.100.20.0/24 oifname "uplink0" masquerade
  }
}
''')

            for node in "abc":
                config = runtime / "configs" / f"{node}.json"
                execute(node, velvetctl, "resolve", "--config", config)
                logs[node] = (runtime / f"{node}.log").open("w+")
                processes[node] = subprocess.Popen(
                    ["ip", "netns", "exec", namespaces[node], str(velvetd),
                     "--config", str(config), "--reconcile-interval", "1s"],
                    stdout=logs[node], stderr=subprocess.STDOUT)

            deadline = time.monotonic() + 75
            while True:
                for node, process in processes.items():
                    if process.poll() is not None:
                        raise RuntimeError(f"{node}: velvetd exited with {process.returncode}")
                try:
                    execute("client", "ping", "-c", "1", "-W", "1", "203.0.113.10")
                    execute("a", "ping", "-6", "-c", "1", "-W", "1", "fd78:abcd::3")
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"{example}: client/loopback traffic did not converge")
                    time.sleep(1)

            execute("a", "ping", "-c", "1", "-W", "3", "-I", "10.100.20.1", "203.0.113.10")
            # Check both directions through B, and the final local delivery at A.
            for node, destination, source, incoming, device, table in (
                ("b", "203.0.113.10", "10.100.20.2", "vl-b-a", "vl-b-c", 20001),
                ("b", "10.100.20.2", "203.0.113.10", "vl-b-c", "vl-b-a", 20000),
                ("a", "10.100.20.2", "203.0.113.10", "vl-a-b", "access0", "main"),
            ):
                route = json.loads(ip(node, "-j", "route", "get", destination,
                                      "from", source, "iif", incoming))[0]
                if route.get("dev") != device or str(route.get("table", "main")) != str(table):
                    raise RuntimeError(f"{example}: wrong forwarding at {node}: {route}")

            protocol = "203" if example == "dynamic_minimal" else "201"
            for table, prefix in (("20000", "10.100.20.0/24"), ("20001", "0.0.0.0/0")):
                routes = json.loads(ip("b", "-j", "route", "show", "table", table,
                                       "exact", prefix, "proto", protocol))
                if not routes:
                    raise RuntimeError(f"{example}: missing protocol-{protocol} route to {prefix}")
            for node in "abc":
                rules = json.loads(ip(node, "-j", "-details", "rule", "show"))
                if not any((rule.get("dst") == "10.100.20.0/24" or
                            (rule.get("dst") == "10.100.20.0" and rule.get("dstlen") == 24))
                           and str(rule.get("table")) == "20000"
                           and str(rule.get("protocol")) == "201" for rule in rules):
                    raise RuntimeError(f"{example}: missing managed return selector at {node}: {rules}")
                if example == "static_minimal" and json.loads(ip(node, "-j", "route", "show", "table", "all", "proto", "203")):
                    raise RuntimeError("static example unexpectedly installed Babel routes")
            print(f"{example}: PASS (client -> A -> B -> C -> NAT/upstream, return, loopbacks)", flush=True)
        except Exception:
            for node, log in logs.items():
                log.flush()
                log.seek(0)
                print(f"{example} {node}:\n{log.read()}", flush=True)
            raise
        finally:
            for process in processes.values():
                if process.poll() is None:
                    process.terminate()
            for process in processes.values():
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs.values():
                log.close()
            for namespace in namespaces.values():
                subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
            subprocess.run(["ip", "link", "del", bridge], capture_output=True)
            for config in configs.values():
                uid = config["node"]["uid"]["uuid"]
                for directory in (Path("/run/velvet") / uid, Path("/var/lib/velvet") / uid):
                    shutil.rmtree(directory, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("velvetd", type=Path)
    parser.add_argument("babel_rs", type=Path)
    parser.add_argument("velvetctl", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run on a disposable root Linux test host")
    for name in ("ip", "wg", "ping", "nft"):
        if shutil.which(name) is None:
            parser.error(f"missing command: {name}")
    for example in ("static_minimal", "dynamic_minimal"):
        scenario(example, args.velvetd.resolve(strict=True), args.babel_rs.resolve(strict=True),
                 args.velvetctl.resolve(strict=True))


if __name__ == "__main__":
    main()
