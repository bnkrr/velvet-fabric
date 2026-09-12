#!/usr/bin/env python3
"""Opt-in endless velvetd membership churn with an independent host verifier."""
import argparse
from collections import deque
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import statistics
import subprocess as sp
import tempfile
import threading
import time
import uuid

from model import process_fd_limit
from model import Topology, PendingLinks, NotConverged, address, audit, parse_wg, is_babel_check, nat_heartbeat_fresh
from coverage_model import Coverage
from materialization import MaterializedLinks


class StopRequested(BaseException):
    pass


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("daemon", nargs="?", type=Path)
    parser.add_argument("babel", nargs="?", type=Path)
    parser.add_argument("--nodes", type=int, default=6)
    parser.add_argument("--min-nodes", type=int, default=3)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=0, help="0: until failure or interruption")
    parser.add_argument("--underlay", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--dynamic", choices=("active", "off"), default="active")
    parser.add_argument("--nat-policy", choices=("active", "passive"), default="active")
    parser.add_argument("--capture", action="store_true", help="bounded bridge UDP capture; requires tcpdump")
    parser.add_argument("--exercise", action="append", default=[],
                        choices=("policy", "blackout", "control-loss", "nat-reset", "nat-rebind"),
                        help="run each selected online mutation once before membership churn")
    parser.add_argument("--settle-timeout", type=float, default=180)
    parser.add_argument("--stable-seconds", type=float, default=10)
    parser.add_argument("--probe-pairs", type=int, default=16)
    parser.add_argument("--rss-growth-mib", type=int, default=64)
    parser.add_argument("--artifacts", type=Path, help="new directory, never reuse an existing run")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--validate", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (args.rounds < 0 or args.probe_pairs < 1 or args.rss_growth_mib < 1
            or not math.isfinite(args.settle_timeout) or not math.isfinite(args.stable_seconds)
            or not 0 < args.stable_seconds < args.settle_timeout):
        parser.error("invalid duration/round/probe/resource bounds")
    try:
        topology = Topology(args.nodes, args.min_nodes, args.seed, args.dynamic == "active")
    except ValueError as error:
        parser.error(str(error))
    if args.dynamic == 'off' and (args.exercise or args.nat_policy != 'active'):
        parser.error('--exercise and --nat-policy require active dynamic discovery')
    if len(args.exercise) != len(set(args.exercise)):
        parser.error('duplicate --exercise')
    if args.dynamic == 'active':
        for node in set(range(args.nodes)) - topology.public:
            topology.modes[node] = args.nat_policy
    if args.plan:
        if not args.rounds:
            parser.error("--plan requires positive --rounds")
    elif not args.validate:
        for path in (args.daemon, args.babel):
            if path is None or not path.is_file() or not os.access(path, os.X_OK):
                parser.error("executable velvetd and pinned babel-rs paths are required")
    return args, topology


def rotating_logger(path, size, backups):
    logger = logging.Logger(str(path))
    handler = RotatingFileHandler(path, maxBytes=size, backupCount=backups)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


class Runner:
    def __init__(self, args, topology, runtime, artifacts):
        self.args, self.topology = args, topology
        self.runtime, self.artifacts = runtime, artifacts
        self.run_id = uuid.uuid4()
        self.token = self.run_id.hex[:8]
        self.bridge = f"veb{self.token}"
        self.uids = {n: str(uuid.uuid5(self.run_id, str(n))) for n in range(topology.size)}
        self.nodes, self.created, self.root_links = {}, set(), set()
        self.routers, self.nat_processes = set(), {}
        self.bridge_created = False
        self.owned_dirs = set()
        self.keys, self.pubs = {}, {}
        self.round, self.probe_cursor = 0, 0
        self.counts = {"add": 0, "delete": 0, "abrupt": 0, "graceful": 0}
        self.started, self.deadline = time.monotonic(), None
        self.stop_signal = None
        self.latest = {}
        self.coverage = Coverage(args.underlay)
        self.pending_links = PendingLinks()
        self.materialized_links = {}
        self.capture = None
        self.wan_epochs = {node: 0 for node in range(topology.size)}
        self.nat_epochs = {node: 0 for node in range(topology.size)}
        self.phase = 'membership'
        self.last_mismatch = None
        self.snapshots = rotating_logger(artifacts / 'observations.jsonl', 4 * 1024 * 1024, 2)
        self.events = rotating_logger(artifacts / "events.jsonl", 4 * 1024 * 1024, 3)
        self.samples = rotating_logger(artifacts / "samples.jsonl", 1024 * 1024, 1)
        self.logs = {}

    def save(self, name, value):
        temporary = self.artifacts / (name + ".tmp")
        temporary.write_text(json.dumps(value, indent=2))
        temporary.replace(self.artifacts / name)

    def record(self, kind, **fields):
        entry = {"kind": kind, "round": self.round, "elapsed": round(time.monotonic() - self.started, 3), "phase": self.phase, **fields}
        value = json.dumps(entry)
        self.events.info(value)
        print(value, flush=True)

    def timeout(self, maximum=5):
        if self.stop_signal is not None:
            raise StopRequested(f"operator requested stop (signal {self.stop_signal})")
        if self.deadline is None:
            return maximum
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("phase deadline exceeded")
        return min(maximum, remaining)

    def run(self, *args, check=True, input=None):
        result = sp.run(args, input=input, capture_output=True, text=True, timeout=self.timeout(),
                        env={**os.environ, "LC_ALL": "C"})
        if check and result.returncode:
            raise RuntimeError(f"{args}: {result.stderr.strip()}")
        return result.stdout.strip()

    def namespace(self, node):
        return f"vfe-{self.token}-{node}"

    def ns(self, node, *args, **kwargs):
        return self.run("ip", "netns", "exec", self.namespace(node), *args, **kwargs)

    def ip(self, node, *args, **kwargs):
        return self.run("ip", "-n", self.namespace(node), *args, **kwargs)

    def wan(self, node):
        host = node + 1 + 128 * (self.wan_epochs[node] % 2)
        return f"192.0.2.{host}" if self.args.underlay == "ipv4" else f"2001:db8:ee::{host:x}"

    def endpoint(self, node, port):
        value = self.wan(node)
        return f"[{value}]:{port}" if ":" in value else f"{value}:{port}"

    def command(self, node, name="status"):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(self.timeout(3))
            sock.connect(str(self.runtime / f"{node}.ctl"))
            with sock.makefile("rwb") as stream:
                def read():
                    line = stream.readline(1024 * 1024 + 1)
                    if not line or len(line) > 1024 * 1024:
                        raise RuntimeError(f"node {node}: invalid control frame size")
                    return json.loads(line)
                if read()["api_version"] != 1:
                    raise RuntimeError("unsupported control API")
                stream.write((json.dumps({"api_version": 1, "id": 1, "command": name, "params": {}}) + "\n").encode())
                stream.flush()
                reply = read()
                if not reply["ok"]:
                    raise RuntimeError(f"node {node}: control rejected {name}: {reply}")
                return reply["result"]

    def prepare(self):
        self.run("ip", "link", "add", self.bridge, "type", "bridge")
        self.bridge_created = True
        self.run("ip", "link", "set", self.bridge, "up")
        for node in range(self.topology.size):
            self.keys[node] = self.run("wg", "genkey")
            self.pubs[node] = self.run("wg", "pubkey", input=self.keys[node] + "\n")
            for root in ("/run/velvet", "/var/lib/velvet"):
                path = Path(root) / self.uids[node]
                path.mkdir(parents=True, exist_ok=False)
                self.owned_dirs.add(path)
        self.psk = self.run("wg", "genpsk")
        if self.args.capture:
            with (self.artifacts / 'capture.log').open('w') as log:
                self.capture = sp.Popen(['tcpdump', '-Z', 'root', '-i', self.bridge, '-n', '-U',
                    '-s', '256', '-C', '10', '-W', '3', '-w', str(self.artifacts / 'underlay.pcap'), 'udp'],
                    stdout=sp.DEVNULL, stderr=log)
            time.sleep(0.1)
            if self.capture.poll() is not None:
                raise RuntimeError('packet capture failed to start; see capture.log')

    def write_config(self, node):
        peers = []
        if node in self.topology.public:
            for peer in range(self.topology.size):
                if peer == node:
                    continue
                # NodeSpec requires an endpoint. This deliberately unused WAN
                # address is only a bootstrap hint; authenticated WG roaming
                # learns the member that actually selects this public receiver.
                placeholder = '[2001:db8:ee::ffff]:9' if self.args.underlay == 'ipv6' else '192.0.2.254:9'
                peers.append({'name': f'in-{peer}', 'public_key': self.pubs[peer],
                    'listen_port': 52000 + peer, 'endpoints': [placeholder],
                    'interface_name': f'vl-in-{peer:02d}', 'persistent_keepalive_seconds': 1})
        bootstrap = self.topology.boot[node]
        if bootstrap is not None:
            peers.append({'name': 'bootstrap', 'public_key': self.pubs[bootstrap],
                'listen_port': 51000 + node, 'endpoints': [self.endpoint(bootstrap, 52000 + node)],
                'interface_name': f'vl-boot-{bootstrap:02d}', 'persistent_keepalive_seconds': 1})
        spec = {'api_version': 'velvet.io/v1alpha1', 'kind': 'NodeSpec',
            'fabric': {'psk': self.psk, 'loopback_prefix_v6': 'fd78:e2ee::/48', 'routing_table_id': 20000},
            'node': {'uid': {'name': f'n{node}', 'uuid': self.uids[node]},
                     'private_key': self.keys[node], 'loopback_address_v6': address(node)},
            'peers': peers, 'babel': {'enabled': True, 'executable': str(self.args.babel.resolve())},
            'dynamic_links': {'mode': self.topology.modes[node], 'allow_candidate_prefixes': [
                '192.0.2.0/24' if self.args.underlay == 'ipv4' else '2001:db8:ee::/64']}}
        (self.runtime / f'{node}.json').write_text(json.dumps(spec))

    def make_namespace(self, node):
        self.run('ip', 'netns', 'add', self.namespace(node))
        self.ip(node, 'link', 'set', 'lo', 'up')
        self.ns(node, 'sysctl', '-qw', 'net.ipv6.conf.default.accept_dad=0', 'net.ipv6.conf.default.autoconf=0')

    def lan(self, node, host):
        return f'10.88.{node}.{host}' if self.args.underlay == 'ipv4' else f'fd42:ee:{node:x}::{host}'

    def add_node(self, node):
        self.created.add(node)
        self.make_namespace(node)
        outer = node
        if node not in self.topology.public:
            outer = f'r{node}'
            self.routers.add(node)
            self.make_namespace(outer)
        root, other = f'ver{self.token}{node:x}', f'ven{self.token}{node:x}'
        self.run('ip', 'link', 'add', root, 'type', 'veth', 'peer', 'name', other)
        self.root_links.update((root, other))
        self.run('ip', 'link', 'set', root, 'master', self.bridge)
        self.run('ip', 'link', 'set', root, 'up')
        self.run('ip', 'link', 'set', other, 'netns', self.namespace(outer), 'name', 'wan')
        self.root_links.discard(other)
        self.ip(outer, 'addr', 'add', self.wan(node) + ('/24' if self.args.underlay == 'ipv4' else '/64'), 'dev', 'wan')
        self.ip(outer, 'link', 'set', 'wan', 'up')
        self.ns(node, 'sysctl', '-qw', 'net.ipv4.ip_local_port_range=31000 32000')
        if outer != node:
            left, right = f'vel{self.token}{node:x}', f'veq{self.token}{node:x}'
            self.run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            self.root_links.update((left, right))
            for owner, device, host in ((node, left, 2), (outer, right, 1)):
                self.run('ip', 'link', 'set', device, 'netns', self.namespace(owner), 'name', 'lan')
                self.root_links.discard(device)
                self.ip(owner, 'addr', 'add', self.lan(node, host) + ('/24' if self.args.underlay == 'ipv4' else '/64'), 'dev', 'lan')
                self.ip(owner, 'link', 'set', 'lan', 'up')
            self.ip(node, '-4' if self.args.underlay == 'ipv4' else '-6', 'route', 'add', 'default', 'via', self.lan(node, 1))
            # AF_PACKET receives frames before this drop. The kernel must not
            # forward a second copy or return ICMP unreachable to the member.
            self.ns(outer, 'nft', '-f', '-', input="""table inet velvet_nat {
 chain prerouting { type filter hook prerouting priority -300; policy accept;
 iifname "lan" meta l4proto udp drop
 }
 chain output { type filter hook output priority 0; policy accept;
 oifname "wan" icmp type destination-unreachable drop
 oifname "wan" icmpv6 type destination-unreachable drop
 }
}""")
            self.start_nat(node)
        self.coverage.reset(node)
        self.write_config(node)
        self.materialized_links[node] = MaterializedLinks(self.namespace(node))
        self.start_daemon(node)

    def on_event(self, node, event):
        """Optional bounded-test instrumentation; never an acceptance oracle."""

    def start_daemon(self, node):
        logger = self.logs.get(node)
        if logger is None:
            logger = rotating_logger(self.artifacts / f"node-{node}.log", 1024 * 1024, 1)
            self.logs[node] = logger
        proc = sp.Popen(["ip", "netns", "exec", self.namespace(node), str(self.args.daemon.resolve()),
            "--config", str(self.runtime / f"{node}.json"), "--control-socket", str(self.runtime / f"{node}.ctl"),
            "--reconcile-interval", "1s"], stdout=sp.PIPE, stderr=sp.STDOUT)
        info = {"proc": proc, "started": time.monotonic(), "resources": {}, "ready": False, "child": None}
        self.nodes[node] = info

        def drain():
            with proc.stdout:
                while chunk := proc.stdout.readline(65536):
                    line = chunk.decode(errors="replace").rstrip("\n")
                    try:
                        event = json.loads(line)
                        event['observed_elapsed'] = round(time.monotonic() - self.started, 6)
                        event['observed_round'] = self.round
                        self.on_event(node, event)
                        if event.get('event') == 'velvet-dynamic-attempt' and event.get('status') == 'proposed':
                            remote = next((n for n, uid in self.uids.items() if uid == event.get('remote_uid')), None)
                            if remote is not None:
                                self.coverage.proposed(node, remote)
                        line = json.dumps(event)
                    except (ValueError, TypeError):
                        pass
                    logger.info(line)

        thread = threading.Thread(target=drain, daemon=True)
        info["thread"] = thread
        thread.start()
        self.record("node-start", node=node, pid=proc.pid, bootstrap=self.topology.boot[node], profile=self.topology.profiles[node])

    def start_nat(self, node):
        mapping, filtering, allocation = self.topology.profiles[node]
        (self.runtime / f'nat-{node}.json').unlink(missing_ok=True)
        with (self.runtime / f'nat-{node}.log').open('w') as log:
            self.nat_processes[node] = sp.Popen(['ip', 'netns', 'exec', self.namespace(f'r{node}'), 'python3',
                str(Path(__file__).with_name('nat.py')), '--wan', self.wan(node), '--mapping', mapping,
                '--filter', filtering, '--allocation', allocation,
                '--seed', str(self.args.seed + node + self.nat_epochs[node]),
                '--status', str(self.runtime / f'nat-{node}.json'), *self.nat_options(node)], stdout=log, stderr=sp.STDOUT)

    def nat_options(self, node):
        return []

    def expected_helpers(self, node):
        return set()

    def stop_node(self, node, abrupt=False):
        info = self.nodes[node]
        proc = info["proc"]
        if proc.poll() is not None:
            raise RuntimeError(f"node {node}: exited before requested removal")
        info["expected_exit"] = -signal.SIGKILL if abrupt else 0
        proc.kill() if abrupt else proc.terminate()
        proc.wait(timeout=self.timeout(15))
        if not abrupt and proc.returncode != 0:
            raise RuntimeError(f"node {node}: graceful shutdown exit {proc.returncode}")
        # Parent-death SIGTERM must retire managed Babel even after SIGKILL.
        until = time.monotonic() + self.timeout(10)
        while self.run("ip", "netns", "pids", self.namespace(node)):
            if time.monotonic() >= until:
                raise RuntimeError(f"node {node}: orphaned process after velvetd stopped")
            time.sleep(0.1)
        info["thread"].join(timeout=self.timeout(3))
        if info["thread"].is_alive():
            raise RuntimeError(f"node {node}: log drain did not stop")
        # Stop the translator while its LAN/WAN interfaces still exist. A
        # deliberate link removal must not look like a translator crash.
        if node in self.nat_processes:
            process = self.nat_processes[node]
            if process.poll() is not None:
                raise RuntimeError(f'node {node}: NAT fixture exited unexpectedly')
            process.terminate()
            process.wait(timeout=self.timeout(5))
            if process.returncode != 0:
                raise RuntimeError(f'node {node}: NAT fixture shutdown failed')
            del self.nat_processes[node]
        del self.nodes[node]
        self.materialized_links.pop(node).close()
        self.pending_links.forget(node)
        root = f'ver{self.token}{node:x}'
        self.run('ip', 'link', 'del', root)
        self.root_links.discard(root)
        self.run('ip', 'netns', 'del', self.namespace(node))
        self.created.remove(node)
        if node in self.routers:
            self.run('ip', 'netns', 'del', self.namespace(f'r{node}'))
            self.routers.remove(node)

    def resources(self, node, role, pid):
        info = self.nodes[node]
        sample = info["resources"].setdefault(role, {"pid": pid, "started": time.monotonic(),
                                                    "rss": deque(maxlen=60), "baseline": None})
        if sample["pid"] != pid:
            raise RuntimeError(f"node {node}: unexpected {role} process replacement")
        try:
            lines = Path(f"/proc/{pid}/status").read_text().splitlines()
            rss = next(int(line.split()[1]) for line in lines if line.startswith("VmRSS:"))
            fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        except (OSError, StopIteration):
            raise RuntimeError(f"node {node}: {role} process disappeared") from None
        sample["rss"].append(rss)
        median = statistics.median(sample["rss"])
        if time.monotonic() - sample['started'] >= 300 and len(sample["rss"]) == 60:
            if sample["baseline"] is None:
                sample["baseline"] = median
            elif median > sample["baseline"] + self.args.rss_growth_mib * 1024:
                raise RuntimeError(f"node {node}: {role} median RSS grew beyond budget")
        limit = process_fd_limit(role, self.topology.size)
        self.samples.info(json.dumps({"round": self.round, "node": node, "role": role, "pid": pid,
            "rss_kib": rss, "fds": fds, "fd_limit": limit, "baseline_kib": sample["baseline"]}))
        if fds > limit:
            raise RuntimeError(f"node {node}: {role} FD count {fds} exceeds pool-sized budget {limit}")

    def observe(self):
        try:
            if self.capture is not None and self.capture.poll() is not None:
                raise RuntimeError('packet capture exited unexpectedly; see capture.log')
            observations = self._observe()
            self.pending_links.observe(observations, time.monotonic())
            return observations
        finally:
            self.snapshots.info(json.dumps({'round': self.round, 'phase': self.phase,
                'elapsed': round(time.monotonic() - self.started, 6),
                'observations': self.latest}))

    def _observe(self):
        self.latest = {}
        for node, info in sorted(self.nodes.items()):
            if info["proc"].poll() is not None:
                raise RuntimeError(f"node {node}: unexpected velvetd exit {info['proc'].returncode}")
            try:
                status = self.command(node)
            except (FileNotFoundError, ConnectionRefusedError):
                if info["ready"]:
                    raise RuntimeError(f"node {node}: established control socket disappeared") from None
                raise NotConverged(f"node {node}: waiting for initial control socket") from None
            info["ready"] = True
            self.resources(node, "velvetd", info["proc"].pid)
            child = status["runtime"].get("babel", {}).get("pid")
            if not child:
                raise NotConverged(f"node {node}: waiting for managed Babel")
            self.resources(node, "babel", child)
            pids = {int(pid) for pid in self.run("ip", "netns", "pids", self.namespace(node)).split()}
            expected = {info["proc"].pid, child} | self.expected_helpers(node)
            if not expected <= pids:
                raise RuntimeError(f"node {node}: missing expected namespace process: {pids}")
            extra = pids - expected
            for pid in extra:
                try:
                    proc = Path('/proc') / str(pid)
                    parent = next(int(line.split()[1]) for line in (proc / 'status').read_text().splitlines()
                                  if line.startswith('PPid:'))
                    executable = os.readlink(proc / 'exe')
                    argv = (proc / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
                except (FileNotFoundError, ProcessLookupError):
                    raise NotConverged(f'node {node}: process exited during inspection')
                if not is_babel_check(parent, executable, argv, info['proc'].pid,
                                      str(self.args.babel.resolve()), f'/run/velvet/{self.uids[node]}/babel-rs.toml'):
                    raise RuntimeError(f"node {node}: unexpected namespace process {pid}")
            if extra:
                # Do not count a phase as stable until even valid short-lived
                # config checkers have exited. A stuck checker hits the same
                # convergence deadline; unrelated/orphan processes still fail.
                raise NotConverged(f'node {node}: Babel configuration validation in progress')
            nat_status = None
            if node in self.nat_processes:
                process = self.nat_processes[node]
                if process.poll() is not None:
                    raise RuntimeError(f'node {node}: NAT fixture failed: ' + (self.runtime / f'nat-{node}.log').read_text()[-2000:])
                self.resources(node, 'nat', process.pid)
                path = self.runtime / f'nat-{node}.json'
                if not path.exists():
                    raise NotConverged(f'node {node}: NAT fixture starting')
                nat_status = json.loads(path.read_text())
                profile = tuple(nat_status[key] for key in ('mapping', 'filter', 'allocation'))
                if profile != tuple(self.topology.profiles[node]):
                    raise RuntimeError(f'node {node}: NAT fixture is running the wrong profile')
                if not nat_heartbeat_fresh(nat_status, time.monotonic()):
                    raise RuntimeError(f'node {node}: NAT fixture stalled')
            self.latest[node] = {"observed_elapsed": round(time.monotonic() - self.started, 6), "status": status, 'nat': nat_status, "wg": parse_wg(self.ns(node, "wg", "show", "all", "dump")),
                "fib": json.loads(self.ip(node, "-6", "-j", "route", "show", "table", "20000")),
                "main": json.loads(self.ip(node, "-6", "-j", "route", "show", "table", "main")),
                "ifindices": {link['ifname']: link['ifindex'] for link in json.loads(self.ip(node, '-j', 'link', 'show', 'type', 'wireguard'))},
                "babel_sockets": self.ns(node, 'ss', '-H', '-uan', 'sport', '=', ':6696'),
                "materialized_ifindices": self.materialized_links[node].read()}
        return self.latest

    def ping(self, source, target):
        result = sp.run(["ip", "netns", "exec", self.namespace(source), "ping", "-6", "-n", "-c", "1",
            "-W", "1", "-I", address(source), address(target)], capture_output=True, text=True, timeout=self.timeout(3),
            env={**os.environ, "LC_ALL": "C"})
        if result.returncode == 2 and ("Network is unreachable" in result.stderr or "No route to host" in result.stderr):
            return False
        if result.returncode not in (0, 1):
            raise RuntimeError(f"ping tool error: {result.stderr}")
        return result.returncode == 0

    def probes(self, pairs):
        count = min(self.args.probe_pairs, len(pairs))
        passed = set()
        for index in range(count):
            pair = pairs[(self.probe_cursor + index) % len(pairs)]
            if not self.ping(*pair):
                raise NotConverged(f"data-plane probe failed {pair}")
            self.coverage.ping(*pair)
            passed.add(pair)
        self.probe_cursor += count
        absent = sorted(set(range(self.topology.size)) - self.topology.active)
        if absent:
            source = sorted(self.topology.active)[self.round % len(self.topology.active)]
            if self.ping(source, absent[self.round % len(absent)]):
                raise NotConverged("deleted node still answers")
        return passed

    def verify(self, survivors=()):
        start, good_since, last_report = time.monotonic(), None, 0
        self.deadline = start + self.args.settle_timeout
        reason = "waiting for first audit"
        self.last_mismatch = None
        probed = set()
        while time.monotonic() < self.deadline:
            # NAT fallback may use the node being removed. Sample forwarding
            # inside the same bounded convergence window, not as an assumed
            # unaffected direct path inherited from the old full-mesh fixture.
            try:
                pairs = audit(self.topology, self.observe())
                probed.update(self.probes(pairs))
                if good_since is None:
                    good_since = time.monotonic()
                if time.monotonic() - good_since >= self.args.stable_seconds and set(pairs) <= probed:
                    if self.args.nat_policy == 'passive':
                        for node in self.topology.active - self.topology.public:
                            if any(self.coverage.proposals[node, peer] for peer in self.topology.active - {node}):
                                raise AssertionError(f'passive NAT node {node} initiated a proposal')
                    self.coverage.verified(self.topology, self.latest)
                    self.save("coverage.json", self.coverage.state())
                    self.save("latest.json", {"round": self.round, "topology": self.topology.state(), "observations": self.latest})
                    self.record("verified", seconds=round(time.monotonic() - start, 3), active=sorted(self.nodes),
                                pairs=len(pairs), operations=self.counts, public=sorted(self.topology.active & self.topology.public))
                    self.deadline = None
                    return
                reason = "checking stable window"
            except NotConverged as error:
                good_since, reason = None, str(error)
                self.last_mismatch = reason
            if time.monotonic() - last_report >= 30:
                self.record("waiting", reason=reason)
                last_report = time.monotonic()
            time.sleep(min(2, self.timeout(2)))
        raise TimeoutError(f"round {self.round}: {reason}")

    def execute(self):
        self.deadline = time.monotonic() + self.args.settle_timeout
        self.prepare()
        for node in sorted(self.topology.active):
            self.add_node(node)
        self.verify()
        if self.args.exercise:
            from mutations import exercise
            for name in self.args.exercise:
                self.round += 1
                self.phase = name
                exercise(self, name)
                self.coverage.operations[name] += 1
                self.save('coverage.json', self.coverage.state())
            self.phase = 'membership'
        membership_round = 0
        while self.args.rounds == 0 or membership_round < self.args.rounds:
            membership_round += 1
            self.round += 1
            self.deadline = time.monotonic() + self.args.settle_timeout
            previous = self.topology.active.copy()
            event = self.topology.next_event()
            self.record("operation", **event)
            if event["operation"] == "add":
                self.add_node(event["node"])
            else:
                self.stop_node(event["node"], event["abrupt"])
                self.counts["abrupt" if event["abrupt"] else "graceful"] += 1
            self.counts[event["operation"]] += 1
            self.coverage.operations[event["operation"]] += 1
            self.verify(sorted(previous & self.topology.active))
        self.record("complete", result="PASS", operations=self.counts)

    def snapshot_failure(self, error):
        self.deadline = None
        self.record("stopped", reason=str(error))
        self.save("coverage.json", self.coverage.state())
        self.save("failure.json", {"round": self.round, "phase": self.phase, "error": str(error),
                                  "last_verifier_mismatch": self.last_mismatch, "topology": self.topology.state(),
                                  "observations": self.latest, "operations": self.counts})
        self.deadline = time.monotonic() + 30
        for node in sorted(self.created):
            if time.monotonic() >= self.deadline:
                break
            diagnostics = {}
            for name, operation in (("routes", lambda: self.ip(node, "-6", "route", "show", "table", "all")),
                ("links", lambda: self.ip(node, "-details", "link", "show")),
                ("sockets", lambda: self.ns(node, "ss", "-tunap")),
                ("wg", lambda: self.ns(node, "wg", "show")), ("status", lambda: self.command(node))):
                try:
                    diagnostics[name] = operation()
                except Exception as failure:
                    diagnostics[name] = str(failure)
            self.save(f"diagnostic-{node}.json", diagnostics)
        self.deadline = None
        # These private, mode-0700 artifacts include test-only credentials.
        for source in list(self.runtime.glob("*.json")) + list(self.runtime.glob("nat-*.log")):
            shutil.copyfile(source, self.artifacts / source.name)
        for node in range(self.topology.size):
            state = Path("/var/lib/velvet") / self.uids[node]
            if state.exists():
                shutil.copytree(state, self.artifacts / f"state-{node}", dirs_exist_ok=True)

    def cleanup(self):
        self.deadline = None
        self.stop_signal = None
        errors = []
        for observer in self.materialized_links.values():
            observer.close()
        self.materialized_links.clear()
        if self.capture is not None:
            if self.capture.poll() is None:
                self.capture.send_signal(signal.SIGINT)
            try:
                self.capture.wait(timeout=5)
            except sp.TimeoutExpired:
                self.capture.kill(); self.capture.wait(timeout=3)
                errors.append('packet capture required forced cleanup')
        for info in self.nodes.values():
            if info["proc"].poll() is None:
                info["proc"].terminate()
        until = time.monotonic() + 15
        for node, info in self.nodes.items():
            try:
                info["proc"].wait(timeout=max(0.01, until - time.monotonic()))
                if info["proc"].returncode != info.get("expected_exit", 0):
                    errors.append(f"node {node}: cleanup exit {info['proc'].returncode}")
            except sp.TimeoutExpired:
                info["proc"].kill()
                info["proc"].wait(timeout=3)
                errors.append(f"node {node}: forced cleanup kill")
        for node, process in self.nat_processes.items():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except sp.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                errors.append(f'node {node}: forced NAT fixture kill')
        namespaces = list(sorted(self.created)) + [f'r{n}' for n in sorted(self.routers)]
        for node in namespaces:
            try:
                # Restrict emergency process cleanup to namespaces owned by this run.
                pids = self.run("ip", "netns", "pids", self.namespace(node)).split()
                while pids and time.monotonic() < until:
                    time.sleep(0.1)
                    pids = self.run("ip", "netns", "pids", self.namespace(node)).split()
                for pid in pids:
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                        errors.append(f"node {node}: orphaned process {pid}")
                    except ProcessLookupError:
                        pass
            except Exception as error:
                errors.append(str(error))
        # Delete host veths before namespace unlinking; otherwise asynchronous
        # namespace destruction can race the presence-check/delete sequence.
        for device in sorted(self.root_links) + ([self.bridge] if self.bridge_created else []):
            try:
                present = json.loads(self.run("ip", "-j", "link", "show"))
                if any(link["ifname"] == device for link in present):
                    self.run("ip", "link", "del", device)
            except Exception as error:
                errors.append(str(error))
        for node in namespaces:
            try:
                self.run("ip", "netns", "del", self.namespace(node))
            except Exception as error:
                errors.append(str(error))
        for info in self.nodes.values():
            info["thread"].join(timeout=3)
            if info["thread"].is_alive():
                errors.append("log drain remained alive")
        for path in self.owned_dirs:
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass
            except OSError as error:
                errors.append(str(error))
        self.record("cleanup", result="FAIL" if errors else "PASS", errors=errors)
        for logger in (self.events, self.samples, self.snapshots, *self.logs.values()):
            for handler in logger.handlers:
                handler.close()
        return errors


def main():
    args, topology = arguments()
    if args.plan:
        print(json.dumps({"seed": args.seed, "nodes": args.nodes, "initial": topology.state(),
                          "exercise_prelude": args.exercise}))
        if 'nat-rebind' in args.exercise:
            node = min(topology.active - topology.public)
            mapping, filtering, allocation = topology.profiles[node]
            topology.profiles[node] = (mapping, filtering, 'offset' if allocation == 'preserve' else 'preserve')
        for round_number in range(1, args.rounds + 1):
            print(json.dumps({"round": len(args.exercise) + round_number, "event": topology.next_event(), "state": topology.state()}))
        return 0
    if args.validate:
        return 0
    if os.geteuid() != 0:
        raise SystemExit("requires root on a disposable Linux test host")
    for tool in ("ip", "wg", "nft", "ping", "sysctl", "ss", *(("tcpdump",) if args.capture else ())):
        if not shutil.which(tool):
            raise SystemExit(f"missing {tool}")
    os.umask(0o077)
    artifacts = (args.artifacts or Path(".local/experiments/endless") / f"{time.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}").resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="velvet-endless-") as directory:
        runner = Runner(args, topology, Path(directory), artifacts)
        hashes = {}
        for name, path in (("velvetd", args.daemon), ("babel", args.babel)):
            with path.open("rb") as binary:
                hashes[name] = hashlib.file_digest(binary, "sha256").hexdigest()
        runner.save("manifest.json", {"arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
            "sha256": hashes, "kernel": os.uname().release, "python": os.sys.version, "pid": os.getpid(),
            "namespace_prefix": f"vfe-{runner.token}-", "bridge": runner.bridge, "uids": runner.uids, "topology": topology.state()})
        for name in ("netns.py", "model.py", "nat.py", "coverage_model.py", "mutations.py", "materialization.py"):
            shutil.copyfile(Path(__file__).with_name(name), artifacts / name)

        def stop(signum, _frame):
            # Finish the current bounded operation and its ownership bookkeeping
            # before unwinding; interruption between creation and tracking must
            # not leak a namespace, veth or newly spawned process.
            runner.stop_signal = signum

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, stop)
        code = 0
        try:
            runner.record("start", artifacts=str(artifacts), seed=args.seed, underlay=args.underlay, dynamic=args.dynamic)
            runner.execute()
        except (Exception, StopRequested) as error:
            code = 130 if isinstance(error, StopRequested) else 1
            runner.stop_signal = None
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(signum, signal.SIG_IGN)
            runner.snapshot_failure(error)
        finally:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(signum, signal.SIG_IGN)
            if runner.cleanup():
                code = 1
        return code


if __name__ == "__main__":
    raise SystemExit(main())
