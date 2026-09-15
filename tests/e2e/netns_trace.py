"""Bounded failure history for interfaces which may disappear before assertion."""
from collections import deque
import hashlib
import json
import subprocess
import threading
import time


class NetnsTrace:
    def __init__(self, namespaces, runtime):
        self.namespaces = namespaces
        self.runtime = runtime
        self.history = deque(maxlen=180)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.collect, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopped.set()
        self.thread.join(timeout=10)

    def command(self, namespace, *args):
        result = subprocess.run(
            ["ip", "netns", "exec", namespace, *args],
            text=True, capture_output=True, timeout=2)
        return result.stdout.strip()

    def collect(self):
        started = time.monotonic()
        offsets = dict.fromkeys(self.namespaces, 0)
        while not self.stopped.is_set():
            sample = {"seconds": round(time.monotonic() - started, 3), "nodes": {}}
            try:
                for node, namespace in self.namespaces.items():
                    if self.stopped.is_set():
                        break
                    # Hash key material before retaining anything. A hash lets
                    # us compare both ends without publishing their secrets.
                    rows = []
                    raw = self.command(namespace, "wg", "show", "all", "dump")
                    for line in raw.splitlines():
                        fields = line.split("\t")
                        if len(fields) == 5:
                            fields[1] = hashlib.sha256(fields[1].encode()).hexdigest()
                        elif len(fields) == 9:
                            fields[2] = hashlib.sha256(fields[2].encode()).hexdigest()
                        else:
                            raise ValueError("unexpected WireGuard dump format")
                        rows.append(fields)
                    with (self.runtime / f"{node}.log").open() as log:
                        log.seek(offsets[node])
                        events = log.read()
                        offsets[node] = log.tell()
                    sample["nodes"][node] = {
                        "wg": rows, "events": events,
                        "addresses": self.command(namespace, "ip", "-j", "-6", "addr", "show"),
                        "udp": self.command(namespace, "ss", "-H", "-u", "-n", "-a"),
                    }
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                sample["error"] = type(error).__name__
            self.history.append(sample)
            self.stopped.wait(1)

    def dump(self, stream):
        self.stop()
        print("--- recent network timeline (key material hashed) ---", file=stream)
        for sample in self.history:
            print(json.dumps(sample), file=stream)
