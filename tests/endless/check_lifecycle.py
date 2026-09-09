#!/usr/bin/env python3
"""Root-only fixture regression: retained namespaces and interrupted creation."""
import os
from pathlib import Path
import signal
import tempfile
import time

from netns import Runner, StopRequested, arguments


def main():
    args, topology = arguments()
    if os.geteuid() != 0 or args.artifacts is None:
        raise SystemExit("requires root and --artifacts naming a new directory")
    os.umask(0o077)
    args.artifacts.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="velvet-endless-lifecycle-") as directory:
        runner = Runner(args, topology, Path(directory), args.artifacts)
        try:
            runner.prepare()
            runner.add_node(0)
            runner.add_node(1)
            runner.add_node(2)

            def wait_ready(node):
                runner.deadline = time.monotonic() + 30
                while True:
                    if runner.nodes[node]["proc"].poll() is not None:
                        raise RuntimeError("recreated velvetd exited during startup")
                    try:
                        status = runner.command(node)
                    except (FileNotFoundError, ConnectionRefusedError):
                        time.sleep(0.1)
                        continue
                    if status["runtime"].get("babel", {}).get("state") == "running":
                        return
                    time.sleep(0.1)

            for iteration in range(5):
                for node in (1, 2):
                    wait_ready(node)
                    with open(f'/run/netns/{runner.namespace(node)}', 'rb'):
                        runner.stop_node(node, abrupt=bool(iteration % 2))
                        runner.add_node(node)
                    runner.record('recreated-with-open-namespace', node=node, iteration=iteration + 1)
            for node in (1, 2):
                wait_ready(node)
            runner.deadline = None
            original = runner.run

            def interrupt_creation(*command, **kwargs):
                result = original(*command, **kwargs)
                if command == ("ip", "netns", "add", runner.namespace(3)):
                    os.kill(os.getpid(), signal.SIGTERM)
                return result

            previous = signal.signal(signal.SIGTERM, lambda signum, frame: setattr(runner, "stop_signal", signum))
            runner.run = interrupt_creation
            try:
                runner.add_node(3)
            except StopRequested:
                assert 3 in runner.created, "signal interrupted ownership bookkeeping"
                runner.record("interrupted-creation-tracked")
            else:
                raise AssertionError("SIGTERM did not stop the next bounded operation")
            finally:
                runner.run = original
                signal.signal(signal.SIGTERM, previous)
        finally:
            if runner.cleanup():
                raise RuntimeError("fixture cleanup failed")
        print("PASS: public and NAT recreation with retained namespace references; SIGTERM during namespace creation")


if __name__ == "__main__":
    main()
