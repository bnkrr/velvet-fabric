#!/usr/bin/env python3
"""Run a selected finite suite serially; preserve every case's result."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from cases import catalog


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('daemon', type=Path)
    p.add_argument('babel', type=Path)
    p.add_argument('--group', choices=('matrix', 'faults', 'all'), default='all')
    p.add_argument('--case', action='append', choices=catalog())
    p.add_argument('--family', choices=('ipv4', 'ipv6', 'both'), default='both')
    p.add_argument('--artifacts', type=Path, required=True)
    args = p.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=False)
    cases = args.case or [c for c in catalog() if args.group == 'all' or (c.startswith('matrix-') == (args.group == 'matrix'))]
    families = ('ipv4', 'ipv6') if args.family == 'both' else (args.family,)
    results, process, stopped = [], None, False
    def stop(*_):
        nonlocal stopped
        stopped = True
        if process and process.poll() is None:
            process.terminate()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)
    for family in families:
        for case in cases:
            if stopped:
                return 130
            label = family + '-' + case
            started = time.monotonic()
            print(json.dumps({'start': label}), flush=True)
            (args.artifacts / 'current.json').write_text(json.dumps({'case': label, 'completed': len(results)}))
            with (args.artifacts / (label + '.log')).open('w') as log:
                process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('run.py')),
                    str(args.daemon.resolve()), str(args.babel.resolve()), '--case', case,
                    '--underlay', family, '--artifacts', str((args.artifacts / label).resolve())], stdout=log, stderr=log)
                try:
                    code = process.wait(timeout=1200)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    code = process.wait(timeout=90)
                    code = code or 124
            result = {'case': label, 'exit_code': code, 'seconds': round(time.monotonic() - started, 3)}
            results.append(result)
            (args.artifacts / 'results.json').write_text(json.dumps(results, indent=2))
            print(json.dumps(result), flush=True)
    return 1 if any(r['exit_code'] for r in results) else 0


if __name__ == '__main__':
    raise SystemExit(main())
