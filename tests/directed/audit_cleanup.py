#!/usr/bin/env python3
"""Read-only ownership audit after a finite suite has finished."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import uuid


def output(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    namespaces = output('ip', 'netns', 'list').splitlines()
    links = json.loads(output('ip', '-j', 'link', 'show'))
    tables = json.loads(output('nft', '-j', 'list', 'tables'))['nftables']
    results = []
    for path in sorted(args.root.rglob('manifest.json')):
        manifest = json.loads(path.read_text())
        prefix = manifest.get('namespace_prefix', '')
        if not re.fullmatch(r'vfe-[0-9a-f]{8}-', prefix):
            raise ValueError(f'invalid namespace ownership: {path}')
        token = prefix[4:-1]
        errors = []
        errors += [n for n in namespaces if n.startswith(prefix)]
        errors += [link['ifname'] for link in links if token in link['ifname']]
        errors += [str(e['table']) for e in tables if 'table' in e and token in e['table']['name']]
        for uid in manifest['uids'].values():
            uuid.UUID(uid)
            for base in ('/run/velvet', '/var/lib/velvet'):
                if (Path(base) / uid).exists():
                    errors.append(str(Path(base) / uid))
        try:
            command = Path(f"/proc/{manifest['pid']}/cmdline").read_bytes().decode().replace('\0', ' ')
            if str(path.parent) in command:
                errors.append('runner still active: ' + command)
        except FileNotFoundError:
            pass
        results.append({'run': str(path.parent), 'remaining': errors})
    if not results:
        raise ValueError('no run manifests found')
    print(json.dumps(results, indent=2))
    return int(any(r['remaining'] for r in results))


if __name__ == '__main__':
    raise SystemExit(main())
