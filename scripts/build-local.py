#!/usr/bin/env python3
"""Build local Linux velvetd, velvetctl and babel-rs into one versioned bundle."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*command, cwd=None, env=None):
    return subprocess.check_output(list(map(str, command)), cwd=cwd, env=env, text=True).strip()


def executable(value, name, fallback):
    candidate = value or shutil.which(name) or (str(fallback) if fallback.is_file() else None)
    if not candidate:
        raise ValueError(f"{name} not found; install the toolchain or pass --{name}")
    result = shutil.which(candidate)
    if result is None:
        raise ValueError(f"executable not found: {candidate}")
    # Keep rustup proxy names intact (resolving the symlink would invoke rustup).
    return os.path.abspath(result)


def git_state(repo, mode='worktree', revision='HEAD'):
    commit = run('git', 'rev-parse', '--verify', revision + '^{commit}', cwd=repo)
    dirty = bool(run('git', 'status', '--porcelain', '--untracked-files=normal', cwd=repo)) if mode == 'worktree' else False
    return {'commit': commit, 'dirty': dirty, 'source': mode}


def pinned_revision(root):
    revision = (root / 'tests/babel-revision').read_text().strip()
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('tests/babel-revision must contain one full commit SHA')
    return revision


def export_revision(repo, revision, target):
    """Export a local commit without checkout/fetch or touching the worktree."""
    archive = target.parent / 'babel-source.tar'
    subprocess.run(['git', '-C', str(repo), 'archive', '--format=tar', '-o', str(archive), revision], check=True)
    target.mkdir()
    links = []
    with tarfile.open(archive) as source:
        for member in source:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or '..' in relative.parts or not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError(f'unsupported source archive entry: {member.name}')
            path = target.joinpath(*relative.parts)
            if member.issym():
                links.append((path, member.linkname))
            elif member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as data, path.open('wb') as dest:
                    shutil.copyfileobj(data, dest)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
    # Cargo's crate LICENSE entries point to ../../LICENSE. Materialize only
    # regular files inside this export; never follow a link out of the tree.
    for path, link in links:
        resolved = (path.parent / link).resolve()
        if not resolved.is_relative_to(target.resolve()) or not resolved.is_file():
            raise ValueError(f'unsupported source symlink: {path.relative_to(target)}')
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, path)


def cargo_artifact(output):
    paths = set()
    for line in output.splitlines():
        item = json.loads(line)
        if (item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'babel-rs'
                and 'bin' in item['target'].get('kind', []) and item.get('executable')):
            paths.add(item['executable'])
    if len(paths) != 1:
        raise ValueError('Cargo did not report exactly one babel-rs executable')
    return Path(paths.pop())


def publish(bundle, output, label):
    """Publish the whole bundle, then atomically advance a relative latest link."""
    latest = output / 'latest'
    if latest.exists() and not latest.is_symlink():
        raise ValueError(f'refusing to replace non-symlink {latest}')
    destination = output / label
    bundle.rename(destination)
    temporary = output / ('.latest-' + uuid.uuid4().hex)
    try:
        temporary.symlink_to(label, target_is_directory=True)
        os.replace(temporary, latest)
    finally:
        temporary.unlink(missing_ok=True)
    return latest


def build(args):
    if platform.system() != 'Linux':
        raise ValueError('this helper builds native Linux binaries; run it on a Linux build host')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise ValueError('supported native architectures: Linux amd64/arm64')
    babel_repo = args.babel_repo.expanduser().resolve()
    output = args.output.expanduser().resolve()
    go = executable(args.go, 'go', Path.home() / '.local/go/bin/go')
    cargo = executable(args.cargo, 'cargo', Path.home() / '.cargo/bin/cargo')
    pin = pinned_revision(ROOT)
    fabric_info = git_state(ROOT)
    babel_info = git_state(babel_repo, args.babel_source, pin if args.babel_source == 'pinned' else 'HEAD')
    tested = babel_info['commit'] == pin and not babel_info['dirty']
    print(f"Fabric: {fabric_info['commit'][:12]}{' + working changes' if fabric_info['dirty'] else ''}", flush=True)
    print(f"Babel:  {babel_info['commit'][:12]} ({args.babel_source}){' + working changes' if babel_info['dirty'] else ''}", flush=True)
    if not tested:
        print('Babel differs from the Fabric E2E pin; use --babel-source pinned for that tested revision.', flush=True)
    output.mkdir(parents=True, exist_ok=True)
    if (output / 'latest').exists() and not (output / 'latest').is_symlink():
        raise ValueError(f"{output / 'latest'} must be absent or a symlink")
    env = dict(os.environ)
    env['PATH'] = os.pathsep.join([str(Path(go).parent), str(Path(cargo).parent), env.get('PATH', '')])
    env.update(CGO_ENABLED='0', GOOS='linux', GOARCH=arch)
    env.setdefault('GOCACHE', str(ROOT / '.local/cache/go-build'))
    env.setdefault('GOMODCACHE', str(ROOT / '.local/cache/go-mod'))
    env.setdefault('CARGO_TARGET_DIR', str(ROOT / '.local/cache/build-local-babel'))
    rustc = shutil.which('rustc', path=env['PATH'])
    if not rustc:
        raise ValueError('rustc not found alongside Cargo or in PATH')
    rust_info = run(rustc, '-vV', cwd=babel_repo, env=env)
    target = next(line.removeprefix('host: ') for line in rust_info.splitlines() if line.startswith('host: '))
    if not target.startswith(('x86_64-unknown-linux-', 'aarch64-unknown-linux-')):
        raise ValueError(f'expected a native Linux Rust toolchain, got {target}')
    version = f"local-{fabric_info['commit'][:12]}" + ('-dirty' if fabric_info['dirty'] else '')
    with tempfile.TemporaryDirectory(prefix='.build-', dir=output) as temporary:
        work = Path(temporary)
        bundle = work / 'bundle'
        bundle.mkdir()
        babel_source = babel_repo
        if args.babel_source == 'pinned':
            babel_source = work / 'babel-source'
            export_revision(babel_repo, pin, babel_source)
        for binary in ('velvetd', 'velvetctl'):
            print(f'Building {binary}...', flush=True)
            subprocess.run([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
                            '-ldflags', f'-X main.releaseVersion={version}', '-o', str(bundle / binary),
                            f'./cmd/{binary}'], cwd=ROOT, env=env, check=True)
        print('Building babel-rs...', flush=True)
        messages = run(cargo, 'build', '--locked', '--release', '--package', 'babel-rs',
                       '--target', target, '--message-format=json-render-diagnostics', cwd=babel_source, env=env)
        shutil.copy2(cargo_artifact(messages), bundle / 'babel-rs')
        versions = {'velvetd': run(bundle / 'velvetd', '--version'),
                    'babel-rs': run(bundle / 'babel-rs', '--version')}
        run(bundle / 'velvetctl', 'resolve', '--help')
        run(bundle / 'babel-rs', 'check', '--config', babel_source / 'examples/babel-rs.toml')
        for name in ('velvetd', 'velvetctl', 'babel-rs'):
            (bundle / name).chmod(0o755)
        info = {'built_at': datetime.now(timezone.utc).isoformat(), 'platform': f'linux/{arch}',
                'fabric': fabric_info, 'babel': babel_info, 'fabric_tested_babel_commit': pin,
                'babel_matches_tested_revision': tested, 'versions': versions,
                'toolchains': {'go': run(go, 'version', cwd=ROOT, env=env),
                               'cargo': run(cargo, '--version', cwd=babel_source, env=env),
                               'rustc': rust_info}, 'rust_target': target}
        (bundle / 'BUILDINFO.json').write_text(json.dumps(info, indent=2) + '\n')
        names = ('velvetd', 'velvetctl', 'babel-rs', 'BUILDINFO.json')
        (bundle / 'SHA256SUMS').write_text(''.join(hashlib.sha256((bundle / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names))
        label = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + fabric_info['commit'][:8] + '-' + uuid.uuid4().hex[:8]
        latest = publish(bundle, output, label)
    print(f'Ready: {latest}\n  velvetd\n  velvetctl\n  babel-rs\n  BUILDINFO.json\n  SHA256SUMS', flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--babel-repo', type=Path, default=ROOT.parent / 'babel-rs')
    parser.add_argument('--babel-source', choices=('worktree', 'pinned'), default='worktree',
                        help='worktree includes local Babel changes (default); pinned exports the Fabric E2E revision')
    parser.add_argument('--output', type=Path, default=ROOT / '.local/dist', help='bundle directory, with an atomically updated latest symlink')
    parser.add_argument('--go', default=os.environ.get('VELVET_GO_BIN'), help='Go executable')
    parser.add_argument('--cargo', default=os.environ.get('VELVET_CARGO_BIN'), help='Cargo executable')
    try:
        build(parser.parse_args(argv))
    except (ValueError, OSError, subprocess.CalledProcessError, StopIteration) as exc:
        print(f'build-local: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
