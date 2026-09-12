"""Exercise VM wrappers without a toolchain, network connection or privileges."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='velvet-vm-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "repo space's"
        source = Path(__file__).resolve().parents[1]
        shutil.copytree(source, self.repo / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
        self.bin = self.base / 'tools'
        self.bin.mkdir()
        self.log = self.base / 'calls.jsonl'
        self.remote = self.base / "VM assets' $(not-a-command)"
        self.babel = self.base / 'babel checkout'
        self.babel.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('VELVET_', 'CARGO_', 'RUSTUP_', 'GO'))}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        VM_TEST_LOG=str(self.log), VM_TEST_ARTIFACT=str(self.base / 'custom target' / 'babel-rs'),
                        VELVET_VM_HOST='root@vm.example', VELVET_VM_REMOTE_ROOT=str(self.remote),
                        VELVET_BABEL_REPO=str(self.babel), GOARCH='arm64',
                        GOCACHE=str(self.base / 'go cache'), GOMODCACHE=str(self.base / 'go modules'),
                        CARGO_HOME=str(self.base / 'cargo home'), CARGO_TARGET_DIR=str(self.base / 'cargo target'),
                        CARGO_BUILD_TARGET='aarch64-unknown-linux-gnu', RUSTUP_TOOLCHAIN='test-toolchain')
        program = '''#!/usr/bin/env python3
import io, json, os, pathlib, subprocess, sys, tarfile
tool, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ['VM_TEST_LOG'], 'a') as log:
    keys = ('GOARCH', 'GOCACHE', 'GOMODCACHE', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN')
    log.write(json.dumps({'tool': tool, 'args': args, 'env': {k: os.environ.get(k) for k in keys}}) + '\\n')
if tool == 'go':
    output = pathlib.Path(args[args.index('-o') + 1])
    output.write_text('#!/bin/sh\\nexit 0\\n'); output.chmod(0o755)
elif tool == 'cargo':
    output = pathlib.Path(os.environ['VM_TEST_ARTIFACT'])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('#!/bin/sh\\nexit 0\\n'); output.chmod(0o755)
    print(json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'babel-rs'}, 'executable': str(output)}))
elif tool == 'git':
    assert args[2] == 'archive', args
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
        entry = tarfile.TarInfo('Cargo.toml'); data = b'# test source\\n'; entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
elif tool == 'ssh':
    # Real local shell quoting/archive extraction, but never execute VM tests.
    if '-tt' not in args:
        subprocess.run(args[-1], shell=True, input=sys.stdin.buffer.read(), check=True)
else:
    raise AssertionError(tool)
'''
        for name in ('go', 'cargo', 'git', 'ssh'):
            path = self.bin / name
            path.write_text(program)
            path.chmod(0o755)

    def run_wrapper(self, suite, *args, env=None):
        return subprocess.run(['bash', str(self.repo / 'tests' / suite / 'run-on-vm.sh'), *args],
                              env=self.env if env is None else env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=20)

    def test_help_and_plan_need_no_configuration_or_tools(self):
        env = {k: v for k, v in self.env.items() if not k.startswith('VELVET_')}
        for suite in ('e2e', 'directed', 'endless'):
            result = self.run_wrapper(suite, '--help', env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_wrapper('endless', '--plan', '--nodes', '4', '--rounds', '1', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())

    def test_missing_host_fails_before_build_or_connection(self):
        env = dict(self.env)
        del env['VELVET_VM_HOST']
        result = self.run_wrapper('e2e', 'static', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('VELVET_VM_HOST', result.stderr)
        self.assertFalse(self.log.exists())

    def test_invalid_host_and_root_fail_before_build(self):
        for key, value in (('VELVET_VM_HOST', '-bad-option'), ('VELVET_VM_REMOTE_ROOT', '/'),
                           ('VELVET_VM_REMOTE_ROOT', 'relative/path')):
            env = {**self.env, key: value}
            result = self.run_wrapper('e2e', 'static', env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.log.exists())

    def test_local_defaults_executable_overrides_and_ssh_config(self):
        directory = self.repo / '.local'
        directory.mkdir()
        (directory / 'vm.env').write_text(': "${VELVET_VM_HOST:=root@fallback.example}"\n')
        tools = self.base / 'other tools'
        tools.mkdir()
        for name in ('go', 'cargo'):
            shutil.copy2(self.bin / name, tools / name)
        env = {**self.env, 'VELVET_GO_BIN': str(tools / 'go'),
               'VELVET_CARGO_BIN': str(tools / 'cargo'), 'VELVET_SSH_CONFIG': str(self.base / "ssh config's")}
        result = self.run_wrapper('e2e', 'static', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        for call in calls:
            if call['tool'] == 'ssh':
                self.assertIn(self.env['VELVET_VM_HOST'], call['args'])
                self.assertEqual(call['args'][call['args'].index('-F') + 1], env['VELVET_SSH_CONFIG'])

    def test_all_wrappers_preserve_build_settings_and_quote_paths(self):
        for suite, args in (('e2e', ['static']), ('directed', ['--case', 'data-mtu', '--family', 'ipv6']),
                            ('endless', ['--nodes', '4', '--rounds', '1'])):
            with self.subTest(suite=suite):
                self.log.unlink(missing_ok=True)
                result = self.run_wrapper(suite, *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                go = next(call for call in calls if call['tool'] == 'go')
                cargo = next(call for call in calls if call['tool'] == 'cargo')
                for name in ('GOARCH', 'GOCACHE', 'GOMODCACHE'):
                    self.assertEqual(go['env'][name], self.env[name])
                for name in ('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN'):
                    self.assertEqual(cargo['env'][name], self.env[name])
                archive = next(call for call in calls if call['tool'] == 'git')
                self.assertEqual(archive['args'][1], str(self.babel))
                self.assertEqual(archive['args'][3], 'dbeede34abd8dff2422c39ab18a15949b0f38f11')
                ssh = [call for call in calls if call['tool'] == 'ssh']
                self.assertTrue(all('-F' not in call['args'] for call in ssh))
                command = shlex.split(ssh[-1]['args'][-1])
                self.assertEqual(command[0], 'sh' if suite == 'e2e' else 'env')
                if suite == 'e2e':
                    command = shlex.split(command[2])
                self.assertTrue(any(str(self.remote) in part for part in command))
                assets = list(self.remote.glob('assets-*'))
                self.assertEqual(len(assets), ('e2e', 'directed', 'endless').index(suite) + 1)
                self.assertTrue(all((asset / 'babel-rs').is_file() for asset in assets))
                self.assertFalse(list((self.repo / '.local/experiments').glob('vm-build.*')))


if __name__ == '__main__':
    unittest.main()
