import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('build_local', ROOT / 'scripts/build-local.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BuildLocalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='build helper test ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_cargo_uses_reported_binary_with_spaces_and_custom_target(self):
        messages = [
            {'reason': 'compiler-artifact', 'target': {'name': 'babel-rs', 'kind': ['lib']}, 'executable': '/wrong'},
            {'reason': 'compiler-artifact', 'target': {'name': 'babel-rs', 'kind': ['bin']}, 'executable': '/custom target/release/babel-rs'},
            {'reason': 'build-finished', 'success': True},
        ]
        self.assertEqual(MODULE.cargo_artifact('\n'.join(map(json.dumps, messages))), Path('/custom target/release/babel-rs'))

    def test_cargo_rejects_missing_or_ambiguous_binary(self):
        with self.assertRaises(ValueError):
            MODULE.cargo_artifact('{"reason":"build-finished","success":true}')
        records = [{'reason': 'compiler-artifact', 'target': {'name': 'babel-rs', 'kind': ['bin']}, 'executable': path} for path in ('/one', '/two')]
        with self.assertRaises(ValueError):
            MODULE.cargo_artifact('\n'.join(map(json.dumps, records)))

    def test_publish_switches_whole_bundle_and_preserves_previous(self):
        first, second = self.root / 'stage-one', self.root / 'stage-two'
        first.mkdir()
        second.mkdir()
        (first / 'velvetd').write_text('old')
        (second / 'velvetd').write_text('new')
        link = MODULE.publish(first, self.root, 'one')
        self.assertEqual((link / 'velvetd').read_text(), 'old')
        MODULE.publish(second, self.root, 'two')
        self.assertEqual((link / 'velvetd').read_text(), 'new')
        self.assertEqual((self.root / 'one/velvetd').read_text(), 'old')
        self.assertEqual(link.readlink(), Path('two'))

    def test_publish_refuses_unowned_latest_directory(self):
        (self.root / 'latest').mkdir()
        staged = self.root / 'stage'
        staged.mkdir()
        with self.assertRaises(ValueError):
            MODULE.publish(staged, self.root, 'build')
        self.assertTrue(staged.exists())
        self.assertFalse((self.root / 'build').exists())

    def test_pin_is_read_from_shared_dependency_file(self):
        workflow = self.root / 'tests/babel-revision'
        workflow.parent.mkdir(parents=True)
        commit = 'a' * 40
        workflow.write_text(commit + '\n')
        self.assertEqual(MODULE.pinned_revision(self.root), commit)
        workflow.write_text('env: {}')
        with self.assertRaises(ValueError):
            MODULE.pinned_revision(self.root)

    def test_pinned_export_keeps_dirty_worktree_and_index_intact(self):
        repo = self.root / 'repo'
        repo.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()
        git('init')
        (repo / 'source.rs').write_text('committed')
        (repo / 'LICENSE').write_text('license')
        (repo / 'crate').mkdir()
        (repo / 'crate/LICENSE').symlink_to('../LICENSE')
        git('add', 'source.rs', 'LICENSE', 'crate/LICENSE')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
        revision = git('rev-parse', 'HEAD')
        (repo / 'source.rs').write_text('staged')
        git('add', 'source.rs')
        (repo / 'source.rs').write_text('working changes')
        (repo / 'new.rs').write_text('untracked')
        before = git('status', '--porcelain')
        MODULE.export_revision(repo, revision, self.root / 'export')
        self.assertEqual((self.root / 'export/source.rs').read_text(), 'committed')
        self.assertFalse((self.root / 'export/new.rs').exists())
        self.assertEqual((self.root / 'export/crate/LICENSE').read_text(), 'license')
        self.assertEqual((repo / 'source.rs').read_text(), 'working changes')
        self.assertEqual(git('status', '--porcelain'), before)
        self.assertEqual(git('show', ':source.rs'), 'staged')
        self.assertTrue(MODULE.git_state(repo)['dirty'])
        self.assertFalse(MODULE.git_state(repo, 'pinned', revision)['dirty'])


if __name__ == '__main__':
    unittest.main()
