"""Release guard tests use temporary files and constructed dummy identifiers."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('public_guard', ROOT / 'tools/check_public_tree.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PublicTreeTests(unittest.TestCase):
    def test_real_public_tree_has_only_reviewed_text_sources(self):
        self.assertEqual(set(guard.audit(ROOT)), guard.PUBLIC_FILES)

    def test_private_mac_path_is_rejected(self):
        text = '/Users' + '/example-person/file'
        with self.assertRaisesRegex(ValueError, 'Personal Mac'):
            guard.check_content('docs/example.md', text.encode())

    def test_non_documentation_ip_is_rejected_without_printing_it(self):
        text = '.'.join(['192', '168', '1', '2'])
        with self.assertRaisesRegex(ValueError, 'Non-documentation IP'):
            guard.check_content('docs/example.md', text.encode())

    def test_documentation_addresses_and_synthetic_identifier_allowed(self):
        guard.check_content('tests/example.py', b'192.0.2.20 198.51.100.2 203.0.113.2 00000001-0000000000000001')

    def test_non_synthetic_device_id_is_rejected(self):
        text = ('A' * 8) + '-' + ('B' * 16)
        with self.assertRaisesRegex(ValueError, 'Non-synthetic'):
            guard.check_content('docs/example.md', text.encode())

    def test_private_key_marker_is_rejected(self):
        text = '-----BEGIN ' + 'PRIVATE KEY-----'
        with self.assertRaisesRegex(ValueError, 'Private-key'):
            guard.check_content('docs/example.md', text.encode())

    def test_parent_git_repository_is_never_selected_implicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'separate repository'):
                guard.audit(Path(directory), tracked=True)

    def make_index(self, root):
        subprocess.run(['git', '-C', str(root), 'init', '--template='],
                       check=True, capture_output=True)
        for name in guard.PUBLIC_FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Synthetic public content\n', encoding='utf-8')
        subprocess.run(['git', '-C', str(root), 'add', '--', *sorted(guard.PUBLIC_FILES)],
                       check=True, capture_output=True)

    def test_tracked_checks_staged_blob_even_when_worktree_is_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_index(root)
            readme = root / 'README.md'
            readme.write_text('/Users' + '/example-person/file\n', encoding='utf-8')
            subprocess.run(['git', '-C', str(root), 'add', '--', 'README.md'],
                           check=True, capture_output=True)
            readme.write_text('Clean working copy\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Personal Mac'):
                guard.audit(root, tracked=True)

    def test_tracked_rejects_staged_symlink_even_when_worktree_is_regular(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_index(root)
            readme = root / 'README.md'
            readme.unlink()
            readme.symlink_to('LICENSE')
            subprocess.run(['git', '-C', str(root), 'add', '--', 'README.md'],
                           check=True, capture_output=True)
            readme.unlink()
            readme.write_text('Regular working copy\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Non-regular index'):
                guard.audit(root, tracked=True)

    def test_tracked_accepts_only_allowed_regular_staged_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_index(root)
            self.assertEqual(set(guard.audit(root, tracked=True)), guard.PUBLIC_FILES)


if __name__ == '__main__':
    unittest.main()
