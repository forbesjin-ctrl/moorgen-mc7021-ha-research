"""Packaging boundary tests run on macOS and Linux without a compiler or runtime.

All archives, inputs and Mach-O headers here are synthetic. No downloaded binary,
GUI, signing command, device component, capture, sudo or network call is executed.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('macos_packager', ROOT / 'tools/build_macos_app.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def archive_at(path, entries):
    with tarfile.open(path, 'w:gz') as archive:
        for name, content, link in entries:
            member = tarfile.TarInfo(name)
            if link is not None:
                member.type = tarfile.SYMTYPE
                member.linkname = link
                archive.addfile(member)
            else:
                member.size = len(content)
                member.mode = 0o6755 if '/bin/' in name else 0o644
                archive.addfile(member, io.BytesIO(content))


class ArchiveVerificationTests(unittest.TestCase):
    def test_matching_fixed_sha_accepts_only_the_expected_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.tar.gz'
            path.write_bytes(b'synthetic pinned archive')
            expected = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertEqual(builder.verified_archive(path, expected), path.resolve())
            path.write_bytes(b'synthetic modified archive')
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                builder.verified_archive(path, expected)

    def test_pins_have_explicit_official_release_and_both_mac_architectures(self):
        self.assertEqual(set(builder.RUNTIMES), {'arm64', 'x86_64'})
        specs = list(builder.RUNTIMES.values()) + [builder.LICENSE_ARCHIVE]
        self.assertEqual(len({item['sha256'] for item in specs}), 3)
        for item in specs:
            self.assertRegex(item['sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(item['download_url'].startswith(
                'https://github.com/astral-sh/python-build-standalone/releases/download/' + builder.RELEASE + '/'))
            self.assertNotIn('/latest/', item['download_url'])

    def test_parent_hop_absolute_and_foreign_root_members_are_rejected(self):
        for member in ('python/../../outside', '/python/bin/executable', 'elsewhere/executable'):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive_at(root / 'bad.tar.gz', [(member, b'private', None)])
                with self.assertRaises(ValueError):
                    builder.extract_runtime(root / 'bad.tar.gz', root / 'runtime')
                self.assertFalse((root / 'outside').exists())

    def test_absolute_and_escaping_symlink_targets_are_rejected(self):
        for link in ('../../../outside', '/outside'):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive_at(root / 'bad.tar.gz', [('python/bin/python3', b'', link)])
                with self.assertRaisesRegex(ValueError, '链接'):
                    builder.extract_runtime(root / 'bad.tar.gz', root / 'runtime')

    def test_safe_sibling_alias_is_preserved_and_privileged_modes_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_at(root / 'good.tar.gz', [
                ('python/bin/python3.12', b'synthetic executable, never run', None),
                ('python/bin/python3', b'', 'python3.12'),
                ('python/lib/python3.12/LICENSE.txt', b'synthetic license', None)])
            builder.extract_runtime(root / 'good.tar.gz', root / 'runtime')
            alias = root / 'runtime/python/bin/python3'
            self.assertTrue(alias.is_symlink())
            self.assertEqual(alias.read_bytes(), b'synthetic executable, never run')
            self.assertEqual(alias.stat().st_mode & 0o7777, 0o755)

    def test_duplicate_and_special_tar_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_at(root / 'duplicate.tar.gz', [('python/x', b'one', None), ('python/x', b'two', None)])
            with self.assertRaisesRegex(ValueError, '重复'):
                builder.extract_runtime(root / 'duplicate.tar.gz', root / 'duplicates')
            with tarfile.open(root / 'special.tar.gz', 'w:gz') as archive:
                member = tarfile.TarInfo('python/device')
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            with self.assertRaisesRegex(ValueError, '类型'):
                builder.extract_runtime(root / 'special.tar.gz', root / 'special')

    def test_missing_python_license_stops_the_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_at(root / 'no-license.tar.gz', [('python/bin/python3.12', b'not run', None)])
            with self.assertRaisesRegex(ValueError, '许可证'):
                builder.extract_runtime(root / 'no-license.tar.gz', root / 'runtime')


class SourceAndLicenseBoundaryTests(unittest.TestCase):
    def make_source(self, root):
        allowed = ['LICENSE', 'README.md'] + ['tools/' + name for name in builder.TOOL_FILES] + [
            'docs/' + name for name in builder.DOCUMENT_FILES] + list(builder.COMPONENT_FILES)
        for name in allowed:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Synthetic source only\n', encoding='utf-8')
        return set(allowed)

    def test_explicit_copy_ignores_private_inputs_history_and_runtime_folders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'source', root / 'resources'
            allowed = self.make_source(source)
            for name in ('captures/traffic.pcap', 'private_reports/报告.html', 'demo_runs/session.json',
                         '.git/config', 'work/runtime.tar.gz', 'source/household.bin',
                         'tools/unreviewed.py', 'docs/private-notes.md'):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'DO NOT PACKAGE THIS CONTENT')
            hashes = builder.copy_owned_sources(source, destination)
            copied = {str(path.relative_to(destination)) for path in destination.rglob('*') if path.is_file()}
            self.assertEqual(copied, allowed)
            self.assertEqual(set(hashes), allowed)
            for path in destination.rglob('*'):
                if path.is_file():
                    self.assertNotIn(b'DO NOT PACKAGE', path.read_bytes())

    def test_allowlisted_source_symlink_is_rejected_instead_of_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            self.make_source(source)
            outside = root / 'private.txt'
            outside.write_text('DO NOT PACKAGE THIS CONTENT')
            (source / 'README.md').unlink()
            (source / 'README.md').symlink_to(outside)
            with self.assertRaises(ValueError):
                builder.copy_owned_sources(source, root / 'resources')

    def test_allowlisted_source_inside_symlinked_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            self.make_source(source)
            (source / 'tools').rename(root / 'outside-tools')
            (source / 'tools').symlink_to(root / 'outside-tools', target_is_directory=True)
            with self.assertRaises(ValueError):
                builder.copy_owned_sources(source, root / 'resources')

    def license_tar_mock(self, bad_version=False):
        names = ['python/licenses/LICENSE.synthetic{}.txt'.format(number) for number in range(10)]
        metadata = {'python_version': '0.0.0' if bad_version else builder.PYTHON_VERSION,
                    'target_triple': 'aarch64-apple-darwin', 'licenses': ['Python-2.0'],
                    'build_info': {'extensions': {'_example': [{'licenses': ['MIT'],
                        'license_paths': ['licenses/LICENSE.synthetic0.txt']}]}}}
        def fake_run(arguments, **kwargs):
            if arguments[1] == '-tf':
                # Only the license names may be copied. These other members are traps.
                text = '\n'.join(names + ['python/build/private.o', 'python/install/bin/python3',
                                          'python/licenses/../outside', 'python/licenses/subdir/LICENSE.txt'])
                return subprocess.CompletedProcess(arguments, 0, stdout=text)
            if arguments[-1] == 'python/PYTHON.json':
                data = json.dumps(metadata).encode()
            elif arguments[-1] in names:
                data = ('Synthetic license for ' + arguments[-1]).encode()
            else:
                raise AssertionError('Unexpected extraction: ' + arguments[-1])
            return subprocess.CompletedProcess(arguments, 0, stdout=data)
        return fake_run

    def test_license_metadata_preserves_source_hash_and_does_not_extract_build_code(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                builder, 'run', side_effect=self.license_tar_mock()) as commands:
            destination = Path(directory) / 'Licenses'
            builder.extract_licenses(Path(directory) / 'verified-full.tar.zst', destination)
            files = list(destination.iterdir())
            self.assertEqual(len(files), 11)
            manifest = json.loads((destination / 'runtime-license-metadata.json').read_text())
            self.assertEqual(manifest['source_sha256'], builder.LICENSE_ARCHIVE['sha256'])
            self.assertEqual(manifest['python_licenses'], ['Python-2.0'])
            self.assertEqual(manifest['extensions']['_example'][0]['licenses'], ['MIT'])
            self.assertFalse(any('build' in str(call.args[0][-1]) for call in commands.call_args_list))

    def test_unexpected_license_runtime_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                builder, 'run', side_effect=self.license_tar_mock(bad_version=True)):
            with self.assertRaisesRegex(ValueError, '元数据'):
                builder.extract_licenses(Path(directory) / 'verified-full.tar.zst', Path(directory) / 'Licenses')


class SigningAndDeclarationTests(unittest.TestCase):
    def test_only_actual_macho_files_and_bundle_are_ad_hoc_signed(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'Synthetic.app'
            app.mkdir()
            binary = app / 'native'
            binary.write_bytes(builder.MACHO_MAGICS[0] + b'synthetic header only')
            (app / 'plain.txt').write_text('not executable')
            (app / 'native-alias').symlink_to('native')
            with mock.patch.object(builder, 'run') as commands:
                self.assertEqual(builder.sign_macho_tree(app), 1)
            values = [call.args[0] for call in commands.call_args_list]
            self.assertEqual(len(values), 3)
            for command in values[:2]:
                self.assertEqual(command[:5], ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none'])
            self.assertEqual(values[0][-1], binary)
            self.assertEqual(values[1][-1], app)
            self.assertEqual(values[-1], ['/usr/bin/codesign', '--verify', '--deep', '--strict', app])

    def test_application_and_runtime_metadata_do_not_claim_apple_notarization(self):
        info = builder.application_info('0.3.0')
        encoded = plistlib.dumps(info)
        self.assertEqual(plistlib.loads(encoded)['LSMinimumSystemVersion'], '12.0')
        self.assertEqual(info['CFBundleExecutable'], 'MC7021Research')
        self.assertNotIn('LSUIElement', info)
        provenance = json.loads(json.dumps(builder.runtime_provenance()))
        self.assertFalse(provenance['notarized'])
        self.assertEqual(provenance['code_signing'], 'ad-hoc; not Developer ID signed or notarized')
        self.assertEqual(set(provenance['runtimes']), {'arm64', 'x86_64'})
        self.assertNotIn('captures', encoded.decode())


if __name__ == '__main__':
    unittest.main()
