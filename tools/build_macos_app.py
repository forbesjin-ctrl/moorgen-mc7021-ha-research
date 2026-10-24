#!/usr/bin/env python3
"""Build the native, self-contained macOS app from explicitly pinned runtimes.

No downloads, package installation, devices, sudo, capture or network access.
Requires macOS, Xcode's Swift compiler, and the three verified local archives.
Only the explicit source allowlist is copied into the app. Generated samples,
reports, git history, home configuration and the build cache are never copied.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
APP_NAME = 'MC7021 单灯研究工具.app'
EXECUTABLE = 'MC7021Research'
MINIMUM_MACOS = '12.0'
RELEASE = '20260901'
PYTHON_VERSION = '3.12.14'
BASE_URL = 'https://github.com/astral-sh/python-build-standalone/releases/download/' + RELEASE + '/'
RUNTIMES = {
    'arm64': {
        'filename': 'cpython-3.12.14+20260901-aarch64-apple-darwin-install_only_stripped.tar.gz',
        'sha256': '81a359f1cfadd4da11766534c5913791cea55f26e1bb902cacd2a531bb1e4b2b',
    },
    'x86_64': {
        'filename': 'cpython-3.12.14+20260901-x86_64-apple-darwin-install_only_stripped.tar.gz',
        'sha256': '65b195c9cedc1fef6767f044f9822069adbd1bd9204d424ece4628776fdc04bb',
    },
}
LICENSE_ARCHIVE = {
    'filename': 'cpython-3.12.14+20260901-aarch64-apple-darwin-pgo+lto-full.tar.zst',
    'sha256': 'dbefa04d4107b449e17022f9c78d3eacbd37a1aa8c166c6220dbd95addf3f318',
}
for _artifact in list(RUNTIMES.values()) + [LICENSE_ARCHIVE]:
    _artifact['download_url'] = BASE_URL + _artifact['filename'].replace('+', '%2B')
TOOL_FILES = (
    'gui_worker.py', 'gui_capture_backend.py', 'capture_mc7021_light.py', 'analyze_capture.py',
    'demo_sample.py', 'offline_shcp.py', 'pcap_reader.py', 'report_view.py',
    'light_state_model.py', 'research_tool.py', 'collection_report.py', 'baseline_review.py', 'ha_handoff.py', 'ha_wizard.py',
)
DOCUMENT_FILES = (
    'MAC_APP_BUILD.md', 'MAC_GUI.md', 'CAPTURE.md', 'AFTER_CAPTURE.md', 'PRIVATE_SAMPLES.md', 'MULTI_DEVICE.md', 'FIRST_LIGHT_REVIEW.md', 'HA_WIZARD.md', 'SELF_SERVICE.md',
)
COMPONENT_FILES = ('ha_component_templates/README.md', 'ha_component_templates/custom_components/mc7021_single_light/__init__.py', 'ha_component_templates/custom_components/mc7021_single_light/manifest.json', 'ha_component_templates/custom_components/mc7021_single_light/config_flow.py', 'ha_component_templates/custom_components/mc7021_single_light/const.py', 'ha_component_templates/custom_components/mc7021_single_light/contract.py', 'ha_component_templates/custom_components/mc7021_single_light/bridge.py', 'ha_component_templates/custom_components/mc7021_single_light/light.py', 'ha_component_templates/custom_components/mc7021_single_light/select.py', 'ha_component_templates/custom_components/mc7021_single_light/button.py', 'ha_component_templates/custom_components/mc7021_single_light/diagnostics.py', 'ha_component_templates/custom_components/mc7021_single_light/strings.json', 'ha_component_templates/custom_components/mc7021_single_light/translations/en.json', 'ha_component_templates/custom_components/mc7021_single_light/translations/zh-Hans.json', 'ha_component_templates/custom_components/mc7021_single_light/driver.py')
MAX_RUNTIME_BYTES = 250 * 1024 * 1024
MACHO_MAGICS = (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe',
                b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def run(arguments, **kwargs):
    return subprocess.run([str(value) for value in arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def verified_archive(path, spec):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('运行时必须是本地普通归档文件')
    if sha256(path) != spec['sha256']:
        raise ValueError('SHA256 不符，停止打包：' + path.name)
    return path


def relative_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'python':
        raise ValueError('归档成员路径越界')
    return path


def extract_runtime(archive, destination):
    """Extract files first and safe relative symlinks last; never tar.extractall."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive, mode='r:gz') as source:
        members = source.getmembers()
        if len(members) > 10000 or sum(member.size for member in members) > MAX_RUNTIME_BYTES:
            raise ValueError('运行时归档大小异常')
        names, links = set(), []
        for member in members:
            name = relative_member(member.name)
            if str(name) in names:
                raise ValueError('运行时归档包含重复成员')
            names.add(str(name))
            if member.issym():
                # Fixed upstream archives use sibling aliases, without parent hops.
                target = PurePosixPath(member.linkname)
                if target.is_absolute() or '..' in target.parts or not target.parts:
                    raise ValueError('运行时归档包含不安全符号链接')
                links.append((name, member.linkname))
            elif not member.isfile() and not member.isdir():
                raise ValueError('运行时归档包含不支持的成员类型')
        for member in members:
            target = destination.joinpath(*relative_member(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as incoming, target.open('xb') as output:
                    shutil.copyfileobj(incoming, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
        for name, linkname in links:
            target = destination.joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(linkname)
            resolved = target.resolve(strict=True)
            if destination.resolve() not in resolved.parents:
                raise ValueError('运行时链接目标越界')
    license_file = destination / 'python/lib/python3.12/LICENSE.txt'
    if not license_file.is_file():
        raise ValueError('运行时缺少 CPython 许可证')


def extract_licenses(archive, destination):
    """Read only license text from the verified full archive, not its build code."""
    destination = Path(destination)
    destination.mkdir(parents=True)
    names = run(['/usr/bin/tar', '-tf', archive], text=True).stdout.splitlines()
    selected = [name for name in names
                if re.fullmatch(r'python/licenses/LICENSE\.[A-Za-z0-9_.+-]+\.txt', name)]
    if len(selected) < 10 or len(selected) != len(set(selected)):
        raise ValueError('完整归档许可证目录异常')
    metadata = json.loads(run(['/usr/bin/tar', '-xOf', archive, 'python/PYTHON.json']).stdout)
    if metadata.get('python_version') != PYTHON_VERSION or metadata.get('target_triple') != 'aarch64-apple-darwin':
        raise ValueError('许可证元数据与固定版本不符')
    manifest = {'release': RELEASE, 'python_version': PYTHON_VERSION,
                'source_filename': LICENSE_ARCHIVE['filename'],
                'source_sha256': LICENSE_ARCHIVE['sha256'],
                'python_licenses': metadata.get('licenses'), 'extensions': {}}
    for extension, variants in metadata.get('build_info', {}).get('extensions', {}).items():
        licenses = [{'licenses': variant.get('licenses', []),
                     'license_paths': variant.get('license_paths', []),
                     'public_domain': variant.get('license_public_domain', False)}
                    for variant in variants if variant.get('license_paths') or variant.get('licenses')]
        if licenses:
            manifest['extensions'][extension] = licenses
    for name in selected:
        data = run(['/usr/bin/tar', '-xOf', archive, name]).stdout
        if len(data) > 1024 * 1024:
            raise ValueError('许可证文本大小异常')
        (destination / PurePosixPath(name).name).write_bytes(data)
    (destination / 'runtime-license-metadata.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def copy_owned_sources(project_root, resources):
    result = {}
    project_root = project_root.resolve()
    for relative in ['LICENSE', 'README.md'] + ['tools/' + name for name in TOOL_FILES] + [
            'docs/' + name for name in DOCUMENT_FILES] + list(COMPONENT_FILES):
        source = project_root / relative
        ancestors = source.relative_to(project_root).parts[:-1]
        linked_parent = any(project_root.joinpath(*ancestors[:index]).is_symlink()
                            for index in range(1, len(ancestors) + 1))
        if source.is_symlink() or linked_parent or not source.is_file():
            raise ValueError('缺少白名单源码文件：' + relative)
        target = resources / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o644)
        result[relative] = sha256(target)
    return result


def sign_macho_tree(root):
    """Sign nested native binaries first, then the application bundle itself."""
    signed = 0
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as source:
            magic = source.read(4)
        if magic in MACHO_MAGICS:
            run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', path])
            signed += 1
    run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', root])
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', root])
    return signed


def application_info(version):
    """Bundle metadata describes the local tool, with no certification claims."""
    return dict(CFBundleName='MC7021 单灯研究工具', CFBundleDisplayName='MC7021 单灯研究工具',
                CFBundleIdentifier='org.mc7021.research', CFBundleExecutable=EXECUTABLE,
                CFBundlePackageType='APPL', CFBundleShortVersionString=version,
                CFBundleVersion=version, LSMinimumSystemVersion=MINIMUM_MACOS,
                NSHighResolutionCapable=True, NSPrincipalClass='NSApplication',
                NSHumanReadableCopyright='MIT project code; bundled runtime licenses in Resources/Licenses')


def runtime_provenance():
    return {'provider': 'astral-sh/python-build-standalone', 'release': RELEASE,
            'version': PYTHON_VERSION, 'runtimes': RUNTIMES,
            'license_archive': LICENSE_ARCHIVE,
            'code_signing': 'ad-hoc; not Developer ID signed or notarized',
            'notarized': False}


def build(args):
    if sys.platform != 'darwin':
        raise ValueError('原生 .app 必须在 macOS 构建')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
        raise ValueError('版本号应为三段数字')
    project = args.project_root.resolve(strict=True)
    swift_source = project / 'macos/MC7021Research.swift'
    if swift_source.is_symlink() or not swift_source.is_file():
        raise ValueError('缺少原生 GUI 源码 macos/MC7021Research.swift')
    helper_source = project / 'macos/capture_helper.c'
    if helper_source.is_symlink() or not helper_source.is_file():
        raise ValueError('缺少原生采样监督器源码 macos/capture_helper.c')
    archives = {architecture: verified_archive(getattr(args, architecture + '_archive'), spec)
                for architecture, spec in RUNTIMES.items()}
    licenses_archive = verified_archive(args.licenses_archive, LICENSE_ARCHIVE)
    # A caller supplies an explicit workspace output directory. Never install to /Applications.
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    final_app = output / APP_NAME
    final_zip = output / ('MC7021-Mac-v' + args.version + '-universal2.zip')
    manifest_path = output / ('MC7021-Mac-v' + args.version + '-build.json')
    if any(path.exists() for path in (final_app, final_zip, manifest_path)):
        raise ValueError('输出已存在，请使用新的 output-dir，避免覆盖已有应用')
    swiftc = run(['/usr/bin/xcrun', '--find', 'swiftc'], text=True).stdout.strip()
    clang = run(['/usr/bin/xcrun', '--find', 'clang'], text=True).stdout.strip()
    sdk = run(['/usr/bin/xcrun', '--show-sdk-path'], text=True).stdout.strip()
    with tempfile.TemporaryDirectory(prefix='mc7021-build-', dir=output) as scratch_name:
        scratch = Path(scratch_name)
        app = scratch / APP_NAME
        contents = app / 'Contents'
        resources, binaries = contents / 'Resources', contents / 'MacOS'
        resources.mkdir(parents=True)
        binaries.mkdir()
        source_hashes = copy_owned_sources(project, resources)
        source_hashes['macos/MC7021Research.swift'] = sha256(swift_source)
        source_hashes['macos/capture_helper.c'] = sha256(helper_source)
        for architecture, archive in archives.items():
            runtime = resources / 'runtime' / architecture
            runtime.parent.mkdir(exist_ok=True)
            extract_runtime(archive, runtime)
            detected = run(['/usr/bin/lipo', '-archs', runtime / 'python/bin/python3.12'], text=True).stdout.strip()
            if detected != architecture:
                raise ValueError('运行时架构与归档名称不符')
        extract_licenses(licenses_archive, resources / 'Licenses')
        shutil.copyfile(project / 'LICENSE', resources / 'Licenses/PROJECT-MIT.txt')
        # A separate cache under the explicit output path avoids writing global tool caches.
        module_cache = scratch / 'swift-module-cache'
        arch_binaries = []
        helper_binaries = []
        for architecture in ('arm64', 'x86_64'):
            binary = scratch / (EXECUTABLE + '-' + architecture)
            run([swiftc, '-O', '-sdk', sdk, '-target', architecture + '-apple-macosx' + MINIMUM_MACOS,
                 '-module-cache-path', module_cache, '-framework', 'AppKit',
                 swift_source, '-o', binary])
            arch_binaries.append(binary)
            helper = scratch / ('capture-helper-' + architecture)
            run([clang, '-O2', '-Wall', '-Wextra', '-isysroot', sdk,
                 '-target', architecture + '-apple-macosx' + MINIMUM_MACOS,
                 helper_source, '-o', helper])
            helper_binaries.append(helper)
        executable = binaries / EXECUTABLE
        run(['/usr/bin/lipo', '-create', *arch_binaries, '-output', executable])
        executable.chmod(0o755)
        architectures = run(['/usr/bin/lipo', '-archs', executable], text=True).stdout.strip().split()
        if set(architectures) != {'arm64', 'x86_64'}:
            raise ValueError('GUI 主程序未包含两种架构')
        helper = resources / 'capture-helper'
        run(['/usr/bin/lipo', '-create', *helper_binaries, '-output', helper])
        helper.chmod(0o755)
        if set(run(['/usr/bin/lipo', '-archs', helper], text=True).stdout.strip().split()) != {'arm64', 'x86_64'}:
            raise ValueError('采样监督器未包含两种架构')
        plist = application_info(args.version)
        with (contents / 'Info.plist').open('wb') as destination:
            plistlib.dump(plist, destination)
        runtime_manifest = runtime_provenance()
        (resources / 'runtime-provenance.json').write_text(
            json.dumps(runtime_manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        signed_count = sign_macho_tree(app)
        native = platform.machine()
        if native not in RUNTIMES:
            raise ValueError('无法确定本机 Python 架构')
        python = resources / 'runtime' / native / 'python/bin/python3'
        # This is the first execution of verified and packaged runtime code. No worker or capture.
        smoke = run([python, '-I', '-B', '-c',
                     'import json,struct,hashlib,fcntl,ipaddress,subprocess,zlib,ssl; '
                     'print(json.dumps({"python":__import__("sys").version.split()[0],'
                     '"architecture":__import__("platform").machine(),"stdlib_imports":"ok"}))'], text=True)
        smoke_result = json.loads(smoke.stdout)
        if smoke_result['python'] != PYTHON_VERSION or smoke_result['architecture'] != native:
            raise ValueError('内置运行时本机启动检查不符')
        shutil.move(str(app), final_app)
    run(['/usr/bin/ditto', '-c', '-k', '--keepParent', '--sequesterRsrc', final_app, final_zip])
    result = {'version': args.version, 'app_name': APP_NAME, 'architectures': architectures,
              'minimum_macos': MINIMUM_MACOS, 'runtime_provenance': runtime_manifest,
              'source_sha256': source_hashes, 'signed_macho_files': signed_count,
              'native_runtime_smoke': smoke_result,
              'other_architecture_execution': 'not tested on this host',
              'codesign_verify_deep_strict': 'passed', 'notarized': False,
              'zip_filename': final_zip.name, 'zip_sha256': sha256(final_zip),
              'zip_bytes': final_zip.stat().st_size,
              'capture_executed': False, 'household_device_access': False}
    manifest_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--arm64-archive', type=Path, required=True)
    parser.add_argument('--x86_64-archive', type=Path, required=True)
    parser.add_argument('--licenses-archive', type=Path, required=True)
    parser.add_argument('--version', default='0.5.0')
    args = parser.parse_args(argv)
    try:
        return build(args)
    except (ValueError, OSError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print('构建未完成：{}'.format(error), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            message = error.stderr.decode(errors='replace') if isinstance(error.stderr, bytes) else error.stderr
            print(message[-6000:], file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
