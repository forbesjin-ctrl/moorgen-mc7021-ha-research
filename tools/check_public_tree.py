#!/usr/bin/env python3
"""Read-only release allowlist and obvious-identifier check, not a secret scanner.

With --tracked inspect Git's index, including force-added ignored files. Without
it inspect the public source tree, skipping designated local private folders.
Never inspect a parent repository or upload content.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import subprocess

PUBLIC_FILES = frozenset({
    'README.md', 'LICENSE', 'CONTRIBUTING.md', '.gitignore', '开始单灯采样.command', '打开研究工具.command',
    'docs/CAPTURE.md', 'docs/PRIVATE_SAMPLES.md', 'docs/PROTOCOL_CANDIDATE.md',
    'docs/COMPATIBILITY.md', 'docs/ROADMAP.md', 'docs/AFTER_CAPTURE.md',
    'tools/capture_mc7021_light.py', 'tools/offline_shcp.py', 'tools/check_public_tree.py',
    'tests/test_capture_mc7021_light.py', 'tests/test_offline_shcp.py',
    'tests/test_public_tree.py', 'tests/test_community_source.py',
    'tools/analyze_capture.py', 'tools/pcap_reader.py', 'tools/report_view.py',
    'tools/demo_sample.py', 'tools/research_tool.py', 'tools/light_state_model.py',
    'tests/test_analyze_capture.py', 'tests/test_pcap_reader.py', 'tests/test_report_view.py',
    'tests/test_research_tool.py', 'tests/test_light_state_model.py',
    'macos/MC7021Research.swift', 'macos/capture_helper.c',
    'tools/gui_worker.py', 'tools/gui_capture_backend.py', 'tools/build_macos_app.py',
    'tests/test_gui_worker.py', 'tests/test_gui_capture_backend.py', 'tests/test_build_macos_app.py',
    'docs/MAC_GUI.md', 'docs/MAC_APP_BUILD.md',
    'docs/MULTI_DEVICE.md', 'tools/collection_report.py', 'tests/test_collection_report.py',
    'docs/FIRST_LIGHT_REVIEW.md', 'tools/baseline_review.py', 'tests/test_baseline_review.py',
    'tools/ha_handoff.py', 'tests/test_ha_handoff.py',
    'tools/ha_wizard.py',
    'tests/test_ha_wizard.py',
    'tests/test_ha_component.py',
    'tests/test_ha_wizard_worker.py',
    'docs/HA_WIZARD.md', 'docs/SELF_SERVICE.md',
    'ha_component_templates/README.md',
    'ha_component_templates/custom_components/mc7021_single_light/__init__.py',
    'ha_component_templates/custom_components/mc7021_single_light/manifest.json',
    'ha_component_templates/custom_components/mc7021_single_light/config_flow.py',
    'ha_component_templates/custom_components/mc7021_single_light/const.py',
    'ha_component_templates/custom_components/mc7021_single_light/contract.py',
    'ha_component_templates/custom_components/mc7021_single_light/bridge.py',
    'ha_component_templates/custom_components/mc7021_single_light/light.py',
    'ha_component_templates/custom_components/mc7021_single_light/select.py',
    'ha_component_templates/custom_components/mc7021_single_light/button.py',
    'ha_component_templates/custom_components/mc7021_single_light/diagnostics.py',
    'ha_component_templates/custom_components/mc7021_single_light/strings.json',
    'ha_component_templates/custom_components/mc7021_single_light/translations/en.json',
    'ha_component_templates/custom_components/mc7021_single_light/translations/zh-Hans.json',
    'ha_component_templates/custom_components/mc7021_single_light/driver.py',
    '.github/ISSUE_TEMPLATE/compatibility.yml', '.github/ISSUE_TEMPLATE/bug_report.md',
    '.github/ISSUE_TEMPLATE/config.yml', '.github/workflows/offline.yml',
})
PRIVATE_DIRS = frozenset({'.git', 'captures', 'demo_runs', 'demo_collections', 'private_reports', 'baseline_reviews', 'private_reviews', 'private_ha_handoffs', 'private_ha_wizards', 'private_ha_forms',
                         'private_samples', 'work', 'artifacts', '__pycache__'})
FAKE_UDIDS = frozenset({'00000001-0000000000000001', '00000000-0000000000000000'})
DOC_NETWORKS = tuple(ipaddress.ip_network(x) for x in
                     ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'])


def check_content(name, data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('Non-text payload in public file: ' + name)
    if re.search(r'/Users/[A-Za-z0-9_.-]+/', text):
        raise ValueError('Personal Mac path in: ' + name)
    for value in re.findall(r'(?<![A-Za-z0-9])\d{1,3}(?:\.\d{1,3}){3}(?![A-Za-z0-9])', text):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        # Explicit malformed-address tests may use loopback, broadcast, etc.
        if address.is_loopback or address.is_multicast or address.is_unspecified or value == '255.255.255.255':
            continue
        if not any(address in network for network in DOC_NETWORKS):
            raise ValueError('Non-documentation IP literal in: ' + name)
    for value in re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{16}(?![0-9a-fA-F])', text):
        if value not in FAKE_UDIDS:
            raise ValueError('Non-synthetic device identifier in: ' + name)
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', text):
        raise ValueError('Private-key marker in: ' + name)


def audit(root, tracked=False):
    root = Path(root).resolve()
    if tracked:
        if not (root / '.git').exists():
            raise ValueError('Expected a separate repository at project root; refusing parent repository')
        top = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
                             check=True, capture_output=True, text=True).stdout.strip()
        if Path(top).resolve() != root:
            raise ValueError('Refusing to inspect a parent repository')
        listed = subprocess.run(['git', '-C', str(root), 'ls-files', '--stage', '-z'],
                                check=True, capture_output=True).stdout.decode().split('\0')
        candidates = set()
        for entry in listed:
            if not entry:
                continue
            metadata, name = entry.split('\t', 1)
            mode, _object_id, stage = metadata.split()
            if stage != '0':
                raise ValueError('Unmerged index entry in: ' + name)
            if mode not in {'100644', '100755'}:
                raise ValueError('Non-regular index entry in: ' + name)
            candidates.add(name)
    else:
        candidates = set()
        for path in root.rglob('*'):
            relative = path.relative_to(root)
            if any(part in PRIVATE_DIRS for part in relative.parts):
                continue
            if path.name == '.DS_Store' or path.suffix == '.pyc':
                continue
            if path.is_file() or path.is_symlink():
                candidates.add(relative.as_posix())
    unexpected = candidates - PUBLIC_FILES
    missing = PUBLIC_FILES - candidates
    if unexpected:
        raise ValueError('Unexpected public paths: ' + ', '.join(sorted(unexpected)))
    if missing:
        raise ValueError('Missing expected public files: ' + ', '.join(sorted(missing)))
    for name in sorted(candidates):
        if tracked:
            # Inspect the staged blob, even when the working copy was edited
            # after git add. Paths have already passed the exact allowlist.
            data = subprocess.run(['git', '-C', str(root), 'show', ':' + name],
                                  check=True, capture_output=True).stdout
        else:
            path = root / name
            if any(part.is_symlink() for part in (path,) + tuple(path.parents) if part != root.parent):
                raise ValueError('Symlink not allowed in public release: ' + name)
            data = path.read_bytes()
        check_content(name, data)
    return sorted(candidates)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tracked', action='store_true')
    args = parser.parse_args()
    try:
        names = audit(Path(__file__).resolve().parents[1], args.tracked)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')
    print('Public allowlist and obvious-identifier checks passed: {} text files'.format(len(names)))


if __name__ == '__main__':
    main()
