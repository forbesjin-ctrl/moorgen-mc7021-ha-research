#!/usr/bin/env python3
"""Compare explicitly selected local capture rounds; never merge device identity.

Only DATA_ROOT/captures/ONE_DIRECTORY/session.json is considered. All inputs
remain read-only. Reports are private local files, without transport or replay.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import stat
import uuid

try:
    from .analyze_capture import analyze_session, load_small, REQUIRED_STEPS
    from .capture_mc7021_light import validate_target_context
except ImportError:
    from analyze_capture import analyze_session, load_small, REQUIRED_STEPS
    from capture_mc7021_light import validate_target_context

VERSION = '0.4.0'
MAX_SESSIONS = 32
MAX_DIRECTORY_ENTRIES = 128
MAX_TOTAL_BYTES = 256 * 1024 * 1024
INPUT_LIMITS = {'session.json': 4 * 1024 * 1024,
                'events.jsonl': 4 * 1024 * 1024,
                'traffic.pcap': 128 * 1024 * 1024}
IDENTIFIER = re.compile(r'^[0-9a-fA-F]{16}$')
UNKNOWN = 'unknown'
IDENTITY_NOTE = ('每轮独立；相同8字节标识只表示字节相同，不能跨住宅、会话或灯路'
                 '自动认作同一物理设备。房间、灯名和采集批次均为操作者声明，尚未核验。')


def _safe_path(value):
    """Reject symlinks before resolving, including a symlinked ancestor."""
    path = Path(os.path.abspath(os.path.expanduser(str(value))))
    if any(part.is_symlink() for part in (path,) + tuple(path.parents)):
        raise ValueError('不接受符号链接目录或文件：' + path.name)
    return path


def _within(path, root):
    return path == root or root in path.parents


def _inventory(capture_root):
    root = _safe_path(capture_root)
    if not root.is_dir():
        raise ValueError('请选择包含captures子目录的数据文件夹')
    captures = _safe_path(root / 'captures')
    if not captures.is_dir():
        raise ValueError('所选数据文件夹没有captures子目录')
    candidates, ignored, total = [], [], 0
    # Do not rglob, walk or follow another directory level.
    with os.scandir(captures) as entries:
        for number, entry in enumerate(entries, 1):
            if number > MAX_DIRECTORY_ENTRIES:
                raise ValueError('captures直属条目超过{}个上限'.format(MAX_DIRECTORY_ENTRIES))
            if entry.is_symlink():
                raise ValueError('captures直属条目是符号链接：' + entry.name)
            if not entry.is_dir(follow_symlinks=False):
                ignored.append(dict(folder=entry.name, reason='不是直属采样目录，未读取'))
                continue
            folder = Path(entry.path)
            metadata = folder / 'session.json'
            if metadata.is_symlink():
                raise ValueError('采样元数据是符号链接：' + entry.name)
            if not metadata.exists():
                ignored.append(dict(folder=entry.name, reason='没有直属session.json；不向更深目录查找'))
                continue
            candidates.append(folder)
            if len(candidates) > MAX_SESSIONS:
                raise ValueError('采样轮数超过{}轮上限；请显式选择较小的采样集合'.format(MAX_SESSIONS))
            for name, limit in INPUT_LIMITS.items():
                source = folder / name
                if source.is_symlink():
                    raise ValueError('采样输入是符号链接：' + entry.name + '/' + name)
                if not source.exists():
                    continue
                info = source.stat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('采样输入不是普通文件：' + entry.name + '/' + name)
                if info.st_size > limit:
                    raise ValueError('采样输入超过单文件上限：' + entry.name + '/' + name)
                total += info.st_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError('采样输入总大小超过{}MiB上限'.format(MAX_TOTAL_BYTES // (1024 * 1024)))
    if not candidates:
        raise ValueError('captures直属目录中没有session.json；不递归搜索更深目录')
    return root, sorted(candidates, key=lambda p: p.name), ignored, total


def _context(metadata):
    value = metadata.get('target_context')
    result = dict(declaration_source=UNKNOWN, declaration_status='missing',
                  identity_verified=False, device_kind_verified=False,
                  label=None, room=None, collection_id=None, kind=None)
    try:
        source = validate_target_context(value)
    except ValueError:
        result.update(declaration_status='invalid',
            validation_note='无效标签整组已忽略；灯名、房间、类型和批次均未知，保留原件供本机核对')
        return result
    if source is not None:
        result.update(source)
        result.update(declaration_source='operator_declared', declaration_status='declared')
    return result


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _sum_known(rows, key):
    values = [_count(row.get('summary', {}).get(key)) for row in rows]
    return sum(values) if values and all(value is not None for value in values) else None


def _round_summary(report, row):
    # The single-round analyzer owns the accepted declaration. Do not present
    # labels which that analyzer rejected (or which changed during its read).
    if report.get('target_context') is not None:
        row['target_context'] = _context(dict(target_context=report['target_context']))
    elif row['target_context']['declaration_status'] == 'declared':
        row['target_context'] = _context({})
        row['target_context'].update(declaration_status='invalid',
            validation_note='单轮分析未采信本轮标签；汇总同样忽略整组声明，物理身份仍未知')
    events = report.get('events', [])
    complete = {event['step'] for event in events if event.get('status') == 'recorded'}
    missing = sorted(REQUIRED_STEPS - complete)
    row.update(status='analyzed', analysis_id=report['analysis_id'], simulation=report.get('simulation'),
        quality=report['quality'], summary=report['summary'],
        steps=dict(required_count=len(REQUIRED_STEPS), complete_required_count=len(REQUIRED_STEPS & complete),
                   missing=missing, events=[dict(step=event.get('step', UNKNOWN),
                     status=event.get('status', UNKNOWN), command_count=event.get('command_count'),
                     state_count=event.get('state_count'), ack_count=event.get('ack_count')) for event in events]),
        device_candidates=report.get('device_candidates', []))
    row['gaps'] = list(report.get('unknowns', []))
    row['gaps'].extend('缺少完整步骤：' + name for name in missing)
    row['gaps'].extend(check['name'] + '：' + str(check.get('detail', UNKNOWN))
                       for check in report['quality'].get('checks', []) if check.get('status') != 'pass')
    if any(row['target_context'][name] is None for name in ('label', 'kind', 'collection_id')):
        row['gaps'].append('灯名、类型或采集批次声明缺失；保留为null，不能补猜物理身份；房间为可选项')
    if row['target_context'].get('validation_note'):
        row['gaps'].append(row['target_context']['validation_note'])
    if report.get('simulation') is not False:
        row['gaps'].append('样本为合成演示或来源未知，不能验证住户兼容性')
    if not any(candidate.get('repeated_command_candidate') for candidate in row['device_candidates']):
        row['gaps'].append('本轮未形成完整重复开关候选；不能自动指定HA实体')


def _collisions(rounds):
    occurrences = defaultdict(list)
    for row in rounds:
        seen = set()
        for candidate in row.get('device_candidates', []):
            identifier = candidate.get('identifier_hex', '')
            if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
                continue
            identifier = identifier.lower()
            if identifier in seen:
                continue
            seen.add(identifier)
            occurrences[identifier].append(dict(round_id=row['round_id'], folder=row['folder'],
                label=row['target_context']['label'], collection_id=row['target_context']['collection_id']))
    return [dict(identifier_hex=identifier, occurrences=rows, identity_verified=False,
                 physical_entities_merged=False, note=IDENTITY_NOTE)
            for identifier, rows in sorted(occurrences.items()) if len(rows) > 1]


def _text(value):
    if value is None or value == UNKNOWN:
        value = '未知'
    return escape(str(value), quote=True)


def _list(values):
    return '<ul>' + ''.join('<li>' + _text(value) + '</li>' for value in values) + '</ul>'


def render_collection(report):
    """Escape all source values; fixed styling only, no scripts or external URLs."""
    rows = []
    details = []
    labels = {'analyzed': '已独立分析', 'failed': '分析失败', 'blocked': '受阻',
              'limited': '存在限制', 'reviewable': '可供人工复核'}
    for row in report['rounds']:
        context, metrics = row['target_context'], row.get('summary', {})
        steps = row.get('steps', {})
        step_count = str(steps.get('complete_required_count', '未知')) + '/10'
        cells = [row['round_id'], row['folder'], context['room'], context['label'],
                 labels.get(row['status'], row['status']),
                 labels.get(row['quality']['level'], row['quality']['level']), step_count,
                 metrics.get('target_packet_count'), metrics.get('frame_count'), metrics.get('device_count')]
        rows.append('<tr>' + ''.join('<td>' + _text(value) + '</td>' for value in cells) + '</tr>')
        content = '<p>采集批次声明：{}；类型声明：{}。这些信息尚未核验。</p>'.format(
            _text(context['collection_id']), _text(context['kind']))
        if row.get('error'):
            content += '<p class="error">失败原因：' + _text(row['error']) + '</p>'
        candidates = row.get('device_candidates', [])
        content += '<h3>仅在本轮成立的设备候选</h3>'
        content += _list('{}：开指令候选{}，关指令候选{}，状态记录{}；物理对应关系待核验'.format(
            candidate.get('identifier_hex', UNKNOWN), candidate.get('command_on_count', UNKNOWN),
            candidate.get('command_off_count', UNKNOWN), candidate.get('state_record_count', UNKNOWN))
                        for candidate in candidates) if candidates else '<p>无可供复核的设备候选，不能据此认定没有设备。</p>'
        content += '<h3>本轮缺口</h3>' + _list(row.get('gaps', []))
        details.append('<section><h2>' + _text(row['round_id']) + ' · ' + _text(context['label'])
                       + '</h2>' + content + '</section>')
    collisions = []
    for item in report['identifier_collisions']:
        occurrences = '；'.join(row['round_id'] + ' / ' + str(row['label'] if row['label'] is not None else '未知')
                               for row in item['occurrences'])
        collisions.append(item['identifier_hex'] + '：' + occurrences + '。只提示相同字节，未合并实体。')
    summary = report['summary']
    return ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
        'base-uri \'none\'; form-action \'none\'">'
        '<title>MC7021 多轮私有采样汇总</title><style>'
        'body{font:16px system-ui,sans-serif;line-height:1.6;margin:2rem auto;max-width:1100px;'
        'padding:0 1rem;color:#152536;background:#f4f7fa}section{background:white;padding:1.2rem;'
        'margin:1rem 0;border-radius:12px}.table{overflow:auto}table{border-collapse:collapse;'
        'min-width:900px}td,th{border:1px solid #ccd4dd;padding:.5rem;text-align:left;'
        'overflow-wrap:anywhere}.error{color:#a11}h1{font-size:1.8rem}</style></head><body>'
        '<h1>MC7021 多轮私有采样汇总</h1><p>仅本机离线分析 · 不上传 · 不重放 · HA实机接入尚未验证。</p>'
        '<section><h2>如何理解本报告</h2><p>' + _text(IDENTITY_NOTE)
        + '</p><p>共{}轮，独立分析{}轮，失败{}轮。完整记录有助于复核，数量多不等于协议已验证。'
          '缺失值显示未知，失败轮次不计为零通信。</p></section>'.format(
              summary['round_count'], summary['analyzed_count'], summary['failed_count'])
        + '<section><h2>各轮对照</h2><div class="table"><table><thead><tr>'
        + ''.join('<th>' + heading + '</th>' for heading in ('轮次', '目录', '房间声明', '灯名声明', '处理结果',
            '质量', '完整核心步骤', '目标相关包', '完整候选帧', '本轮候选数'))
        + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div></section>'
        + '<section><h2>跨轮相同字节提示</h2>' + (_list(collisions) if collisions else
          '<p>未发现跨轮相同8字节候选标识；这不证明各轮一定是不同设备。</p>') + '</section>'
        + ''.join(details) + '<section><h2>下一步</h2>' + _list(report['next_actions'])
        + '</section><section><h2>未读取的直属条目</h2>'
        + (_list(item['folder'] + '：' + item['reason'] for item in report['ignored_entries'])
           if report['ignored_entries'] else '<p>无。</p>') + '</section></body></html>')


def analyze_collection(capture_root, output_root=None):
    """Return (private_destination, collection_dict), retaining each round's identity.

    Input is a data root containing ``captures`` (not an arbitrary recursive
    search root). Preflight bounds are applied before any report is written.
    A corrupt round remains a failed row while other valid rounds are analyzed.
    """
    root, candidates, ignored, total = _inventory(capture_root)
    output = _safe_path(output_root if output_root is not None else root / 'private_reports')
    if _within(output, root / 'captures'):
        raise ValueError('输出目录不能位于captures输入目录内，原始采样保持只读')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = output / ('collection_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                            + '_' + uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    rounds = []
    for index, folder in enumerate(candidates, 1):
        row = dict(round_id='round-{:03d}'.format(index), folder=folder.name, status='failed',
                   target_context=_context({}), quality=dict(level='blocked', checks=[], warnings=[]),
                   summary={}, device_candidates=[], gaps=[], identity_verified=False,
                   physical_feedback_verified=False, can_start_live_ha=False)
        try:
            metadata = json.loads(load_small(folder / 'session.json'))
            if not isinstance(metadata, dict):
                raise ValueError('session.json必须为对象')
            row['target_context'] = _context(metadata)
            per_round = destination / 'rounds' / row['round_id']
            # No ordinary_ids: a label/type declaration cannot confirm a wire ID.
            analysis_dir, report = analyze_session(folder, output_root=per_round, ordinary_ids=())
            row['analysis_directory'] = analysis_dir.relative_to(destination).as_posix()
            _round_summary(report, row)
        except Exception as error:
            # Preserve a failed round and its reason, without masking it as no traffic.
            row.update(status='failed', quality=dict(level='blocked', checks=[], warnings=[]),
                       summary={}, device_candidates=[])
            row.pop('steps', None)
            row['error'] = type(error).__name__ + '：' + str(error)[:600]
            row['gaps'] = ['本轮分析失败，包数、帧数及步骤覆盖均未知；请私下保留原件和错误记录']
        rounds.append(row)
    failed = sum(row['status'] == 'failed' for row in rounds)
    blocked = sum(row['quality']['level'] == 'blocked' for row in rounds)
    collisions = _collisions(rounds)
    simulations = [row.get('simulation') for row in rounds]
    simulation = True if all(value is True for value in simulations) else (
        False if all(value is False for value in simulations) else None)
    metrics = {key: _sum_known(rounds, key) for key in ('packet_count', 'target_packet_count',
                                                      'payload_packets', 'frame_count')}
    metrics.update(round_count=len(rounds), analyzed_count=len(rounds) - failed, failed_count=failed,
                   blocked_count=blocked, input_bytes=total, identifier_collision_count=len(collisions),
                   candidate_occurrence_count=_sum_known(rounds, 'device_count'), device_count=None)
    report = dict(schema_version=VERSION, artifact='private_capture_collection',
        collection_analysis_id=uuid.uuid4().hex, simulation=simulation, private=True,
        scope='explicit_data_root/captures/one_session_directory/session.json',
        source=dict(folder=root.name, max_depth=1, max_sessions=MAX_SESSIONS, max_input_bytes=MAX_TOTAL_BYTES),
        quality=dict(level='blocked' if blocked else 'limited' if any(
            row['quality']['level'] != 'reviewable' for row in rounds) else 'reviewable',
            warnings=['单轮失败保留在汇总内，不会作为零通信或成功采样处理'] if failed else []),
        summary=metrics, rounds=rounds, ignored_entries=ignored, identifier_collisions=collisions,
        identity_note=IDENTITY_NOTE,
        readiness=dict(can_start_live_ha=False, physical_feedback_verified=False,
                       cross_session_identity_verified=False, automatic_entity_mapping_enabled=False),
        next_actions=['逐轮核对灯名、房间、同一实际灯路和10个核心步骤；每轮只操作一组灯',
            '优先补齐面板独立状态、App关闭期间面板操作、重进App回读，再补采新灯',
            '将不同灯路、不同时间和不同住户的记录保留为独立轮次；不自动合并标识',
            '私下提交原始采样与本报告供逐包核验；不要把住户原始数据放到公开仓库',
            '认证、会话、地址映射和独立状态经核验后，再实现和现场验证HA适配；不生成猜测控制指令'])
    for name, content in [('collection.json', json.dumps(report, ensure_ascii=False, indent=2)),
                          ('collection.html', render_collection(report))]:
        path = destination / name
        with path.open('x', encoding='utf-8') as handle:
            path.chmod(0o600)
            handle.write(content + '\n')
    return destination, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', required=True, type=Path,
                        help='显式选择的数据根目录，内部应有captures子目录')
    parser.add_argument('--output-root', type=Path)
    args = parser.parse_args(argv)
    try:
        destination, report = analyze_collection(args.capture_root, args.output_root)
    except (OSError, ValueError) as error:
        parser.exit(2, '多轮离线汇总未完成：{}\n原始采样未修改。\n'.format(error))
    print('私有多轮报告：{}\n共{}轮，失败{}轮；设备身份未跨轮合并，HA实机接入仍未验证。'.format(
        destination / 'collection.html', report['summary']['round_count'], report['summary']['failed_count']))
    return 1 if report['summary']['failed_count'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
