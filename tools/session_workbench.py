"""Source-bound, non-executable session candidates from local original captures.

No socket, subprocess, credential export, driver import, or executable recipe is
provided. Candidate predictions use only preceding observations and fixed narrow
rules. Counterexamples and missing evidence remain visible.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import uuid

try:
    from . import adapter_recipe as recipe
    from . import analyze_capture as analysis
    from . import baseline_review as baseline
    from . import demo_sample as demo
    from . import offline_shcp as codec
    from . import sampling_gaps as gaps
except ImportError:
    import adapter_recipe as recipe
    import analyze_capture as analysis
    import baseline_review as baseline
    import demo_sample as demo
    import offline_shcp as codec
    import sampling_gaps as gaps

VERSION = '0.9.0'
MAX_CONNECTIONS = analysis.MAX_FLOWS
MAX_AUTH_FIELDS = 20000
MAX_COMPARISONS = 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
SCOPE = ('只从本机原件研究受支持明文会话、序号、查询和重进App的候选规则；'
         '序号只按前一观察值作离线预测，不复制待检验帧序号。认证字段只显示编号、长度和同异关系。'
         '没有认证字段不证明免认证；候选一致不证明会话可用、实物状态或HA验收。'
         '不上传、不发包、不执行或生成联网驱动。')
SESSION_NAMES = {(1, 1): '连接请求', (1, 3): '连接应答', (2, 4): '认证请求',
                 (2, 6): '认证成功类应答', (2, 5): '认证失败类应答', (2, 19): '无权限类应答'}
RESPONSE_TO = {(1, 3): (1, 1), (2, 6): (2, 4), (2, 5): (2, 4),
               (2, 19): (2, 4), (3, 8): (3, 7), (4, 10): (4, 9), (4, 11): (4, 9)}
STATUS_LABELS = {'candidate_supported': '候选获支持，未实机验证', 'conflict': '存在冲突',
                 'insufficient': '证据不足', 'ambiguous': '多个规则仍难区分',
                 'needs_sample': '需正常补采', 'manual_required': '需人工核对',
                 'software_required': '待实现', 'evidence_present_unverified': '已有线索，未验证'}


def _pair(frame):
    value = frame['parsed_frame']
    return value['protocol_type'], value['link_code']


def _order(frame):
    return (frame['timestamp_start'], min(frame['packet_indices']), frame['stream_offset'], frame['index'])


def _strictly_before(first, second):
    # Offsets define order within one reassembled direction even when coalesced
    # frames share a packet timestamp. Cross-direction overlap is ambiguous.
    if first['flow_id'] == second['flow_id']:
        return first['stream_offset'] < second['stream_offset']
    return first['timestamp_end'] < second['timestamp_start']


def _ref(frame, round_name, connection_id):
    return dict(round=round_name, connection_id=connection_id, frame_index=frame['index'])


def _connections(source, round_name):
    flows = analysis.split_flows(source['capture']['packets'], source['metadata']['target_ip'])
    result, by_key, flow_connection = [], {}, {}
    for flow in flows:
        endpoints = tuple(sorted(((flow['src'], flow['sport']), (flow['dst'], flow['dport']))))
        key = (flow['transport'], endpoints, flow['generation'])
        if key not in by_key:
            if len(result) >= MAX_CONNECTIONS:
                raise ValueError('会话连接数超过有界分析上限')
            row = dict(id=round_name + '-connection-' + str(len(result) + 1), round=round_name,
                transport=flow['transport'], endpoints=[dict(ip=ip, port=port) for ip, port in endpoints],
                generation=flow['generation'], flow_ids=[], _packets=[], _frames=[])
            by_key[key] = row
            result.append(row)
        row = by_key[key]
        row['flow_ids'].append(flow['id'])
        row['_packets'].extend(flow['packets'])
        flow_connection[flow['id']] = row
    for frame in source['report']['frames']:
        flow_connection[frame['flow_id']]['_frames'].append(frame)
    for row in result:
        row['_packets'].sort(key=lambda p: (p['timestamp'], p['packet_index']))
        row['_frames'].sort(key=_order)
        packets = row['_packets']
        row['timestamp_start'] = min(p['timestamp'] for p in packets)
        row['timestamp_end'] = max(p['timestamp'] for p in packets)
        row['packet_count'] = len(packets)
        row['frame_count'] = len(row['_frames'])
        row['tcp_events'] = [dict(packet_index=p['packet_index'], timestamp=p['timestamp'],
            direction='from_host' if p['src'] == source['metadata']['target_ip'] else 'to_host',
            syn=bool(p['flags'] & 2), ack=bool(p['flags'] & 16), fin=bool(p['flags'] & 1), rst=bool(p['flags'] & 4))
            for p in packets if p['transport'] == 'tcp' and p['flags'] & (2 | 1 | 4)]
        row['syn_visible'] = any(p['syn'] and not p['ack'] and p['direction'] == 'to_host' for p in row['tcp_events'])
        row['syn_ack_visible'] = any(p['syn'] and p['ack'] and p['direction'] == 'from_host' for p in row['tcp_events'])
        row['initial_capture_status'] = 'client_syn_observed' if row['syn_visible'] else 'initial_boundary_unknown'
        row['session_timeline'] = [dict(frame_index=f['index'], direction=f['direction'],
            timestamp_start=f['timestamp_start'], timestamp_end=f['timestamp_end'],
            protocol_type=_pair(f)[0], link_code=_pair(f)[1], label=SESSION_NAMES[_pair(f)])
            for f in row['_frames'] if f['parsed_frame']['protocol_number'] == 1 and _pair(f) in SESSION_NAMES]
    result.sort(key=lambda row: (row['timestamp_start'], row['id']))
    return result


def _connection_summary(row):
    return {key: value for key, value in row.items() if not key.startswith('_')}


def _session_rule(connections):
    checks = []
    expected = (((1, 1), 'to_host'), ((1, 3), 'from_host'), ((2, 4), 'to_host'), ((2, 6), 'from_host'))
    for connection in connections:
        frames = [f for f in connection['_frames'] if f['parsed_frame']['protocol_number'] == 1 and _pair(f) in SESSION_NAMES]
        reasons, cursor, previous, matched = [], 0, None, []
        failures = [f['index'] for f in frames if _pair(f) in ((2, 5), (2, 19)) and f['direction'] == 'from_host']
        wrong_directions = [f['index'] for f in frames if (_pair(f), f['direction']) not in expected
                            and _pair(f) not in ((2, 5), (2, 19))]
        for frame in frames:
            if cursor < len(expected) and (_pair(frame), frame['direction']) == expected[cursor]:
                if previous is not None and not _strictly_before(previous, frame):
                    reasons.append('双向帧时间重叠，不能断言请求应答顺序')
                    break
                matched.append(frame['index'])
                previous = frame
                cursor += 1
        if not connection['syn_visible']:
            reasons.append('未捕获客户端SYN，初始边界未知；不能判免认证')
        if cursor != len(expected):
            reasons.append('没有完整、方向正确且顺序明确的连接请求/应答和认证请求/成功类应答')
        if any(sum((_pair(f), f['direction']) == item for f in frames) > 1 for item in expected):
            reasons.append('同一连接存在重复连接或认证步骤，未划分会话轮次，不能当唯一成功时序')
        if wrong_directions:
            reasons.append('会话类型的方向与窄候选不同')
        checks.append(dict(connection_id=connection['id'], round=connection['round'],
            status='conflict' if failures or wrong_directions else 'candidate_supported' if not reasons else 'insufficient',
            matched_frame_indices=matched, failure_frame_indices=failures,
            direction_conflict_frame_indices=wrong_directions, reasons=reasons,
            authentication_required=None, authentication_verified=False))
    support = [row['connection_id'] for row in checks if row['status'] == 'candidate_supported']
    conflicts = [row['connection_id'] for row in checks if row['status'] == 'conflict']
    return dict(id='normal_session_order', title='正常连接和认证时序候选',
        status='conflict' if conflicts else 'candidate_supported' if len(support) >= 2 and len(support) == len(checks)
            else 'insufficient', supports=support, conflicts=conflicts,
        insufficient=[row['connection_id'] for row in checks if row['status'] == 'insufficient'],
        checks=checks, authentication_required=None, authentication_verified=False,
        note='成功类报文只是类型与方向观察；不保存凭证、不生成认证报文，也不能证明主机已授权。')


def _authentication(connections):
    observations, groups, field_count, methods, encryption = [], {}, 0, [], []
    for connection in connections:
        for frame in connection['_frames']:
            packet = frame['parsed_frame']
            is_auth = packet['protocol_number'] == 1 and _pair(frame) in SESSION_NAMES
            selected = list(enumerate(packet['fields'])) if is_auth else [(i, f) for i, f in enumerate(packet['fields']) if f['id'] in (93, 160)]
            if not selected and not is_auth:
                continue
            field_count += len(selected)
            if field_count > MAX_AUTH_FIELDS:
                raise ValueError('认证字段形状数超过有界分析上限')
            observations.append(dict(**_ref(frame, connection['round'], connection['id']), direction=frame['direction'],
                protocol_type=packet['protocol_type'], link_code=packet['link_code'],
                fields=[dict(id=field['id'], length=field['length'], position=i) for i, field in selected]))
            ids = {field['id'] for _, field in selected}
            if _pair(frame) == (2, 4) and frame['direction'] == 'to_host':
                names = []
                if {12, 13}.issubset(ids):
                    names.append('username_password_field_shape_candidate')
                if ids.intersection((793, 871)) and 797 in ids:
                    names.append('phone_or_email_session_field_shape_candidate')
                if ids.intersection((793, 871)) and {794, 795}.issubset(ids):
                    names.append('token_field_shape_candidate')
                methods.append(dict(**_ref(frame, connection['round'], connection['id']),
                    candidates=names or ['unknown_authentication_field_shape'], verified=False))
            if _pair(frame) == (1, 3) and frame['direction'] == 'from_host':
                choices = [field for _, field in selected if field['id'] == 160]
                enum = int(choices[0]['value_hex'], 16) if len(choices) == 1 and choices[0]['length'] == 1 else None
                encryption.append(dict(**_ref(frame, connection['round'], connection['id']),
                    field_id=160, observed_enum=enum if enum in (0, 1, 2, 3) else None,
                    status='nonzero_encryption_branch_unsupported' if enum in (1, 2, 3)
                        else 'zero_enum_observed_not_whole_session_proof' if enum == 0 else 'unknown',
                    decryption_performed=False, absence_means_no_encryption=False))
            for i, field in selected:
                key = (packet['protocol_type'], packet['link_code'], frame['direction'], field['id'], i)
                groups.setdefault(key, {}).setdefault(connection['id'], []).append((field['value_hex'], frame['index'], field['length']))
    comparisons = []
    # Compare in memory against one reference connection, never persist values
    # or their hashes. Multiple differing values within a connection are not a
    # usable constant and are explicitly incomparable.
    for key, by_connection in sorted(groups.items()):
        items = list(by_connection.items())
        if len(items) < 2:
            continue
        first_id, first_rows = items[0]
        for other_id, other_rows in items[1:]:
            if len(comparisons) >= MAX_COMPARISONS:
                raise ValueError('跨连接认证字段比较超过有界分析上限')
            a, b = {r[0] for r in first_rows}, {r[0] for r in other_rows}
            relation = 'same' if len(a) == len(b) == 1 and a == b else 'different' if len(a) == len(b) == 1 else 'not_comparable'
            comparisons.append(dict(protocol_type=key[0], link_code=key[1], direction=key[2],
                field_id=key[3], position=key[4], first_connection=first_id, second_connection=other_id,
                first_frame_indices=[r[1] for r in first_rows], second_frame_indices=[r[1] for r in other_rows],
                first_lengths=sorted({r[2] for r in first_rows}), second_lengths=sorted({r[2] for r in other_rows}),
                relation=relation, rule_verified=False))
    return dict(observations=observations, comparisons=comparisons, method_candidates=methods,
        encryption_observations=encryption, required=None, verified=False,
        values_copied=False, value_hashes_copied=False, reusable_material_exported=False,
        note='同值不证明可复用；异值不证明挑战应答或算法。认证需求、密钥来源和有效期保持未知。')


def _serial_partitions(connections, has_holdout):
    tcp = [row for row in connections if row['transport'] == 'tcp']
    primary = [row for row in tcp if row['round'] == 'primary']
    training = primary if has_holdout else primary[:1]
    holdout = [row for row in tcp if row['round'] == 'holdout'] if has_holdout else primary[1:]
    return training, holdout


def _serial_sequence(connections):
    frames = [(f, row) for row in connections for f in row['_frames']
              if f['direction'] == 'to_host' and f['parsed_frame']['protocol_number'] == 1]
    frames.sort(key=lambda item: _order(item[0]))
    return frames


def _counter_predictions(sequence, mode):
    predictions, insufficient = [], []
    previous = None
    for frame, connection in sequence:
        if previous is not None:
            before, before_connection = previous
            # An independent capture has an unknown initial App-global seed.
            if before_connection['round'] != connection['round']:
                insufficient.append(dict(**_ref(frame, connection['round'], connection['id']), reason='独立新轮初始序号未知，只作为新种子'))
            elif not _strictly_before(before, frame):
                insufficient.append(dict(**_ref(frame, connection['round'], connection['id']), reason='跨流时间重叠，序号先后不能确定'))
            else:
                expected = (before['parsed_frame']['serial_number'] + (1 if mode == 'increment' else 0)) % 65536
                actual = frame['parsed_frame']['serial_number']
                predictions.append(dict(**_ref(frame, connection['round'], connection['id']),
                    previous_frame_index=before['index'], previous_connection_id=before_connection['id'],
                    expected_serial=expected, observed_serial=actual, matches=expected == actual,
                    delta_modulo_65536=(actual - before['parsed_frame']['serial_number']) % 65536,
                    prediction_basis='preceding_observation_plus_one_mod65536' if mode == 'increment' else 'preceding_observation_constant',
                    causation_verified=False))
        previous = frame, connection
    return predictions, insufficient


def _reply_pairs(connections):
    pairs, uncertain = [], []
    for connection in connections:
        pending = {}
        for frame in connection['_frames']:
            if frame['parsed_frame']['protocol_number'] != 1:
                continue
            pair = _pair(frame)
            if frame['direction'] == 'to_host' and pair in set(RESPONSE_TO.values()):
                pending.setdefault(pair, []).append(frame)
            elif frame['direction'] == 'from_host' and pair in RESPONSE_TO:
                key = RESPONSE_TO[pair]
                requests = pending.get(key, [])
                if len(requests) == 1 and _strictly_before(requests[0], frame):
                    request = requests[0]
                    pairs.append(dict(connection=connection, request=request, response=frame))
                    pending[key] = []
                else:
                    uncertain.append(dict(**_ref(frame, connection['round'], connection['id']),
                        reason='没有唯一先于应答的未配对同类请求；不按真实序号倒推请求配对',
                        candidate_request_indices=[r['index'] for r in requests]))
                    # Multiple outstanding requests make this whole response
                    # epoch ambiguous; none is promoted by a matching serial.
                    pending[key] = []
    return pairs, uncertain


def _echo_predictions(connections):
    pairs, insufficient = _reply_pairs(connections)
    predictions = []
    for pair in pairs:
        request, response, connection = pair['request'], pair['response'], pair['connection']
        expected = request['parsed_frame']['serial_number']
        actual = response['parsed_frame']['serial_number']
        predictions.append(dict(**_ref(response, connection['round'], connection['id']),
            request_frame_index=request['index'], request_serial=expected,
            expected_serial=expected, observed_serial=actual, matches=expected == actual,
            prediction_basis='uniquely_prior_opposite_direction_request',
            request_pair=list(_pair(request)), response_pair=list(_pair(response)),
            causation_verified=False))
    return predictions, insufficient


def _serial_rule(key, title, training, holdout, mode):
    evaluate = _echo_predictions if mode == 'echo' else lambda rows: _counter_predictions(_serial_sequence(rows), mode)
    train_predictions, train_insufficient = evaluate(training)
    # Keep the preceding training frame when testing the next connection in
    # the same round, so a per-connection reset is not silently overlooked.
    if mode != 'echo' and holdout and training and training[0]['round'] == holdout[0]['round']:
        preceding = _serial_sequence(training)[-1:]
        test_sequence = preceding + _serial_sequence(holdout)
        test_predictions, test_insufficient = _counter_predictions(test_sequence, mode)
    else:
        test_predictions, test_insufficient = evaluate(holdout)
    predictions = train_predictions + test_predictions
    supports = [row for row in predictions if row['matches']]
    conflicts = [row for row in predictions if not row['matches']]
    insufficient = train_insufficient + test_insufficient
    if len(train_predictions) < 2:
        insufficient.append(dict(reason='训练集少于两个非重叠预测，不能形成稳定候选'))
    if not holdout or len(test_predictions) < 2:
        insufficient.append(dict(reason='缺少独立轮次或可区分连接的至少两个留出预测'))
    if mode == 'echo' and len({row['request_serial'] for row in predictions}) < 2:
        insufficient.append(dict(reason='请求序号没有至少两种值，无法区分响应回显与恒定值巧合'))
    status = 'conflict' if conflicts else 'insufficient' if insufficient else 'candidate_supported'
    return dict(id=key, title=title, status=status,
        training=dict(connection_ids=[c['id'] for c in training], predictions=train_predictions),
        holdout=dict(connection_ids=[c['id'] for c in holdout], predictions=test_predictions),
        supports=supports, conflicts=conflicts, insufficient=insufficient,
        predictions=predictions, rule_verified=False, initial_serial=None,
        note=('原厂静态候选是App全局构帧自增并按65536回绕；目标IP过滤可能漏掉其它构帧，'
              '跳号保留为严格可见连续模型的冲突，不证明全局计数器算法错误。'
              '本检验不能预测未观察的初始值，也不能授权在线发包。') if mode == 'increment'
              else '窄候选只接受所见方向及唯一时序配对；不据此生成在线序号。')


def _queries(connections, identifier):
    pairs, _ = _reply_pairs(connections)
    by_request = {(p['connection']['id'], p['request']['index']): p for p in pairs if _pair(p['request']) == (3, 7)}
    results = []
    for connection in connections:
        for frame in connection['_frames']:
            packet = frame['parsed_frame']
            if frame['direction'] != 'to_host' or packet['protocol_number'] != 1 or _pair(frame) != (3, 7):
                continue
            fields = packet['fields']
            supported_request = ([f['id'] for f in fields] == [15, 4] and fields[0]['length'] == 1
                and fields[0]['value_hex'] == '48' and fields[1]['length'] == 8 and fields[1]['value_hex'] == identifier)
            pair = by_request.get((connection['id'], frame['index']))
            response = pair['response'] if pair else None
            state = recipe._state_check(response, identifier) if response else None
            supported_response = bool(state and state['supported'] and _pair(response) == (3, 8))
            results.append(dict(**_ref(frame, connection['round'], connection['id']),
                request_type='48' if supported_request else 'other_or_unsupported',
                response_frame_index=response['index'] if response else None,
                response_context='04' if supported_response else None,
                status='candidate_pair_observed' if supported_request and supported_response else 'insufficient',
                candidate_state=state['candidate_state'] if supported_response else None,
                causation_verified=False, physical_feedback_verified=False,
                note='请求TLV15=48与应答TLV15=04分别检查；应答值不能反推请求值，ACK不作为状态。'))
    return results


def _reopen_checks(source, connections, identifier):
    result = []
    windows = source['windows']
    closed = [w for w in windows if w['step'] == '关闭App' and w['status'] == 'recorded']
    changed = [w for w in windows if w['step'] == 'App关闭期间面板开' and w['status'] == 'recorded']
    for window in [w for w in windows if w['step'] == '重进App读状态']:
        reasons, candidates, opposite_states, unsupported_states = [], [], [], []
        ready = analysis.timestamp(window['ready_at']) if window.get('ready_at') else None
        end = analysis.timestamp(window['window_end']) if window.get('window_end') else None
        before = [w for w in closed if ready is not None and analysis.timestamp(w['window_end']) < ready]
        closed_time = max((analysis.timestamp(w['window_end']) for w in before), default=None)
        changed_before = [w for w in changed if closed_time is not None and ready is not None
                          and closed_time < analysis.timestamp(w['ready_at'])
                          and analysis.timestamp(w['window_end']) < ready]
        if window['status'] != 'recorded' or len(before) != 1 or len(changed_before) != 1:
            reasons.append('关闭App、关闭期间面板改变及重进窗口记录不完整或不唯一')
        if len(changed_before) == 1:
            change = changed_before[0]
            if change.get('physical_light') != 'on' or change.get('app_display') != 'not_visible':
                reasons.append('App关闭期间面板开未记录实物开且App不可见，不能确认规定的状态改变声明')
            previous = [w for w in windows if w['status'] == 'recorded' and w.get('physical_light') in ('on', 'off')
                and closed_time is not None and analysis.timestamp(w['window_end']) < closed_time]
            latest = max(previous, key=lambda w: analysis.timestamp(w['window_end']), default=None)
            if latest is None or latest.get('physical_light') != 'off':
                reasons.append('关闭前缺少明确实物关的观察，不能确认关闭期间发生相反状态改变')
            if window.get('physical_light') != change.get('physical_light'):
                reasons.append('重进App实物观察与关闭期间面板改变的实物声明不一致')
        closed_commands = [f['index'] for connection in connections for f in connection['_frames']
            if closed_time is not None and ready is not None and closed_time < f['timestamp_start'] < ready
            and f['direction'] == 'to_host' and _pair(f) == (4, 9)
            and recipe._has_target(f['parsed_frame'], identifier)]
        if closed_commands:
            reasons.append('声明App关闭期间仍出现同目标App执行请求帧{}，需要人工排除混入操作'.format(closed_commands))
        for connection in connections:
            # A SYN before close/old connection with a newly timed response is
            # not a reconnect, even if its state happens to match observation.
            syns = [e for e in connection['tcp_events'] if e['syn'] and not e['ack'] and e['direction'] == 'to_host']
            new_syn = bool(connection['transport'] == 'tcp' and closed_time is not None and end is not None
                and connection['timestamp_start'] > closed_time
                and any(closed_time < e['timestamp'] <= end for e in syns))
            if not new_syn:
                continue
            frame_set = set(window['frame_indices'])
            queries = [q for q in _queries([connection], identifier) if q['frame_index'] in frame_set
                       and q['status'] == 'candidate_pair_observed' and q['response_frame_index'] in frame_set]
            for query in queries:
                request = next(f for f in connection['_frames'] if f['index'] == query['frame_index'])
                response = next(f for f in connection['_frames'] if f['index'] == query['response_frame_index'])
                syn_before_request = any(e['timestamp'] < request['timestamp_start'] for e in syns)
                if (syn_before_request and request.get('nearby_steps') == ['重进App读状态'] and response.get('nearby_steps') == ['重进App读状态']
                        and not request.get('event_association_ambiguous', True) and not response.get('event_association_ambiguous', True)):
                    candidates.append(query)
        if len(candidates) != 1:
            reasons.append('没有唯一的新TCP连接、窗口内新48查询及主机04独立状态候选；旧连接/缓存/ACK不计')
        if len(candidates) == 1 and (window.get('physical_light') != candidates[0]['candidate_state']
                                   or window.get('app_display') != candidates[0]['candidate_state']):
            reasons.append('主机候选状态与实物及App显示声明不一致或未知')
        # Inspect every target state in the window, including unsolicited
        # pushes after an apparently matching query response. A matching
        # response cannot conceal a contradictory or unsupported state frame.
        frame_set = set(window['frame_indices'])
        expected_state = candidates[0]['candidate_state'] if len(candidates) == 1 else window.get('physical_light')
        for connection in connections:
            for frame in connection['_frames']:
                if (frame['index'] not in frame_set or frame['direction'] != 'from_host'
                        or _pair(frame) not in ((5, 12), (3, 8))
                        or not recipe._has_target(frame['parsed_frame'], identifier)):
                    continue
                state = recipe._state_check(frame, identifier)
                if not state['supported']:
                    unsupported_states.append(frame['index'])
                elif expected_state in ('on', 'off') and state['candidate_state'] != expected_state:
                    opposite_states.append(frame['index'])
        if opposite_states:
            reasons.append('同一窗口有同目标相反独立状态帧{}；不能只挑匹配查询应答忽略冲突'.format(opposite_states))
        if unsupported_states:
            reasons.append('同一窗口有同目标但窄状态模型不支持的帧{}；不能忽略未知字段或状态布局'.format(unsupported_states))
        result.append(dict(round=connections[0]['round'] if connections else 'unknown',
            step='重进App读状态', status='candidate_supported' if not reasons else 'insufficient',
            candidates=candidates, reasons=reasons, fresh_connection_required=True,
            conflicting_state_frame_indices=opposite_states, unsupported_state_frame_indices=unsupported_states,
            acknowledgement_is_state=False, causation_verified=False, physical_feedback_verified=False))
    if not result:
        result.append(dict(round=connections[0]['round'] if connections else 'unknown', step='重进App读状态',
            status='insufficient', candidates=[], reasons=['缺少重进App操作窗口'], fresh_connection_required=True,
            conflicting_state_frame_indices=[], unsupported_state_frame_indices=[],
            acknowledgement_is_state=False, causation_verified=False, physical_feedback_verified=False))
    return result


def _source_summary(source, connections):
    stop = source['metadata'].get('capture_stop')
    stats = stop.get('stats') if isinstance(stop, dict) else None
    dropped = stats.get('dropped_by_kernel') if isinstance(stats, dict) else None
    dropped = dropped if type(dropped) is int and dropped >= 0 else None
    return dict(source_paths=source['paths'], source_bindings=source['binding'],
        simulation=source['metadata']['simulation'], target_ip=source['metadata']['target_ip'],
        capture_status=source['metadata'].get('status'), connection_count=len(connections),
        tcp_connection_count=sum(c['transport'] == 'tcp' for c in connections),
        frame_count=len(source['report']['frames']), target_packet_count=source['capture']['target_packet_count'],
        dropped_by_kernel=dropped,
        sampling_transport_issue_count=len(source['capture']['issues']) + sum(
            sum('载荷未识别为已支持明文' not in issue and 'TCP未捕获SYN' not in issue for issue in flow['issues'])
            for flow in source['report']['flows']),
        initial_boundary_unknown_count=sum(
            sum('TCP未捕获SYN' in issue for issue in flow['issues']) for flow in source['report']['flows']),
        transport_issue_count=len(source['capture']['issues']) + sum(len(f['issues']) for f in source['report']['flows']),
        opaque_flow_ids=list(source['evidence']['session_authentication']['opaque_flow_ids']))


def _tasks(session, serial, auth, reopen, primary, holdout, quality_findings):
    tasks = []
    def add(key, title, category, status, why, instructions, expected):
        tasks.append(dict(id=key, title=title, category=category, status=status, why=why,
            instructions=list(instructions), expected_evidence=list(expected), capture_allowed=False,
            preparation_only=True, bytes_sent=0))
    sampling_quality = [row['reason'] for row in quality_findings if row['category'] == 'recapture']
    software_quality = [row['reason'] for row in quality_findings if row['category'] == 'software_support']
    quality_category = 'recapture' if sampling_quality else 'software_support' if software_quality else 'manual_check'
    quality_status = 'needs_sample' if sampling_quality else 'software_required' if software_quality else 'evidence_present_unverified'
    add('source_quality', '原件质量与解析能力限制', quality_category, quality_status,
        '；'.join(sampling_quality + software_quality) if quality_findings else
            '未发现当前可识别的采样质量限制；这不证明全量捕获、认证或实物状态充分。',
        ('中止、丢包未知或非零、实际截断或重组冲突：保留本轮原件，按原完整单灯流程正常补采，不手改统计或配置。',
         '仅缺SYN或流首未知：最多补一轮正常启动；两轮仍缺时保持初始边界未知，转策略支持，不无限重复。',
         '不透明载荷或主机非零加密选择：转匹配解析与策略支持，不靠重复相同采样或改网络强行通过。'),
        ('完整停止记录、明确0丢包和可解释边界；对于加密或不透明分支需匹配且经过验证的软件支持。',))
    start_missing = session['status'] == 'insufficient'
    start_sample = start_missing and (holdout is None or bool(sampling_quality))
    add('normal_start', '正常启动与认证时序核对',
        'recapture' if start_sample else 'software_support' if start_missing else 'manual_check',
        'needs_sample' if start_sample else 'software_required' if start_missing else 'manual_required',
        '缺失起点不能判免认证；成功类报文不等于已实现认证。',
        ('采样开始后再正常打开App，等待初始同步，只操作同一组普通灯；不退出账号、不改网络或配置。',
         '若已有两轮仍无受支持明文会话，应转解析能力研究，不无限重采。'),
        ('可区分连接的SYN和方向正确的连接/认证时间线，保留失败和无权限报文。',))
    add('auth_fields', '认证字段变化研究', 'manual_check', 'manual_required',
        '已在内存比较跨连接字段同异；不保存值或其哈希，也不能从相同字段推出可复用凭证。',
        ('在本机查看字段编号、长度和同异关系；不要复制认证值、填令牌、重放或改原件。',),
        ('有匹配来源和说明的认证策略实现；真实数据不能自动推出密钥或任意加密算法。',))
    missing_serial = not any(r['status'] == 'candidate_supported' for r in serial[:2])
    serial_sample = missing_serial and (holdout is None or bool(sampling_quality))
    add('serial_policy', '序号候选训练与留出核对',
        'recapture' if serial_sample else 'software_support' if missing_serial else 'manual_check',
        'needs_sample' if serial_sample else 'software_required' if missing_serial else 'manual_required',
        '逐条显示前值预测、实际值、支持与冲突；App全局序号可能因未捕获其它对象构帧而跳号。',
        ('另存同一已知主机和同灯的独立完整一轮，并加入第二轮；保留原件，不手改序号。',),
        ('两个可区分连接或独立轮次的训练和留出；至少两个明确预测，冲突不能被藏掉。',))
    reopen_missing = any(row['status'] != 'candidate_supported' for row in reopen)
    reopen_sample = reopen_missing and (holdout is None or bool(sampling_quality))
    add('fresh_reopen', '关闭App后改变灯态并重进回读',
        'recapture' if reopen_sample else 'software_support' if reopen_missing else 'manual_check',
        'needs_sample' if reopen_sample else 'software_required' if reopen_missing else 'manual_required',
        '必须有新连接、新请求和主机独立状态候选；旧连接或ACK不证明真实回读。',
        ('按原向导关闭App，在关闭期间用面板改变同灯，再正常重进该灯页面；逐项记录实际亮灭和显示。',
         '原App可能复用原连接；不要改网络或配置迫使新连接，保持候选未知并等待匹配策略。'),
        ('新SYN、新48详情请求、04主机状态候选和现场观察；时间邻近仍需人工排除缓存和轮询。',))
    opaque = (primary['opaque_flow_ids'] or bool(holdout and holdout['opaque_flow_ids'])
        or any(row['status'] == 'nonzero_encryption_branch_unsupported' for row in auth['encryption_observations']))
    add('opaque_support', '不透明或加密分支', 'software_support', 'software_required' if opaque else 'evidence_present_unverified',
        '明文窄模型不能解密或推导任意认证算法；没有不透明线索也不证明全程明文。',
        ('资料留本机；不装证书、不绕过加密，不以无限重复补采替代软件实现。',),
        ('合法、可说明且有独立测试的匹配封装和认证实现。',))
    add('live_driver', '完整驱动及HA实物验收', 'software_support', 'software_required',
        '本工作台生成不可执行候选策略，尚未生成联网驱动，也不解锁原有HA门槛。',
        ('等待匹配且经过验证的完整驱动；随后仍由业主现场授权和验收单灯、面板反馈、掉线不可用与重连新读回。',),
        ('可信驱动、真实单灯接入及实物验收；通过前不扩展其它设备。',))
    return tasks


def render_task_text(record, task_id):
    task = next((row for row in record['tasks'] if row['id'] == task_id), None)
    if task is None:
        raise ValueError('未知会话工作台任务')
    lines = [task['title'] + '：' + STATUS_LABELS.get(task['status'], task['status']), '原因：' + task['why']]
    if task_id == 'source_quality':
        lines.append('当前原件限制：')
        lines.extend('• ' + value for value in record['quality_limitations'])
        if not record['quality_limitations']:
            lines.append('未发现当前工具可识别的质量限制；仍不证明充分性。')
    elif task_id == 'normal_start':
        lines.extend('原件限制：' + value for value in record['quality_limitations'])
        for check in record['session_rule']['checks']:
            lines.append('连接{}：{}；顺序匹配帧{}；失败或无权限帧{}。'.format(
                check['connection_id'], STATUS_LABELS[check['status']], check['matched_frame_indices'], check['failure_frame_indices']))
            lines.extend('  限制：' + value for value in check['reasons'])
        lines.append('完整时间线（按捕获时间与流内偏移，非帧号顺序）：')
        for connection in record['connections']:
            lines.append('连接{}：客户端SYN{}，主机SYN/ACK{}。'.format(connection['id'],
                '可见' if connection['syn_visible'] else '未见', '可见' if connection['syn_ack_visible'] else '未见'))
            lines.extend('  帧{} · {} · {}'.format(row['frame_index'],
                'App→主机' if row['direction'] == 'to_host' else '主机→App', row['label'])
                for row in connection['session_timeline'])
    elif task_id == 'auth_fields':
        lines.append('字段形状（无字段值）：')
        for row in record['authentication']['observations']:
            lines.append('连接{} · 帧{}：{}'.format(row['connection_id'], row['frame_index'],
                '；'.join('字段{} 长度{}字节'.format(f['id'], f['length']) for f in row['fields']) or '未见字段'))
        lines.append('跨连接比较（只在内存比较）：')
        for row in record['authentication']['comparisons']:
            relation = {'same': '所见值相同，不能据此复用', 'different': '所见值不同，算法未知',
                        'not_comparable': '连接内有多个不同值，不作常量比较'}[row['relation']]
            lines.append('字段{} · {}帧{} 与 {}帧{}：{}。'.format(row['field_id'], row['first_connection'],
                row['first_frame_indices'], row['second_connection'], row['second_frame_indices'], relation))
        for row in record['authentication']['encryption_observations']:
            lines.append('连接{} · 帧{}：字段160枚举{}；{}。'.format(row['connection_id'], row['frame_index'],
                '未知' if row['observed_enum'] is None else row['observed_enum'],
                '非零加密分支未实现，不解密' if row['status'] == 'nonzero_encryption_branch_unsupported'
                else '不能证明全程无需加密'))
    elif task_id == 'serial_policy':
        for rule in record['serial_rules']:
            lines.append('{}：{}；训练预测{}条，留出预测{}条，支持{}条，冲突{}条，证据不足{}项。'.format(
                rule['title'], STATUS_LABELS[rule['status']], len(rule['training']['predictions']),
                len(rule['holdout']['predictions']), len(rule['supports']), len(rule['conflicts']), len(rule['insufficient'])))
            lines.append('预测详情：')
            for row in rule['predictions'][:24]:
                lines.append('  {} · 帧{}：根据此前{}帧{}，预测序号{}，实见{}，{}。'.format(
                    '第一轮' if row['round'] == 'primary' else '留出轮', row['frame_index'],
                    '反方向请求' if 'request_frame_index' in row else '可见请求',
                    row.get('request_frame_index', row.get('previous_frame_index')), row['expected_serial'],
                    row['observed_serial'], '一致' if row['matches'] else '冲突'))
            if len(rule['predictions']) > 24:
                lines.append('界面仅显示前24条；完整条目保存在本机会话适配.json。')
            lines.extend('不足：' + row['reason'] for row in rule['insufficient'][:24])
    elif task_id == 'fresh_reopen':
        for row in record['reopen_checks']:
            lines.append('{}：{}。'.format('第一轮' if row['round'] == 'primary' else '留出轮', STATUS_LABELS[row['status']]))
            for candidate in row['candidates']:
                lines.append('  新连接{}：请求帧{}的值48，主机状态帧{}的上下文04，候选状态{}。'.format(
                    candidate['connection_id'], candidate['frame_index'], candidate['response_frame_index'],
                    '开' if candidate['candidate_state'] == 'on' else '关'))
            lines.extend('  限制：' + value for value in row['reasons'])
    lines.extend(['操作重点：'] + ['• ' + s for s in task['instructions']])
    lines.extend(['期待证据：'] + ['• ' + s for s in task['expected_evidence']])
    lines.append('此页不会启动补采、不上传、不发包、不生成驱动或解除HA门槛。')
    text = '\n'.join(lines) + '\n'
    return text if len(text) <= 100000 else text[:100000] + '\n〔界面截断，请在本机JSON查看完整白名单证据〕\n'


def render_text(record):
    lines = ['MC7021 本机会话策略工作台', SCOPE,
        '来源：' + ('合成演练' if record['simulation'] else '真实采样声明，身份和实物观察未认证'),
        '完整候选标识：' + (record['selected_identifier'] or '尚未选定'),
        '结论：资料充分性尚未证明；联网驱动未生成；HA未就绪；发送字节数0。',
        '连接{}个；会话时序：{}。'.format(len(record['connections']), STATUS_LABELS[record['session_rule']['status']])]
    for rule in record['serial_rules']:
        lines.append('{}：{}；训练{}条、留出{}条、支持{}条、冲突{}条。'.format(rule['title'],
            STATUS_LABELS[rule['status']], len(rule['training']['predictions']), len(rule['holdout']['predictions']),
            len(rule['supports']), len(rule['conflicts'])))
    lines.append('认证字段{}项；跨连接比较{}项；只含编号、长度和同异关系，认证需求与实现仍未知。'.format(
        len(record['authentication']['observations']), len(record['authentication']['comparisons'])))
    lines.append('查询候选{}项；新连接重进回读候选通过{} / {}项；因果与物理反馈均未验证。'.format(
        len(record['query_checks']), sum(r['status'] == 'candidate_supported' for r in record['reopen_checks']), len(record['reopen_checks'])))
    if record['quality_limitations']:
        lines.append('原件质量与解析限制（先处理下列具体原因，不把坏采样误判为算法未知）：')
        lines.extend('• ' + value for value in record['quality_limitations'])
    for task in record['tasks']:
        lines.extend(['', task['title'] + '：' + STATUS_LABELS.get(task['status'], task['status']), task['why']])
        lines.extend('操作：' + value for value in task['instructions'])
    return '\n'.join(lines) + '\n'


def create_workbench(session_directory, data_root, selected_identifier='', comparison_directory=None):
    root = baseline._safe_path(data_root)
    if not root.is_dir():
        raise ValueError('请先选择已存在的本机数据目录')
    primary = gaps._read_source(session_directory, root)
    identifier, selection_mode = recipe._select(primary, selected_identifier)
    candidates = sorted({field['value_hex'] for frame in primary['report']['frames']
        for field in frame['parsed_frame']['fields'] if field['id'] == 4 and field['length'] == 8})
    if len(candidates) > 1024:
        raise ValueError('完整标识候选超过1024个有界上限；未自动选取或截断设备列表')
    holdout = None
    if comparison_directory is not None:
        holdout = gaps._read_source(comparison_directory, root)
        if primary['binding']['traffic.pcap']['sha256'] == holdout['binding']['traffic.pcap']['sha256']:
            raise ValueError('第二轮PCAP与第一轮相同；复制或改元数据不能作为独立留出')
        if primary['metadata']['target_ip'] != holdout['metadata']['target_ip']:
            raise ValueError('第二轮主机不同；不能合并不同主机或住宅证据')
        if primary['metadata']['simulation'] is not holdout['metadata']['simulation']:
            raise ValueError('不能混合真实与合成来源进行会话留出验证')
        if identifier is None:
            raise ValueError('先核对第一轮完整标识，不能从第二轮拼目标')
        recipe._select(holdout, identifier)
    first_connections = _connections(primary, 'primary')
    second_connections = _connections(holdout, 'holdout') if holdout else []
    connections = first_connections + second_connections
    first_summary = _source_summary(primary, first_connections)
    second_summary = _source_summary(holdout, second_connections) if holdout else None
    training, testing = _serial_partitions(connections, holdout is not None)
    rules = [_serial_rule('app_global_increment_mod65536', 'App全局可见请求序号+1并回绕候选', training, testing, 'increment'),
             _serial_rule('constant_request_serial', '请求序号恒定候选', training, testing, 'constant'),
             _serial_rule('response_echo', '唯一反方向请求的响应回显候选', training, testing, 'echo')]
    counter_candidates = [r for r in rules[:2] if r['status'] == 'candidate_supported']
    if len(counter_candidates) > 1:
        for rule in counter_candidates:
            rule['status'] = 'ambiguous'
            rule['insufficient'].append(dict(reason='多种请求序号模型均获支持，尚不能区分'))
    session = _session_rule(connections)
    auth = _authentication(connections)
    reopen = _reopen_checks(primary, first_connections, identifier)
    if holdout:
        reopen.extend(_reopen_checks(holdout, second_connections, identifier))
    queries = _queries(connections, identifier)
    quality_findings = []
    def limit(reason, category):
        quality_findings.append(dict(reason=reason, category=category))
    for name, summary in [('primary', first_summary)] + ([('holdout', second_summary)] if second_summary else []):
        label = '第一轮' if name == 'primary' else '留出轮'
        if summary['capture_status'] != 'completed':
            limit(label + '：采样未正常完成', 'recapture')
        if summary['dropped_by_kernel'] != 0:
            limit(label + '：内核丢包未知或非零', 'recapture')
        if summary['sampling_transport_issue_count']:
            limit(label + '：存在传输重组、截断或边界限制', 'recapture')
        if summary['initial_boundary_unknown_count']:
            limit(label + '：未捕获SYN，初始连接边界未知；正常启动补一轮后仍缺时转策略支持',
                'recapture' if holdout is None else 'software_support')
        if summary['opaque_flow_ids']:
            limit(label + '：存在未解析加密或不透明流', 'software_support')
    if any(row['status'] == 'nonzero_encryption_branch_unsupported' for row in auth['encryption_observations']):
        limit('观察到主机非零加密选择枚举；当前不解密或验证相应分支', 'software_support')
    quality_limits = [row['reason'] for row in quality_findings]
    if quality_limits:
        for rule in rules:
            rule['insufficient'].extend(dict(reason=text) for text in quality_limits)
            if rule['status'] in ('candidate_supported', 'ambiguous'):
                rule['status'] = 'insufficient'
        if session['status'] == 'candidate_supported':
            session['status'] = 'insufficient'
        for row in reopen:
            row['reasons'].extend(quality_limits)
            if row['status'] == 'candidate_supported':
                row['status'] = 'insufficient'
    tasks = _tasks(session, rules, auth, reopen, first_summary, second_summary, quality_findings)
    strategy = dict(artifact='non_executable_session_candidate_strategy', executable=False,
        scope='offline_transcript_comparison_only', selected_identifier=identifier,
        session_order_candidate=[dict(protocol_type=p[0], link_code=p[1], direction=d) for p, d in
            (((1, 1), 'to_host'), ((1, 3), 'from_host'), ((2, 4), 'to_host'), ((2, 6), 'from_host'))],
        authentication_payload=None, authentication_algorithm='unknown', authentication_required=None,
        initial_serial=None, initial_serial_policy='unknown',
        serial_rule_candidates=[dict(id=r['id'], status=r['status']) for r in rules],
        query_request=dict(protocol_number=1, protocol_type=3, link_code=7, tlv15='48'),
        details_response=dict(protocol_number=1, protocol_type=3, link_code=8, tlv15='04'),
        reconnect_policy='new_connection_new_query_independent_state_required_unverified',
        can_generate_live_driver=False, can_start_live_ha=False)
    record = dict(schema_version=VERSION, artifact='private_mc7021_session_workbench',
        workbench_id=uuid.uuid4().hex, created_at=datetime.now(timezone.utc).isoformat(), scope=SCOPE,
        simulation=primary['metadata']['simulation'], target_ip=primary['metadata']['target_ip'],
        target_context=primary['target_context'], selected_identifier=identifier, selection_mode=selection_mode,
        candidate_identifiers=candidates, candidate_identifiers_truncated=False,
        session_path=primary['paths']['session_dir'], source_paths=primary['paths'], source_bindings=primary['binding'],
        primary=first_summary, holdout=second_summary, independent_second_round=holdout is not None,
        connections=[_connection_summary(c) for c in connections], session_rule=session,
        authentication=auth, serial_rules=rules, query_checks=queries, reopen_checks=reopen,
        quality_limitations=quality_limits, quality_findings=quality_findings,
        candidate_strategy=strategy, tasks=tasks, machine_sufficiency='not_proven',
        online_ready=False, driver_generated=False, can_generate_live_driver=False, can_start_live_ha=False,
        physical_feedback_verified=False, executable_code=False, bytes_sent=0, upload_performed=False,
        network_access_performed=False, credential_values_copied=False, credential_value_hashes_copied=False,
        raw_pcap_copied=False, causal_pairing_verified=False)
    recipe._verify_unchanged(primary, root)
    if holdout:
        recipe._verify_unchanged(holdout, root)
    parent = baseline._safe_path(root / 'private_session_workbenches')
    for source in (primary, holdout):
        if source:
            for relative in source['paths'].values():
                original = root / relative
                if parent == original or original in parent.parents:
                    raise ValueError('工作台输出不能覆盖或位于原件目录内')
    raw = json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    if len(raw.encode('utf-8')) > MAX_ARTIFACT_BYTES:
        raise ValueError('会话候选结果超过16MiB有界上限；未保存候选策略')
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    destination = parent / ('session_' + record['workbench_id'])
    destination.mkdir(mode=0o700)
    path = destination / '会话适配.json'
    recipe._write_private(path, raw)
    recipe._write_private(destination / '会话适配说明.txt', render_text(record))
    return path, record


def create_demo(data_root):
    """Two synthetic transcripts with explicit new connections and wraparound.

    Endpoints are documentation addresses. These bytes never leave the machine
    and do not supply an executable authentication or driver template.
    """
    root = baseline._safe_path(data_root)
    if not root.is_dir():
        raise ValueError('请先选择已存在的本机数据目录')
    directories = []
    for round_number in range(2):
        directory = demo.create_demo_sample(root / 'demo_runs')
        metadata = json.loads((directory / 'session.json').read_text(encoding='utf-8'))
        metadata['script_version'] = VERSION + '-session-synthetic'
        metadata['target_context'] = dict(label='合成测试灯', room='合成演示房间', kind='ordinary_switch_light',
            collection_id='f' * 32)
        rows = [json.loads(line) for line in (directory / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
        base = analysis.timestamp(rows[0]['timestamp']) - 10
        packets, sequences = [], {demo.PHONE: 1000 + round_number * 30000, demo.HOST: 8000 + round_number * 30000}
        serial = (65532 + round_number * 10) % 65536
        def send(offset, src, payload=b'', flags=24):
            packet = demo.network_packet(src, demo.HOST if src == demo.PHONE else demo.PHONE, payload, sequences[src], flags)
            packets.append((base + offset, packet))
            sequences[src] += len(payload) + bool(flags & 2) + bool(flags & 1)
        def request(offset, kind, link, fields, response_kind=None, response_link=None, response_fields=()):
            nonlocal serial
            current = serial
            serial = (serial + 1) % 65536
            send(offset, demo.PHONE, codec.build_frame(1, kind, link, current, fields))
            if response_kind is not None:
                send(offset + .2, demo.HOST, codec.build_frame(1, response_kind, response_link, current, response_fields))
        def connect(offset):
            send(offset, demo.PHONE, flags=2)
            send(offset + .01, demo.HOST, flags=18)
            request(offset + .05, 1, 1, [], 1, 3)
            request(offset + .5, 2, 4, [(93, b'SYNTHETIC_ONLY_NOT_A_CREDENTIAL_' + bytes([round_number]))], 2, 6)
        def state(on, detail=False):
            return ([(15, b'\x04')] if detail else [(27, b'\x03')]) + [(4, demo.DEVICE), (11, bytes([int(on)]))]
        connect(0)
        request(11.3, 3, 7, [(15, b'\x48'), (4, demo.DEVICE)], 3, 8, state(False, True))
        for index, on in enumerate((True, False, True, False)):
            start = 40 + index * 30
            request(start + 1.1, 4, 9, [(16, b'\x01'), (4, demo.DEVICE), (9, b'light-on' if on else b'light-off')], 4, 11)
            send(start + 2.3, demo.HOST, codec.build_frame(1, 5, 12, 50 + index, state(on)))
        send(162.3, demo.HOST, codec.build_frame(1, 5, 12, 54, state(True)))
        send(192.3, demo.HOST, codec.build_frame(1, 5, 12, 55, state(False)))
        send(222, demo.PHONE, flags=17)
        send(222.1, demo.HOST, flags=17)
        sequences = {demo.PHONE: 20000 + round_number * 30000, demo.HOST: 40000 + round_number * 30000}
        connect(281.05)
        request(282.3, 3, 7, [(15, b'\x48'), (4, demo.DEVICE)], 3, 8, state(True, True))
        raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
        for when, packet in sorted(packets):
            seconds = int(when)
            raw.extend(struct.pack('<IIII', seconds, int(round((when - seconds) * 1000000)), len(packet), len(packet)))
            raw.extend(packet)
        metadata['pcap'] = dict(file='traffic.pcap', size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        metadata['capture_stop']['stats']['captured'] = len(packets)
        (directory / 'traffic.pcap').write_bytes(raw)
        (directory / 'session.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
        (directory / 'traffic.pcap').chmod(0o600)
        (directory / 'session.json').chmod(0o600)
        directories.append(directory)
    return tuple(directories)
