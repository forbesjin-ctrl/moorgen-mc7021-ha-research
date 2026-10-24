"""Bounded local single-light adaptation evidence, without transport or drivers.

Reparse the exact bytes whose SHA256 is recorded.  The existing report must bind
those originals, but its frames, conclusions and proposed commands are never
trusted as wire evidence.  All generated artifacts are private local evidence;
no capture, socket, upload, driver import or replay exists here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import uuid

try:
    from . import analyze_capture as analysis
    from . import baseline_review as baseline
    from . import offline_shcp as codec
    from . import pcap_reader
except ImportError:
    import analyze_capture as analysis
    import baseline_review as baseline
    import offline_shcp as codec
    import pcap_reader

VERSION = '0.1.0'
MAX_REPORT = 16 * 1024 * 1024
SOURCE_LIMITS = dict(analysis.INPUT_LIMITS, **{'report.json': MAX_REPORT})
EXPECTED_COMMAND_STEPS = {'App开1', 'App关1', 'App开2', 'App关2'}
AUTH_FIELD_IDS = frozenset((93, 160))
SESSION_PROTOCOL_PAIRS = frozenset(((2, 4), (2, 5), (2, 6), (2, 19), (1, 1), (1, 3)))


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('不接受重复JSON键：' + key)
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('不接受非有限JSON值')))
    except RecursionError as error:
        raise ValueError('JSON嵌套超过解析上限') from error
    if not isinstance(value, dict):
        raise ValueError('JSON须为对象')
    return value


def _digest(raw):
    return dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _snapshot(session_directory, report_directory):
    session, report_dir = map(baseline._safe_path, (session_directory, report_directory))
    if not session.is_dir() or not report_dir.is_dir():
        raise ValueError('采样和报告目录须已存在')
    paths = {name: report_dir / name if name == 'report.json' else session / name
             for name in SOURCE_LIMITS}
    raw = {name: baseline._read_file(path, SOURCE_LIMITS[name]) for name, path in paths.items()}
    bindings = {name: _digest(value) for name, value in raw.items()}
    metadata, old_report = _json(raw['session.json']), _json(raw['report.json'])
    source = old_report.get('source')
    target = metadata.get('target_ip')
    if not isinstance(target, str) or '%' in target:
        raise ValueError('采样主机须为已知IP字面值')
    ipaddress.ip_address(target)
    if type(metadata.get('simulation')) is not bool:
        raise ValueError('采样须明确声明真实或合成来源')
    if not isinstance(source, dict) or source.get('folder') != session.name:
        raise ValueError('报告与采样文件夹不对应')
    if source.get('target_ip') != target or old_report.get('simulation') is not metadata['simulation']:
        raise ValueError('报告与采样主机或来源不对应')
    if source.get('capture_status') != metadata.get('status'):
        raise ValueError('报告与采样完成状态不对应')
    if old_report.get('target_context') != metadata.get('target_context'):
        raise ValueError('报告与采样灯路声明不对应')
    original_bindings = {name: bindings[name] for name in analysis.INPUT_LIMITS}
    if source.get('input_files') != original_bindings:
        raise ValueError('原件与分析时三文件哈希不同或缺少绑定；请重新分析原件')
    if source.get('input_integrity') != bindings['traffic.pcap']:
        raise ValueError('报告PCAP绑定与原件不一致')
    if not isinstance(metadata.get('pcap'), dict) or any(
            metadata['pcap'].get(key) != value for key, value in bindings['traffic.pcap'].items()):
        raise ValueError('原始PCAP与采样时哈希或大小不一致')
    rows = [_json(line.encode('utf-8')) for line in raw['events.jsonl'].decode('utf-8').splitlines() if line.strip()]
    if len(rows) > analysis.MAX_EVENTS:
        raise ValueError('事件数超过离线分析上限')
    for row in rows:
        if row.get('simulation') is not metadata['simulation']:
            raise ValueError('事件与会话来源声明不一致')
        row['_time'] = analysis.timestamp(row.get('timestamp'))
    if any(a['_time'] > b['_time'] for a, b in zip(rows, rows[1:])):
        raise ValueError('事件时间倒退，不能可靠关联')
    return session, report_dir, metadata, rows, raw, bindings


def _request_type(packet):
    if (packet['protocol_number'], packet['protocol_type'], packet['link_code']) != (1, 3, 7):
        return None
    try:
        field = codec.unique_field(packet['fields'], 15)
        return field['value_hex'] if field else None
    except codec.ParseError:
        return None


def _request_identifier(packet):
    if (packet['protocol_number'], packet['protocol_type'], packet['link_code']) != (1, 3, 7):
        return None
    try:
        field = codec.unique_field(packet['fields'], 4)
        return field['value_hex'] if field and field['length'] == 8 else None
    except codec.ParseError:
        return None


def _frame_observation(frame):
    packet = frame['parsed_frame']
    # Do not copy arbitrary TLV payloads (including auth tokens or names) into
    # this additional artifact. Known command/state values are explicit below.
    states = []
    for state in frame['states']:
        states.append(dict(identifier_hex=state['device_identifier_hex'],
            raw_state=state['raw_state'], state_present=state['state_present'],
            status_context=dict(state['status_context']), candidate_is_on=None,
            ordinary_light_type_verified=False, physical_feedback_verified=False,
            independent_state_candidate=bool(frame['direction'] == 'from_host'
                and state['state_present'] and state['status_context']['device_status_context_confirmed'])))
    return dict(frame_index=frame['index'], flow_id=frame['flow_id'], direction=frame['direction'],
        packet_indices=frame['packet_indices'], stream_offset=frame['stream_offset'],
        timestamp_start=frame['timestamp_start'], timestamp_end=frame['timestamp_end'],
        protocol_number=packet['protocol_number'], protocol_type=packet['protocol_type'],
        link_code=packet['link_code'], serial_number=packet['serial_number'],
        field_shapes=[dict(id=item['id'], length=item['length']) for item in packet['fields']],
        kind=frame['kind'], command=frame['command'], identifiers=frame['device_identifiers'],
        request_type_hex=_request_type(packet), request_identifier_hex=_request_identifier(packet), states=states,
        nearby_steps=frame.get('nearby_steps', []),
        event_association_ambiguous=frame.get('event_association_ambiguous', True),
        notes=frame['notes'], acknowledgement_is_state=False,
        physical_feedback_verified=False)


def _serial_observations(frames):
    by_flow = {}
    for frame in frames:
        by_flow.setdefault(frame['flow_id'], []).append(frame)
    result = []
    for flow_id, items in by_flow.items():
        items.sort(key=lambda frame: frame['stream_offset'])
        observations = []
        previous = None
        for frame in items:
            serial = frame['parsed_frame']['serial_number']
            observations.append(dict(frame_index=frame['index'], serial_number=serial,
                delta_modulo_65536=None if previous is None else (serial - previous) % 65536))
            previous = serial
        result.append(dict(flow_id=flow_id, observations=observations,
            rule_verified=False, note='仅按同一方向重组流偏移列出序号变化；不推断跨方向响应匹配、初始值或重连规则。'))
    return result


def build_evidence(metadata, capture, windows, flows, frames, bindings):
    """Pure derived evidence for UI/tests; callers must separately bind sources."""
    observations = [_frame_observation(frame) for frame in frames]
    candidates = analysis.device_candidates(frames, windows, ())
    for candidate in candidates:
        identifier = candidate['identifier_hex']
        candidate['command_evidence'] = [row for row in observations if row['direction'] == 'to_host'
            and row['kind'] == 'light_command_candidate' and identifier in row['identifiers']]
        candidate['state_evidence'] = [dict(frame_index=row['frame_index'], flow_id=row['flow_id'],
            direction=row['direction'], nearby_steps=row['nearby_steps'],
            event_association_ambiguous=row['event_association_ambiguous'], **state)
            for row in observations for state in row['states'] if state['identifier_hex'] == identifier]
        candidate['on_off_semantics_verified'] = False
    auth_observations = [dict(frame_index=row['frame_index'], flow_id=row['flow_id'],
        direction=row['direction'], field_id=field['id'], length=field['length'])
        for row in observations for field in row['field_shapes'] if field['id'] in AUTH_FIELD_IDS]
    session_timeline = [dict(frame_index=row['frame_index'], flow_id=row['flow_id'],
        direction=row['direction'], protocol_number=row['protocol_number'],
        protocol_type=row['protocol_type'], link_code=row['link_code'])
        for row in observations if row['protocol_number'] == 1
        and (row['protocol_type'], row['link_code']) in SESSION_PROTOCOL_PAIRS]
    request_observations = [dict(frame_index=row['frame_index'], flow_id=row['flow_id'],
        direction=row['direction'], request_type_hex=row['request_type_hex'],
        identifier_hex=row['request_identifier_hex'],
        classification='single_device_details_request_candidate_static_unverified'
            if row['request_type_hex'] == '48' and row['request_identifier_hex'] is not None
            else 'observed_request_value_unverified',
        note='仅报告所见请求值；响应中TLV15=04不用于推断请求常量，本户查询及响应配对仍需验证。')
        for row in observations if row['direction'] == 'to_host'
        and (row['protocol_number'], row['protocol_type'], row['link_code']) == (1, 3, 7)]
    opaque_flows = [flow['id'] for flow in flows if 'tls_like' in flow['payload_classification']
                    or 'opaque' in flow['payload_classification']]
    repeated = [item for item in candidates if item['repeated_command_candidate']]
    confirmed = ['已从本机原件重新重组和严格解析，原报告中的帧内容不作为协议事实。',
        '四文件内容绑定已记录SHA256及大小；这不认证样本作者、住宅身份或人工观察。',
        '观察到目标主机相关{}包、{}个方向流、{}个完整受支持明文帧。'.format(
            capture['target_packet_count'], len(flows), len(frames))]
    pending = ['完整8字节对象标识是否对应同一实际普通灯路，以及原始状态位与实物亮灭的对应关系。',
        '面板和重进App窗口的主机状态候选是否独立于控制ACK、缓存及周期轮询。',
        '认证、会话建立/过期、加密分支、序号生成及异常断线后的规则；没有认证字段也不证明免认证。']
    resample = []
    if metadata.get('status') != 'completed':
        resample.append('采样未标记正常完成：先核对采样停止和清理记录，再另存一次完整单灯采样。')
    stop = metadata.get('capture_stop')
    stats = stop.get('stats') if isinstance(stop, dict) else None
    dropped = stats.get('dropped_by_kernel') if isinstance(stats, dict) else None
    if type(dropped) is not int or dropped != 0:
        resample.append('内核丢包为未知或非零；不能把缺少认证、响应或状态报文解释为协议不需要这些步骤。')
    if metadata['simulation']:
        resample.append('当前为合成演练；需在本户原App和面板正常时重新采真实首组，不能据此完成实机适配。')
    if not capture['target_packet_count']:
        resample.append('未见已知目标IP相关通信：核对原件、已记录IP和原App本地控制状态，不扫描地址。')
    if not frames:
        resample.append('没有完整受支持明文帧：先保留原件核对封装和采样起止，不能扫描偏移、猜解密或重放。')
    if len(repeated) != 1:
        resample.append('没有唯一完整标识覆盖App开1/关1/开2/关2：只对同一组灯重采四步并逐项记实物。')
    if len(repeated) == 1:
        item = repeated[0]
        if set(item['panel_state_windows']) != {'面板开', '面板关'}:
            resample.append('首组候选缺少面板开和关的独立主机状态候选：保持App可观察，面板逐步操作并等待记录。')
        if not item['reopen_state_windows']:
            resample.append('首组候选缺少重进App回读：关闭App后面板改变同一灯，再进入设备页并记录当前实物状态。')
    if not request_observations:
        resample.append('未见主机方向的数据请求帧(1/3/7)：补采正常进入设备列表/该灯页面的过程，不限定请求值、不手工发查询。')
    if len({(flow['src'], flow['sport'], flow['dst'], flow['dport'], flow['generation'])
            for flow in flows if flow['transport'] == 'tcp' and flow['direction'] == 'to_host'}) < 2:
        resample.append('当前不足两个可区分TCP连接：另存一轮正常退出/重进App和初始同步样本，比较会话与序号；不修改网络。')
    if opaque_flows:
        resample.append('存在不透明或类似TLS载荷：保持加密/认证未知；本工具不装证书、不解密、不绕过。')
    incomplete = sorted(analysis.REQUIRED_STEPS - {row['step'] for row in windows if row['status'] == 'recorded'})
    if incomplete:
        resample.append('事件记录未完整覆盖：' + '、'.join(incomplete))
    if capture['issues'] or any(flow['issues'] for flow in flows):
        resample.append('存在采样或TCP重组限制，先查看transport.issues；缺失字节之后不恢复猜测帧。')
    missing = [dict(id='physical_mapping', title='实物及对象映射', status='manual_required',
        detail='人工逐项核对同一组灯和原始状态；机器解析不能完成实物验收。'),
        dict(id='session_authentication', title='会话与认证实现', status='unsupported',
        detail='本机样本只能形成线索；没有实现且验证会话/认证策略，不能生成可用在线驱动。'),
        dict(id='sequence_reconnect', title='序号与重连规则', status='unverified',
        detail='需跨正常连接/多轮样本复核；同一方向序号列表不是通用递增规则。'),
        dict(id='independent_state', title='独立状态及不可用处理', status='unverified',
        detail='详情/推送是候选；需排除ACK与缓存，再验证掉线不可用和重连新回读。'),
        dict(id='live_acceptance', title='HA单灯实机验收', status='blocked',
        detail='需匹配并经过验证的完整驱动、明确在线授权和现场逐项验收；本分析不连接设备。')]
    endpoint_rows = [dict(flow_id=flow['id'], transport=flow['transport'],
        direction=flow['direction'], src=flow['src'], source_port=flow['sport'],
        dst=flow['dst'], destination_port=flow['dport'], generation=flow['generation'],
        packet_count=flow['packet_count'], frame_count=flow['frame_count'],
        payload_classification=flow['payload_classification'], issues=flow['issues']) for flow in flows]
    return dict(schema_version=VERSION, artifact='private_mc7021_local_adaptation_evidence',
        simulation=metadata['simulation'], target_ip=metadata['target_ip'], source_bindings=bindings,
        transport=dict(flows=endpoint_rows, observed_host_ports=sorted({
            flow['sport'] if flow['direction'] == 'from_host' else flow['dport'] for flow in flows}),
            issues=capture['issues'], note='端点和端口只表示样本中观察到的通信，不是控制地址、Modbus地址或扫描结果。'),
        frame_observations=observations, device_candidates=candidates, request_observations=request_observations,
        serial_observations=_serial_observations(frames),
        session_authentication=dict(status='unknown', authentication_required=None,
            observations=auth_observations, session_protocol_timeline=session_timeline, opaque_flow_ids=opaque_flows,
            credential_values_copied=False, verified=False,
            note='只记录所见会话字段ID及长度；出现字段不证明认证成功，未出现也不证明免认证。'),
        summary=dict(packet_count=capture['packet_count'], target_packet_count=capture['target_packet_count'],
            frame_count=len(frames), candidate_count=len(candidates),
            repeated_candidate_count=len(repeated),
            acknowledgement_count=sum(row['kind'] in ('ack_not_state', 'execution_response_not_state') for row in observations),
            independent_state_candidate_count=sum(state['independent_state_candidate']
                for row in observations for state in row['states'])),
        confirmed=confirmed, pending=pending, resample=resample, missing_capabilities=missing,
        next_steps=['在本机保留本报告和四原件；先按需补采清单采同一组灯，另存新一轮，不覆盖旧原件。',
            '具备能力的业主在本机核对帧号、完整标识、操作窗口和实物记录；不需要写Python，不能把候选确认当成完整驱动。',
            '只有匹配的编解码、会话/认证、独立状态和断线重连全部有实现及证据，才进入现有可信驱动导入及HA现场验收。'],
        driver_generated=False, can_generate_live_driver=False, online_ready=False, can_start_live_ha=False,
        physical_feedback_verified=False, compatibility_verified=False,
        upload_performed=False, network_access_performed=False,
        note='这是本机离线适配证据与缺口报告，不是可加载驱动，也不会放宽首组核对或HA接入条件。')


def render_markdown(report):
    """Local readable report, escaping untrusted values without HTML rendering."""
    def text(value):
        return str(value).replace('`', "'").replace('\r', ' ').replace('\n', ' ')
    rows = ['# MC7021 本机适配分析', '',
        '来源：' + ('合成演练，不能用于实机适配。' if report['simulation'] else '真实采样声明，住宅和观察身份未经认证。'),
        '在线接入：未解锁；没有生成可用驱动。资料仅保存在本机。', '']
    for key, title in [('confirmed', '已确认的文件及解析事实'), ('pending', '需业主实物核对'),
                       ('resample', '需补采'), ('next_steps', '下一步')]:
        rows.extend(['## ' + title, ''])
        rows.extend('- ' + text(item) for item in report[key])
        if not report[key]:
            rows.append('- 未发现这一类缺口；这不表示协议或实机验收通过。')
        rows.append('')
    rows.extend(['## 候选对象与帧号', ''])
    for item in report['device_candidates']:
        rows.append('- 完整候选标识 `' + text(item['identifier_hex']) + '`：开/关请求候选 {}/{}，主机状态记录候选 {}；实际灯路和普通灯类型未自动确认。'.format(
            item['command_on_count'], item['command_off_count'], item['state_record_count']))
        rows.append('  请求帧：' + ', '.join(str(row['frame_index']) for row in item['command_evidence']) +
                    '；状态帧：' + ', '.join(str(row['frame_index']) for row in item['state_evidence']))
    if not report['device_candidates']:
        rows.append('- 没有完整候选对象。')
    rows.extend(['', '## 尚缺驱动能力', ''])
    rows.extend('- ' + text(item['title']) + '：' + text(item['detail']) for item in report['missing_capabilities'])
    rows.extend(['', '## 内容绑定', ''])
    rows.extend('- `' + name + '`：{} 字节，SHA256 `{}`'.format(value['size_bytes'], value['sha256'])
                for name, value in report['source_bindings'].items())
    rows.extend(['', '完整重组帧、方向、端点、序号和状态原始值见同目录“适配分析.json”。不复制认证字段值。', ''])
    return '\n'.join(rows)


render_text = render_markdown


def analyze_adaptation(session_directory, report_directory, data_root):
    """Return (private output directory, evidence); never authorize live access."""
    session, report_dir, metadata, rows, raw, bindings = _snapshot(session_directory, report_directory)
    root = baseline._safe_path(data_root)
    output = baseline._safe_path(root / 'private_local_adaptations')
    if any(output == source or source in output.parents for source in (session, report_dir)):
        raise ValueError('输出位置不能覆盖或位于原始采样/报告目录内')
    # Reuse the bounded stream reader on immutable source bytes. Reopening the
    # path would allow parsing different bytes than those recorded in bindings.
    capture = pcap_reader._read_stream(io.BytesIO(raw['traffic.pcap']), str(ipaddress.ip_address(metadata['target_ip'])))
    windows = analysis.event_windows(rows)
    flows = analysis.split_flows(capture['packets'], str(ipaddress.ip_address(metadata['target_ip'])))
    frames = analysis.decode_flows(flows, ())
    analysis.correlate(windows, capture['packets'], frames)
    report = build_evidence(metadata, capture, windows, flows, frames, bindings)
    _, _, _, _, _, final_bindings = _snapshot(session, report_dir)
    if final_bindings != bindings:
        raise ValueError('分析期间原件或报告发生变化；未保存适配报告')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    destination = output / ('adaptation_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    content = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    for name, value in [('适配分析.json', content), ('适配分析.md', render_markdown(report))]:
        descriptor = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(value)
    return destination, report
