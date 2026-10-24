"""Private, source-bound single-light evidence gaps. No transport or driver code.

Every plan is recomputed from the three capture originals. It is an explanation
and normal-App sampling preparation, never permission for a socket or HA write.
Missing protocol implementations are kept separate from repeatable sample gaps.
"""
from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import os
import re
import uuid

try:
    from . import adapter_recipe as recipe
    from . import analyze_capture as analysis
    from . import baseline_review as baseline
    from . import local_adaptation as adaptation
    from . import pcap_reader
except ImportError:
    import adapter_recipe as recipe
    import analyze_capture as analysis
    import baseline_review as baseline
    import local_adaptation as adaptation
    import pcap_reader

VERSION = '0.8.0'
SCOPE = ('只检查本机不变原件与已支持明文的证据缺口；观察到字段不等于协议已验证，'
         '缺少字段不等于协议不需要。补采只使用原App和面板正常操作同一组普通灯。'
         '本计划不生成驱动、不联网、不上传，也不解除首组或HA实物验收门槛。')
NORMAL_CAPTURE = ('另存一轮完整单灯采样，不覆盖原件；只操作同一组普通开关灯。',
    '在新一轮按界面完成初始同步、App开关各两次、面板开关、关闭App期间面板改变状态、重进App回读。',
    '逐步记录灯实际亮灭和App显示；不扫描，不退出账号、改网络或厂家配置，不重放报文。')
STATUS_LABELS = {'needs_sample': '需补采', 'manual_required': '需人工核对',
    'software_required': '待软件支持', 'evidence_present_unverified': '已有线索，未验证'}


def _read_source(directory, root):
    """Recompute the existing analysis, then parse the exact bound bytes again."""
    source = recipe._read_source(directory, root)
    session = root / source['paths']['session_dir']
    report_dir = root / source['paths']['report_dir']
    _, _, metadata, rows, raw, bindings = adaptation._snapshot(session, report_dir)
    if bindings != source['binding']:
        raise ValueError('原件或报告读取期间变化；请重新分析不变原件')
    capture = pcap_reader._read_stream(io.BytesIO(raw['traffic.pcap']), metadata['target_ip'])
    windows = analysis.event_windows(rows)
    flows = analysis.split_flows(capture['packets'], metadata['target_ip'])
    frames = analysis.decode_flows(flows, ())
    analysis.correlate(windows, capture['packets'], frames)
    source['evidence'] = adaptation.build_evidence(metadata, capture, windows, flows, frames, bindings)
    source['windows'] = windows
    source['capture'] = capture
    source['metadata'] = metadata
    source['target_context'] = analysis.validate_target_context(metadata.get('target_context'))
    return source


def _source_summary(source, identifier):
    """Copy only necessary facts; never copy TLV payloads or arbitrary notes."""
    evidence = source['evidence']
    stop = source['metadata'].get('capture_stop')
    stats = stop.get('stats') if isinstance(stop, dict) else None
    dropped = stats.get('dropped_by_kernel') if isinstance(stats, dict) else None
    dropped = dropped if type(dropped) is int and dropped >= 0 else None
    evaluation = recipe._evaluate(source, identifier)
    candidate = next((item for item in evidence['device_candidates']
                      if item['identifier_hex'] == identifier), None)
    auth = evidence['session_authentication']
    return dict(source_paths=source['paths'], source_bindings=source['binding'],
        simulation=source['metadata']['simulation'], capture_status=source['metadata'].get('status'),
        target_ip=source['metadata']['target_ip'], summary=evidence['summary'], dropped_by_kernel=dropped,
        skipped_steps_declared=bool(source['metadata'].get('skipped_steps')),
        transport_issue_count=len(evidence['transport']['issues']) + sum(
            len(row['issues']) for row in evidence['transport']['flows']),
        tcp_connection_count=len({(row['src'], row['source_port'], row['dst'], row['destination_port'], row['generation'])
            for row in evidence['transport']['flows'] if row['transport'] == 'tcp' and row['direction'] == 'to_host'}),
        opaque_flow_ids=auth['opaque_flow_ids'], auth_field_shapes=auth['observations'],
        session_protocol_timeline=auth['session_protocol_timeline'], authentication_required=None,
        authentication_verified=False, credential_values_copied=False,
        request_frame_indices=[row['frame_index'] for row in evidence['request_observations']],
        repeated_switch_candidate=bool(candidate and candidate['repeated_command_candidate']),
        candidate_frame_indices=sorted({row['frame_index'] for key in ('command_evidence', 'state_evidence')
            for row in candidate[key]}) if candidate else [],
        event_steps=[dict(step=row['step'], status=row['status']) for row in source['windows']],
        case_checks=[dict(step=row['step'], status=row['status'],
            command_frame_indices=row['command_frame_indices'], state_frame_indices=row['state_frame_indices'])
            for row in evaluation['per_case_checks']],
        codec_consistency=evaluation['codec_consistency'], unsupported_frame_indices=evaluation['unsupported_frames'],
        physical_feedback_verified=False)


def _build_tasks(first, second, identifier, simulation, target_context):
    tasks = []
    all_sources = [('primary', first)] + ([('comparison', second)] if second else [])
    preparation_blockers = []
    if simulation:
        preparation_blockers.append('合成演练不能准备真实采样。')
    if baseline._identifier(identifier) is None:
        preparation_blockers.append('先在本机核对原件中真实出现的完整标识；不猜填标识以启用按钮。')
    if target_context is None:
        preparation_blockers.append('缺少有效普通灯标签；先人工确认同灯并整理本机原始采样声明，不改文件让结果通过。')

    def add(key, title, category, status, why, instructions, expected, refs=(), level='possible'):
        tasks.append(dict(id=key, title=title, category=category, status=status, why=why,
            evidence_level=level, evidence_refs=list(refs), instructions=list(instructions),
            expected_evidence=list(expected), capture_allowed=bool(category == 'recapture'
                and status == 'needs_sample' and not preparation_blockers),
            capture_preparation_blockers=list(preparation_blockers),
            preparation_only=True, bytes_sent=0))

    def sample_task(key, title, missing, why, focus, expected, refs=(), blocked_by_parser=False):
        if missing and blocked_by_parser:
            add(key, title, 'software_support', 'software_required',
                why + ' 当前封装或字段形状不受支持，不能把无法解析误判为只需重复采样。',
                ('先保留本机原件并等待匹配解析策略；不要无限重采、猜参数或修改字节让结果通过。',),
                expected, refs, 'unsupported')
            return
        add(key, title, 'recapture', 'needs_sample' if missing else 'evidence_present_unverified',
            why, NORMAL_CAPTURE + tuple(focus) if missing else ('已有相应解析线索；仍须人工核对，不能视作协议或实灯通过。',),
            expected, refs, 'possible' if missing else 'observed')

    def refs_for(field):
        return [dict(round=name, field=field) for name, _ in all_sources]

    sample_task('sample_origin', '真实本户样本声明', simulation,
        '合成演练不能用于适配本户。真实声明也不能认证住宅或观察身份。',
        ('只在本户原App和面板均正常时采集真实首组；演示计划只能查看，不能直接准备实采。',),
        ('各轮session与事件均明确声明真实来源。',), refs_for('simulation'))
    sample_task('capture_complete', '完整保存与清理', any(s['capture_status'] != 'completed' for _, s in all_sources),
        '未正常完成的采样可能缺结尾报文；不能把中止当作完成。',
        ('等待全部步骤、停止抓包与清理结束，再检查保存结果。',),
        ('新一轮completed原件和正常保存记录。',), refs_for('capture_status'))
    sample_task('target_traffic', '指定已知主机的有效通信', any(
        type(s['summary']['target_packet_count']) is not int or s['summary']['target_packet_count'] <= 0
        for _, s in all_sources),
        '零包、未知和解析失败不能解释为正常；只检查已经确认的主机IP。',
        ('从现有记录核对主机IP，确认手机处于日常控制Wi-Fi且原App能控制此灯；不猜地址、不扫描。',),
        ('指定主机方向的有效通信包及同轮事件。',), refs_for('summary.target_packet_count'))
    sample_task('capture_loss', '丢包统计', any(s['dropped_by_kernel'] != 0 for _, s in all_sources),
        '丢包未知或非零时，缺认证、查询或状态都不能解释为协议不需要。',
        ('保留失败原件，另采完整一轮并等待工具记录停止统计；不要手改统计值。',),
        ('明确的整数0内核丢包统计；它也不能证明所有网络数据均已捕获。',), refs_for('dropped_by_kernel'))
    sample_task('transport_integrity', 'TCP重组和截断限制', any(
        s['transport_issue_count'] for _, s in all_sources),
        '重组缺字节、冲突、截断或未知流首使后续帧证据不完整；工具不会越过缺口猜帧。',
        ('新采样开始后再正常打开App，完整等待初始同步；保持同一组灯逐步操作。',),
        ('没有已知重组限制的新一轮；仍不证明任意封装均受支持。',), refs_for('transport_issue_count'))
    incomplete = [(name, sorted(analysis.REQUIRED_STEPS - {
        row['step'] for row in s['event_steps'] if row['status'] == 'recorded'})) for name, s in all_sources]
    duplicate = any(len([row for row in s['event_steps'] if row['step'] == step]) != 1
        for _, s in all_sources for step in analysis.REQUIRED_STEPS)
    sample_task('event_coverage', '完整且唯一的操作窗口', duplicate or any(rows for _, rows in incomplete)
        or any(s['skipped_steps_declared'] for _, s in all_sources),
        '每步必须有唯一动作及现场观察记录；缺步骤、重复窗口和未知亮灭都不能用总包数补足。',
        ('不要跳步；每步按提示先准备、操作、确认，再观察并记录亮灭和App显示。',),
        ('十个必需步骤各有唯一完整窗口；动作区间与报文时间一致。',), refs_for('event_steps'))
    add('target_selection', '完整标识与实际灯路', 'manual_check', 'manual_required',
        '完整8字节标识必须与本户同一组实际普通灯对应；配置偏移、简称和自动唯一候选都不是实物认证。',
        ('核对重复开关帧、完整标识和实物；有多个候选时在本机明确选择，不选第一个碰运气。',),
        ('人工核对同一完整标识、同组普通灯及原始亮灭观察。',),
        [dict(round='primary', field='candidate_frame_indices')], 'observed' if identifier else 'possible')
    parser_missing = any(s['opaque_flow_ids'] or not s['summary']['frame_count']
        or s['unsupported_frame_indices'] for _, s in all_sources)
    command_bad = any(not s['repeated_switch_candidate'] or any(row['status'] != 'consistent'
        for row in s['case_checks'] if row['step'] in baseline.COMMAND_STEPS) for _, s in all_sources)
    sample_task('repeated_switches', '同一组灯的两轮App开关', command_bad,
        '需要同一完整标识在开1、关1、开2、关2各有匹配请求和独立状态；ACK不能代替状态。',
        ('只操作该灯；每次等实物和App稳定后再进入下一步，避免多次连点。',),
        ('四步请求、主机独立状态、实物及App显示记录一致的候选证据。',), refs_for('case_checks'), parser_missing)
    for task_id, title, steps, why, focus in (
        ('panel_feedback', '面板开关的独立状态候选', ('面板开', '面板关'),
         '面板窗口不能混入App执行请求；状态与操作时间邻近仍不是因果证明。',
         '保持App可观察，只按面板开、关同一组灯，等待后分别记录，不在App补点或刷新。'),
        ('reopen_readback', 'App关闭后的改变与重新回读', ('重进App读状态',),
         '重进App必须观察当前状态；缓存、ACK或上一次开关值不能当回读。',
         '按向导关闭App，在关闭期间用面板改变该灯，再正常打开同灯页面并记录当前实物和显示。')):
        missing = any(any(row['status'] != 'consistent' for row in s['case_checks'] if row['step'] in steps)
                      for _, s in all_sources)
        sample_task(task_id, title, missing, why, (focus,),
            ('同一完整标识的主机独立状态候选及对应现场观察。',), refs_for('case_checks'), parser_missing)
    sample_task('normal_queries', '正常页面查询线索', any(not s['request_frame_indices'] for _, s in all_sources),
        '没有观察到数据请求不证明无需查询；观察到请求值也不证明请求与状态已正确配对。',
        ('从正常打开App、初始同步到进入该灯页面都保留在采样中；不手工构造查询。',),
        ('正常进入页面产生的请求及主机应答候选，后续仍需验证配对和含义。',), refs_for('request_frame_indices'), parser_missing)
    connections = sum(s['tcp_connection_count'] for _, s in all_sources)
    sample_task('connection_comparison', '正常连接与重进App的比较', connections < 2,
        '少于两个可区分连接不足以比较初始会话与序号；多连接也不证明序号或重连策略正确。',
        ('新一轮在开始采样后正常打开App并完成初始同步，按完整流程关闭和重进；不改网络、不退出账号。',),
        ('至少两个可区分连接的时间线；每个方向的序号只能作为观察值。',), refs_for('tcp_connection_count'))
    sample_task('independent_round', '独立新一轮留出样本', second is None,
        '改文件夹、元数据或复制同一PCAP不能当独立第二轮；同主机同标识的新一轮仅提供离线对照。',
        ('另存完整第二轮后选择“加入第二轮”；保留第一轮原件，仍只采同一已知主机与灯组。',),
        ('不同PCAP内容、同主机及相同完整标识的独立第二轮。',),
        [dict(round='primary', field='source_bindings.traffic.pcap.sha256')],)
    timeline = any(s['session_protocol_timeline'] for _, s in all_sources)
    if not timeline and second is None:
        sample_task('normal_session_start', '补一轮正常App启动线索', True,
            '当前没有受支持会话报文线索，可补一轮正常启动；没有字段不能判定免认证。',
            ('只补一轮正常启动和完整单灯流程；若仍无会话线索，转软件能力缺口，不反复无目的采样。',),
            ('正常启动及初始同步线索；认证是否需要和是否成功继续保持未知。',), refs_for('session_protocol_timeline'))
    else:
        add('normal_session_start', '正常App启动线索', 'manual_check' if timeline else 'software_support',
            'evidence_present_unverified' if timeline else 'software_required',
            '观察到会话类报文不证明认证成功；第二轮仍无可解线索时应研究解析能力，不能无限补采。',
            ('在本机对照启动时间线；等待工具支持相应封装与认证策略，不猜填凭证或会话常量。',),
            ('有实现和证据支持的会话状态机；当前尚未具备。',), refs_for('session_protocol_timeline'),
            'observed' if timeline else 'unsupported')
    add('physical_mapping', '实物状态与独立反馈核对', 'manual_check', 'manual_required',
        '机器看不到灯本体，不能排除缓存、轮询、其它操作或业主误记。',
        ('对照帧号、完整标识、面板窗口与现场记录；不确定就记待验证，保留冲突并补采。',),
        ('本机逐项人工核对声明；之后仍需HA现场验收。',), refs_for('case_checks'))
    add('authentication_strategy', '认证、会话及序号策略尚缺实现', 'software_support', 'software_required',
        '当前工具没有经过本户验证的认证、会话建立/过期、序号与重连策略。字段存在不证明成功，字段缺失不证明免认证。',
        ('原件只留本机；等待相应公开工具策略实现及验证，或由业主在自己的环境研究。',
         '不要复制认证字段、猜填令牌、重放旧连接或用重复补采替代策略实现。'),
        ('匹配本户且经过验证的会话、认证、序号和重连实现及独立读回证据。',),
        refs_for('auth_field_shapes'), 'unsupported')
    opaque = any(s['opaque_flow_ids'] for _, s in all_sources)
    add('opaque_transport', '加密或不透明封装支持', 'software_support',
        'software_required' if opaque or not first['summary']['frame_count'] else 'evidence_present_unverified',
        '看到TLS样式、不透明载荷或无明文帧时，补采不能自动解密；没有这类线索也不证明全程明文。',
        ('保留本机原件，等待合法且已验证的相应支持；不装证书、不绕过加密、不扫描载荷中的偏移。',),
        ('受支持的封装与会话分支，及跨独立样本验证。',), refs_for('opaque_flow_ids'),
        'unsupported' if opaque or not first['summary']['frame_count'] else 'observed')
    unsupported = any(s['unsupported_frame_indices'] for _, s in all_sources)
    add('codec_support', '已支持明文配方的适用范围', 'software_support',
        'software_required' if unsupported or not identifier else 'evidence_present_unverified',
        '窄配方拒绝未知、额外、重复或不同顺序字段；离线字节一致只证明当前配方与这些原件一致。',
        ('工具会本机重新核对；不把未知字段吸收成常量，不改文件让结果通过。',),
        ('有说明和测试的匹配编解码实现；跨轮一致也不会自动生成联网驱动。',), refs_for('unsupported_frame_indices'),
        'unsupported' if unsupported or not identifier else 'observed')
    add('driver_integration', '完整驱动适配与实现', 'software_support', 'software_required',
        '当前没有自动生成经过验证的联网驱动；采样线索齐全也不等于驱动就绪。',
        ('待工具内置匹配且经验证的策略，或在本机取得可信且匹配的完整驱动材料后，使用原有驱动导入流程。',),
        ('完整编解码、会话、独立状态、断线不可用及重连回读实现，并保持原有来源及版本核对。',),
        (), 'unsupported')
    add('ha_acceptance', 'HA单灯真实状态验收', 'manual_check', 'manual_required',
        '离线计划不能验证真实灯控，也不授权HA接入；需首组核对、匹配驱动及明确现场授权。',
        ('满足原有条件后，在HA逐步验收重复开关、面板反馈、断线不可用和重连新回读；任一冲突停止扩展。',),
        ('同组灯实物与HA真实状态验收；不从本计划自动设置通过。',), (), 'possible')
    return tasks


def _reference_value(source, field):
    """Project fixed summary fields only; never follow a caller supplied path."""
    if not isinstance(field, str):
        return '未支持的证据引用', '不显示未列入白名单的字段'
    def number(value):
        return value if type(value) is int and 0 <= value <= 2**64 - 1 else None

    def mapping(value):
        return value if isinstance(value, dict) else {}

    def rows(value):
        return value[:5000] if isinstance(value, list) else []

    def ids(value):
        return [item for item in rows(value) if type(item) is int and 0 < item <= 2**64 - 1]

    def flow(value):
        return value if isinstance(value, str) and re.fullmatch(r'flow-[0-9]{1,8}', value) else '未知流'

    def step(value):
        return value if isinstance(value, str) and value in analysis.REQUIRED_STEPS else '未知步骤'

    def digest(value):
        return value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) else '未知'

    source = mapping(source)
    numeric_fields = {'summary.target_packet_count': ('指定主机相关包数', 'target_packet_count'),
        'summary.packet_count': ('全部包数', 'packet_count'),
        'summary.frame_count': ('受支持完整明文帧数', 'frame_count')}
    if field in numeric_fields:
        label, name = numeric_fields[field]
        return label, number(mapping(source.get('summary')).get(name))
    if field == 'summary':
        return '采样与解析计数', {label: number(mapping(source.get('summary')).get(name))
            for name, label in (('packet_count', '全部包数'), ('target_packet_count', '指定主机相关包数'),
                ('frame_count', '完整明文帧数'), ('candidate_count', '候选设备数'),
                ('acknowledgement_count', '应答候选数'),
                ('independent_state_candidate_count', '独立状态候选数'))}
    if field == 'simulation':
        return '样本来源声明', '合成演练' if source.get('simulation') is True else (
            '真实采样声明，身份未认证' if source.get('simulation') is False else '未知')
    if field == 'capture_status':
        status = source.get('capture_status')
        return '采样完成状态', {'completed': '已完成', 'interrupted': '已中止',
            'failed': '失败', 'capturing': '采集中'}.get(status if isinstance(status, str) else None, '未知或未完成')
    if field in ('dropped_by_kernel', 'transport_issue_count', 'tcp_connection_count'):
        labels = {'dropped_by_kernel': '内核丢包数（null为未知）',
            'transport_issue_count': '截断、重组与流边界限制条数', 'tcp_connection_count': '可区分TCP连接数'}
        return labels[field], number(source.get(field))
    if field in ('candidate_frame_indices', 'request_frame_indices', 'unsupported_frame_indices'):
        labels = {'candidate_frame_indices': '当前完整标识的候选帧号',
            'request_frame_indices': '正常数据请求候选帧号', 'unsupported_frame_indices': '当前窄配方不支持的帧号'}
        return labels[field], ids(source.get(field))
    if field == 'opaque_flow_ids':
        return '不透明或TLS样式方向流', [flow(value) for value in rows(source.get(field))]
    if field == 'event_steps':
        statuses = {'recorded': '完整记录', 'partial': '记录不完整',
            'skipped': '已跳过', 'incomplete': '步骤未完成'}
        return '逐步操作记录', [{'步骤': step(mapping(row).get('step')),
            '记录': statuses.get(mapping(row).get('status'), '未知')}
            for row in rows(source.get(field))]
    if field == 'case_checks':
        return '逐步开关与独立状态核对', [{'步骤': step(mapping(row).get('step')),
            '结果': '离线一致，未验证实物' if mapping(row).get('status') == 'consistent' else '需补充证据',
            '开关请求帧号': ids(mapping(row).get('command_frame_indices')),
            '独立状态候选帧号': ids(mapping(row).get('state_frame_indices'))}
            for row in rows(source.get(field))]
    if field in ('auth_field_shapes', 'session_protocol_timeline'):
        result = []
        for item in rows(source.get(field)):
            item = mapping(item)
            row = {'帧号': number(item.get('frame_index')), '方向流': flow(item.get('flow_id')),
                '方向': {'to_host': 'App到主机', 'from_host': '主机到App'}.get(item.get('direction'), '未知')}
            if field == 'auth_field_shapes':
                row.update({'字段ID': number(item.get('field_id')), '字段长度': number(item.get('length'))})
            else:
                row['协议三元组'] = [number(item.get(name)) for name in
                    ('protocol_number', 'protocol_type', 'link_code')]
            result.append(row)
        return ('认证相关字段形状（只显示ID和长度，不显示字段值）' if field == 'auth_field_shapes'
                else '会话候选时间线（协议号、类型、链路码）'), result
    if field == 'source_bindings.traffic.pcap.sha256':
        return '原始抓包内容SHA256', digest(mapping(mapping(source.get('source_bindings')).get('traffic.pcap')).get('sha256'))
    if field == 'source_bindings':
        return '固定四文件内容绑定', {name: {'字节数': number(mapping(mapping(
            source.get('source_bindings')).get(name)).get('size_bytes')), 'SHA256': digest(mapping(mapping(
            source.get('source_bindings')).get(name)).get('sha256'))}
            for name in ('session.json', 'events.jsonl', 'traffic.pcap', 'report.json')}
    return '未支持的证据引用', '不显示未列入白名单的字段'


def render_task_text(record, task_id):
    """Pure, bounded Chinese task details from fixed local summary attributes.

    No paths are evaluated or opened. Arbitrary nested payload/credential fields
    are not copied even if an unexpected key was inserted in a saved summary.
    This text is display only and never authorizes capture or network access.
    """
    tasks = record.get('tasks') if isinstance(record, dict) else None
    task = next((row for row in tasks if isinstance(row, dict) and row.get('id') == task_id), None) \
        if isinstance(tasks, list) else None
    if task is None:
        raise ValueError('没有这个补采或能力缺口任务')
    lines = [str(task.get('title', '本机缺口任务')),
        '当前状态：' + STATUS_LABELS.get(task.get('status'), '未知，不能准备补采'),
        '原因：' + str(task.get('why', '尚未提供原因')), '', '本机证据：']
    refs = task.get('evidence_refs')
    shown = False
    for ref in refs[:32] if isinstance(refs, list) else []:
        if not isinstance(ref, dict) or ref.get('round') not in ('primary', 'comparison'):
            continue
        name = ref['round']
        label, value = _reference_value(record.get(name), ref.get('field'))
        serialized = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(', ', ': '))
        if len(serialized) > 1500:
            serialized = serialized[:1500] + '…〔已截断；请在本机完整计划中查看其余白名单证据〕'
        lines.append(('第一轮' if name == 'primary' else '第二轮') + ' · ' + label + '：' + serialized)
        shown = True
    if not shown:
        lines.append('本项是人工或软件能力门槛，当前没有可自动证明充分性的报文引用。')
    lines.append('以上只是样本中的观察或缺失线索，不证明认证成功、免认证、因果或真实物理反馈。')
    for key, label in (('instructions', '操作重点'), ('expected_evidence', '下一步期待的证据'),
                       ('capture_preparation_blockers', '准备补采前还需处理')):
        values = task.get(key)
        lines.extend(['', label + '：'])
        if isinstance(values, list) and values:
            lines.extend('• ' + str(value) for value in values[:32])
        else:
            lines.append('无额外项目；这不表示协议或实物验收通过。')
    if task.get('category') == 'manual_check':
        lines.append('这是人工核对项，不提供补采准备按钮；请在现场核对同灯和实际亮灭。')
    elif task.get('category') == 'software_support':
        lines.append('这是软件能力缺口，不提供补采准备按钮；重复采样不能替代匹配策略实现。')
    elif task.get('capture_allowed') is True:
        lines.append('可准备原有完整单灯采样表单；准备不启动采样，仍须现场确认同灯并由业主另行开始。')
    else:
        lines.append('当前不提供补采准备；先处理上列来源、完整标识或标签条件，不猜填或修改原件让按钮可用。')
    lines.append('本页仅本机显示：不上传、不发包、不生成驱动，也不解除HA接入门槛。')
    return '\n'.join(lines) + '\n'


def render_text(record):
    """Plain local Chinese text; no raw packet or credential values are shown."""
    lines = ['MC7021 本机缺口与补采引导', SCOPE,
        '来源：' + ('合成演练' if record['simulation'] else '真实采样声明，身份和现场观察未认证'),
        '完整候选标识：' + (record['selected_identifier'] or '尚未选定唯一候选'),
        '结论：资料充分性尚未证明；未生成驱动，HA在线接入未就绪，发送字节数为0。',
        '补采任务仅可填入原有完整单灯采样表单；须有原件中出现的完整标识和有效普通灯标签。',
        '自动唯一标识仍只是候选；须现场确认同灯，由业主另行启动，不会自动连接设备。', '']
    for task in record['tasks']:
        lines.extend([task['title'] + '：' + STATUS_LABELS[task['status']], '原因：' + task['why']])
        lines.extend('操作：' + item for item in task['instructions'])
        lines.extend('期待证据：' + item for item in task['expected_evidence'])
        lines.append('')
    lines.append('原件内容绑定（不复制PCAP或认证字段值）：')
    for name, value in record['source_bindings'].items():
        lines.append('{}：{}字节；SHA256 {}'.format(name, value['size_bytes'], value['sha256']))
    return '\n'.join(lines) + '\n'


def create_plan(session_directory, data_root, selected_identifier='', comparison_directory=None):
    """Return (private plan.json path, record), recomputing rather than trusting plans."""
    root = baseline._safe_path(data_root)
    if not root.is_dir():
        raise ValueError('请先选择已存在的本机数据目录')
    first_source = _read_source(session_directory, root)
    identifier, mode = recipe._select(first_source, selected_identifier)
    second_source = None
    if comparison_directory is not None:
        second_source = _read_source(comparison_directory, root)
        if first_source['binding']['traffic.pcap']['sha256'] == second_source['binding']['traffic.pcap']['sha256']:
            raise ValueError('第二轮PCAP与第一轮相同；复制或改元数据不是新的补采进展')
        if first_source['metadata']['target_ip'] != second_source['metadata']['target_ip']:
            raise ValueError('比较轮次主机不同；不能合并不同主机或住宅的证据')
        if identifier is None:
            raise ValueError('请先核对第一轮完整标识，不能用第二轮拼出目标')
        recipe._select(second_source, identifier)
    first = _source_summary(first_source, identifier)
    second = _source_summary(second_source, identifier) if second_source else None
    simulation = first['simulation'] is not False or bool(second and second['simulation'] is not False)
    tasks = _build_tasks(first, second, identifier, simulation, first_source['target_context'])
    record = dict(schema_version=VERSION, artifact='private_mc7021_sampling_gap_plan',
        plan_id=uuid.uuid4().hex, created_at=datetime.now(timezone.utc).isoformat(), scope=SCOPE,
        target_ip=first['target_ip'], target_context=first_source['target_context'],
        session_path=first['source_paths']['session_dir'], source_bindings=first['source_bindings'],
        source_paths=first['source_paths'], simulation=simulation,
        selected_identifier=identifier, selection_mode=mode, primary=first, comparison=second,
        independent_second_round=second is not None, tasks=tasks,
        counts={status: sum(task['status'] == status for task in tasks) for status in (
            'needs_sample', 'manual_required', 'software_required', 'evidence_present_unverified')},
        machine_sufficiency='not_proven', online_ready=False, driver_generated=False,
        can_generate_live_driver=False, can_start_live_ha=False, physical_feedback_verified=False,
        executable_code=False, bytes_sent=0, upload_performed=False, network_access_performed=False,
        credential_values_copied=False, raw_pcap_copied=False,
        note='旧计划只供查看；重新分析和准备补采必须重新读取原件，不信任修改后的任务状态或权限。')
    recipe._verify_unchanged(first_source, root)
    if second_source:
        recipe._verify_unchanged(second_source, root)
    parent = baseline._safe_path(root / 'private_sampling_plans')
    # Never place output beneath either capture or a source report.
    for source in (first_source, second_source):
        if source:
            for name in source['paths'].values():
                original = root / name
                if parent == original or original in parent.parents:
                    raise ValueError('计划输出不能覆盖或位于原件目录内')
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    destination = parent / ('plan_' + record['plan_id'])
    destination.mkdir(mode=0o700)
    path = destination / 'plan.json'
    recipe._write_private(path, json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    recipe._write_private(destination / '补采与能力缺口.txt', render_text(record))
    return path, record
