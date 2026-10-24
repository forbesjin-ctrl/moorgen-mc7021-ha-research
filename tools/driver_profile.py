"""Bounded, private matching for one implemented plaintext single-light strategy.

Raw captures are reread locally. Credentials are freshly supplied in memory and
only tested for exact encoding equality; neither values nor their digests enter
the result. A matching profile permits an experimental driver package, never
claims live authentication, physical feedback, or HA acceptance.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import uuid

try:
    from . import adapter_recipe as recipe
    from . import baseline_review as baseline
    from . import sampling_gaps as gaps
    from . import session_workbench as session
except ImportError:
    import adapter_recipe as recipe
    import baseline_review as baseline
    import sampling_gaps as gaps
    import session_workbench as session

VERSION = '0.10.0'
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
SCOPE = ('只匹配内置的窄明文单灯策略；重新读取本机原件，不复制认证字段、令牌、密钥或旧序号。'
         '凭据仅在内存中核对已知输入的编码，不保存值或凭据摘要；不上传、不联网。'
         '两轮相符仅支持实验驱动打包；住宅身份、实时认证、物理状态与HA验收仍未验证。')
NORMAL_CAPTURE = ('只用原App与面板正常操作同一组普通开关灯，不扫描、不改配置。',
                  '先开始采样再正常打开App，保留初始连接与状态同步；完成十步后正常停止保存。',
                  '另存独立第二轮，保持同一已知主机与同一灯组，逐步记录实际亮灭和App显示。')


def _ref(connection, frame):
    return dict(round=connection['round'], connection_id=connection['id'], frame_index=frame['index'])


def _ascii(value):
    return (isinstance(value, str) and 1 <= len(value) <= 128
            and bool(value.strip()) and all(32 <= ord(char) <= 126 for char in value))


def _credentials(auth_frames, credentials, enabled):
    result = dict(status='not_supplied', matched_transform=None, values_persisted=False,
                  credential_hashes_persisted=False, raw_auth_fields_persisted=False,
                  verified_against_sources=False)
    if credentials is None:
        return result
    if not enabled:
        result['status'] = 'not_checked_until_wire_and_real_sources_match'
        return result
    if (not isinstance(credentials, dict) or set(credentials) != {'username', 'password'}
            or not _ascii(credentials.get('username')) or not _ascii(credentials.get('password'))
            or credentials['username'].strip() != credentials['username']):
        result['status'] = 'unsupported_input'
        return result
    username = credentials['username'].encode('ascii')
    password = credentials['password'].encode('ascii')
    digest = hashlib.md5(password).hexdigest()
    candidates = {'raw_ascii': password, 'md5_hex_lower': digest.encode('ascii'),
                  'md5_hex_upper': digest.upper().encode('ascii')}
    matching = []
    for transform, value in candidates.items():
        matches = bool(auth_frames)
        for frame in auth_frames:
            fields = frame['parsed_frame']['fields']
            # Schema validation occurs independently; never find-first or
            # silently collapse duplicate credential fields.
            if [field['id'] for field in fields] != [12, 13]:
                matches = False
                continue
            same_user = hmac.compare_digest(bytes.fromhex(fields[0]['value_hex']), username)
            same_password = hmac.compare_digest(bytes.fromhex(fields[1]['value_hex']), value)
            matches = bool(matches & same_user & same_password)
        if matches:
            matching.append(transform)
    if len(matching) == 1:
        result.update(status='matched', matched_transform=matching[0], verified_against_sources=True)
    else:
        result['status'] = 'ambiguous' if matching else 'no_match'
    return result


def _layout(connections, identifier, target_ip):
    """Check fixed transport/session shapes without exporting their payloads."""
    checks, auth_frames, ports = [], [], set()
    allowed = {((1, 1), 'to_host'), ((1, 3), 'from_host'), ((2, 4), 'to_host'),
               ((2, 6), 'from_host'), ((3, 7), 'to_host'), ((3, 8), 'from_host'),
               ((4, 9), 'to_host'), ((4, 10), 'from_host'), ((4, 11), 'from_host'),
               ((5, 12), 'from_host'), ((6, 13), 'from_host'), ((6, 14), 'to_host')}
    for connection in connections:
        successes = [frame for frame in connection['_frames'] if session._pair(frame) == (2, 6)
                     and frame['direction'] == 'from_host']
        heartbeat_pending = None
        for endpoint in connection['endpoints']:
            if endpoint['ip'] == target_ip:
                ports.add(endpoint['port'])
        if connection['transport'] != 'tcp':
            checks.append(dict(round=connection['round'], connection_id=connection['id'],
                               reason='当前策略只支持有明确新连接边界的TCP，不支持UDP。'))
        for frame in connection['_frames']:
            packet, pair = frame['parsed_frame'], session._pair(frame)
            fields = packet['fields']
            reason = None
            if any(f['id'] in (93, 530) or (f['id'] == 160 and pair != (1, 3)) for f in fields):
                reason = '出现密钥或会话外加密选择字段；不能复用旧材料或忽略重新协商。'
            elif packet['protocol_number'] != 1 or (pair, frame['direction']) not in allowed:
                reason = '协议类型或方向超出当前窄策略；不能猜测或忽略未知会话。'
            elif pair == (1, 1) and fields:
                reason = '连接请求含额外字段；当前不支持AppID、RSA或其它初始化参数。'
            elif pair == (1, 3) and not (len(fields) == 1 and fields[0]['id'] == 160
                    and fields[0]['length'] == 1 and fields[0]['value_hex'] == '00'):
                reason = '连接应答须恰好含160=00；缺少选择值不证明明文，额外密钥字段或非零加密分支待软件支持。'
            elif pair == (2, 4):
                if ([f['id'] for f in fields] != [12, 13] or any(not 1 <= f['length'] <= 128
                        or not bytes.fromhex(f['value_hex']).strip()
                        or not all(32 <= byte <= 126 for byte in bytes.fromhex(f['value_hex'])) for f in fields)
                        or (fields and bytes.fromhex(fields[0]['value_hex']).strip()
                            != bytes.fromhex(fields[0]['value_hex']))):
                    reason = '认证须恰好为12、13两个有界ASCII字段；令牌、会话、AppID或未知编码待匹配策略。'
                else:
                    auth_frames.append(frame)
            elif pair == (2, 6) and fields:
                reason = '认证成功类应答含当前不支持的字段。'
            elif pair in ((6, 13), (6, 14)) and fields:
                reason = '心跳包含未知字段；当前仅实现空字段13请求和14应答。'
            elif pair == (4, 9) and not recipe._has_target(packet, identifier):
                reason = '同轮存在其它完整标识或未标明目标的执行请求；不能混入其它灯后当作首组样本。'
            elif pair == (3, 7) and not ([f['id'] for f in fields] == [15, 4]
                    and fields[0]['value_hex'] == '48' and fields[0]['length'] == 1
                    and fields[1]['value_hex'] == identifier and fields[1]['length'] == 8):
                reason = '当前只支持同一完整标识的48单设备查询；全设备或其它查询待匹配策略。'
            if pair not in ((1, 1), (1, 3), (2, 4), (2, 6)) and (len(successes) != 1
                    or not session._strictly_before(successes[0], frame)):
                reason = '业务或心跳帧不在唯一认证成功类应答之后；不能跳过认证顺序。'
            if pair == (6, 13) and frame['direction'] == 'from_host':
                if heartbeat_pending is not None:
                    reason = '重叠的主机心跳请求尚未配对，当前窄心跳策略不匹配。'
                heartbeat_pending = frame
            elif pair == (6, 14) and frame['direction'] == 'to_host':
                if heartbeat_pending is None or not session._strictly_before(heartbeat_pending, frame):
                    reason = '客户端心跳应答没有唯一先行主机请求；不猜测主动心跳策略。'
                heartbeat_pending = None
            if reason:
                checks.append(dict(**_ref(connection, frame), reason=reason))
    pairs, _ = session._reply_pairs(connections)
    for row in pairs:
        if session._pair(row['request']) in ((1, 1), (2, 4)) and (
                row['request']['parsed_frame']['serial_number'] != row['response']['parsed_frame']['serial_number']):
            checks.append(dict(**_ref(row['connection'], row['response']),
                reason='连接或认证应答序号未回显唯一先行请求，当前状态机不匹配。'))
    if len(ports) != 1 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        checks.append(dict(reason='没有唯一、有效的实际主机TCP服务端口；不猜填9000。'))
    return checks, auth_frames, next(iter(ports)) if len(ports) == 1 else None


def _readback(connections, identifier):
    """Require a unique prior same-connection query, then equal serial details."""
    pairs, uncertain = session._reply_pairs(connections)
    by_connection, checks = {}, []
    for row in pairs:
        request, response, connection = row['request'], row['response'], row['connection']
        if session._pair(request) != (3, 7):
            continue
        fields = request['parsed_frame']['fields']
        valid_request = ([f['id'] for f in fields] == [15, 4] and fields[0]['value_hex'] == '48'
                         and fields[0]['length'] == 1 and fields[1]['value_hex'] == identifier
                         and fields[1]['length'] == 8)
        state = recipe._state_check(response, identifier)
        valid = (valid_request and session._pair(response) == (3, 8) and state['supported']
                 and request['parsed_frame']['serial_number'] == response['parsed_frame']['serial_number'])
        checks.append(dict(**_ref(connection, request), response_frame_index=response['index'],
                           supported=valid, candidate_state=state['candidate_state'] if valid else None))
        by_connection.setdefault(connection['id'], []).append(valid)
    # Any unsupported/unpaired query response is significant; an unrelated
    # successful query must never conceal ambiguous duplicates or stale replies.
    ambiguous_queries = [row for row in uncertain if any(
        frame['index'] == row['frame_index'] and session._pair(frame) == (3, 8)
        for connection in connections for frame in connection['_frames'])]
    request_count = sum(session._pair(frame) == (3, 7) and frame['direction'] == 'to_host'
                        for connection in connections for frame in connection['_frames'])
    supported = (bool(connections) and len(checks) == request_count and not ambiguous_queries
                 and all(row['supported'] for row in checks)
                 and all(any(by_connection.get(row['id'], [])) for row in connections))
    return dict(supported=supported, checks=checks, ambiguous_response_count=len(ambiguous_queries),
                correlation='query_serial_echo', causation_verified=False)


def _record(primary, holdout, identifier, selection_mode, credentials):
    sources = [('primary', primary)] + ([('holdout', holdout)] if holdout else [])
    connections = [row for name, source in sources for row in session._connections(source, name)]
    summaries = {name: session._source_summary(source, [row for row in connections if row['round'] == name])
                 for name, source in sources}
    tasks = []

    def add(key, title, supported, category, reason, instructions):
        tasks.append(dict(id=key, title=title, category='manual_check' if supported else category,
            status='evidence_present_unverified' if supported else 'needs_sample' if category == 'recapture'
                else 'manual_required' if category == 'manual_check' else 'software_required',
            supported=bool(supported), why=reason, instructions=list(instructions), bytes_sent=0))

    real = all(source['metadata']['simulation'] is False
               and source['metadata'].get('sample_origin') == 'external_owner_household'
               and Path(source['paths']['session_dir']).parent == Path('captures') for _, source in sources)
    add('real_sources', '真实本户原件声明', real, 'recapture',
        '合成或来源未知数据不能用于住宅驱动打包；真实声明本身也不是身份认证。', NORMAL_CAPTURE)
    add('independent_round', '独立第二轮', holdout is not None, 'recapture',
        '必须是同一主机、同一完整标识的新一轮PCAP；复制文件不能算第二轮。', NORMAL_CAPTURE)
    contexts_match = (primary['target_context'] is not None and (not holdout
                      or primary['target_context'] == holdout['target_context']))
    add('ordinary_target', '同一普通灯与完整标识', bool(identifier and contexts_match), 'manual_check',
        '需核对同一完整8字节标识及普通开关灯声明；声明不会替代首组人工核对。',
        ('在首组核对页确认实际灯路、完整标识及标签；不要猜填地址或选第一个设备。',))
    quality = all(s['capture_status'] == 'completed' and s['dropped_by_kernel'] == 0
                  and s['target_packet_count'] > 0 and s['frame_count'] > 0
                  and s['transport_issue_count'] == 0 and not s['opaque_flow_ids']
                  for s in summaries.values())
    quality_loss = any(s['capture_status'] != 'completed' or s['dropped_by_kernel'] != 0
        or s['target_packet_count'] <= 0 or s['sampling_transport_issue_count'] for s in summaries.values())
    quality_category = 'recapture' if quality_loss or (holdout is None and any(
        s['initial_boundary_unknown_count'] for s in summaries.values())) else 'software_support'
    add('capture_quality', '原件完整、连接边界与丢包', quality, quality_category,
        '须完整保存、内核丢包明确为0、TCP无重组缺口且捕获SYN；未知或加密载荷不当作正常。', NORMAL_CAPTURE)
    layout_issues, auth_frames, port = _layout(connections, identifier, primary['metadata']['target_ip'])
    order = session._session_rule(connections)
    layout = not layout_issues and order['status'] == 'candidate_supported'
    add('session_layout', '内置明文连接与认证分支', layout, 'software_support',
        '只支持空连接请求、唯一160=00连接应答、12/13认证及空成功类应答；其它分支明确保留为待支持。',
        ('保留本机原件；先核对连接时间线。缺启动时只补完整正常启动；仍不匹配时等待匹配软件，不无限重采。',))
    training, testing = session._serial_partitions(connections, holdout is not None)
    serial = session._serial_rule('app_global_increment_mod65536', '全局请求序号自增候选',
                                   training, testing, 'increment')
    add('serial_policy', '新序号策略', serial['status'] == 'candidate_supported', 'software_support',
        '只匹配跨连接可见请求逐次加1并回绕；驱动使用自己的新计数器，绝不复制抓包序号。跳号未被解释时保持未匹配。',
        ('完整保留正常启动、查询与开关的原始流；如仍冲突，等待新的序号策略支持。',))
    evaluations = {name: recipe._evaluate(source, identifier) for name, source in sources}
    codec = all(e['codec_consistency'] for e in evaluations.values())
    add('switch_and_panel', '重复开关与面板独立反馈', codec, 'recapture',
        '四次App操作与两次面板操作必须对应同一完整标识和独立状态；ACK、执行应答与缓存不能替代。', NORMAL_CAPTURE)
    readback = _readback(connections, identifier)
    add('query_readback', '每次连接的新查询与独立应答', readback['supported'], 'software_support',
        '每次新连接须有48单设备查询、唯一先行请求及相同序号的04详情应答；不从状态推回查询。',
        ('正常打开该灯页面并等待同步，保留初始和重进App全过程；匹配仍失败时等待对应查询策略。',))
    reopen = [row for _, source in sources for row in session._reopen_checks(
        source, [c for c in connections if c['round'] == ('primary' if source is primary else 'holdout')], identifier)]
    reopened = bool(reopen) and all(row['status'] == 'candidate_supported' for row in reopen)
    add('reopen_readback', 'App关闭后改变与新连接回读', reopened, 'recapture',
        '关闭前灯关，App关闭期间面板开且App不可见，再正常打开；须新TCP连接、新查询及一致状态，冲突不能隐藏。', NORMAL_CAPTURE)
    wire_keys = ('independent_round', 'ordinary_target', 'capture_quality', 'session_layout',
                 'serial_policy', 'switch_and_panel', 'query_readback', 'reopen_readback')
    wire = all(next(row['supported'] for row in tasks if row['id'] == key) for key in wire_keys)
    verification = _credentials(auth_frames, credentials, wire and real)
    credential_ok = verification['status'] == 'matched'
    add('credential_encoding', '本机核对已知账户输入的编码', credential_ok, 'manual_check',
        '只从12/13形状无法区分密码原文或摘要。需本机输入本户合法且已知的账户与原密码，内存核对raw/MD5小写/MD5大写，必须唯一匹配全部会话；不保存值或摘要。',
        ('线格式匹配后，在安全输入框中输入正常App所用的已知账户与原密码；不要从抓包复制字段、猜密码或提供令牌。',
         '不匹配或未知凭据时停止打包，保留本机资料并等待适用的认证策略。'))
    eligible = bool(real and wire and credential_ok)
    profile = _profile(identifier, port, verification['matched_transform']) if eligible else None
    status = ('source_matched_unverified' if eligible else 'requires_local_credential_check' if real and wire
              else 'needs_sample' if any(not t['supported'] and t['category'] == 'recapture' for t in tasks)
              else 'software_required')
    tasks.append(dict(id='ha_physical_acceptance', title='HA首组真实状态验收', category='manual_check',
        status='manual_required', supported=False, why='驱动线格式匹配不代表实机认证或灯具通过；首组人工核对、明确现场启用及八步HA实物验收仍必须完成。',
        instructions=['安装后先独立回读，再验证HA重复开关、面板改变、断线不可用和重连新回读；冲突时停止扩展。'], bytes_sent=0))
    return dict(schema_version=VERSION, artifact='private_mc7021_driver_profile', profile_id=uuid.uuid4().hex,
        created_at=datetime.now(timezone.utc).isoformat(), scope=SCOPE, status=status,
        simulation=primary['metadata']['simulation'], source_origin_eligible=real,
        target_ip=primary['metadata']['target_ip'], target_context=primary['target_context'],
        selected_identifier=identifier, selection_mode=selection_mode, source_paths=primary['paths'],
        source_bindings=primary['binding'], holdout=summaries.get('holdout'), primary=summaries['primary'],
        independent_second_round=holdout is not None, wire_compatible=wire, package_eligible=eligible,
        profile=profile, credential_verification=verification, tasks=tasks,
        layout_issues=layout_issues, session_order=order, serial_check=serial, readback_checks=readback,
        reopen_checks=reopen, heartbeat_observed=any(session._pair(frame) in ((6, 13), (6, 14))
            for connection in connections for frame in connection['_frames']),
        heartbeat_absence_limitation='未观察到心跳不证明不需要；内置空心跳应答仅来自静态分支，实机需验收。',
        online_ready=False, runtime_authentication_verified=False, physical_feedback_verified=False,
        bytes_sent=0, upload_performed=False, network_access_performed=False,
        credential_values_copied=False, credential_value_hashes_copied=False, raw_auth_fields_copied=False)


def _profile(identifier, port, transform):
    return dict(schema_version='1.0', strategy='plain_shcp_account_v1', protocol_number=1,
        protocol_name='dooyashcp', port=port, target_identifier=identifier, ordinary_light_confirmed=True,
        conn_request_fields=[], conn_response_encryption_selector=0, auth_request_fields=[12, 13],
        credential_input_kind='owner_supplied_account_credentials',
        auth_password_transform=transform, credentials_verified_against_sources=True,
        serial_strategy='client_increment_mod65536', query_strategy='single_device_48',
        state_strategy='ordinary_light_bit0', readback_correlation='query_serial_echo',
        heartbeat_strategy='request_13_response_14_fresh_serial', evidence_status='source_matched_two_rounds')


def render_text(record):
    labels = {'source_matched_unverified': '已匹配内置策略，实机未验证',
              'requires_local_credential_check': '线格式相符，需本机核对已知凭据编码',
              'needs_sample': '需补采', 'software_required': '待匹配软件支持'}
    lines = ['首组内置驱动适配：' + labels[record['status']], SCOPE,
             '完整标识：' + (record['selected_identifier'] or '待人工选择'),
             '实际服务端口：' + (str(record['profile']['port']) if record['profile'] else '尚未形成可打包匹配'),
             '实时认证、物理状态及HA验收：均未验证；本次发送0字节。']
    for row in record['tasks']:
        lines.append('{}：{}\n{}\n{}'.format(row['title'],
            '已有线索，未实机验证' if row['supported'] else row['status'], row['why'], '\n'.join(row['instructions'])))
    return '\n\n'.join(lines)


def create_profile(session_directory, data_root, selected_identifier='', comparison_directory=None, credentials=None):
    """Reparse immutable originals and return a private, secret-free match result.

    ``credentials`` is an ephemeral dict with username/password. The caller must
    not persist it or put it in process arguments. This function never includes
    credentials, their values, or their digests in a result or exception.
    """
    root = baseline._safe_path(data_root)
    if not root.is_dir():
        raise ValueError('请先选择已存在的本机数据目录')
    primary = gaps._read_source(session_directory, root)
    identifier, selection_mode = recipe._select(primary, selected_identifier)
    holdout = None
    if comparison_directory is not None:
        holdout = gaps._read_source(comparison_directory, root)
        if primary['binding']['traffic.pcap']['sha256'] == holdout['binding']['traffic.pcap']['sha256']:
            raise ValueError('第二轮PCAP与第一轮相同，不能用复制件代替独立新轮次')
        if primary['metadata']['target_ip'] != holdout['metadata']['target_ip']:
            raise ValueError('第二轮主机不同，不能混合住宅或主机证据')
        if primary['metadata']['simulation'] is not holdout['metadata']['simulation']:
            raise ValueError('不能混合真实与合成来源')
        if identifier is None:
            raise ValueError('请先人工核对第一轮的完整标识')
        recipe._select(holdout, identifier)
    record = _record(primary, holdout, identifier, selection_mode, credentials)
    recipe._verify_unchanged(primary, root)
    if holdout:
        recipe._verify_unchanged(holdout, root)
    parent = baseline._safe_path(root / 'private_driver_profiles')
    for source in (primary, holdout):
        if source:
            for relative in source['paths'].values():
                original = root / relative
                if parent == original or original in parent.parents:
                    raise ValueError('适配输出不能覆盖或位于原件目录内')
    encoded = json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    if len(encoded.encode('utf-8')) > MAX_ARTIFACT_BYTES:
        raise ValueError('适配结果超过2MiB有界上限，未保存')
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    directory = parent / ('profile_' + record['profile_id'])
    directory.mkdir(mode=0o700)
    path = directory / '驱动适配.json'
    recipe._write_private(path, encoded)
    recipe._write_private(directory / '驱动适配说明.txt', render_text(record))
    return path, record


def validate_saved_profile(profile_path, data_root):
    """Recheck originals and the complete canonical, secret-free profile record.

    The old credential match is an explicitly local attestation, not identity
    authentication. It cannot be rerun without asking for credentials again;
    intentionally no reusable verification secret or digest is saved. Importers
    must bind the validated file hash and require the separate baseline review.
    """
    root, path = map(baseline._safe_path, (data_root, profile_path))
    if not root.is_dir() or not baseline._under(path, root):
        raise ValueError('适配记录必须位于所选本机数据目录内')
    raw = baseline._read_file(path, MAX_ARTIFACT_BYTES)
    saved = gaps.adaptation._json(raw)
    if (saved.get('artifact') != 'private_mc7021_driver_profile'
            or saved.get('schema_version') != VERSION
            or saved.get('package_eligible') is not True or saved.get('simulation') is not False
            or not isinstance(saved.get('profile_id'), str)
            or not re.fullmatch('[0-9a-f]{32}', saved['profile_id'])):
        raise ValueError('不是可核对的当前真实适配记录')
    try:
        created = saved['created_at']
        if not isinstance(created, str) or len(created) > 40 or datetime.fromisoformat(created).tzinfo is None:
            raise ValueError('时间格式不符')
        identifier = baseline._identifier(saved['selected_identifier'])
        if identifier is None:
            raise ValueError('完整标识格式不符')
        sources = []
        for item in (saved, saved['holdout']):
            paths, binding = item['source_paths'], item['source_bindings']
            _, _, current, normalized = baseline._snapshot(root, root / paths['report_dir'], root / paths['session_dir'])
            if normalized != paths or current != binding:
                raise ValueError('绑定原件或报告已变化')
            source = gaps._read_source(root / paths['session_dir'], root)
            if any(source['binding'][name] != binding[name] for name in baseline.INPUT_LIMITS):
                raise ValueError('重新解析期间原件发生变化')
            sources.append(source)
        primary, holdout = sources
        if primary['binding']['traffic.pcap']['sha256'] == holdout['binding']['traffic.pcap']['sha256']:
            raise ValueError('独立第二轮原件不成立')
        if primary['metadata']['target_ip'] != holdout['metadata']['target_ip']:
            raise ValueError('两轮主机不一致')
        for source in sources:
            recipe._select(source, identifier)
        mode = saved['selection_mode']
        if mode not in ('explicit_selection', 'unique_repeated_candidate'):
            raise ValueError('目标选择方式不受支持')
        if mode == 'unique_repeated_candidate' and recipe._select(primary, '')[0] != identifier:
            raise ValueError('唯一候选不成立')
        fresh = _record(primary, holdout, identifier, mode, None)
        if fresh['simulation'] is not False or fresh['source_origin_eligible'] is not True or not fresh['wire_compatible']:
            raise ValueError('本机原件不再匹配内置策略')
        verification = saved['credential_verification']
        transform = verification['matched_transform']
        expected_verification = dict(status='matched', matched_transform=transform, values_persisted=False,
            credential_hashes_persisted=False, raw_auth_fields_persisted=False, verified_against_sources=True)
        if transform not in ('raw_ascii', 'md5_hex_lower', 'md5_hex_upper') or verification != expected_verification:
            raise ValueError('凭据编码的本机声明格式不受支持')
        connections = [row for label, source in (('primary', primary), ('holdout', holdout))
                       for row in session._connections(source, label)]
        issues, auth_frames, port = _layout(connections, identifier, fresh['target_ip'])
        if issues:
            raise ValueError('认证字段形状不再匹配')
        if not auth_frames or any(any(not hmac.compare_digest(bytes.fromhex(field['value_hex']),
                bytes.fromhex(auth_frames[0]['parsed_frame']['fields'][index]['value_hex']))
                for index, field in enumerate(frame['parsed_frame']['fields'])) for frame in auth_frames):
            raise ValueError('全部会话的凭据编码与单一已知输入声明不一致')
        if transform != 'raw_ascii':
            pattern = '[0-9a-f]{32}' if transform == 'md5_hex_lower' else '[0-9A-F]{32}'
            if any(not re.fullmatch(pattern, bytes.fromhex(frame['parsed_frame']['fields'][1]['value_hex']).decode('ascii'))
                   for frame in auth_frames):
                raise ValueError('摘要编码声明与捕获的字段形状不符')
        fresh.update(profile_id=saved['profile_id'], created_at=saved['created_at'],
            status='source_matched_unverified', package_eligible=True,
            profile=_profile(identifier, port, transform), credential_verification=expected_verification)
        for name, original in (('primary', saved['primary']), ('holdout', saved['holdout'])):
            fresh[name]['source_paths'] = original['source_paths']
            fresh[name]['source_bindings'] = original['source_bindings']
        fresh['source_paths'], fresh['source_bindings'] = saved['source_paths'], saved['source_bindings']
        credential_task = next(row for row in fresh['tasks'] if row['id'] == 'credential_encoding')
        credential_task.update(supported=True, category='manual_check', status='evidence_present_unverified')
        # Compare serialized types too: Python's True == 1 is not an acceptable
        # substitute for exact boolean/schema validation.
        if json.dumps(fresh, sort_keys=True, ensure_ascii=True) != json.dumps(saved, sort_keys=True, ensure_ascii=True):
            raise ValueError('适配记录被修改或包含非标准字段')
        for source in sources:
            recipe._verify_unchanged(source, root)
        if baseline._read_file(path, MAX_ARTIFACT_BYTES) != raw:
            raise ValueError('适配记录读取期间变化')
        return saved
    except (KeyError, TypeError, AttributeError, UnicodeError) as error:
        raise ValueError('适配记录缺少标准字段或类型不符') from error
