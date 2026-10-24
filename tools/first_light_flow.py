"""One private, source-bound first-light journey. Offline orchestration only.

A saved journey is a display, never an authorization token. Every refresh reads
capture originals again and revalidates separately saved review/HA artifacts.
The owner does not write Python or upload captures. Actual light observations
and installing/authorizing a connection inside HA remain explicit owner steps.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

try:
    from . import adapter_recipe as recipe
    from . import baseline_review as baseline
    from . import ha_wizard as wizard
    from . import sampling_gaps as gaps
    from . import session_workbench as sessions
except ImportError:
    import adapter_recipe as recipe
    import baseline_review as baseline
    import ha_wizard as wizard
    import sampling_gaps as gaps
    import session_workbench as sessions

VERSION = '0.10.0'
ARTIFACT = 'private_mc7021_first_light_flow'
MAX_BYTES = 2 * 1024 * 1024
STATUS_LABELS = {'confirmed': '已确认', 'pending': '待验证',
                 'needs_sample': '需补采', 'software_required': '待软件支持'}
STAGES = (('capture', '真实首组采样'), ('baseline', '首组人工核对'),
          ('codec', '开关与独立状态字节核对'), ('session', '认证、序号和重连'),
          ('driver', '匹配本机驱动'), ('ha_package', 'HA安装包、安装与授权'),
          ('acceptance', 'HA真实状态验收'))
ACTIONS = frozenset(('prepare_capture', 'select_identifier', 'review_baseline',
    'open_session_workbench', 'match_driver', 'open_ha_wizard', 'build_ha_bundle',
    'record_installation', 'record_ha_acceptance', 'complete', 'software_support'))
CAPTURE_STEPS = (
    ('初始同步', '开始采样后再正常打开摩根App，等待初始同步并进入同一组灯页面；记录实际亮灭和App显示。'),
    ('App开1', '在App打开这组灯，等灯和显示稳定，分别记录实际亮灭与App显示。'),
    ('App关1', '在App关闭这组灯，等灯和显示稳定，分别记录实际亮灭与App显示。'),
    ('App开2', '在App再次打开同一组灯，等稳定后记录；不要连点。'),
    ('App关2', '在App再次关闭同一组灯，等稳定后记录。'),
    ('面板开', '保持App可观察，只用原面板开这组灯；不要在App补点，记录灯与显示。'),
    ('面板关', '只用原面板关这组灯，等待后记录灯与App显示。'),
    ('关闭App', '按现有向导关闭App，不退出账号、不改网络或厂家配置。'),
    ('App关闭期间面板开', 'App关闭期间用原面板开同一组灯；记录实际亮灯，App显示选不可见。'),
    ('重进App读状态', '正常重进App这组灯页面，保持实物不变，记录当前实际亮灭与App读回显示。'),
)
SCOPE = ('首组全过程只操作同一已知MC7021和一组普通开关灯；资料保存在业主本机。'
         '本页不联网、不扫描、不上传、不重放、不修改配置，也不执行驱动。'
         '已确认只指所列离线检查或人工声明；工具看不到灯本体，不能自动证明真实物理反馈。'
         '匹配的软件、原件核对和HA现场验收均须通过，才可引导其它普通灯。')


def _bindings(source):
    return {name: source['binding'][name] for name in baseline.INPUT_LIMITS}


def _relative(path, root):
    if path is None:
        return None
    path = baseline._safe_path(path)
    if not baseline._under(path, root):
        raise ValueError('流程材料必须在所选本机数据目录内')
    return str(path.relative_to(root))


def _task(key, title, status, action, instructions, *, stage='capture', allowed=False,
          why='', existing_task_id=None):
    if action not in ACTIONS or status not in STATUS_LABELS:
        raise ValueError('内部流程动作或状态无效')
    return dict(id=key, title=title, status=status, status_label=STATUS_LABELS[status],
        action=action, stage_id=stage, why=why, instructions=list(instructions),
        capture_allowed=bool(allowed and action == 'prepare_capture' and status == 'needs_sample'),
        existing_task_id=existing_task_id, source_task_kind=('session_workbench' if key.startswith('session_') else 'sampling_gaps') if existing_task_id else None,
        preparation_only=True, bytes_sent=0)


def _stage(key, status='pending', summary='尚未取得当前步骤的完整证据。'):
    return dict(id=key, title=dict(STAGES)[key], status=status,
                status_label=STATUS_LABELS[status], summary=summary)


def _review(review_file, root, source, identifier):
    if review_file is None:
        return dict(valid=False, passed=False, supplied=False, reason='not_selected'), None
    relative = _relative(review_file, root)
    result = baseline.validate_review(root / relative, root,
        expected_host=source['metadata']['target_ip'], expected_target_context=source['target_context'])
    record = result.get('record')
    matches = bool(result.get('valid') is True and isinstance(record, dict)
        and record.get('source', {}).get('session_dir') == source['paths']['session_dir']
        and record.get('selected_identifier') == identifier
        and {name: record.get('input_integrity', {}).get(name) for name in baseline.INPUT_LIMITS} == _bindings(source))
    passed = bool(matches and result.get('passed') is True and source['metadata']['simulation'] is False
        and baseline.assess_report(source['report'])['eligible_for_manual_review'])
    return dict(valid=matches, passed=passed, supplied=True,
        reason='matched' if matches else 'invalid_or_other_source', file=relative), result if matches else None


def _wizard(wizard_file, root, source, identifier, review):
    if wizard_file is None:
        return dict(valid=False, supplied=False, reason='not_selected'), None
    relative = _relative(wizard_file, root)
    result = wizard.load(root / relative, root, expected_host=source['metadata']['target_ip'])
    state = result.get('state')
    matches = bool(review['passed'] and result.get('valid') is True and isinstance(state, dict)
        and state.get('simulation') is False and state.get('selected_identifier') == identifier
        and state.get('target_context') == source['target_context']
        and state.get('baseline_review', {}).get('file') == review.get('file')
        and {name: state.get('baseline_input_integrity', {}).get(name) for name in baseline.INPUT_LIMITS} == _bindings(source))
    if not matches:
        return dict(valid=False, supplied=True, reason='invalid_or_other_source', file=relative), None
    assessment = result['assessment']
    return dict(valid=True, supplied=True, reason='matched', file=relative,
        stage=assessment['stage'], owner_declared_acceptance_passed=assessment['passed'],
        driver_present=bool(state.get('driver')), bundle_present=bool(state.get('bundle')),
        installation_declared=bool(state.get('installation', {}) and state['installation'].get('confirmed') is True),
        diagnostic_present=bool(state.get('diagnostics')),
        acceptance=[dict(id=row['id'], title=row['title'], status=row['status'])
                    for row in assessment['criteria']]), result


def _profile(session_directory, root, identifier, comparison_directory):
    # The fixed shipped matcher always reparses original captures itself. No
    # plugin, callable, user-supplied profile JSON or saved flags are executed.
    try:
        if __package__:
            from . import driver_profile
        else:
            import driver_profile
    except ImportError:
        return dict(status='software_required', wire_compatible=False, package_eligible=False,
                    credential_check_required=False, profile_id=None), None
    path, record = driver_profile.create_profile(session_directory, root,
        selected_identifier=identifier or '', comparison_directory=comparison_directory)
    status = record.get('status')
    if status not in ('needs_sample', 'software_required', 'requires_local_credential_check', 'source_matched_unverified'):
        status = 'software_required'
    # No credentials are passed to this overview; it must not issue a packaging
    # grant, even if an unexpected future matcher record asserts one.
    return dict(status=status, wire_compatible=record.get('wire_compatible') is True,
        package_eligible=False, credential_check_required=status == 'requires_local_credential_check',
        profile_id='plain_shcp_account_v1' if record.get('wire_compatible') is True else None,
        tasks=[{key: row[key] for key in ('id', 'title', 'category', 'status', 'why', 'instructions')}
               for row in record.get('tasks', []) if isinstance(row, dict) and row.get('id') in (
                   'real_sources', 'independent_round', 'ordinary_target', 'capture_quality',
                   'session_layout', 'serial_policy', 'switch_and_panel', 'query_readback',
                   'reopen_readback', 'credential_encoding', 'ha_physical_acceptance')]), path


def _capture_task(key='first_capture', title='现场采集首组灯', *, allowed=True, why='尚无真实首组样本。'):
    return _task(key, title, 'needs_sample', 'prepare_capture', (
        '需要Mac、USB数据线、iPhone，以及当前能正常控制该灯的原摩根App；人在这套房子内。',
        '从现有记录填写已知主机IP，从Finder复制iPhone UDID；不猜IP、不扫描。',
        '确认保留原主机和面板，只测同一组普通开关灯；按以下十步操作并等待保存、统计和清理完成。',
        '失败或不确定如实记录，保留本轮原件，不能修改原件让核对通过。') + tuple(
            str(index + 1) + '. ' + title + '：' + detail for index, (title, detail) in enumerate(CAPTURE_STEPS)),
        stage='capture', allowed=allowed, why=why)


def refresh_flow(session_directory, data_root, selected_identifier='', comparison_directory=None,
                 review_file=None, wizard_file=None):
    """Return (private flow.json Path, display record), recomputing all gates.

    session_directory=None displays the initial capture guide. Explicit selected
    review/wizard paths are revalidated; no saved stage/next-action flags are
    accepted as input. A comparison is one independent new normal-App capture.
    """
    root = baseline._safe_path(data_root)
    if not root.is_dir():
        raise ValueError('请先选择现有本机数据目录')
    if session_directory is None and any(value is not None for value in (comparison_directory, review_file, wizard_file)):
        raise ValueError('须先选择首组原始采样文件夹，不能只凭下游材料跳过采样')
    stages = {key: _stage(key) for key, _ in STAGES}
    tasks, artifacts, sources = [], {}, []
    record = dict(schema_version=VERSION, artifact=ARTIFACT, flow_id=uuid.uuid4().hex,
        created_at=datetime.now(timezone.utc).isoformat(), scope=SCOPE,
        simulation=None, selected_identifier=None, target_ip=None, target_context=None,
        session_path=None, source_bindings=None, comparison=None, review=None, wizard=None,
        candidate_identifiers=[], independent_second_round=False,
        supported_profile=dict(status='not_assessed', wire_compatible=False, package_eligible=False,
            credential_check_required=False, profile_id=None),
        owner_declared_acceptance_passed=False, can_expand_to_other_lights=False,
        machine_physical_feedback_verified=False, physical_feedback_verified=False,
        can_generate_live_driver=False, can_start_live_ha=False, driver_executed=False,
        network_access_performed=False, upload_performed=False, raw_pcap_copied=False,
        credential_values_copied=False, credential_value_hashes_copied=False, bytes_sent=0)
    if session_directory is None:
        stages['capture'] = _stage('capture', 'needs_sample', '尚未选择首组原件；先在现场按十步正常操作采样。')
        tasks.append(_capture_task())
    else:
        primary = gaps._read_source(session_directory, root)
        sources.append(primary)
        identifier, mode = recipe._select(primary, selected_identifier)
        comparison = None
        if comparison_directory is not None:
            comparison = gaps._read_source(comparison_directory, root)
            sources.append(comparison)
            if primary['metadata']['simulation'] is not comparison['metadata']['simulation']:
                raise ValueError('不能合并真实与合成来源')
            if primary['metadata']['target_ip'] != comparison['metadata']['target_ip']:
                raise ValueError('两轮主机不同，不能合并不同主机或住宅')
            if primary['target_context'] != comparison['target_context']:
                raise ValueError('两轮普通灯标签或采集组不对应，不能合并不同灯路')
            if primary['binding']['traffic.pcap']['sha256'] == comparison['binding']['traffic.pcap']['sha256']:
                raise ValueError('两轮PCAP相同，复制原件不能作为独立第二轮')
            if identifier is None:
                raise ValueError('先明确选择第一轮完整标识，再加入第二轮')
            recipe._select(comparison, identifier)
        simulation = primary['metadata']['simulation']
        candidates = sorted({field['value_hex'] for frame in primary['report']['frames']
            for field in frame['parsed_frame']['fields'] if field['id'] == 4 and field['length'] == 8})
        if len(candidates) > 1024:
            raise ValueError('完整标识候选超过1024个上限；请在本机缩小采样范围')
        record.update(simulation=simulation, selected_identifier=identifier, selection_mode=mode,
            target_ip=primary['metadata']['target_ip'], target_context=primary['target_context'],
            session_path=primary['paths']['session_dir'], source_bindings=primary['binding'],
            candidate_identifiers=candidates, independent_second_round=comparison is not None)
        if comparison:
            record['comparison'] = dict(session_path=comparison['paths']['session_dir'],
                source_bindings=comparison['binding'])
        artifacts['report_directory'] = primary['paths']['report_dir']
        first_summary = gaps._source_summary(primary, identifier)
        second_summary = gaps._source_summary(comparison, identifier) if comparison else None
        gap_tasks = gaps._build_tasks(first_summary, second_summary, identifier, simulation, primary['target_context'])
        for row in gap_tasks:
            # Protocol implementation deficits are explained once by the
            # profile/session stages below; do not keep obsolete generic gates.
            if row['category'] == 'recapture' and row['status'] == 'needs_sample':
                tasks.append(_task('sample_' + row['id'], row['title'], 'needs_sample', 'prepare_capture',
                    row['instructions'], why=row['why'], allowed=row['capture_allowed'], existing_task_id=row['id']))
        machine = baseline.assess_report(primary['report'])
        record['baseline_machine_reviewable'] = machine['eligible_for_manual_review']
        review_status, _ = _review(review_file, root, primary, identifier)
        record['review'] = review_status
        wizard_status, _ = _wizard(wizard_file, root, primary, identifier, review_status)
        record['wizard'] = wizard_status
        stages['capture'] = _stage('capture', 'needs_sample' if simulation or any(row['id'] in (
            'sample_capture_complete', 'sample_target_traffic', 'sample_capture_loss',
            'sample_event_coverage') for row in tasks) else 'confirmed',
            '合成样本只能演练，不能作为本户材料。' if simulation else
            '已从本机原件重新读取采样、事件和PCAP并核对内容绑定；来源和亮灭仍是业主声明。')
        if identifier is None:
            tasks.insert(0, _task('select_target', '选择并核对完整灯标识', 'pending', 'select_identifier',
                ('选择原件中实际出现的完整16位标识，逐帧核对同一组普通灯；不自动选第一个，不用配置偏移。',), stage='baseline'))
        review_state = 'confirmed' if review_status['passed'] else 'pending'
        stages['baseline'] = _stage('baseline', review_state,
            '五项本机人工声明与当前原件、主机和灯路对应；这不等于机器看到了实灯。' if review_status['passed'] else
            '须在首组核对页逐项核对质量、同灯标识、两次开关、面板反馈及重进回读。')
        if not review_status['passed']:
            tasks.append(_task('review_baseline', '逐项核对首组，保存人工声明', 'pending', 'review_baseline',
                tuple(title + '：保留帧号与现场依据；不确定选待验证或需补采。' for _, title in baseline.CRITERIA), stage='baseline',
                why='未选择有效通过的同轮记录。' if not review_status['supplied'] else '所选记录未通过或与当前原件/标识不对应。'))
        codec_first = recipe._evaluate(primary, identifier)
        codec_second = recipe._evaluate(comparison, identifier) if comparison else None
        codec_supported = codec_first['codec_consistency'] and bool(codec_second and codec_second['codec_consistency'])
        codec_unsupported = bool(codec_first['unsupported_frames'] or codec_second and codec_second['unsupported_frames'])
        stages['codec'] = _stage('codec', 'software_required' if codec_unsupported else
            'confirmed' if codec_supported and not simulation else 'pending',
            '发现窄配方不支持的目标字段形状，须匹配软件支持；不要无限重采同样报文。' if codec_unsupported else
            '两轮开关编码和独立状态字段离线一致；ACK、执行应答未作状态，尚未证明实物因果。' if codec_supported else
            '仍需同一完整标识、独立新一轮的开关与面板/回读证据；相同PCAP不计新轮次。')
        workbench_path, workbench = sessions.create_workbench(session_directory, root,
            selected_identifier=identifier or '', comparison_directory=comparison_directory)
        if {name: workbench['source_bindings'][name] for name in baseline.INPUT_LIMITS} != _bindings(primary):
            raise ValueError('会话分析期间原件改变，未保存流程')
        artifacts['session_workbench_file'] = _relative(workbench_path, root)
        software_limits = [row for row in workbench['quality_findings'] if row['category'] == 'software_support']
        session_status = 'software_required' if software_limits else 'pending'
        stages['session'] = _stage('session', session_status,
            '存在加密、不透明或两轮后仍未知的连接边界；当前只保留线索，不推断免认证。' if software_limits else
            '已重算连接、认证字段形状、序号预测及重连回读；候选获支持仍需匹配固定驱动。')
        for row in workbench['tasks']:
            if row['category'] == 'recapture' and row['status'] == 'needs_sample':
                tasks.append(_task('session_' + row['id'], row['title'], 'needs_sample', 'prepare_capture',
                    row['instructions'], stage='session', why=row['why'],
                    allowed=bool(not simulation and identifier and primary['target_context']), existing_task_id=row['id']))
        profile, profile_path = _profile(session_directory, root, identifier, comparison_directory)
        record['supported_profile'] = profile
        if profile_path:
            artifacts['driver_profile_file'] = _relative(profile_path, root)
        for row in profile.get('tasks', []):
            if row['category'] == 'recapture' and row['status'] == 'needs_sample':
                task = _task('profile_' + row['id'], row['title'], 'needs_sample', 'prepare_capture',
                    row['instructions'], stage='driver', why=row['why'],
                    allowed=bool(not simulation and identifier and primary['target_context']), existing_task_id=row['id'])
                task['source_task_kind'] = 'driver_profile'
                tasks.append(task)
        stages['driver'] = _stage('driver', 'pending' if profile['wire_compatible'] else
            'needs_sample' if profile['status'] == 'needs_sample' else 'software_required',
            '报文字段与已实现窄策略相符；还须在本机凭据表单核对正常凭据来源，运行效果未验证。' if profile['wire_compatible'] else
            '当前尚无与本户证据完整匹配的驱动；加密、未知字段或认证不能靠猜填解决。')
        tasks.append(_task('match_driver', '匹配本机固定驱动策略',
            'pending' if profile['wire_compatible'] else 'software_required',
            'match_driver' if profile['wire_compatible'] else 'software_support',
            ('在本机核对策略；有受支持认证时仅在专用表单输入业主自己的正常凭据，不复制抓包认证字段。',
             '原件、凭据和匹配结果均留本机；未支持分支继续等待适配，不上传、不写Python。'),
            stage='driver'))
        stages['ha_package'] = _stage('ha_package', 'confirmed' if wizard_status.get('installation_declared') else 'pending',
            '已重新核对本户固定单灯安装包，操作者声明在HA安装和授权；这不认证操作者或实际安装。' if wizard_status.get('installation_declared') else
            '已核对本户驱动、固定模板安装包和内容绑定；安装与连接须在HA界面另行明确授权。' if wizard_status.get('bundle_present') else
            '首组通过且有匹配驱动后，图形向导生成单灯HA安装包；不要求业主编写Python。')
        owner_passed = wizard_status.get('owner_declared_acceptance_passed') is True
        record['owner_declared_acceptance_passed'] = owner_passed
        record['can_expand_to_other_lights'] = bool(owner_passed and not simulation)
        stages['acceptance'] = _stage('acceptance', 'confirmed' if owner_passed else 'pending',
            '八项HA日志与业主现场声明对齐；保留人工核对范围，不宣称机器验证灯本体。' if owner_passed else
            'HA开关各两次、面板开关、适配断开不可用、重连新读回，共八步；每步都要日志和肉眼状态。')
        for row in wizard.CASE_TITLES:
            tasks.append(_task('ha_' + row[0], row[1], 'confirmed' if owner_passed else 'pending',
                'record_ha_acceptance', ('在HA设备页选择此验收步骤并开始窗口，再执行动作，记录实际灯与HA显示。',
                    '导出该集成诊断到本机后，在图形工具选择对应事件并逐项写依据；ACK、缓存和旧代次不算真实状态。'), stage='acceptance'))
        # A valid imported driver is an explicit existing advanced path; do not
        # force it through the fixed matcher, but preserve all wizard checks.
        if wizard_status.get('driver_present'):
            stages['driver'] = _stage('driver', 'confirmed', '已重新核对操作者选定驱动的API、SHA和证据声明；Mac未执行，协议运行待验收。')
        next_task = _next_task(record, stages, tasks, workbench)
        record['next_action'] = next_task
    if session_directory is None:
        record['next_action'] = tasks[0]
    record.update(stages=[stages[key] for key, _ in STAGES], tasks=tasks, artifacts=artifacts,
        counts={key: sum(stage['status'] == key for stage in stages.values()) for key in STATUS_LABELS})
    for source in sources:
        recipe._verify_unchanged(source, root)
    parent = baseline._safe_path(root / 'private_first_light_flows')
    for source in sources:
        for relative in source['paths'].values():
            original = root / relative
            if parent == original or original in parent.parents:
                raise ValueError('流程输出不能位于原件或原分析目录内')
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    destination = parent / ('flow_' + record['flow_id'])
    destination.mkdir(mode=0o700)
    path = destination / 'flow.json'
    raw = json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    if len(raw.encode('utf-8')) > MAX_BYTES:
        raise ValueError('流程概览超过2MiB上限；未保存')
    recipe._write_private(path, raw)
    recipe._write_private(destination / '首组全过程.txt', render_text(record))
    return path, record


def _next_task(record, stages, tasks, workbench):
    def find(key):
        return next(row for row in tasks if row['id'] == key)
    if record['simulation'] is not False:
        return _capture_task('real_capture', '另采本户真实首组', allowed=False,
            why='演示不可转成真实样本；从采样页新建实采，不能改来源标记。')
    quality = [row for row in tasks if row['id'] in ('sample_capture_complete', 'sample_target_traffic',
        'sample_capture_loss', 'sample_event_coverage')]
    if quality:
        return quality[0]
    # A parser/software limitation cannot be solved by marking every baseline
    # checkbox; reveal it before asking the owner to review unsupported bytes.
    if stages['codec']['status'] == 'software_required' or any(row['category'] == 'software_support'
            for row in workbench['quality_findings']):
        return _task('inspect_unsupported', '查看封装或策略支持缺口', 'software_required', 'open_session_workbench',
            ('查看本机原件中的不透明、加密或字段冲突；保留原件，等待匹配实现，不无限重采相同动作。',), stage='session')
    if record['selected_identifier'] is None:
        return find('select_target')
    if not record['review']['passed']:
        if record['baseline_machine_reviewable']:
            return find('review_baseline')
        sampling = [row for row in tasks if row['stage_id'] == 'capture' and row['status'] == 'needs_sample'
                    and row['id'] != 'sample_independent_round']
        return sampling[0] if sampling else find('review_baseline')
    saved_wizard = record['wizard']
    if saved_wizard.get('valid') and saved_wizard.get('driver_present'):
        if not saved_wizard['bundle_present']:
            return _task('build_bundle', '生成本户单灯HA安装包', 'pending', 'build_ha_bundle',
                ('在HA接入页生成单灯安装包；核对固定主机、灯标识、代码版本和SHA后继续。',), stage='ha_package')
        if not saved_wizard['installation_declared']:
            return _task('install_bundle', '在HA界面安装并明确授权', 'pending', 'record_installation',
                ('按安装包内说明复制组件、重启HA并添加集成；核对固定主机和单灯标识，再由业主明确确认连接。',
                 '记录light实体ID，回本机图形工具填写安装声明。'), stage='ha_package')
        if not saved_wizard['owner_declared_acceptance_passed']:
            return _task('accept_ha', '完成八步真实状态验收', 'pending', 'record_ha_acceptance',
                tuple(title for _, title, _ in wizard.CASE_TITLES), stage='acceptance')
        return _task('complete', '首组人工现场验收已完成', 'confirmed', 'complete',
            ('保留这一组的原件、驱动、HA日志与现场声明；可再采下一组普通灯，每组独立核对与验收。',), stage='acceptance')
    if not record['independent_second_round']:
        return find('sample_independent_round')
    if record['supported_profile']['wire_compatible']:
        return find('match_driver')
    profile_sampling = [row for row in tasks if row['id'].startswith('profile_') and row['status'] == 'needs_sample']
    if profile_sampling:
        return profile_sampling[0]
    sampling = [row for row in tasks if row['stage_id'] == 'session' and row['status'] == 'needs_sample']
    if sampling:
        return sampling[0]
    return find('match_driver')


def render_text(record):
    lines = ['MC7021 首组灯全过程', SCOPE, '', '当前下一步：' + record['next_action']['title'],
             '状态：' + record['next_action']['status_label']]
    lines.extend('• ' + text for text in record['next_action']['instructions'])
    lines.extend(['', '全过程状态：'])
    for stage in record['stages']:
        lines.extend([stage['title'] + '：' + stage['status_label'], stage['summary']])
    lines.extend(['', '全部缺口与现场动作：'])
    for task in record['tasks']:
        lines.append(task['title'] + '：' + task['status_label'])
        lines.extend('• ' + text for text in task['instructions'])
    lines.extend(['', '资料只在本机。概览没有复制PCAP、认证值或认证值哈希；旧概览不授予采样、驱动或HA控制权限。'])
    return '\n'.join(lines) + '\n'


def worker_summary(record):
    """Bounded presentation fields for the native GUI; never a live grant."""
    if record.get('artifact') != ARTIFACT or record.get('schema_version') != VERSION:
        raise ValueError('不是当前首组流程概览')
    return {key: record[key] for key in ('simulation', 'selected_identifier', 'target_ip',
        'target_context', 'session_path', 'candidate_identifiers', 'independent_second_round',
        'stages', 'next_action', 'tasks', 'artifacts', 'counts', 'review', 'wizard',
        'supported_profile', 'owner_declared_acceptance_passed', 'can_expand_to_other_lights')} | dict(
        report_text=render_text(record), can_generate_live_driver=False, can_start_live_ha=False,
        physical_feedback_verified=False, bytes_sent=0, upload_performed=False)
