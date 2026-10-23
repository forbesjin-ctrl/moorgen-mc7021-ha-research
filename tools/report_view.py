#!/usr/bin/env python3
"""Render a private, standalone Chinese HTML view of an offline sample report.

No file access, scripts, external assets, network requests or uploads occur here.
All report values are untrusted text. Native HTML details provide disclosure.
"""
from __future__ import annotations

from collections.abc import Mapping
from html import escape
import json


UNKNOWN = '未知'


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def _rows(value):
    return value if isinstance(value, (list, tuple)) else []


def _text(value, default=UNKNOWN):
    if value is None or value == '':
        value = default
    elif isinstance(value, bool):
        value = '是' if value else '否'
    elif isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return escape(str(value), quote=True)


def _dump(value):
    return escape(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True,
                             default=str), quote=True)


def _status(value):
    # Classes are constants, never derived from an untrusted status string.
    labels = {
        'pass': ('ok', '通过'), 'ok': ('ok', '通过'),
        'complete': ('ok', '记录完整'), 'completed': ('ok', '记录完成'),
        'good': ('ok', '可继续核对'), 'warning': ('warn', '需注意'),
        'warn': ('warn', '需注意'), 'partial': ('warn', '不完整'),
        'incomplete': ('warn', '不完整'), 'fail': ('bad', '未通过'),
        'failed': ('bad', '未通过'), 'error': ('bad', '错误'),
        'blocked': ('bad', '受阻'), 'unknown': ('muted', UNKNOWN),
        'pending': ('muted', '待核对'), 'skipped': ('muted', '已跳过'),
        'reviewable': ('muted', '可供人工离线复核'),
        'limited': ('warn', '存在限制'), 'recorded': ('muted', '记录完整'),
        'candidate': ('muted', '候选'),
    }
    css, label = labels.get(str(value), ('muted', value if value else UNKNOWN))
    return '<span class="badge {}">{}</span>'.format(css, _text(label))


def _list(values, empty):
    entries = _rows(values)
    if not entries:
        return '<p class="empty">{}</p>'.format(escape(empty))
    return '<ul>' + ''.join('<li>{}</li>'.format(_text(value)) for value in entries) + '</ul>'


def _raw(title, value):
    return '<details><summary>{}</summary><pre>{}</pre></details>'.format(
        escape(title), _dump(value))


def _observed(value):
    return _text({'on': '亮 / 开', 'off': '灭 / 关', 'not_visible': '当前未显示',
                  'unknown': UNKNOWN}.get(str(value), value))


def _table(headings, rows, empty):
    if not rows:
        return '<p class="empty">{}</p>'.format(escape(empty))
    return ('<div class="table-scroll"><table><thead><tr>'
            + ''.join('<th scope="col">{}</th>'.format(escape(item)) for item in headings)
            + '</tr></thead><tbody>'
            + ''.join('<tr>' + ''.join('<td>{}</td>'.format(item) for item in row)
                      + '</tr>' for row in rows)
            + '</tbody></table></div>')


def _baseline(report):
    assessment = _mapping(report.get('baseline_assessment'))
    current = assessment.get('artifact') == 'first_light_baseline_assessment'
    if not current:
        return ('<section id="baseline"><h2><span>首组</span>首组报文核对</h2>'
                '<div class="ha-state"><strong>首组核对：未知，尚未人工确认</strong>'
                '<p>此报告缺少首组自动核对字段，可能由旧版工具生成。请用新版重新分析同一份原件；'
                '缺少字段不能视为通过，也不能据此引导采其他灯。</p></div></section>')
    # A saved report is untrusted input. In particular its passed flag must not
    # turn this read-only rendering into approval of a physical correspondence.
    eligible = (report.get('simulation') is False
                and assessment.get('eligible_for_manual_review') is True)
    heading = '可进入逐项人工核对' if eligible else '证据仍有缺口，先按提示核对或补采'
    columns = (
        ('已确认', '仅限机器检查到的文件与记录结构事实', 'confirmed',
         '尚无可确认的文件或结构事实；不能把未知当作零或正常。'),
        ('待验证', '协议候选及与实际灯路的对应关系', 'pending',
         '未提供待验证项；实际灯路、真实状态与会话条件仍需人工核对。'),
        ('需补采', '缺少或冲突的证据及建议动作', 'resample',
         '自动检查暂未列出补采项；仍须人工逐项核对，不能据此认定首组通过。'),
    )
    groups = '<div class="baseline-groups">' + ''.join(
        '<div><h3>{}</h3><p class="note">{}</p>{}</div>'.format(
            escape(title), escape(note), _list(assessment.get(key), empty))
        for title, note, key, empty in columns) + '</div>'
    rows = []
    states = {'ready': '有候选证据，仍须人工核对', 'pending': '待验证', 'resample': '需补采'}
    for value in _rows(assessment.get('criteria')):
        item = _mapping(value)
        rows.append((_text(item.get('title')),
                     _text(states.get(str(item.get('machine_status')), UNKNOWN)),
                     _list(item.get('evidence'), '未提供可复核证据，不能视为通过。'),
                     '必须由人工逐项确认，并记录依据；未核对保持待验证'))
    simulation = ('<p class="baseline-blocker">合成演练只能体验核对流程，不能确认首组真实灯路，'
                  '不能解锁其他灯采样。</p>') if report.get('simulation') is True else ''
    return ('<section id="baseline"><h2><span>首组</span>首组报文核对</h2>'
            '<div class="ha-state"><strong>首组核对：尚未人工确认 · ' + heading + '</strong>'
            '<p>自动检查不会确认真实灯路。“已确认”仅指文件与结构事实；'
            '开关含义、状态来源、面板对应及重进 App 回读仍是候选解释，ACK 不能作为状态反馈。'
            '人工通过是本轮证据的复核声明，不改变 HA 接入或真实物理反馈的自动验证标记。</p></div>'
            + simulation + groups
            + '<h3>逐项人工必需核对</h3>'
            + _table(('核对项目', '自动检查结果', '证据与引用（私有）', '人工要求'), rows,
                     '缺少逐项核对项目；请重新分析原件，不能确认首组或采其他灯。')
            + '<h3>当前阻碍</h3>'
            + _list(assessment.get('blockers'), '未列出机器阻碍，仍须完成人工复核。')
            + '<p class="note">可由具备分析能力的业主或协助分析者复核原始样本。'
            '在图形工具中逐项填写依据并保存绑定本轮原件的复核记录后，才引导采其他灯。'
            '本页是静态报告，不提供确认按钮，也不批准在线控制。</p></section>')


def _quality(report):
    quality = _mapping(report.get('quality'))
    checks = []
    for value in _rows(quality.get('checks')):
        item = _mapping(value)
        checks.append((_text(item.get('name')), _status(item.get('status')),
                       _text(item.get('detail'))))
    return ('<section id="quality"><h2><span>01</span>样本质量</h2>'
            '<p>质量结论：' + _status(quality.get('level'))
            + '。质量通过只说明样本可用于分析，不表示协议或设备兼容。</p>'
            + _table(('检查项', '结果', '说明'), checks, '尚无质量检查结果，不能判断样本是否完整。')
            + '<h3>采样与解析提醒</h3>'
            + _list(quality.get('warnings'), '未提供提醒记录；这不代表没有丢包、缺口或其他问题。')
            + '</section>')


def _events(report):
    rows = []
    for value in _rows(report.get('events')):
        item = _mapping(value)
        window = ('<span class="time">准备：{}</span><span class="time">确认：{}</span>'
                  '<span class="time">观察至：{}</span>').format(
                      _text(item.get('ready_at')), _text(item.get('confirmed_at')),
                      _text(item.get('window_end')))
        observations = '肉眼：{}<br>App：{}'.format(
            _observed(item.get('physical_light')), _observed(item.get('app_display')))
        evidence = ('包：{} · 帧：{}<br>命令：{} · 状态：{}<br>执行应答：{} · ACK：{}').format(
            _text(item.get('packet_count')), _text(item.get('frame_indices')),
            _text(item.get('command_count')), _text(item.get('state_count')),
            _text(item.get('execution_response_count')),
            _text(item.get('ack_count')))
        rows.append(('<strong>{}</strong>'.format(_text(item.get('step'))), window,
                     observations, evidence, _status(item.get('status'))))
    return ('<section id="events"><h2><span>02</span>单灯动作时间线</h2>'
            '<p class="note">实际动作发生在“准备”至“确认”之间。时间邻近仅供关联，'
            '不能证明因果；肉眼记录、App 显示、协议状态分开核对。ACK 不是状态反馈。</p>'
            + _table(('步骤', '动作与观察区间', '用户观察', '区间内证据', '记录状态'),
                     rows, '尚无动作记录，不能把报文归属到一次具体操作。')
            + '</section>')


def _devices(report):
    rows = []
    for value in _rows(report.get('device_candidates')):
        item = _mapping(value)
        confirmed = item.get('ordinary_light_verified') is True
        context = ('输入标记：普通灯已确认；仍需核对依据' if confirmed
                   else '普通灯类型待确认')
        if item.get('ordinary_light_context') == 'operator_declared':
            context = '人工声明，尚未验证'
        rows.append(('<code>{}</code>'.format(_text(item.get('identifier_hex'))),
                     '开：{} · 关：{}'.format(_text(item.get('command_on_count')),
                                             _text(item.get('command_off_count'))),
                     _text(item.get('state_record_count')),
                     _text(item.get('panel_state_windows')),
                     _text(item.get('reopen_state_windows')), escape(context)))
    return ('<section id="devices"><h2><span>03</span>设备候选与状态线索</h2>'
            '<p class="note">完整标识来自通信中的候选记录；不把配置文件偏移或内部键当作通信地址。'
            '同一标识出现在开关和状态记录中，仍需结合单灯操作验证。</p>'
            + _table(('标识（私有）', 'App 开关命令', '状态记录', '面板步骤窗口',
                      '重进 App 窗口', '设备类型依据'), rows,
                     '尚未识别设备候选；不自动填入地址或生成可发送的控制配置。')
            + '</section>')


def _flows(report):
    rows = []
    for value in _rows(report.get('flows')):
        item = _mapping(value)
        endpoints = '{}:{} → {}:{}'.format(_text(item.get('src')), _text(item.get('sport')),
                                           _text(item.get('dst')), _text(item.get('dport')))
        rows.append((_text(item.get('id')), '{} / {}'.format(_text(item.get('transport')),
                                                           _text(item.get('direction'))),
                     '<span class="endpoint">{}</span>'.format(endpoints),
                     _text(item.get('payload_bytes')), _text(item.get('frame_count')),
                     _text(item.get('payload_classification')),
                     _list(item.get('issues'), '未提供问题记录')))
    return ('<section id="flows"><h2><span>04</span>通信流与重组情况</h2>'
            '<p class="note">未识别、加密、不支持或存在缺口的数据保留未知。'
            '未解析到明文帧不等于没有通信。</p>'
            + _table(('流', '协议 / 方向', '端点（私有）', '载荷字节', '帧数',
                      '载荷分类', '重组问题'), rows, '尚无通信流分析。') + '</section>')


def _frames(report):
    rows = []
    for value in _rows(report.get('frames')):
        item = _mapping(value)
        provenance = '流：{}<br>包号：{}<br>{}<br>至 {}'.format(
            _text(item.get('flow_id')), _text(item.get('packet_indices')),
            _text(item.get('timestamp_start')), _text(item.get('timestamp_end')))
        detail = '设备：{}<br>命令：{}'.format(_text(item.get('device_identifiers')),
                                             _text(item.get('command')))
        detail += _raw('查看本帧原始分析字段', item)
        rows.append((_text(item.get('index')), provenance, _text(item.get('direction')),
                     _text(item.get('kind')), detail))
    return ('<section id="frames"><h2><span>05</span>协议帧证据索引</h2>'
            '<p class="note">可展开查看字段与状态原值。执行应答、ACK、状态推送、详情回读'
            '应分别识别；收到状态字节并不能证明灯具实际发光。</p>'
            + _table(('帧', '来源与时间', '方向', '分类', '内容与原始字段'), rows,
                     '尚无可解析协议帧。若载荷为加密或未知格式，需继续离线研究。')
            + '</section>')


def _readiness(report):
    readiness = _mapping(report.get('readiness'))
    rows = []
    for value in _rows(readiness.get('gates')):
        item = _mapping(value)
        rows.append((_text(item.get('name')), _status(item.get('status')),
                     _text(item.get('detail'))))
    return ('<section id="next"><h2><span>06</span>证据缺口与下一步</h2>'
            '<div class="ha-state"><strong>Home Assistant 接入：待人工验证</strong>'
            '<p>本报告不批准实时控制，不生成可直接启用的家庭设备配置。'
            '需要人工确认协议分支、普通灯标识、会话条件、独立状态与重连回读；'
            '分析结果和合成测试通过不能替代住户实测。</p></div>'
            + _table(('验证条件', '当前证据状态', '说明'), rows,
                     '尚无接入条件检查，不能开始实时接入。')
            + '<h3>保留未知</h3>'
            + _list(report.get('unknowns'), '未提供未知项清单；人工验证仍未完成。')
            + '<h3>建议下一步</h3>'
            + _list(report.get('next_actions'), '先复核样本质量及单灯动作证据，再决定需要补充的最小样本。')
            + '</section>')


STYLE = '''
:root{color-scheme:light;--ink:#1d2a32;--muted:#5b6b74;--line:#dce3e6;--accent:#086b74}
*{box-sizing:border-box}body{margin:0;background:#f4f6f6;color:var(--ink);font:15px/1.65 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:1240px;margin:0 auto;background:#fff;padding:38px 44px 28px}header{border-top:5px solid var(--accent);padding-top:22px}h1{font-size:30px;line-height:1.3;margin:12px 0}h2{font-size:21px;margin:0 0 15px}h2>span{color:var(--accent);font-size:14px;letter-spacing:1px;margin-right:13px}h3{font-size:16px;margin:23px 0 8px}p{margin:8px 0 14px}.eyebrow{color:var(--accent);font-size:12px;letter-spacing:2px;font-weight:700}.privacy{background:#eaf4f4;border-left:4px solid var(--accent);padding:12px 16px;margin:19px 0}.privacy strong{display:block;font-size:17px}.privacy p,.ha-state p{margin-bottom:0}.simulation{background:#fff3d9;border:2px solid #9a6c0b;padding:13px 16px;margin:15px 0;color:#684600;font-weight:700}.meta{font-size:13px;color:var(--muted);overflow-wrap:anywhere}.counts{display:flex;flex-wrap:wrap;border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:25px 0 18px;padding:15px 0;gap:16px 38px}.counts div{min-width:110px}.counts dt{font-size:12px;color:var(--muted)}.counts dd{font-size:26px;font-weight:650;margin:0;line-height:1.4}nav{display:flex;gap:8px 20px;flex-wrap:wrap;padding-bottom:6px}nav a{color:var(--accent);text-decoration:none;font-size:13px}nav a:hover{text-decoration:underline}section{border-top:1px solid var(--line);margin-top:28px;padding-top:27px}.note,.empty{color:var(--muted);font-size:14px}.empty{background:#f7f9f9;padding:12px 14px}.table-scroll{overflow-x:auto;margin-top:16px}table{width:100%;border-collapse:collapse;font-size:13px;text-align:left}th{padding:10px 12px;background:#edf2f3;font-size:12px;white-space:nowrap}td{vertical-align:top;padding:13px 12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere;max-width:430px}td ul{margin:0;padding-left:16px;min-width:120px}.time{display:block;font-size:12px;white-space:nowrap}.badge{display:inline-block;border-radius:3px;padding:2px 7px;font-size:12px;white-space:nowrap}.badge.ok{background:#e5f1e9;color:#285c3b}.badge.warn{background:#fff0ce;color:#805709}.badge.bad{background:#fde9e6;color:#9d302b}.badge.muted{background:#edf0f1;color:#5c6970}code,pre,.endpoint{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}code{font-size:12px}details{margin-top:10px}summary{color:var(--accent);cursor:pointer;font-size:12px}pre{font-size:11px;line-height:1.6;background:#f1f4f4;white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;max-height:430px;overflow:auto}.ha-state{border-left:4px solid #b68325;background:#fff8e9;padding:14px 17px;margin:16px 0}.ha-state strong{color:#725214}li{margin:6px 0}footer{border-top:1px solid var(--line);margin-top:35px;padding-top:16px;font-size:12px;color:var(--muted)}
.baseline-groups{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:19px 0}.baseline-groups>div{border:1px solid var(--line);padding:0 16px 12px;overflow-wrap:anywhere}.baseline-groups h3{margin-top:13px}.baseline-groups ul{padding-left:18px}.baseline-blocker{background:#fff0ce;color:#805709;padding:12px 16px;font-weight:650}
@media(max-width:740px){main{padding:24px 18px}h1{font-size:25px}.counts{gap:12px 24px}.counts div{min-width:82px}.counts dd{font-size:23px}td,th{padding:10px 9px}nav{gap:8px 15px}.baseline-groups{grid-template-columns:1fr}}
@media print{body{background:white}main{max-width:none;padding:12px}nav{display:none}.table-scroll{overflow:visible}pre{max-height:none}section{break-inside:auto}thead{display:table-header-group}.privacy,.simulation,.ha-state,th{print-color-adjust:exact}a{color:inherit}details>pre{display:block}summary{display:none}}
'''


def render_report(report: dict) -> str:
    """Return complete UTF-8 HTML; absent fields remain explicitly unknown.

    This view never trusts an input flag to authorize live Home Assistant use.
    The caller owns private file storage and must not publish the report.
    """
    report = _mapping(report)
    summary = _mapping(report.get('summary'))
    metrics = [('packet_count', '原始包数'), ('target_packet_count', '目标主机包数'),
               ('payload_packets', '载荷包数'), ('frame_count', '可解析帧'),
               ('device_count', '设备候选')]
    counts = '<dl class="counts">' + ''.join(
        '<div><dt>{}</dt><dd>{}</dd></div>'.format(label, _text(summary.get(key)))
        for key, label in metrics) + '</dl>'
    simulation = report.get('simulation')
    banner = ('<div class="simulation" role="note">合成演练报告 · 不是住户实际通信 · '
              '不能用于判断设备兼容或真实灯光反馈</div>') if simulation is True else ''
    if simulation is not True and simulation is not False:
        banner = '<div class="simulation" role="note">样本是否为合成演练：未知。请先核对原始来源。</div>'
    title = 'MC7021 单灯离线分析报告'
    return ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<meta name="referrer" content="no-referrer"><title>' + title + '</title>'
            '<style>' + STYLE + '</style></head><body><main><header>'
            '<div class="eyebrow">MC7021 / 单组普通灯 / 离线研究记录</div><h1>' + title + '</h1>'
            '<p class="meta">分析编号：' + _text(report.get('analysis_id'))
            + '　·　报告格式：' + _text(report.get('schema_version')) + '</p>'
            '<div class="privacy" role="note"><strong>私有报告，不上传</strong>'
            '<p>本页可能包含住户 IP、设备标识、操作时间及报文字段。仅在本机审阅；'
            '不要把报告或原始抓包提交到公开仓库、Issue 或业主群。页面无需联网。</p></div>'
            + banner + counts
            + '<nav aria-label="报告章节"><a href="#baseline">首组核对</a>'
            '<a href="#quality">样本质量</a>'
            '<a href="#events">动作时间线</a><a href="#devices">设备候选</a>'
            '<a href="#flows">通信流</a><a href="#frames">协议帧</a>'
            '<a href="#next">接入条件与下一步</a></nav></header>'
            + _baseline(report) + _quality(report) + _events(report) + _devices(report)
            + _flows(report) + _frames(report) + _readiness(report)
            + '<section id="source"><h2><span>附</span>来源与完整性记录</h2>'
            + _raw('展开输入来源记录（私有）', _mapping(report.get('source')))
            + '</section><footer>本报告为离线分析视图。已观测事实、协议候选与未验证结论应分别核对。'
            '本页不会扫描设备、发送控制指令、修改配置或上传样本。</footer>'
            '</main></body></html>')
