"""Export local first-light evidence for HA integration research, never control.

This module only reads and writes bounded private files. It has no network,
package installation, protocol replay, Home Assistant configuration or device
control path. A passed human review opens research, not a working adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid
from datetime import datetime, timezone

try:
    from . import baseline_review as baseline
except ImportError:
    import baseline_review as baseline


VERSION = '0.5.0'
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_MODEL_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 34 * 1024 * 1024
STATE_MODEL_PATH = Path(__file__).absolute().parent / 'light_state_model.py'
STEPS = (
    ('connection_authentication', '连接与认证', '核对本户正常会话的连接、认证及加密条件；协议和端口均待验证，不能把9000认定为标准Modbus。'),
    ('command_session', '命令与会话', '研究已核对普通灯的开关字段及当前会话、序列、认证约束；采到的旧报文不能直接重放。'),
    ('independent_state', '独立状态', '实现同一完整标识的独立状态解析；ACK、执行应答、App缓存和本地开关请求不能更新真实状态。'),
    ('unavailable_reconnect', '断线与重连', '断线或状态过期应不可用；重连建立新接收代次，旧回调不得更新新会话，取得当前独立状态后再恢复可用。'),
    ('single_light_acceptance', '单灯现场验收', '另行安排HA开关、实体面板同步、断线不可用与重连读回的单灯实测；通过后逐组增加同类灯，新设备类型另采另验。'),
)

GUIDE = """# 开始 HA 接入研究（私有）

这份材料来自本机已经通过的首组五项人工核对。具备协议分析和 Home
Assistant 开发经验的业主，可以据此自行继续研究和编写单灯适配器。
首组核对是研究入口，不是可运行适配器，也不证明机器已验证物理反馈。

## 材料及隐私

manifest.json 索引人工选定的完整候选标识、本机原件相对路径、原件与复制
文件的 SHA-256。baseline_review.json 是人工声明副本，report.json 是完整
私有分析报告，可能包含主机地址、设备标识、原始帧或认证字段。全部仅供
本机或事先约定的私下核对，不要上传公开 GitHub、业主群或公开工单。
原始 PCAP 没有复制；仍在所选本机数据目录中，按 manifest 索引查找。

## 按顺序推进

1. **连接与认证**：核对正常通信的协议封装、端口、认证和加密条件。
   9000 只是此前线索，不能据此认定标准 Modbus，也不能猜寄存器地址。
2. **命令与会话**：核对开关字段及当前会话、序列和认证约束，再编写适配。
   配置文件偏移不是通信地址；正常样本不等于可直接重放的控制指令。
3. **独立状态**：把主机独立状态与面板变化对照。ACK、执行应答、缓存和
   本地请求都不能当作灯已亮灭。light_state_model.py 是可复用的纯离线
   状态内核；其代次是软件代次，不是厂家会话，不能替代协议解析。
4. **断线与重连**：断线或状态过期标记不可用，重连后读回当前独立状态；
   旧接收回调不得写入新代次。内核的默认超时只是本地策略，未测得厂家心跳。
5. **单灯验收**：另行明确安排现场验证 HA 开/关、实体面板同步、断线
   不可用与重连读回。先保留原主机和面板，只验证这一组普通灯。

五项通过后再逐组扩展同类灯；调光、窗帘、场景等新类型须独立采样和核对。
本轮人工声明不能认证住宅身份，也不能套用成其它主机或设备的协议结论。

## 当前边界

协议、认证、端口、会话规则、开关字节及独立状态解码器仍留空待验证。
这不是可直接导入的 HA 配置，不启用在线控制。导出操作不会连接或扫描
设备、安装 HA、上传文件、索取或写入密钥、发送报文、重放抓包或修改配置。
后续线上测试需要另行安排；不操作物业安防。
"""


def _safe_path(value):
    path = Path(os.path.abspath(os.path.expanduser(str(value))))
    if any(item.is_symlink() for item in (path,) + tuple(path.parents)):
        raise ValueError('不接受符号链接目录或文件：' + path.name)
    return path


def _read(path, limit):
    path = _safe_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('导出输入不是普通文件或超过大小上限：' + path.name)
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            raw = source.read(limit + 1)
        after = os.fstat(descriptor)
        if len(raw) > limit or (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('读取期间文件发生变化：' + path.name)
        return raw
    finally:
        os.close(descriptor)


def _digest(raw):
    return dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as destination:
        os.fchmod(destination.fileno(), 0o600)
        destination.write(raw)
        destination.flush()
        os.fsync(destination.fileno())


def _passed(review_file, root, expected_host):
    validation = baseline.validate_review(review_file, root, expected_host=expected_host)
    if validation.get('valid') is not True or validation.get('passed') is not True:
        raise ValueError('首组核对未通过或已失效，不能进入HA接入研究；先核对原件、主机和五项人工结论。')
    return validation['record']


def export_handoff(review_file, data_root, expected_host=None):
    """Return (private directory, manifest) only after an unchanged passed review.

    Interrupted/failed exports retain a hidden incomplete folder and an explicit
    failure marker. Originals are never edited or deleted; no partial folder is
    returned as a successful handoff.
    """
    root, review_file = _safe_path(data_root), _safe_path(review_file)
    if not root.is_dir():
        raise ValueError('请选择现有本机数据目录。')
    record = _passed(review_file, root, expected_host)
    review_raw = _read(review_file, MAX_JSON_BYTES)
    if json.loads(review_raw.decode('utf-8')) != record:
        raise ValueError('读取期间人工核对记录发生变化，请重新检查。')
    report_file = _safe_path(root / record['source']['report_dir'] / 'report.json')
    report_raw = _read(report_file, MAX_JSON_BYTES)
    if _digest(report_raw) != record['input_integrity']['report.json']:
        raise ValueError('报告已改变，旧核对失效。')
    model_raw = _read(STATE_MODEL_PATH, MAX_MODEL_BYTES)
    copied = {'baseline_review.json': review_raw, 'report.json': report_raw,
              'light_state_model.py': model_raw, '开始HA接入.md': GUIDE.encode('utf-8')}
    total_bytes = sum(len(raw) for raw in copied.values())
    if total_bytes > MAX_OUTPUT_BYTES:
        raise ValueError('接入材料超过导出大小上限。')
    original_files = {}
    for name in baseline.INPUT_LIMITS:
        original_files[name] = dict(path=str(Path(record['source']['session_dir']) / name),
                                    **record['input_integrity'][name])
    manifest = dict(schema_version=VERSION, artifact='private_ha_integration_handoff',
        created_at=datetime.now(timezone.utc).isoformat(), stage='integration_research',
        can_start_integration_work=True, live_control_enabled=False,
        private=True, contains_private_protocol_evidence=True, automatic_upload_enabled=False,
        identity_authenticated=False, physical_feedback_verified=False,
        selected_wire_identifier=record['selected_identifier'],
        selected_identifier_source='explicit_human_review_candidate',
        host_ip=record['host_ip'], target_context=record.get('target_context'),
        baseline_review_ref=dict(path=str(review_file.relative_to(root)),
                                 review_id=record.get('review_id'), **_digest(review_raw)),
        baseline_source=record['source'], baseline_input_integrity=record['input_integrity'],
        local_originals=original_files, pcap_copied=False,
        copied_files={name: _digest(raw) for name, raw in copied.items()},
        ha_steps=[dict(id=key, title=title, status='pending', detail=detail)
                  for key, title, detail in STEPS],
        unresolved_parameters=dict(protocol=None, transport=None, port=None,
            authentication=None, encryption=None, session_rules=None, sequence_rules=None,
            on_command_bytes=None, off_command_bytes=None, independent_state_decoder=None,
            state_query_bytes=None, credentials=None),
        note='这是私有接入研究材料，不是可导入HA配置；人工通过不代表可运行适配或机器验证物理反馈。')
    manifest_raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if total_bytes + len(manifest_raw) > MAX_OUTPUT_BYTES:
        raise ValueError('接入材料超过导出大小上限。')
    folder = _safe_path(root / 'private_ha_handoffs')
    folder.mkdir(mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise ValueError('私有接入材料保存位置不是目录。')
    folder.chmod(0o700)
    identifier = uuid.uuid4().hex
    staging = folder / ('.handoff_' + identifier + '.incomplete')
    destination = folder / ('handoff_' + identifier)
    staging.mkdir(mode=0o700)
    staging.chmod(0o700)
    try:
        for name, raw in copied.items():
            _write(staging / name, raw)
        _write(staging / 'manifest.json', manifest_raw)
        for name, raw in dict(copied, **{'manifest.json': manifest_raw}).items():
            if _digest(_read(staging / name, MAX_OUTPUT_BYTES)) != _digest(raw):
                raise ValueError('导出副本校验失败：' + name)
        current = _passed(review_file, root, expected_host)
        if current != record or _read(review_file, MAX_JSON_BYTES) != review_raw:
            raise ValueError('导出期间人工核对记录发生变化；本次材料未完成。')
        if _read(report_file, MAX_JSON_BYTES) != report_raw:
            raise ValueError('导出期间报告发生变化；本次材料未完成。')
        if destination.exists() or destination.is_symlink():
            raise ValueError('导出目标已存在，请重新导出。')
        staging.rename(destination)
    except Exception as error:
        try:
            _write(staging / 'EXPORT_FAILED.txt', (
                '本次导出未完成，不可作为接入材料。原始采样未修改。\n' + str(error)[:2000] + '\n').encode('utf-8'))
        except OSError:
            pass
        raise
    return destination, manifest
