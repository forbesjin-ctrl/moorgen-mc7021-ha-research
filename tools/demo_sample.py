#!/usr/bin/env python3
"""Create synthetic TCP/IP/SHCP and event fixtures locally; never capture or send.

All endpoints are documentation addresses. The complete sample is explicitly
synthetic, including the PCAP metadata and every event. It proves tooling only.
"""
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import uuid

try:
    from . import offline_shcp as codec
except ImportError:
    import offline_shcp as codec

HOST = '192.0.2.20'
PHONE = '198.51.100.2'
DEVICE = bytes.fromhex('0102030405060708')


def checksum(raw):
    if len(raw) % 2:
        raw += b'\0'
    value = sum(struct.unpack('!{}H'.format(len(raw) // 2), raw))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def network_packet(src, dst, payload, sequence, flags=0x18):
    source, destination = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    sport, dport = (49152, 9000) if src == PHONE else (9000, 49152)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, sequence, 0, 0x50, flags, 65535, 0, 0) + payload
    pseudo = source + destination + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return ip + tcp


def create_demo_sample(output_root):
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    folder = root / ('SYNTHETIC_' + uuid.uuid4().hex[:12])
    folder.mkdir(mode=0o700)
    beginning = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=8)))
    base = beginning.timestamp()
    packets, events = [], []
    sequences = {PHONE: 1000, HOST: 8000}
    def event(offset, kind, **values):
        stamp = (beginning + timedelta(seconds=offset)).isoformat()
        events.append(dict(timestamp=stamp, event=kind, simulation=True, **values))
        return stamp
    def send(offset, src, payload=b'', flags=0x18):
        packet = network_packet(src, HOST if src == PHONE else PHONE, payload, sequences[src], flags)
        packets.append((base + offset, packet))
        sequences[src] += len(payload) + bool(flags & 2)
    def state(on, detail=False):
        return codec.build_frame(
                1, 3 if detail else 5, 8 if detail else 12, 1,
                ([(15, b'\x04')] if detail else [(27, b'\x03')]) +
                [(4, DEVICE), (6, '合成测试灯'.encode()), (11, bytes([int(on)]))])
    send(0, PHONE, flags=2)
    send(0.01, HOST, flags=0x12)
    names = [('初始同步', False), ('App开1', True), ('App关1', False), ('App开2', True),
             ('App关2', False), ('面板开', True), ('面板关', False), ('关闭App', None),
             ('App关闭期间面板开', True), ('重进App读状态', True)]
    for number, (step, on) in enumerate(names):
        start = 10 + number * 30
        event(start, 'instruction', step=step, instruction='合成动作；不操作实际设备')
        ready = event(start + 1, 'action_ready', step=step)
        confirmed = event(start + 2, 'action_confirmed', step=step, ready_at=ready,
                          user_reports_executed=True, exact_action_time_unknown=True)
        if step.startswith('App') and step in ('App开1', 'App关1', 'App开2', 'App关2'):
            frame = codec.build_candidate_light_frame(DEVICE, on, number)
            send(start + 1.1, PHONE, frame[:13])
            send(start + 1.2, PHONE, frame[13:])
            send(start + 2.1, HOST, codec.build_frame(1, 4, 11, number, []))
            send(start + 2.3, HOST, state(on))
        elif step in ('初始同步', '重进App读状态'):
            send(start + 1.3, PHONE, codec.build_frame(1, 3, 7, number, [(15, b'\x04')]))
            send(start + 2.3, HOST, state(on, detail=True))
        elif step in ('面板开', '面板关'):
            send(start + 2.3, HOST, state(on))
        if on is not None:
            event(start + 20, 'observation', step=step, physical_light='on' if on else 'off',
                  app_display='not_visible' if step == 'App关闭期间面板开' else 'on' if on else 'off',
                  update_observed='yes', evidence='synthetic_not_household_observation')
        event(start + 21, 'step_finished', step=step, ready_at=ready, confirmed_at=confirmed)
    raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))
    for when, packet in sorted(packets):
        seconds = int(when)
        raw.extend(struct.pack('<IIII', seconds, int(round((when - seconds) * 1000000)), len(packet), len(packet)))
        raw.extend(packet)
    metadata = dict(script_version='0.2.0-synthetic', simulation=True, status='completed', target_ip=HOST,
        sample_origin='synthetic_fixture', runtime_compatibility_verified=False,
        project_household_verified=False, skipped_steps=[],
        pcap=dict(file='traffic.pcap', size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
        capture_stop=dict(stats=dict(captured=len(packets), dropped_by_kernel=0)))
    for name, content in [('traffic.pcap', bytes(raw)),
                          ('session.json', json.dumps(metadata, ensure_ascii=False, indent=2).encode()),
                          ('events.jsonl', ('\n'.join(json.dumps(e, ensure_ascii=False) for e in events) + '\n').encode()),
                          ('合成演示说明.txt', '全部报文、设备和观察均为程序合成，没有接触家庭设备；不是住户样本。\n'.encode())]:
        path = folder / name
        path.write_bytes(content)
        path.chmod(0o600)
    return folder
