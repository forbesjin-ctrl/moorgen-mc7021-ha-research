"""Read a bounded install binding before executing explicitly approved code.

This is an integrity check, not a sandbox or proof of driver safety/correctness.
No imports of user driver code occur in this module's inspection function.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import ipaddress
import json
from pathlib import Path
import re
import types

from .const import DRIVER_API_VERSION, VERSION


def inspect_builtin_profile(value, identifier):
    """Fixed data schema only; no packet/auth values can enter this binding."""
    fixed = dict(schema_version='1.0', strategy='plain_shcp_account_v1', protocol_number=1,
        protocol_name='dooyashcp', ordinary_light_confirmed=True, conn_request_fields=[],
        conn_response_encryption_selector=0, auth_request_fields=[12, 13],
        credential_input_kind='owner_supplied_account_credentials', credentials_verified_against_sources=True,
        serial_strategy='client_increment_mod65536', query_strategy='single_device_48',
        readback_correlation='query_serial_echo', state_strategy='ordinary_light_bit0',
        heartbeat_strategy='request_13_response_14_fresh_serial', evidence_status='source_matched_two_rounds')
    if not isinstance(value, dict) or set(value) != set(fixed) | {'port', 'target_identifier', 'auth_password_transform'}:
        raise ValueError('Unsupported built-in profile')
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in fixed.items()):
        raise ValueError('Unsupported built-in strategy')
    if (type(value['port']) is not int or not 1 <= value['port'] <= 65535
            or value['target_identifier'] != identifier
            or value['auth_password_transform'] not in ('raw_ascii', 'md5_hex_lower', 'md5_hex_upper')):
        raise ValueError('Invalid source-matched target or credentials encoding')
    return value


def inspect_install(directory=None):
    directory = Path(directory) if directory else Path(__file__).parent
    paths = [directory / 'binding.json', directory / 'driver.py']
    raw = []
    for path, limit in zip(paths, (16384, 256 * 1024)):
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError('Symlinked driver or binding is not accepted')
        if not path.is_file() or path.stat().st_size > limit:
            raise ValueError('Missing or oversized private driver/binding')
        value = path.read_bytes()
        if len(value) > limit:
            raise ValueError('Oversized private driver/binding')
        raw.append(value)
    binding = json.loads(raw[0])
    if not isinstance(binding, dict) or binding.get('schema_version') != VERSION:
        raise ValueError('Unsupported binding schema')
    if binding.get('simulation') is not False:
        raise ValueError('Simulation cannot start a live integration')
    host = binding.get('host_ip')
    address = ipaddress.ip_address(host)
    if address.version != 4 or address.is_loopback or address.is_multicast or address.is_unspecified or str(address) != host or host == '255.255.255.255':
        raise ValueError('A known unicast IPv4 address is required')
    if not re.fullmatch(r'[0-9a-f]{16}', binding.get('target_identifier', '')):
        raise ValueError('A complete reviewed eight-byte identifier is required')
    for key in ('driver_sha256', 'baseline_review_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', binding.get(key, '')):
            raise ValueError('Missing binding digest')
    for key in ('package_id', 'wizard_id'):
        value = binding.get(key)
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value):
            raise ValueError('Missing package/wizard identity')
    if hashlib.sha256(raw[1]).hexdigest() != binding['driver_sha256']:
        raise ValueError('Driver changed after packaging')
    if 'builtin_profile' in binding:
        inspect_builtin_profile(binding['builtin_profile'], binding['target_identifier'])
    tree = ast.parse(raw[1])
    constants = {}
    for item in tree.body:
        if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = item.value.value
    if type(constants.get('DRIVER_API_VERSION')) is not int or constants['DRIVER_API_VERSION'] != DRIVER_API_VERSION or constants.get('DRIVER_IS_PLACEHOLDER') is True:
        raise ValueError('Unsupported or placeholder driver')
    return binding, raw[1]


def load_approved_driver(raw):
    """Execute the already-read bytes only on HA after explicit owner consent.

Caller uses HA's executor for module execution. Driver methods and callbacks
must be event-loop safe. Approval means trusting all of this Python code.
"""
    module = types.ModuleType('owner_reviewed_mc7021_driver')
    exec(compile(raw, '<owner-reviewed driver.py>', 'exec'), module.__dict__)
    if getattr(module, 'DRIVER_API_VERSION', None) != DRIVER_API_VERSION or getattr(module, 'DRIVER_IS_PLACEHOLDER', False):
        raise ValueError('Unsupported or placeholder driver')
    cls = getattr(module, 'Driver', None)
    if not isinstance(cls, type):
        raise ValueError('Driver class is required')
    for name in ('async_connect', 'async_set_power', 'async_request_state', 'async_disconnect'):
        if not inspect.iscoroutinefunction(getattr(cls, name, None)):
            raise ValueError('Driver requires asynchronous contract methods')
    return cls
