"""Finite plaintext SHCP adapter; household compatibility is not established.

This module is self contained so the exact reviewed file can become HA's
``driver.py``. Importing or constructing it never opens a connection. Only an
explicit ``async_connect`` with a source-matched profile and fresh, locally
entered credentials can open one TCP connection to one literal IPv4 address.
There is no discovery, upload, replay, configuration write, or automatic retry.

The supported branch is deliberately small: empty connection request, explicit
plaintext negotiation, account authentication, one ordinary switch light,
single-device query, and empty heartbeat request/response. Runtime observations
are protocol readbacks, not proof of the lamp's physical state or identity.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import struct
import threading
import time

DRIVER_API_VERSION = 1
DRIVER_IS_PLACEHOLDER = False
DRIVER_STRATEGY = 'plain_shcp_account_v1'
DRIVER_HOUSEHOLD_VERIFIED = False
MAX_FRAME_SIZE = 65538
OPERATION_TIMEOUT = 8.0

_FIXED_PROFILE = {
    'schema_version': '1.0',
    'strategy': DRIVER_STRATEGY,
    'protocol_number': 1,
    'protocol_name': 'dooyashcp',
    'ordinary_light_confirmed': True,
    'conn_request_fields': [],
    'conn_response_encryption_selector': 0,
    'auth_request_fields': [12, 13],
    'credential_input_kind': 'owner_supplied_account_credentials',
    'credentials_verified_against_sources': True,
    'serial_strategy': 'client_increment_mod65536',
    'query_strategy': 'single_device_48',
    'readback_correlation': 'query_serial_echo',
    'state_strategy': 'ordinary_light_bit0',
    'heartbeat_strategy': 'request_13_response_14_fresh_serial',
    'evidence_status': 'source_matched_two_rounds',
}
_VARIABLE_KEYS = {'port', 'target_identifier', 'auth_password_transform'}
_TRANSFORMS = {'raw_ascii', 'md5_hex_lower', 'md5_hex_upper'}


class DriverError(ValueError):
    """Sanitized, fixed-message error; never include packets or credentials."""
    def __init__(self, message, *, fatal_setup=False):
        super().__init__(message)
        self.fatal_setup = fatal_setup is True


class UnsupportedProtocolError(DriverError):
    """Unsupported local profile/credentials/protocol; never retry unchanged."""
    def __init__(self, message):
        super().__init__(message, fatal_setup=True)


class _SerialCounter:
    """Fresh process counter, shared across reconnects and driver instances."""
    def __init__(self, initial=0):
        self.value = initial
        self.lock = threading.Lock()

    def next(self):
        with self.lock:
            self.value = (self.value + 1) & 0xffff
            return self.value


_SERIALS = _SerialCounter()


async def _bounded(awaitable):
    """A bounded await that preserves cancellation, including on Python 3.9."""
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=OPERATION_TIMEOUT)
        if not done:
            raise asyncio.TimeoutError
        return task.result()
    except BaseException:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise


def validate_profile(profile):
    """Validate the finite data schema, without trusting it as live evidence."""
    if not isinstance(profile, dict) or set(profile) != set(_FIXED_PROFILE) | _VARIABLE_KEYS:
        raise UnsupportedProtocolError('A complete supported source-matched profile is required')
    for key, expected in _FIXED_PROFILE.items():
        value = profile[key]
        if type(value) is not type(expected) or value != expected:
            raise UnsupportedProtocolError('The profile requests an unsupported strategy')
    if type(profile['port']) is not int or not 1 <= profile['port'] <= 65535:
        raise UnsupportedProtocolError('An explicit captured TCP port is required')
    if not isinstance(profile['target_identifier'], str) or not re.fullmatch('[0-9a-f]{16}', profile['target_identifier']):
        raise UnsupportedProtocolError('A complete ordinary-light identifier is required')
    if not isinstance(profile['auth_password_transform'], str) or profile['auth_password_transform'] not in _TRANSFORMS:
        raise UnsupportedProtocolError('Unsupported authentication input transformation')
    # Own the mutable lists; a caller cannot alter the profile after validation.
    return {**profile, 'conn_request_fields': [], 'auth_request_fields': [12, 13]}


def _credential_bytes(credentials, transform):
    if not isinstance(credentials, dict) or set(credentials) != {'username', 'password'}:
        raise UnsupportedProtocolError('Fresh local account credentials are required')
    values = []
    for key in ('username', 'password'):
        value = credentials[key]
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(not 32 <= ord(c) <= 126 for c in value):
            raise UnsupportedProtocolError('Only bounded printable ASCII account credentials are supported')
        if not value.strip() or (key == 'username' and value != value.strip()):
            raise UnsupportedProtocolError('The account credential text is unsupported')
        values.append(value.encode('ascii'))
    if transform != 'raw_ascii':
        # This transformation is permitted only after an in-memory fresh-input
        # probe uniquely matched both original normal-communication rounds.
        digest = hashlib.md5(values[1]).hexdigest()
        values[1] = (digest.upper() if transform == 'md5_hex_upper' else digest).encode('ascii')
    return values


def _frame(protocol_type, link_code, serial, fields):
    body = b''.join(struct.pack('<HH', field, len(value)) + value for field, value in fields)
    if len(body) > 65518:
        raise UnsupportedProtocolError('The outgoing frame exceeds the supported size')
    return (b'#' + struct.pack('<H', 17 + len(body)) + b'dooyashcp'
            + bytes((1, protocol_type, link_code))
            + struct.pack('<HH', serial, len(body)) + body + b'#')


def _parse(raw):
    if (not isinstance(raw, bytes) or not 20 <= len(raw) <= MAX_FRAME_SIZE
            or raw[0] != 35 or raw[-1] != 35 or raw[3:12] != b'dooyashcp'
            or raw[12] != 1 or struct.unpack_from('<H', raw, 1)[0] + 3 != len(raw)
            or struct.unpack_from('<H', raw, 17)[0] != len(raw) - 20):
        raise UnsupportedProtocolError('Unsupported or malformed plaintext frame')
    fields, cursor = [], 19
    while cursor < len(raw) - 1:
        if cursor + 4 > len(raw) - 1:
            raise UnsupportedProtocolError('Malformed plaintext TLV boundary')
        field, size = struct.unpack_from('<HH', raw, cursor)
        end = cursor + 4 + size
        if end > len(raw) - 1:
            raise UnsupportedProtocolError('Malformed plaintext TLV boundary')
        fields.append((field, raw[cursor + 4:end]))
        cursor = end
    return raw[13], raw[14], struct.unpack_from('<H', raw, 15)[0], fields


def _unique(fields, field, required=False):
    matches = [value for kind, value in fields if kind == field]
    if len(matches) > 1 or (required and not matches):
        raise UnsupportedProtocolError('Ambiguous or missing protocol field')
    return matches[0] if matches else None


def _no_encryption(fields, *, selector_required=False):
    selector = _unique(fields, 160, required=selector_required)
    if (selector is not None and selector != b'\x00') or any(field in (93, 530) for field, _ in fields):
        raise UnsupportedProtocolError('Encryption or key negotiation is unsupported')


class Driver:
    """HA API 1 adapter; no activity until explicitly connected by HA."""
    def __init__(self, profile=None, credentials=None, *, open_connection=None, clock=time.monotonic):
        self._profile_input = profile
        self._credentials = credentials
        self._open_connection = open_connection
        self._clock = clock
        self._profile = None
        self._reader = self._writer = self._receive_task = None
        self._on_state = self._on_disconnect = None
        self._connected = False
        self.fatal_setup_error = False
        self._ready = False
        self._query = None
        self._pending_power = None
        self._send_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()

    async def _send(self, kind, link, fields):
        async with self._send_lock:
            if self._writer is None:
                raise DriverError('The adapter is disconnected')
            serial = _SERIALS.next()
            self._writer.write(_frame(kind, link, serial, fields))
            await _bounded(self._writer.drain())
            return serial

    async def _read(self):
        prefix = await self._reader.readexactly(3)
        if prefix[0] != 35:
            raise UnsupportedProtocolError('Unsupported framing; no resynchronization attempted')
        length = struct.unpack_from('<H', prefix, 1)[0] + 3
        if not 20 <= length <= MAX_FRAME_SIZE:
            raise UnsupportedProtocolError('Unsupported frame size')
        return _parse(prefix + await self._reader.readexactly(length - 3))

    async def async_connect(self, *, host, identifier, on_state, on_disconnect):
        async with self._lifecycle_lock:
            if self._operation_lock.locked():
                raise DriverError('Wait for the outstanding operation to finish closing')
            await self._close(notify=False)
            self.fatal_setup_error = False
            self._profile = validate_profile(self._profile_input)
            username, password = _credential_bytes(self._credentials, self._profile['auth_password_transform'])
            try:
                address = ipaddress.IPv4Address(host)
            except (ValueError, TypeError):
                raise UnsupportedProtocolError('One explicit literal IPv4 host is required') from None
            if address.is_multicast or address.is_unspecified or address.is_loopback or int(address) == 0xffffffff or str(address) != host:
                raise UnsupportedProtocolError('One explicit unicast IPv4 host is required')
            if identifier != self._profile['target_identifier'] or not callable(on_state) or not callable(on_disconnect):
                raise UnsupportedProtocolError('The selected light does not match the profile')
            self._identifier = identifier
            self._identifier_bytes = bytes.fromhex(identifier)
            self._on_state, self._on_disconnect = on_state, on_disconnect
            try:
                opener = self._open_connection or asyncio.open_connection
                self._reader, self._writer = await _bounded(opener(host, self._profile['port']))
                conn_serial = await self._send(1, 1, [])
                kind, link, serial, fields = await _bounded(self._read())
                if (kind, link) != (1, 3) or serial != conn_serial:
                    raise UnsupportedProtocolError('A fresh connection negotiation is required')
                _no_encryption(fields, selector_required=True)
                if fields != [(160, b'\x00')]:
                    raise UnsupportedProtocolError('Unsupported connection response layout')
                auth_serial = await self._send(2, 4, [(12, username), (13, password)])
                kind, link, serial, fields = await _bounded(self._read())
                _no_encryption(fields)
                if (kind, link) != (2, 6) or serial != auth_serial or fields:
                    raise UnsupportedProtocolError('Fresh account authentication was not accepted')
                self._connected = True
                self._receive_task = asyncio.create_task(self._receive())
            except asyncio.CancelledError:
                await self._close(notify=False)
                raise
            except Exception as error:
                self.fatal_setup_error = getattr(error, 'fatal_setup', False) is True
                await self._close(notify=False)
                raise DriverError('Connection or fresh authentication did not complete',
                                  fatal_setup=self.fatal_setup_error) from None

    def _state(self, kind, link, serial, fields):
        if (kind, link) not in ((3, 8), (5, 12)):
            return
        device = _unique(fields, 4)
        if device != self._identifier_bytes:
            return
        category = 15 if kind == 3 else 27
        expected = b'\x04' if kind == 3 else b'\x03'
        if _unique(fields, category, required=True) != expected:
            raise UnsupportedProtocolError('Unsupported target state category')
        if [field for field, _ in fields] not in ([category, 4, 11], [category, 4, 6, 11]):
            raise UnsupportedProtocolError('Unsupported target state layout')
        status = _unique(fields, 11, required=True)
        _unique(fields, 6)
        if len(status) != 1:
            raise UnsupportedProtocolError('Unsupported ordinary-light state width')
        power = bool(status[0] & 1)
        if kind == 3:
            if self._query is None or serial != self._query[0]:
                return  # An unsolicited/cached details frame cannot open an epoch.
            self._ready = True
            source = 'independent_readback'
        else:
            if not self._ready:
                return  # New connection must first obtain its own query readback.
            source = 'independent_push'
        if self._pending_power is power:
            self._pending_power = None
        self._on_state({'identifier': self._identifier, 'power': power, 'source': source})
        if kind == 3 and self._query is not None and not self._query[1].done():
            self._query[1].set_result(None)

    async def _receive(self):
        try:
            while self._connected:
                kind, link, serial, fields = await self._read()
                _no_encryption(fields)
                if (kind, link) == (6, 13):
                    if fields:
                        raise UnsupportedProtocolError('Unsupported heartbeat layout')
                    await self._send(6, 14, [])
                elif (kind, link) == (6, 14):
                    if fields:
                        raise UnsupportedProtocolError('Unsupported heartbeat layout')
                elif kind in (1, 2):
                    raise UnsupportedProtocolError('Session renegotiation requires a new explicit connection')
                else:
                    # ACK 4/11 and execution response 4/10 never become state.
                    self._state(kind, link, serial, fields)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.fatal_setup_error = getattr(error, 'fatal_setup', False) is True
            await self._close(notify=True)

    async def async_request_state(self):
        if self._operation_lock.locked():
            raise DriverError('Wait for the outstanding operation to finish')
        async with self._operation_lock:
            await self._request_state()

    async def _request_state(self):
        if not self._connected:
            raise DriverError('Fresh authenticated connection is required')
        if self._query is not None:
            raise DriverError('Wait for the current single-device readback')
        future = asyncio.get_running_loop().create_future()
        try:
            # Reserve the next serial while holding the same send lock used by
            # heartbeat responses, before drain yields to the receiver task.
            async with self._send_lock:
                if self._writer is None:
                    raise DriverError('The adapter is disconnected')
                serial = _SERIALS.next()
                self._query = (serial, future)
                self._writer.write(_frame(3, 7, serial, [(15, b'\x48'), (4, self._identifier_bytes)]))
                await _bounded(self._writer.drain())
            await _bounded(future)
        except BaseException as error:
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()  # Consume a close error even if drain failed first.
            await self._close(notify=True)
            if isinstance(error, asyncio.CancelledError):
                raise
            raise DriverError('Fresh single-device readback did not complete',
                              fatal_setup=self.fatal_setup_error or getattr(error, 'fatal_setup', False) is True) from None
        finally:
            self._query = None

    async def async_set_power(self, power):
        if type(power) is not bool:
            raise UnsupportedProtocolError('Only a boolean ordinary-light command is supported')
        if self._operation_lock.locked():
            raise DriverError('Wait for the outstanding operation to finish')
        async with self._operation_lock:
            await self._set_power(power)

    async def _set_power(self, power):
        if not self._connected or not self._ready:
            raise DriverError('Current independent readback is required before control')
        if self._pending_power is not None or self._query is not None:
            raise DriverError('Wait for independent feedback from the previous operation')
        self._pending_power = power
        try:
            await self._send(4, 9, [(16, b'\x01'), (4, self._identifier_bytes),
                                    (9, b'light-on' if power else b'light-off')])
            await self._request_state()
        except BaseException as error:
            await self._close(notify=True)
            if isinstance(error, asyncio.CancelledError):
                raise
            raise DriverError('The command did not obtain fresh independent readback',
                              fatal_setup=self.fatal_setup_error or getattr(error, 'fatal_setup', False) is True) from None

    async def _close(self, *, notify):
        was_connected = self._connected
        self._connected = self._ready = False
        self._pending_power = None
        task, self._receive_task = self._receive_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        if self._query is not None and not self._query[1].done():
            self._query[1].set_exception(DriverError('The connection closed before readback',
                                                   fatal_setup=self.fatal_setup_error))
        writer, self._writer = self._writer, None
        self._reader = None
        if writer is not None:
            try:
                writer.close()
                await _bounded(writer.wait_closed())
            except Exception:
                pass
        if notify and was_connected and self._on_disconnect is not None:
            self._on_disconnect()

    async def async_disconnect(self):
        async with self._lifecycle_lock:
            await self._close(notify=False)
