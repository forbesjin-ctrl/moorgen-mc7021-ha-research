"""Finite runtime adapter tests using only in-memory byte streams.

The peer below is synthetic. Passing these tests establishes implementation
behavior, never household compatibility, successful real authentication, or
physical lamp feedback. No loopback listener or network connection is created.
"""
import asyncio
import copy
import hashlib
import importlib
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import offline_shcp as codec
import single_light_driver as adapter

IDENTIFIER = '0102030405060708'
HOST = '192.0.2.20'
CREDS = {'username': 'owner-demo', 'password': 'example-only'}


def profile(**changes):
    result = copy.deepcopy(adapter._FIXED_PROFILE)
    result.update(port=9000, target_identifier=IDENTIFIER, auth_password_transform='raw_ascii')
    result.update(changes)
    return result


class MemoryPeer:
    """Protocol peer with separately modeled synthetic lamp state."""
    def __init__(self):
        self.connections = []
        self.frames = []
        self.power = False
        self.auto_query = True
        self.execute_commands = True
        self.connection_fields = [(160, b'\x00')]
        self.auth_pair = (2, 6)
        self.auth_fields = []
        self.bad_connection_serial = False
        self.bad_auth_serial = False
        self.on_query = None

    async def open(self, host, port):
        if (host, port) != (HOST, 9000):
            raise AssertionError('Unexpected peer; no real network is permitted')
        reader = asyncio.StreamReader()
        writer = MemoryWriter(self, reader)
        self.connections.append(writer)
        return reader, writer

    def send(self, kind, link, serial, fields, *, writer=None):
        writer = writer or self.connections[-1]
        raw = codec.build_frame(1, kind, link, serial, fields)
        # Exercise readexactly with a split fixed header and split TLV payload.
        writer.reader.feed_data(raw[:2])
        writer.reader.feed_data(raw[2:21])
        writer.reader.feed_data(raw[21:])

    def readback(self, serial, *, identifier=IDENTIFIER, raw_state=None):
        self.send(3, 8, serial, [(15, b'\x04'), (4, bytes.fromhex(identifier)),
                                  (11, bytes([int(self.power) if raw_state is None else raw_state]))])

    def panel(self, power):
        self.power = power
        self.send(5, 12, 400, [(27, b'\x03'), (4, bytes.fromhex(IDENTIFIER)), (11, bytes([int(power)]))])

    def receive(self, writer, raw):
        packet = codec.parse_frame(raw)
        self.frames.append(packet)
        pair = packet['protocol_type'], packet['link_code']
        serial = packet['serial_number']
        fields = [(item['id'], bytes.fromhex(item['value_hex'])) for item in packet['fields']]
        if pair == (1, 1):
            if fields:
                raise AssertionError('Only the finite empty connection request is supported')
            self.send(1, 3, (serial + int(self.bad_connection_serial)) & 65535, self.connection_fields, writer=writer)
        elif pair == (2, 4):
            self.send(*self.auth_pair, (serial + int(self.bad_auth_serial)) & 65535, self.auth_fields, writer=writer)
        elif pair == (3, 7):
            if fields != [(15, b'\x48'), (4, bytes.fromhex(IDENTIFIER))]:
                raise AssertionError('This is not the supported single-device details query')
            if self.on_query:
                self.on_query(serial)
            elif self.auto_query:
                self.readback(serial)
        elif pair == (4, 9):
            if fields[:2] != [(16, b'\x01'), (4, bytes.fromhex(IDENTIFIER))] or fields[2] not in ((9, b'light-on'), (9, b'light-off')):
                raise AssertionError('Unsupported synthetic ordinary-light command')
            if self.execute_commands:
                self.power = fields[2][1] == b'light-on'
            self.send(4, 11, serial, [])
            self.send(4, 10, serial, [])
        elif pair != (6, 14) or fields:
            raise AssertionError('Unexpected outgoing protocol operation')


class MemoryWriter:
    def __init__(self, peer, reader):
        self.peer, self.reader = peer, reader
        self.closed = False

    def write(self, raw):
        if self.closed:
            raise OSError('Synthetic closed stream')
        self.peer.receive(self, raw)

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        if not self.closed:
            self.closed = True
            self.reader.feed_eof()

    async def wait_closed(self):
        await asyncio.sleep(0)


class RuntimeDriverTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.peer = MemoryPeer()
        self.states, self.disconnections = [], []
        self.drivers = []
        for name in ('socket', 'create_connection', 'getaddrinfo'):
            patcher = mock.patch.object(socket, name, side_effect=AssertionError('No sockets in adapter tests'))
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(adapter, '_SERIALS', adapter._SerialCounter())
        patcher.start()
        self.addCleanup(patcher.stop)

    async def asyncTearDown(self):
        for driver in self.drivers:
            await driver.async_disconnect()

    def driver(self, **kwargs):
        result = adapter.Driver(profile=kwargs.pop('profile', profile()), credentials=kwargs.pop('credentials', CREDS),
                                open_connection=self.peer.open, **kwargs)
        self.drivers.append(result)
        return result

    async def connect(self, driver=None, **kwargs):
        driver = driver or self.driver()
        await driver.async_connect(host=kwargs.get('host', HOST), identifier=kwargs.get('identifier', IDENTIFIER),
                                   on_state=self.states.append, on_disconnect=lambda: self.disconnections.append(True))
        return driver

    async def settle(self):
        for _ in range(8):
            await asyncio.sleep(0)

    async def test_default_refuses_before_opening_any_transport(self):
        driver = adapter.Driver(open_connection=self.peer.open)
        with self.assertRaises(adapter.DriverError) as error:
            await self.connect(driver)
        self.assertTrue(error.exception.fatal_setup)
        self.assertEqual(self.peer.connections, [])

    async def test_profile_requires_exact_finite_schema_and_real_boolean_types(self):
        changes = ({'port': True}, {'port': 0}, {'ordinary_light_confirmed': 1},
                   {'credentials_verified_against_sources': False}, {'conn_request_fields': [531]},
                   {'auth_request_fields': [793, 797]}, {'auth_password_transform': 'guess'},
                   {'readback_correlation': 'latest_state'}, {'unknown': 1})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(adapter.DriverError):
                await self.connect(self.driver(profile=profile(**change)))
        self.assertEqual(self.peer.connections, [])

    async def test_no_host_discovery_dns_or_wrong_identifier(self):
        for host in ('localhost', '127.0.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '192.0.2.020'):
            with self.subTest(host=host), self.assertRaises(adapter.DriverError):
                await self.connect(self.driver(), host=host)
        with self.assertRaises(adapter.DriverError):
            await self.connect(self.driver(), identifier='1111111111111111')
        self.assertEqual(self.peer.connections, [])

    async def test_credentials_must_be_fresh_bounded_ascii_account_inputs(self):
        for creds in (None, {'username': 'owner-demo'}, {**CREDS, 'token': 'forbidden'},
                      {**CREDS, 'username': ' owner-demo'}, {**CREDS, 'password': 'x\n'},
                      {**CREDS, 'password': '密码'}, {**CREDS, 'password': ''},
                      {**CREDS, 'password': 'a' * 129}):
            with self.subTest(creds=creds), self.assertRaises(adapter.DriverError):
                await self.connect(self.driver(credentials=creds))
        self.assertEqual(self.peer.connections, [])

    async def test_fresh_handshake_has_no_captured_tokens_or_replayed_seed(self):
        driver = await self.connect()
        self.assertEqual([(f['protocol_type'], f['link_code']) for f in self.peer.frames], [(1, 1), (2, 4)])
        self.assertEqual([f['serial_number'] for f in self.peer.frames], [1, 2])
        self.assertEqual(self.peer.frames[1]['fields'][0]['value_hex'], CREDS['username'].encode().hex())
        self.assertEqual(self.peer.frames[1]['fields'][1]['value_hex'], CREDS['password'].encode().hex())
        self.assertEqual(self.states, [])
        with self.assertRaises(adapter.DriverError):
            await driver.async_set_power(True)

    async def test_verified_explicit_password_transform_only(self):
        for transform in ('md5_hex_lower', 'md5_hex_upper'):
            driver = await self.connect(self.driver(profile=profile(auth_password_transform=transform)))
            actual = bytes.fromhex(self.peer.frames[-1]['fields'][1]['value_hex']).decode()
            expected = hashlib.md5(CREDS['password'].encode()).hexdigest()
            self.assertEqual(actual, expected.upper() if transform.endswith('upper') else expected)
            await driver.async_disconnect()

    async def test_plaintext_selector_is_required_and_encryption_rejected_before_auth(self):
        for fields in ([], [(160, b'\x01')], [(160, b'\x00'), (160, b'\x00')],
                       [(160, b'\x00'), (93, b'key')], [(160, b'\x00'), (530, b'rsa')],
                       [(160, b'\x00'), (531, b'app')]):
            self.peer.connection_fields = fields
            self.peer.frames.clear()
            with self.subTest(fields=fields), self.assertRaises(adapter.DriverError):
                await self.connect()
            self.assertEqual(len(self.peer.frames), 1)

    async def test_handshake_responses_must_echo_fresh_request_serials(self):
        self.peer.bad_connection_serial = True
        with self.assertRaises(adapter.DriverError):
            await self.connect()
        self.peer.bad_connection_serial = False
        self.peer.bad_auth_serial = True
        with self.assertRaises(adapter.DriverError):
            await self.connect()
        self.assertEqual(self.states, [])

    async def test_auth_rejection_no_permissions_and_unknown_payload_fail_closed(self):
        for pair, fields in (((2, 5), []), ((2, 19), []), ((2, 6), [(797, b'private')])):
            self.peer.auth_pair, self.peer.auth_fields = pair, fields
            with self.subTest(pair=pair, fields=fields), self.assertRaises(adapter.DriverError) as context:
                await self.connect()
            self.assertTrue(context.exception.fatal_setup)
            self.assertNotIn('private', str(context.exception))
            self.assertNotIn(CREDS['password'], str(context.exception))
        self.assertEqual(self.states, [])

    async def test_single_device_readback_opens_state_epoch(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.assertEqual(self.states, [{'identifier': IDENTIFIER, 'power': False, 'source': 'independent_readback'}])
        query = self.peer.frames[-1]
        self.assertEqual([(f['id'], f['value_hex']) for f in query['fields']], [(15, '48'), (4, IDENTIFIER)])

    async def test_real_codec_bytes_switch_on_off_with_independent_readbacks(self):
        driver = await self.connect()
        await driver.async_request_state()
        await driver.async_set_power(True)
        await driver.async_set_power(False)
        self.assertEqual([s['power'] for s in self.states], [False, True, False])
        self.assertTrue(all(s['source'] == 'independent_readback' for s in self.states))
        commands = [f for f in self.peer.frames if (f['protocol_type'], f['link_code']) == (4, 9)]
        self.assertEqual([bytes.fromhex(f['fields'][-1]['value_hex']) for f in commands], [b'light-on', b'light-off'])

    async def test_ack_and_execution_response_never_become_state(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.execute_commands = False
        await driver.async_set_power(True)
        self.assertEqual([s['power'] for s in self.states], [False, False])
        with self.assertRaises(adapter.DriverError):
            await driver.async_set_power(False)
        self.assertEqual(len([f for f in self.peer.frames if f['protocol_type'] == 4]), 1)

    async def test_panel_push_requires_initial_readback_then_updates_independently(self):
        driver = await self.connect()
        self.peer.panel(True)
        await self.settle()
        self.assertEqual(self.states, [])
        await driver.async_request_state()
        self.peer.panel(False)
        await self.settle()
        self.assertEqual([s['power'] for s in self.states], [True, False])
        self.assertEqual(self.states[-1]['source'], 'independent_push')

    async def test_wrong_identifier_and_unsolicited_serial_cannot_satisfy_query(self):
        driver = await self.connect()
        def replies(serial):
            self.peer.readback(serial, identifier='1111111111111111')
            self.peer.readback((serial + 50) & 65535, raw_state=1)
            self.peer.readback(serial, raw_state=0)
        self.peer.on_query = replies
        await driver.async_request_state()
        self.assertEqual([s['power'] for s in self.states], [False])

    async def test_duplicate_or_unknown_target_state_layout_disconnects(self):
        for extra in ((11, b'\x00'), (999, b'unknown')):
            driver = await self.connect()
            await driver.async_request_state()
            self.peer.send(5, 12, 444, [(27, b'\x03'), (4, bytes.fromhex(IDENTIFIER)), (11, b'\x01'), extra])
            await self.settle()
            self.assertFalse(driver._connected)
            self.assertEqual(self.states[-1]['power'], False)
        self.assertEqual(len(self.disconnections), 2)

    async def test_upper_flags_are_not_misread_as_power(self):
        driver = await self.connect()
        self.peer.on_query = lambda serial: self.peer.readback(serial, raw_state=0x80)
        await driver.async_request_state()
        self.assertFalse(self.states[-1]['power'])

    async def test_heartbeat_consumes_fresh_counter_and_wraps_without_echo(self):
        adapter._SERIALS = adapter._SerialCounter(65534)
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.send(6, 13, 500, [])
        await self.settle()
        self.assertEqual([f['serial_number'] for f in self.peer.frames], [65535, 0, 1, 2])
        self.assertEqual((self.peer.frames[-1]['protocol_type'], self.peer.frames[-1]['link_code']), (6, 14))

    async def test_reconnect_authenticates_fresh_requires_readback_and_never_replays_commands(self):
        driver = await self.connect()
        await driver.async_request_state()
        await driver.async_set_power(True)
        last_serial = self.peer.frames[-1]['serial_number']
        await driver.async_disconnect()
        self.peer.power = False
        await self.connect(driver)
        self.assertEqual(self.peer.frames[-2]['serial_number'], last_serial + 1)
        with self.assertRaises(adapter.DriverError):
            await driver.async_set_power(False)
        await driver.async_request_state()
        self.assertFalse(self.states[-1]['power'])
        self.assertEqual(len([f for f in self.peer.frames if f['protocol_type'] == 4]), 1)
        self.assertEqual(len(self.peer.connections), 2)

    async def test_readback_timeout_closes_and_does_not_report_requested_state(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.auto_query = False
        with mock.patch.object(adapter, 'OPERATION_TIMEOUT', 0.03), self.assertRaises(adapter.DriverError) as error:
            await driver.async_set_power(True)
        self.assertFalse(error.exception.fatal_setup)
        self.assertFalse(driver._connected)
        self.assertEqual([s['power'] for s in self.states], [False])
        self.assertEqual(self.disconnections, [True])

    async def test_eof_notifies_once_and_discards_old_readiness(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.connections[-1].reader.feed_eof()
        await self.settle()
        self.assertEqual(self.disconnections, [True])
        self.assertFalse(driver._ready)
        await driver.async_disconnect()
        self.assertEqual(self.disconnections, [True])

    async def test_runtime_encryption_change_disconnects_without_cached_state(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.send(5, 12, 444, [(160, b'\x02')])
        await self.settle()
        self.assertFalse(driver._connected)
        self.assertTrue(driver.fatal_setup_error)
        self.assertEqual(len(self.states), 1)

    async def test_transport_failure_is_temporary_and_does_not_expose_exception_text(self):
        async def unavailable(host, port):
            raise OSError('Synthetic private transport detail')
        driver = self.driver()
        driver._open_connection = unavailable
        with self.assertRaises(adapter.DriverError) as error:
            await self.connect(driver)
        self.assertFalse(error.exception.fatal_setup)
        self.assertNotIn('private', str(error.exception))

    async def test_concurrent_operations_never_overwrite_query_or_queue_a_command(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.auto_query = False
        query = asyncio.create_task(driver.async_request_state())
        await self.settle()
        for operation in (driver.async_request_state(), driver.async_set_power(True), self.connect(driver)):
            with self.assertRaises(adapter.DriverError):
                await operation
        self.assertEqual(len([f for f in self.peer.frames if f['protocol_type'] == 4]), 0)
        self.peer.readback(self.peer.frames[-1]['serial_number'])
        await query

    async def test_cancelled_command_closes_and_preserves_cancellation_without_replay(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.auto_query = False
        operation = asyncio.create_task(driver.async_set_power(True))
        await self.settle()
        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation
        self.assertFalse(driver._connected)
        self.assertEqual(self.disconnections, [True])
        self.peer.auto_query = True
        await self.connect(driver)
        await driver.async_request_state()
        self.assertEqual(len([f for f in self.peer.frames if f['protocol_type'] == 4]), 1)

    async def test_state_before_identifier_is_not_accepted(self):
        driver = await self.connect()
        await driver.async_request_state()
        self.peer.send(5, 12, 444, [(27, b'\x03'), (11, b'\x01'), (4, bytes.fromhex(IDENTIFIER))])
        await self.settle()
        self.assertFalse(driver._connected)
        self.assertEqual([s['power'] for s in self.states], [False])

    async def test_bridge_runs_complete_simulated_acceptance_transport(self):
        name = '_finite_driver_component_test'
        package = types.ModuleType(name)
        package.__path__ = [str(ROOT / 'ha_component_templates/custom_components/mc7021_single_light')]
        sys.modules[name] = package
        bridge_class = importlib.import_module(name + '.bridge').SingleLightBridge
        bridge = bridge_class(self.driver, {'host_ip': HOST, 'target_identifier': IDENTIFIER})
        try:
            await bridge.async_connect()
            self.assertTrue(bridge.available)
            self.assertFalse(bridge.power)
            for power in (True, False, True, False):
                await bridge.async_set_power(power)
                self.assertIs(bridge.power, power)
            self.peer.panel(True)
            await self.settle()
            self.assertTrue(bridge.power)
            self.peer.panel(False)
            await self.settle()
            self.assertFalse(bridge.power)
            await bridge.async_disconnect()
            self.assertFalse(bridge.available)
            self.peer.power = True
            await bridge.async_connect()
            self.assertTrue(bridge.available)
            self.assertTrue(bridge.power)
            events = list(bridge.events)
            self.assertEqual(len([e for e in events if e['kind'] == 'command_requested']), 4)
            self.assertTrue(all(e['source'] in ('independent_readback', 'independent_push') for e in events if e['kind'] == 'state'))
        finally:
            await bridge.async_shutdown()


if __name__ == '__main__':
    unittest.main()
