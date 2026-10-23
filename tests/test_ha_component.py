"""Executable single-light bridge tests. No installed HA or household network.

HA wrapper tests use small contract fakes; they do not claim actual HA runtime
compatibility or validate any manufacturer protocol/driver/physical device.
"""
import asyncio
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'ha_component_templates/custom_components/mc7021_single_light'
PACKAGE = '_offline_mc7021_component'
package = types.ModuleType(PACKAGE)
package.__path__ = [str(TEMPLATE)]
sys.modules[PACKAGE] = package
bridge_module = importlib.import_module(PACKAGE + '.bridge')
contract = importlib.import_module(PACKAGE + '.contract')
Bridge = bridge_module.SingleLightBridge
IDENTIFIER = '0102030405060708'


def binding(raw=b'DRIVER_API_VERSION = 1\nclass Driver: pass\n'):
    return dict(schema_version='0.6.0', host_ip='192.0.2.20', target_identifier=IDENTIFIER,
        driver_sha256=hashlib.sha256(raw).hexdigest(), baseline_review_sha256='a' * 64,
        package_id='package_test', wizard_id='wizard_test', simulation=False)


class FakeDriver:
    def __init__(self):
        self.calls = []
        self.on_state = self.on_disconnect = None
        self.readback = None
        self.fail_connect = self.fail_command = self.fail_query = False

    async def async_connect(self, *, host, identifier, on_state, on_disconnect):
        self.calls.append(('connect', host, identifier))
        self.on_state, self.on_disconnect = on_state, on_disconnect
        if self.fail_connect:
            raise RuntimeError('private-token-never-export')

    async def async_set_power(self, power):
        self.calls.append(('set', power))
        if self.fail_command:
            raise RuntimeError('private-token-never-export')
        return {'ack': True, 'power': power}

    async def async_request_state(self):
        self.calls.append(('query',))
        if self.fail_query:
            raise RuntimeError('private-token-never-export')
        if type(self.readback) is bool:
            self.emit(self.readback, source='independent_readback')

    async def async_disconnect(self):
        self.calls.append(('disconnect',))

    def emit(self, power, *, source='independent_push', identifier=IDENTIFIER):
        self.on_state(dict(power=power, source=source, identifier=identifier))


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now = 1.0
        self.drivers = []
        def factory():
            item = FakeDriver()
            self.drivers.append(item)
            return item
        self.factory = factory
        self.bridge = Bridge(factory, binding(), clock=lambda: self.now, max_age=60)
        # None of these tests should need a socket even for synthetic data.
        for name in ('socket', 'create_connection', 'getaddrinfo'):
            patcher = mock.patch.object(socket, name, side_effect=AssertionError('Offline HA bridge test'))
            patcher.start()
            self.addCleanup(patcher.stop)

    async def connect(self, state=False):
        await self.bridge.async_connect()
        if type(state) is bool:
            self.drivers[-1].emit(state, source='independent_readback')
        return self.drivers[-1]

    async def test_initial_state_unknown_and_no_driver_created(self):
        self.assertFalse(self.bridge.available)
        self.assertIsNone(self.bridge.power)
        self.assertEqual(self.drivers, [])

    async def test_connect_queries_exactly_the_bound_host_and_one_identifier(self):
        driver = await self.connect(None)
        self.assertEqual(driver.calls, [('connect', '192.0.2.20', IDENTIFIER), ('query',)])
        self.assertFalse(self.bridge.available)
        driver.emit(False, source='independent_readback')
        self.assertTrue(self.bridge.available)
        self.assertIs(self.bridge.power, False)

    async def test_push_does_not_open_a_new_receive_generation(self):
        driver = await self.connect(None)
        driver.emit(True)
        self.assertFalse(self.bridge.available)
        driver.emit(True, source='independent_readback')
        self.assertTrue(self.bridge.available)

    async def test_wrong_identifier_ack_cached_or_non_boolean_state_are_ignored(self):
        driver = await self.connect(False)
        count = len(self.bridge.events)
        for value, source, identifier in [(True, 'ack', IDENTIFIER), (True, 'cached', IDENTIFIER),
                (1, 'independent_push', IDENTIFIER), (True, 'independent_push', '1111111111111111')]:
            driver.emit(value, source=source, identifier=identifier)
        self.assertIs(self.bridge.power, False)
        self.assertEqual(len(self.bridge.events), count)

    async def test_command_return_ack_does_not_set_state(self):
        await self.connect(False)
        await self.bridge.async_set_power(True)
        self.assertIs(self.bridge.power, False)
        self.assertEqual(self.bridge.events[-1]['kind'], 'command_requested')
        self.assertIs(self.bridge.events[-1]['state'], True)
        self.assertFalse(self.bridge.events[-1]['independent'])

    async def test_pending_command_blocks_second_command_and_new_window(self):
        driver = await self.connect(False)
        await self.bridge.async_set_power(True)
        with self.assertRaises(ValueError):
            await self.bridge.async_set_power(False)
        with self.assertRaises(ValueError):
            self.bridge.begin_window()
        driver.emit(False)
        with self.assertRaises(ValueError):
            self.bridge.begin_window()
        driver.emit(True)
        self.bridge.begin_window()
        self.assertFalse(self.bridge.events[-1]['pending_command'])

    async def test_real_independent_callback_changes_state_and_clears_pending(self):
        driver = await self.connect(False)
        await self.bridge.async_set_power(True)
        driver.emit(True)
        self.assertIs(self.bridge.power, True)
        self.assertEqual(self.bridge.events[-1]['kind'], 'state')
        self.assertTrue(self.bridge.events[-1]['independent'])
        self.assertFalse(self.bridge.events[-1]['pending_command'])

    async def test_no_command_without_readback_and_only_boolean_command(self):
        await self.connect(None)
        with self.assertRaises(ValueError):
            await self.bridge.async_set_power(True)
        with self.assertRaises(ValueError):
            await self.bridge.async_set_power(1)

    async def test_old_state_and_disconnect_callbacks_cannot_affect_new_generation(self):
        old = await self.connect(False)
        old_state, old_disconnect = old.on_state, old.on_disconnect
        new = await self.connect(True)
        old_state(dict(identifier=IDENTIFIER, power=False, source='independent_readback'))
        old_disconnect()
        self.assertTrue(self.bridge.available)
        self.assertIs(self.bridge.power, True)
        self.assertEqual(self.bridge.generation, 2)
        new.on_disconnect()
        self.assertFalse(self.bridge.available)

    async def test_reconnect_requires_new_readback_even_if_old_state_known(self):
        await self.connect(True)
        await self.bridge.async_disconnect()
        self.assertIsNone(self.bridge.power)
        driver = await self.connect(None)
        driver.emit(True)
        self.assertIsNone(self.bridge.power)
        driver.emit(False, source='independent_readback')
        self.assertIs(self.bridge.power, False)

    async def test_failed_reconnect_does_not_retain_old_available_state(self):
        await self.connect(True)
        bad = FakeDriver()
        bad.fail_connect = True
        self.bridge.driver_factory = lambda: bad
        with self.assertRaises(RuntimeError):
            await self.bridge.async_connect()
        self.assertFalse(self.bridge.available)
        self.assertIsNone(self.bridge.power)
        self.assertNotIn('private-token', json.dumps(self.bridge.diagnostics()))

    async def test_manual_disconnect_prevents_automatic_reconnection(self):
        await self.connect(False)
        await self.bridge.async_disconnect()
        self.now += 100
        await self.bridge.async_maintain()
        self.assertEqual(len(self.drivers), 1)
        self.assertFalse(self.bridge.available)

    async def test_unexpected_disconnect_reconnects_only_after_local_backoff(self):
        driver = await self.connect(False)
        driver.on_disconnect()
        await self.bridge.async_maintain()
        self.assertEqual(len(self.drivers), 1)
        self.now += 31
        await self.bridge.async_maintain()
        self.assertEqual(len(self.drivers), 2)
        self.assertFalse(self.bridge.available)
        self.assertEqual(self.bridge.generation, 2)

    async def test_expired_state_is_unavailable_and_push_cannot_reopen_it(self):
        driver = await self.connect(False)
        self.now += 61
        self.assertFalse(self.bridge.available)
        self.assertIsNone(self.bridge.power)
        self.bridge.check_stale()
        self.assertEqual(self.bridge.events[-1]['source'], 'stale')
        driver.emit(True)
        self.assertFalse(self.bridge.available)
        driver.emit(True, source='independent_readback')
        self.assertTrue(self.bridge.available)

    async def test_push_cannot_revive_expired_state_before_next_maintenance_tick(self):
        driver = await self.connect(False)
        self.now += 61
        driver.emit(True)
        self.assertFalse(self.bridge.available)
        self.assertEqual(self.bridge.events[-1]['source'], 'stale')
        driver.emit(True, source='independent_readback')
        self.assertTrue(self.bridge.available)

    async def test_query_failure_and_command_failure_mark_unavailable(self):
        for operation in ('query', 'command'):
            with self.subTest(operation=operation):
                driver = await self.connect(False)
                if operation == 'query':
                    driver.fail_query = True
                    call = self.bridge.async_request_state()
                else:
                    driver.fail_command = True
                    call = self.bridge.async_set_power(True)
                with self.assertRaises(RuntimeError):
                    await call
                self.assertFalse(self.bridge.available)
                self.assertNotIn('private-token', json.dumps(self.bridge.diagnostics()))

    async def test_only_selected_case_begin_button_opens_an_event_window(self):
        driver = await self.connect(False)
        self.bridge.select_case('panel_on')
        driver.emit(False)
        self.assertIsNone(self.bridge.events[-1]['window_case'])
        self.bridge.begin_window()
        start = self.bridge.events[-1]
        self.assertEqual(start['kind'], 'window_started')
        self.assertIs(start['state'], False)
        self.bridge.select_case('panel_off')
        driver.emit(True)
        self.assertEqual(self.bridge.events[-1]['window_case'], 'panel_on')
        self.assertEqual(self.bridge.events[-1]['window_id'], start['window_id'])

    async def test_reset_log_does_not_operate_device_and_uses_new_session(self):
        driver = await self.connect(False)
        old_session = self.bridge.session_id
        before = list(driver.calls)
        self.bridge.begin_window()
        self.bridge.reset_log()
        self.assertNotEqual(old_session, self.bridge.session_id)
        self.assertEqual(driver.calls, before)
        self.assertEqual(len(self.bridge.events), 1)
        self.assertIsNone(self.bridge.window_case)
        self.assertTrue(self.bridge.available)

    async def test_diagnostic_fixed_whitelist_does_not_dump_driver_or_binding_extras(self):
        driver = await self.connect(False)
        self.bridge.binding['secret'] = 'do-not-export-this'
        driver.token = 'do-not-export-that'
        driver.on_state(dict(identifier=IDENTIFIER, power=True, source='independent_push', secret='do-not-export-extra'))
        document = self.bridge.diagnostics()
        serialized = json.dumps(document)
        self.assertNotIn('do-not-export', serialized)
        self.assertEqual(document['artifact'], 'mc7021_ha_acceptance_diagnostics')
        self.assertFalse(document['simulation'])
        self.assertFalse(document['physical_feedback_verified'])
        self.assertTrue(document['private'])
        ids = [event['event_id'] for event in document['events']]
        self.assertEqual(ids, sorted(set(ids)))

    async def test_bounded_ring_marks_dropped_events(self):
        driver = await self.connect(False)
        for _ in range(1100):
            driver.emit(False)
        self.assertEqual(len(self.bridge.events), 1000)
        self.assertGreater(self.bridge.diagnostics()['dropped_events'], 0)

    async def test_shutdown_cannot_be_revived_by_late_callbacks_or_reconnect(self):
        driver = await self.connect(False)
        await self.bridge.async_shutdown()
        driver.emit(True, source='independent_readback')
        driver.on_disconnect()
        self.now += 100
        await self.bridge.async_maintain()
        with self.assertRaises(ValueError):
            await self.bridge.async_connect()
        self.assertFalse(self.bridge.available)

    async def test_shutdown_during_connect_prevents_a_new_state_query(self):
        driver = FakeDriver()
        started, resume = asyncio.Event(), asyncio.Event()
        original = driver.async_connect
        async def paused(**kwargs):
            await original(**kwargs)
            started.set()
            await resume.wait()
        driver.async_connect = paused
        self.bridge.driver_factory = lambda: driver
        connecting = asyncio.create_task(self.bridge.async_connect())
        await started.wait()
        stopping = asyncio.create_task(self.bridge.async_shutdown())
        await asyncio.sleep(0)
        resume.set()
        with self.assertRaises(ValueError):
            await connecting
        await stopping
        self.assertNotIn(('query',), driver.calls)
        self.assertFalse(self.bridge.available)

    async def test_shutdown_during_old_disconnect_prevents_creating_a_new_driver(self):
        driver = await self.connect(False)
        started, resume = asyncio.Event(), asyncio.Event()
        async def paused():
            started.set()
            await resume.wait()
        driver.async_disconnect = paused
        connecting = asyncio.create_task(self.bridge.async_connect())
        await started.wait()
        stopping = asyncio.create_task(self.bridge.async_shutdown())
        await asyncio.sleep(0)
        resume.set()
        with self.assertRaises(ValueError):
            await connecting
        await stopping
        self.assertEqual(len(self.drivers), 1)
        self.assertFalse(self.bridge.available)

    async def test_driver_calls_have_a_bounded_timeout(self):
        driver = FakeDriver()
        async def stuck(**kwargs):
            await asyncio.Future()
        driver.async_connect = stuck
        self.bridge.driver_factory = lambda: driver
        with mock.patch.object(bridge_module, 'DRIVER_TIMEOUT', 0.001):
            with self.assertRaises(asyncio.TimeoutError):
                await self.bridge.async_connect()
        self.assertFalse(self.bridge.available)

    async def test_cancelled_command_disconnects_instead_of_retaining_known_state(self):
        driver = await self.connect(False)
        started = asyncio.Event()
        async def stuck(power):
            started.set()
            await asyncio.Future()
        driver.async_set_power = stuck
        task = asyncio.create_task(self.bridge.async_set_power(True))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.bridge.available)
        self.assertIn(('disconnect',), driver.calls)


class InstallContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.raw = b'DRIVER_API_VERSION = 1\nraise RuntimeError("must never execute during inspection")\n'
        self.install()

    def install(self, **updates):
        data = dict(binding(self.raw), **updates)
        (self.directory / 'binding.json').write_text(json.dumps(data))
        (self.directory / 'driver.py').write_bytes(self.raw)

    def test_inspection_hashes_without_importing_or_executing_driver(self):
        data, raw = contract.inspect_install(self.directory)
        self.assertEqual(raw, self.raw)
        self.assertEqual(data['host_ip'], '192.0.2.20')

    def test_changed_driver_and_missing_binding_are_rejected(self):
        (self.directory / 'driver.py').write_bytes(self.raw + b'\n')
        with self.assertRaises(ValueError):
            contract.inspect_install(self.directory)
        (self.directory / 'binding.json').unlink()
        with self.assertRaises(ValueError):
            contract.inspect_install(self.directory)

    def test_simulation_wrong_identifier_or_invalid_hash_never_load(self):
        for updates in ({'simulation': True}, {'target_identifier': '0102'}, {'driver_sha256': 'z' * 64},
                        {'host_ip': '127.0.0.1'}, {'wizard_id': '../escape'}):
            with self.subTest(updates=updates):
                self.install(**updates)
                with self.assertRaises(ValueError):
                    contract.inspect_install(self.directory)

    def test_placeholder_is_rejected_before_its_code_can_execute(self):
        self.raw = (TEMPLATE / 'driver.py').read_bytes()
        self.install()
        with self.assertRaises(ValueError):
            contract.inspect_install(self.directory)

    def test_symlinked_driver_is_rejected(self):
        target = self.directory / 'real.py'
        target.write_bytes(self.raw)
        (self.directory / 'driver.py').unlink()
        (self.directory / 'driver.py').symlink_to(target)
        with self.assertRaises(ValueError):
            contract.inspect_install(self.directory)

    def test_driver_contract_requires_all_async_methods(self):
        with self.assertRaises(ValueError):
            contract.load_approved_driver(b'DRIVER_API_VERSION = 1\nclass Driver: pass\n')
        source = b'''DRIVER_API_VERSION = 1
class Driver:
    async def async_connect(self, **kwargs): pass
    async def async_set_power(self, power): pass
    async def async_request_state(self): pass
    async def async_disconnect(self): pass
'''
        self.assertEqual(contract.load_approved_driver(source).__name__, 'Driver')


def fake_ha_modules():
    modules = {}
    for name in ('homeassistant', 'homeassistant.config_entries', 'homeassistant.const',
                 'homeassistant.exceptions', 'homeassistant.helpers', 'homeassistant.helpers.event',
                 'homeassistant.helpers.entity', 'homeassistant.components',
                 'homeassistant.components.light', 'homeassistant.components.select',
                 'homeassistant.components.button', 'voluptuous'):
        modules[name] = types.ModuleType(name)
    class Flow:
        def __init_subclass__(cls, **kwargs):
            pass
        async def async_set_unique_id(self, unique_id): self.unique_id = unique_id
        def _abort_if_unique_id_configured(self): pass
        def async_abort(self, **kwargs): return dict(type='abort', **kwargs)
        def async_show_form(self, **kwargs): return dict(type='form', **kwargs)
        def async_create_entry(self, **kwargs): return dict(type='create_entry', **kwargs)
    class Entity:
        async def async_added_to_hass(self): pass
        def async_on_remove(self, callback): self.remove_callback = callback
        def async_write_ha_state(self): pass
    class Required:
        def __init__(self, key, default=None): self.key, self.default = key, default
    modules['homeassistant'].config_entries = modules['homeassistant.config_entries']
    modules['homeassistant.config_entries'].ConfigFlow = Flow
    modules['homeassistant.const'].Platform = types.SimpleNamespace(LIGHT='light', SELECT='select', BUTTON='button')
    modules['homeassistant.exceptions'].ConfigEntryNotReady = type('ConfigEntryNotReady', (Exception,), {})
    modules['homeassistant.exceptions'].HomeAssistantError = type('HomeAssistantError', (Exception,), {})
    modules['homeassistant.helpers.event'].async_track_time_interval = lambda *args: lambda: None
    modules['homeassistant.helpers.entity'].EntityCategory = types.SimpleNamespace(DIAGNOSTIC='diagnostic')
    modules['homeassistant.components.light'].LightEntity = Entity
    modules['homeassistant.components.light'].ColorMode = types.SimpleNamespace(ONOFF='onoff')
    modules['homeassistant.components.select'].SelectEntity = Entity
    modules['homeassistant.components.button'].ButtonEntity = Entity
    modules['voluptuous'].Required = Required
    modules['voluptuous'].Schema = lambda value: value
    return modules


class HAWrapperTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.patcher = mock.patch.dict(sys.modules, fake_ha_modules())
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        for name in ('config_flow', 'light', 'select', 'button', 'diagnostics'):
            sys.modules.pop(PACKAGE + '.' + name, None)
        self.flow_module = importlib.import_module(PACKAGE + '.config_flow')
        self.light_module = importlib.import_module(PACKAGE + '.light')
        self.button_module = importlib.import_module(PACKAGE + '.button')
        self.select_module = importlib.import_module(PACKAGE + '.select')
        self.diag_module = importlib.import_module(PACKAGE + '.diagnostics')
        self.entrypoint = types.ModuleType(PACKAGE + '._entrypoint')
        self.entrypoint.__package__ = PACKAGE
        exec(compile((TEMPLATE / '__init__.py').read_bytes(), str(TEMPLATE / '__init__.py'), 'exec'),
             self.entrypoint.__dict__)
        async def executor(function, *args): return function(*args)
        self.hass = types.SimpleNamespace(async_add_executor_job=executor)
        self.entry = types.SimpleNamespace(data=dict(name='测试单灯', **{key: binding()[key] for key in
            ('target_identifier', 'driver_sha256', 'baseline_review_sha256')}),
            unique_id='192.0.2.20_' + IDENTIFIER, entry_id='test_entry')

    async def test_setup_without_explicit_approval_neither_inspects_nor_imports_driver(self):
        with mock.patch.object(self.entrypoint, 'inspect_install', side_effect=AssertionError('Must not read driver')):
            with self.assertRaises(self.entrypoint.ConfigEntryNotReady):
                await self.entrypoint.async_setup_entry(self.hass, self.entry)

    async def test_setup_checks_binding_before_importing_driver_and_hides_exceptions(self):
        self.entry.data.update(host='192.0.2.21', package_id='package_test',
                               driver_approved=True, enable_single_light_control=True)
        with mock.patch.object(self.entrypoint, 'inspect_install', return_value=(binding(), b'not executed')):
            with mock.patch.object(self.entrypoint, 'load_approved_driver', side_effect=AssertionError('Must not execute changed binding')):
                with self.assertRaises(self.entrypoint.ConfigEntryNotReady) as caught:
                    await self.entrypoint.async_setup_entry(self.hass, self.entry)
        self.assertNotIn('192.0.2.', str(caught.exception))

    async def test_changed_driver_hash_with_same_package_id_cannot_reuse_approval(self):
        self.entry.data.update(host='192.0.2.20', package_id='package_test',
                               driver_approved=True, enable_single_light_control=True)
        changed = dict(binding(), driver_sha256='b' * 64)
        with mock.patch.object(self.entrypoint, 'inspect_install', return_value=(changed, b'not executed')):
            with mock.patch.object(self.entrypoint, 'load_approved_driver', side_effect=AssertionError('New driver not approved')):
                with self.assertRaises(self.entrypoint.ConfigEntryNotReady):
                    await self.entrypoint.async_setup_entry(self.hass, self.entry)

    async def test_setup_forwards_native_platforms_and_unload_permanently_stops_bridge(self):
        self.entry.data.update(host='192.0.2.20', package_id='package_test',
                               driver_approved=True, enable_single_light_control=True)
        callbacks, forwarded = [], []
        self.entry.async_on_unload = callbacks.append
        async def forward(entry, platforms): forwarded.extend(platforms)
        async def unload(entry, platforms): return True
        self.hass.config_entries = types.SimpleNamespace(async_forward_entry_setups=forward,
            async_unload_platforms=unload)
        self.hass.data = {}
        with mock.patch.object(self.entrypoint, 'inspect_install', return_value=(binding(), b'not executed')):
            with mock.patch.object(self.entrypoint, 'load_approved_driver', return_value=FakeDriver):
                self.assertTrue(await self.entrypoint.async_setup_entry(self.hass, self.entry))
        self.assertEqual(set(forwarded), {'light', 'select', 'button'})
        self.assertEqual(len(callbacks), 1)
        bridge = self.hass.data['mc7021_single_light'][self.entry.entry_id]
        self.assertFalse(bridge.available)  # Connect alone is not independent readback.
        bridge._driver.emit(False, source='independent_readback')
        self.assertTrue(bridge.available)
        self.assertTrue(await self.entrypoint.async_unload_entry(self.hass, self.entry))
        self.assertFalse(bridge.available)
        with self.assertRaises(ValueError):
            await bridge.async_connect()
        self.assertNotIn(self.entry.entry_id, self.hass.data['mc7021_single_light'])

    async def test_failed_platform_setup_shuts_down_driver_and_removes_runtime(self):
        self.entry.data.update(host='192.0.2.20', package_id='package_test',
                               driver_approved=True, enable_single_light_control=True)
        self.entry.async_on_unload = lambda callback: None
        async def forward(entry, platforms): raise RuntimeError('platform fixture')
        self.hass.config_entries = types.SimpleNamespace(async_forward_entry_setups=forward)
        self.hass.data = {}
        driver = FakeDriver()
        with mock.patch.object(self.entrypoint, 'inspect_install', return_value=(binding(), b'not executed')):
            with mock.patch.object(self.entrypoint, 'load_approved_driver', return_value=lambda: driver):
                with self.assertRaises(RuntimeError):
                    await self.entrypoint.async_setup_entry(self.hass, self.entry)
        self.assertIn(('disconnect',), driver.calls)
        self.assertNotIn(self.entry.entry_id, self.hass.data['mc7021_single_light'])

    async def test_config_flow_missing_approval_stays_form_and_never_loads_driver(self):
        flow = self.flow_module.ConfigFlow()
        flow.hass = self.hass
        with mock.patch.object(self.flow_module, 'inspect_install', return_value=(binding(), b'raise RuntimeError')):
            result = await flow.async_step_user(dict(host='192.0.2.20', name='测试单灯', driver_approved=False, enable_single_light_control=True))
        self.assertEqual(result['type'], 'form')
        self.assertEqual(result['errors']['base'], 'approval_required')

    async def test_config_flow_approved_exact_host_creates_entry_without_connecting(self):
        flow = self.flow_module.ConfigFlow()
        flow.hass = self.hass
        with mock.patch.object(self.flow_module, 'inspect_install', return_value=(binding(), b'raise RuntimeError')):
            result = await flow.async_step_user(dict(host='192.0.2.20', name='  测试单灯  ', driver_approved=True, enable_single_light_control=True))
        self.assertEqual(result['type'], 'create_entry')
        self.assertEqual(result['title'], '测试单灯')
        self.assertEqual(flow.unique_id, '192.0.2.20_' + IDENTIFIER)
        self.assertEqual(result['data']['package_id'], 'package_test')
        self.assertEqual(result['data']['driver_sha256'], binding()['driver_sha256'])

    async def test_config_flow_mismatched_host_or_invalid_package_is_rejected(self):
        flow = self.flow_module.ConfigFlow()
        flow.hass = self.hass
        with mock.patch.object(self.flow_module, 'inspect_install', return_value=(binding(), b'')):
            result = await flow.async_step_user(dict(host='192.0.2.21', name='灯', driver_approved=True, enable_single_light_control=True))
            self.assertEqual(result['errors']['host'], 'host_mismatch')
        with mock.patch.object(self.flow_module, 'inspect_install', side_effect=ValueError('secret')):
            self.assertEqual((await flow.async_step_user())['reason'], 'invalid_private_package')

    async def test_light_has_only_onoff_mode_and_waits_for_feedback(self):
        driver = FakeDriver()
        bridge = Bridge(lambda: driver, binding())
        light = self.light_module.ReviewedLight(bridge, self.entry)
        self.assertEqual(light._attr_supported_color_modes, {'onoff'})
        self.assertIsNone(light.is_on)
        await bridge.async_connect()
        driver.emit(False, source='independent_readback')
        await light.async_turn_on()
        self.assertIs(light.is_on, False)
        driver.emit(True)
        self.assertIs(light.is_on, True)

    async def test_select_and_buttons_offer_native_acceptance_without_service_console(self):
        driver = FakeDriver()
        bridge = Bridge(lambda: driver, binding())
        await bridge.async_connect()
        driver.emit(False, source='independent_readback')
        selector = self.select_module.AcceptanceStep(bridge, self.entry)
        await selector.async_select_option(selector._attr_options[4])
        self.assertEqual(bridge.selected_case, 'panel_on')
        begin = self.button_module.AcceptanceButton(bridge, self.entry, 'begin', 'begin', 'icon')
        await begin.async_press()
        self.assertEqual(bridge.window_case, 'panel_on')
        disconnect = self.button_module.AcceptanceButton(bridge, self.entry, 'disconnect', 'disconnect', 'icon')
        await disconnect.async_press()
        self.assertFalse(bridge.available)
        reconnect = self.button_module.AcceptanceButton(bridge, self.entry, 'reconnect', 'reconnect', 'icon')
        await reconnect.async_press()
        self.assertEqual(bridge.generation, 2)
        self.assertFalse(bridge.available)

    async def test_diagnostics_returns_only_private_bridge_log(self):
        bridge = Bridge(FakeDriver, binding())
        self.hass.data = {'mc7021_single_light': {self.entry.entry_id: bridge}}
        result = await self.diag_module.async_get_config_entry_diagnostics(self.hass, self.entry)
        self.assertTrue(result['private'])
        self.assertNotIn('data', result)
        self.assertNotIn('name', result)


if __name__ == '__main__':
    unittest.main()
