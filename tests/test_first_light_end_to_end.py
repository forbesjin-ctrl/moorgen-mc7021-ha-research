"""Whole first-light software chain, with fabricated originals and RAM peers.

These tests intentionally exercise owner-origin declarations in a temporary
fixture. They never establish real household compatibility, authenticate an
actual MC7021, install HA, or observe a physical lamp. The fixed packaged driver
is executed only inside this test with an injected in-memory transport. Socket,
DNS, subprocess and upload paths remain blocked by the source fixture.
"""
import asyncio
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import analyze_capture
import baseline_review
import demo_sample
import first_light_flow
import gui_worker
import ha_wizard
import offline_shcp
import test_driver_profile as fixtures
import test_ha_component as ha_fixture
from test_single_light_driver import MemoryPeer


class CapturedPortPeer(MemoryPeer):
    """RAM-only host requiring the port and fresh credentials in the fixture."""
    def __init__(self, testcase, credentials):
        super().__init__()
        self.testcase, self.credentials = testcase, credentials
        self.open_calls = []

    async def open(self, host, port):
        self.testcase.assertEqual((host, port), (demo_sample.HOST, 12345))
        self.open_calls.append((host, port))
        # The reused synthetic peer validates its own fixed test port. This
        # translation occurs entirely in RAM; no listener/socket is involved.
        return await super().open(host, 9000)

    def receive(self, writer, raw):
        packet = offline_shcp.parse_frame(raw)
        if (packet['protocol_type'], packet['link_code']) == (2, 4):
            self.testcase.assertEqual([(field['id'], bytes.fromhex(field['value_hex']))
                for field in packet['fields']], [(12, self.credentials['username'].encode('ascii')),
                                                (13, self.credentials['password'].encode('ascii'))])
        super().receive(writer, raw)


class FirstLightEndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # IsolatedAsyncioTestCase creates its loop before these fixture socket
        # guards are installed; the guard therefore cannot mask loop creation.
        asyncio.get_running_loop().slow_callback_duration = 2.0
        self.fixture = fixtures.DriverProfileTests('runTest')
        self.fixture.setUp()
        self.root = self.fixture.root
        self.bridges = []

    async def asyncTearDown(self):
        try:
            for bridge in self.bridges:
                await bridge.async_shutdown()
        finally:
            self.fixture.doCleanups()

    def prepare_packaged_driver(self):
        directory, report = analyze_capture.analyze_session(self.fixture.first, self.root / 'private_reports')
        form = baseline_review.draft_review(report)
        form.update(decisions={key: 'pass' for key in baseline_review.CRITERION_IDS},
            notes={key: 'Fabricated integration-test declaration only; no physical observation.'
                   for key in baseline_review.CRITERION_IDS}, selected_identifier=demo_sample.DEVICE.hex())
        review, _ = baseline_review.save_review(directory, self.fixture.first, self.root, **form)
        arguments = ['--data-dir', str(self.root), 'first-light-adapt',
            '--session-dir', str(self.fixture.first), '--comparison-dir', str(self.fixture.second),
            '--identifier', demo_sample.DEVICE.hex(), '--review-file', str(review)]
        output = io.StringIO()
        protocol = gui_worker.Protocol(io.StringIO(), output)
        with mock.patch.object(protocol, 'request_credentials', side_effect=lambda: self.fixture.credentials()) as prompt:
            code = gui_worker.run(arguments, protocol=protocol)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(code, 0, events)
        self.assertEqual(prompt.call_count, 1)
        result = next(row for row in events if row['type'] == 'ha_wizard')
        path, state = Path(result['wizard_file']), result['state']
        self.assertFalse(state['assessment']['passed'])
        self.assertFalse(state['physical_feedback_verified'])
        self.assertFalse(any(row['type'] in ('capture_preflight', 'sampling_preparation') for row in events))
        prefix = 'custom_components/mc7021_single_light/'
        component = self.root / 'TEST_ONLY_EXTRACTED_COMPONENT'
        component.mkdir()
        with zipfile.ZipFile(path.parent / state['bundle']['file']) as archive:
            binding_raw, driver_raw = archive.read(prefix + 'binding.json'), archive.read(prefix + 'driver.py')
            self.assertEqual(driver_raw, (ROOT / 'tools/single_light_driver.py').read_bytes())
            self.assertEqual(archive.read(prefix + 'bridge.py'),
                (ROOT / 'ha_component_templates/custom_components/mc7021_single_light/bridge.py').read_bytes())
            for name in archive.namelist():
                raw = archive.read(name)
                self.assertNotIn(fixtures.USERNAME.encode(), raw)
                self.assertNotIn(fixtures.PASSWORD.encode(), raw)
        (component / 'binding.json').write_bytes(binding_raw)
        (component / 'driver.py').write_bytes(driver_raw)
        binding, inspected_raw = ha_fixture.contract.inspect_install(component)
        self.assertEqual(binding['builtin_profile']['port'], 12345)
        self.assertEqual(binding['driver_sha256'], hashlib.sha256(driver_raw).hexdigest())
        # Explicit test-only execution of our exact packaged implementation.
        # Production Mac code never invokes this loader.
        driver_class = ha_fixture.contract.load_approved_driver(inspected_raw)
        peer = CapturedPortPeer(self, self.fixture.credentials())
        bridge = ha_fixture.Bridge(lambda: driver_class(profile=binding['builtin_profile'],
            credentials=self.fixture.credentials(), open_connection=peer.open), binding)
        self.bridges.append(bridge)
        _, state = ha_wizard.record_installation(path, self.root, dict(entity_id='light.fabricated_end_to_end',
            confirmed=True, notes='Fabricated integration test only; HA is not installed or running.'))
        return path, state, review, binding, driver_class, peer, bridge

    async def settle(self):
        for _ in range(12):
            await asyncio.sleep(0)

    def observation(self, bridge, case, *, physical, ha_state, kind='state'):
        event = next(row for row in reversed(bridge.events) if row['step_id'] == case and row['kind'] == kind)
        return dict(decision='pass', physical_light=physical, ha_state=ha_state,
            notes='Synthetic RAM peer and fabricated manual declaration; never a real physical acceptance.',
            event_id=event['event_id'])

    def import_diagnostics(self, path, bridge):
        diagnostics = bridge.diagnostics()
        self.assertFalse(diagnostics['physical_feedback_verified'])
        self.assertFalse(diagnostics['identity_authenticated'])
        serialized = json.dumps(diagnostics)
        self.assertNotIn(fixtures.USERNAME, serialized)
        self.assertNotIn(fixtures.PASSWORD, serialized)
        source = self.root / 'TEST_ONLY_RAM_PEER_DIAGNOSTICS.json'
        source.write_text(serialized, encoding='utf-8')
        return ha_wizard.import_diagnostics(path, source, self.root)

    def refresh(self, review, wizard):
        return first_light_flow.refresh_flow(self.fixture.first, self.root,
            selected_identifier=demo_sample.DEVICE.hex(), comparison_directory=self.fixture.second,
            review_file=review, wizard_file=wizard)

    async def test_complete_packaged_driver_bridge_diagnostics_and_owner_declaration_chain(self):
        path, _, review, binding, _, peer, bridge = self.prepare_packaged_driver()
        await bridge.async_connect()
        self.assertTrue(bridge.available)
        self.assertFalse(bridge.power)
        observations = {}
        for case, _, expected in ha_wizard.CASE_TITLES:
            bridge.select_case(case)
            bridge.begin_window()
            if case.startswith('ha_'):
                await bridge.async_set_power(expected)
                self.assertIs(bridge.power, expected)
                observations[case] = self.observation(bridge, case,
                    physical='on' if peer.power else 'off', ha_state='on' if bridge.power else 'off')
            elif case.startswith('panel_'):
                peer.panel(expected)
                await self.settle()
                self.assertIs(bridge.power, expected)
                observations[case] = self.observation(bridge, case,
                    physical='on' if peer.power else 'off', ha_state='on' if bridge.power else 'off')
            elif case == 'disconnect':
                await bridge.async_disconnect()
                peer.power = True  # Model the original panel while this adapter is disconnected.
                self.assertFalse(bridge.available)
                self.assertIsNone(bridge.power)
                observations[case] = self.observation(bridge, case, physical='on',
                    ha_state='unavailable', kind='unavailable')
            else:
                await bridge.async_connect()
                self.assertTrue(bridge.available)
                self.assertTrue(bridge.power)
                observations[case] = self.observation(bridge, case, physical='on', ha_state='on')
        self.assertEqual(peer.open_calls, [(demo_sample.HOST, 12345)] * 2)
        self.assertEqual(len([row for row in peer.frames if (row['protocol_type'], row['link_code']) == (4, 9)]), 4)
        self.assertEqual(len([row for row in peer.frames if (row['protocol_type'], row['link_code']) == (2, 4)]), 2)
        reconnect_event = next(row for row in bridge.events if row['event_id'] == observations['reconnect']['event_id'])
        self.assertEqual(reconnect_event['source'], 'independent_readback')
        self.assertEqual(reconnect_event['generation'], 2)
        self.assertEqual(binding['target_identifier'], demo_sample.DEVICE.hex())
        self.import_diagnostics(path, bridge)
        _, state = ha_wizard.save_acceptance(path, self.root, observations)
        self.assertTrue(state['assessment']['passed'], state['assessment'])
        self.assertEqual(state['assessment']['stage'], 'complete')
        self.assertFalse(state['assessment']['physical_feedback_verified'])
        self.assertTrue(all(row['status'] == 'confirmed' for row in state['assessment']['criteria']))
        _, flow = self.refresh(review, path)
        self.assertTrue(flow['owner_declared_acceptance_passed'])
        self.assertTrue(flow['can_expand_to_other_lights'])
        self.assertEqual(flow['next_action']['action'], 'complete')
        self.assertFalse(flow['physical_feedback_verified'])
        self.assertFalse(flow['machine_physical_feedback_verified'])
        self.assertFalse(flow['network_access_performed'])
        self.assertFalse(flow['driver_executed'])
        self.assertFalse(flow['upload_performed'])

    async def test_ack_only_command_cannot_pass_even_with_claimed_manual_success(self):
        path, _, review, _, driver_class, peer, bridge = self.prepare_packaged_driver()
        # Bound only this test's exec-created module; no production source edit.
        driver_class.async_connect.__globals__['OPERATION_TIMEOUT'] = 0.03
        await bridge.async_connect()
        self.assertTrue(bridge.available)
        peer.auto_query = False
        peer.execute_commands = False
        bridge.select_case('ha_on_1')
        bridge.begin_window()
        error_class = driver_class.async_connect.__globals__['DriverError']
        with self.assertRaises(error_class) as error:
            await bridge.async_set_power(True)
        self.assertFalse(error.exception.fatal_setup)
        self.assertFalse(bridge.available)
        self.assertIsNone(bridge.power)
        self.assertFalse(peer.power)
        self.assertFalse(any(row['kind'] == 'state' and row['step_id'] == 'ha_on_1' for row in bridge.events))
        self.import_diagnostics(path, bridge)
        # A falsely optimistic declaration tied to the actual request event
        # must still fail: neither ACK nor a request is independent feedback.
        claimed = self.observation(bridge, 'ha_on_1', physical='on', ha_state='on', kind='command_requested')
        _, state = ha_wizard.save_acceptance(path, self.root, {'ha_on_1': claimed})
        self.assertFalse(state['assessment']['passed'])
        first = next(row for row in state['assessment']['criteria'] if row['id'] == 'ha_on_1')
        self.assertEqual(first['status'], 'resample')
        self.assertTrue(any('独立状态' in text for text in first['gaps']))
        _, flow = self.refresh(review, path)
        self.assertFalse(flow['owner_declared_acceptance_passed'])
        self.assertFalse(flow['can_expand_to_other_lights'])
        self.assertEqual(flow['next_action']['action'], 'record_ha_acceptance')


if __name__ == '__main__':
    unittest.main()
