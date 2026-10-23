"""Pure offline state-machine tests with one synthetic explicit identifier."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('community_light_state_model',
                                             ROOT / 'tools/light_state_model.py')
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)
IDENTIFIER = bytes.fromhex('0102030405060708')


def report(is_on=True, **changes):
    value = {'device_identifier_hex': IDENTIFIER.hex(), 'state_present': True,
             'device_type_context': 'ordinary_light',
             'status_context': {'device_status_context_confirmed': True},
             'candidate_is_on': is_on, 'physical_feedback_verified': False}
    value.update(changes)
    return value


class LightStateModelTests(unittest.TestCase):
    def new(self, stale=10):
        model = state.LightStateModel(IDENTIFIER, stale_after_seconds=stale)
        session = model.connect(0)
        return model, session

    def test_initial_state_unknown_disconnected_and_unavailable(self):
        model = state.LightStateModel(IDENTIFIER)
        self.assertFalse(model.connected)
        self.assertFalse(model.available)
        self.assertIsNone(model.is_on)
        self.assertIsNone(model.last_state_at)
        self.assertIsNone(model.source)
        self.assertIsNone(model.pending)
        self.assertIsNone(model.session_id)
        self.assertFalse(model.physical_feedback_verified)

    def test_constructor_requires_eight_explicit_bytes(self):
        for identifier in (None, True, 0x1234, IDENTIFIER.hex(), b'', b'1234567', b'123456789'):
            with self.subTest(identifier=identifier), self.assertRaises(state.StateModelError):
                state.LightStateModel(identifier)
        mutable = bytearray(IDENTIFIER)
        model = state.LightStateModel(mutable)
        mutable[0] = 255
        self.assertEqual(model.target_identifier, IDENTIFIER)

    def test_staleness_must_be_positive_finite_numeric(self):
        for timeout in (0, -1, True, False, '10', None, float('nan'), float('inf'), 10 ** 1000):
            with self.subTest(timeout=repr(timeout)[:30]), self.assertRaises(state.StateModelError):
                state.LightStateModel(IDENTIFIER, timeout)

    def test_connect_waits_for_new_report(self):
        model, session = self.new()
        self.assertEqual(session, 1)
        self.assertTrue(model.connected)
        self.assertFalse(model.available)
        self.assertIsNone(model.is_on)
        self.assertFalse(model.tick(1))

    def test_request_requires_connection_and_bool(self):
        model = state.LightStateModel(IDENTIFIER)
        with self.assertRaisesRegex(state.StateModelError, 'connected'):
            model.request(True, 0)
        model.connect(0)
        before = model.snapshot()
        for desired in (0, 1, None, 'on', [], b'\x01'):
            with self.subTest(desired=desired), self.assertRaisesRegex(state.StateModelError, 'bool'):
                model.request(desired, 1)
        self.assertEqual(model.snapshot(), before)

    def test_request_is_intent_only_and_ack_is_not_state(self):
        model, session = self.new()
        pending = model.request(True, 1)
        self.assertEqual(pending, {'request_id': 1, 'session_id': session,
                                  'requested_is_on': True, 'requested_at': 1.0,
                                  'acknowledged_at': None})
        self.assertIsNone(model.is_on)
        self.assertFalse(model.available)
        self.assertIsNone(model.last_state_at)
        self.assertTrue(model.ack(2))
        self.assertEqual(model.pending['acknowledged_at'], 2)
        self.assertIsNone(model.is_on)
        self.assertFalse(model.available)
        self.assertIsNone(model.last_state_at)
        self.assertIsNone(model.source)

    def test_request_and_ack_preserve_observed_state_availability_and_time(self):
        model, session = self.new()
        model.apply_state(report(False), 1, session_id=session)
        model.request(True, 2)
        model.ack(3)
        self.assertFalse(model.is_on)
        self.assertTrue(model.available)
        self.assertEqual(model.last_state_at, 1)
        self.assertEqual(model.source, 'independent_report_candidate')
        self.assertIsNotNone(model.pending)

    def test_ack_without_pending_or_connection_is_only_an_observation(self):
        model, session = self.new()
        self.assertFalse(model.ack(1))
        self.assertFalse(model.available)
        model.disconnect()
        self.assertFalse(model.ack(2))
        self.assertFalse(model.available)

    def test_qualifying_report_updates_candidate_state(self):
        model, session = self.new()
        self.assertTrue(model.apply_state(report(True), 1, session_id=session))
        self.assertTrue(model.is_on)
        self.assertTrue(model.available)
        self.assertEqual(model.last_state_at, 1)
        self.assertEqual(model.source, 'independent_report_candidate')
        self.assertFalse(model.physical_feedback_verified)
        self.assertFalse(model.physical_verified)
        self.assertFalse(model.snapshot()['physical_feedback_verified'])

    def test_report_cannot_claim_physical_verification(self):
        model, session = self.new()
        self.assertTrue(model.apply_state(report(physical_feedback_verified=True), 1, session_id=session))
        self.assertFalse(model.physical_feedback_verified)
        self.assertFalse(model.snapshot()['physical_feedback_verified'])
        with self.assertRaises(AttributeError):
            model.physical_feedback_verified = True

    def test_another_target_cannot_update_or_refresh_state(self):
        model, session = self.new()
        model.apply_state(report(False), 1, session_id=session)
        self.assertFalse(model.apply_state(report(device_identifier_hex='0807060504030201'), 2,
                                           session_id=session))
        self.assertFalse(model.is_on)
        self.assertEqual(model.last_state_at, 1)
        self.assertFalse(model.tick(11))

    def test_missing_or_malformed_identifier_is_rejected(self):
        for identifier in (None, 1, True, IDENTIFIER, '', '01020304', 'g' * 16,
                           '01 02030405060708', '010203040506070800'):
            model, session = self.new()
            self.assertFalse(model.apply_state(report(device_identifier_hex=identifier), 1,
                                               session_id=session))
            self.assertFalse(model.available)

    def test_uppercase_explicit_hex_identifier_is_supported(self):
        model = state.LightStateModel(bytes.fromhex('aabbccdd01020304'))
        session = model.connect(0)
        self.assertTrue(model.apply_state(report(device_identifier_hex='AABBCCDD01020304'), 1,
                                          session_id=session))

    def test_required_status_context_and_light_type_are_strict(self):
        changes = [
            {'state_present': None}, {'state_present': False}, {'state_present': 1},
            {'device_type_context': None}, {'device_type_context': 'unconfirmed'},
            {'device_type_context': 'dimmer'}, {'status_context': None},
            {'status_context': {}}, {'status_context': []},
            {'status_context': {'device_status_context_confirmed': False}},
            {'status_context': {'device_status_context_confirmed': 1}},
            {'status_context': {'device_status_context_confirmed': 'true'}},
        ]
        for changeset in changes:
            with self.subTest(changeset=changeset):
                model, session = self.new()
                self.assertFalse(model.apply_state(report(**changeset), 1, session_id=session))
                self.assertIsNone(model.is_on)
                self.assertFalse(model.available)

    def test_each_missing_required_field_rejects_observation(self):
        for field in ('device_identifier_hex', 'state_present', 'device_type_context',
                      'status_context', 'candidate_is_on'):
            model, session = self.new()
            record = report()
            record.pop(field)
            self.assertFalse(model.apply_state(record, 1, session_id=session))
            self.assertFalse(model.available)

    def test_candidate_is_on_requires_explicit_bool(self):
        for candidate in (None, 0, 1, 'true', 'on', b'\x01', [], {}):
            model, session = self.new()
            self.assertFalse(model.apply_state(report(candidate), 1, session_id=session))
            self.assertIsNone(model.is_on)

    def test_invalid_records_are_rejected(self):
        for record in (None, True, [], '', 1):
            model, session = self.new()
            self.assertFalse(model.apply_state(record, 1, session_id=session))
            self.assertFalse(model.available)

    def test_apply_state_requires_explicit_software_generation(self):
        model, session = self.new()
        with self.assertRaises(TypeError):
            model.apply_state(report(), 1)
        for generation in (None, True, str(session), session + 1, 0):
            self.assertFalse(model.apply_state(report(), 1, session_id=generation))
        self.assertFalse(model.available)

    def test_old_generation_cannot_restore_cached_state_after_reconnect(self):
        model, old_session = self.new()
        old_record = report(True)
        model.apply_state(old_record, 1, session_id=old_session)
        model.request(False, 2)
        model.disconnect()
        self.assertFalse(model.available)
        self.assertTrue(model.is_on)
        self.assertIsNone(model.pending)
        self.assertIsNone(model.session_id)
        new_session = model.connect(3)
        self.assertNotEqual(new_session, old_session)
        self.assertFalse(model.apply_state(old_record, 4, session_id=old_session))
        self.assertFalse(model.available)
        self.assertEqual(model.last_state_at, 1)
        self.assertIsNone(model.snapshot()['session_state_at'])
        self.assertFalse(model.ack(5))
        self.assertFalse(model.tick(6))
        self.assertTrue(model.apply_state(report(False), 7, session_id=new_session))
        self.assertFalse(model.is_on)
        self.assertTrue(model.available)

    def test_disconnect_invalidates_current_receive_callback(self):
        model, session = self.new()
        model.disconnect()
        self.assertFalse(model.apply_state(report(), 1, session_id=session))
        self.assertIsNone(model.is_on)
        self.assertFalse(model.connected)

    def test_repeated_connect_always_starts_fresh_generation(self):
        model, session = self.new()
        model.apply_state(report(True), 1, session_id=session)
        model.request(False, 2)
        new_session = model.connect(3)
        self.assertGreater(new_session, session)
        self.assertTrue(model.is_on)
        self.assertFalse(model.available)
        self.assertIsNone(model.pending)
        self.assertFalse(model.tick(4))

    def test_expiry_boundary_preserves_last_known_state(self):
        model, session = self.new()
        model.apply_state(report(True), 1, session_id=session)
        self.assertTrue(model.tick(10.999))
        self.assertFalse(model.tick(11))
        self.assertTrue(model.is_on)
        self.assertEqual(model.last_state_at, 1)
        self.assertFalse(model.tick(100))

    def test_only_new_report_restores_expired_availability(self):
        model, session = self.new()
        model.apply_state(report(True), 1, session_id=session)
        model.tick(11)
        model.request(False, 12)
        model.ack(13)
        self.assertFalse(model.available)
        self.assertEqual(model.last_state_at, 1)
        self.assertTrue(model.apply_state(report(False), 14, session_id=session))
        self.assertTrue(model.available)
        self.assertEqual(model.last_state_at, 14)
        self.assertIsNone(model.pending)

    def test_panel_report_updates_state_without_request(self):
        model, session = self.new()
        model.apply_state(report(True), 1, session_id=session)
        self.assertTrue(model.apply_state(report(False), 2, session_id=session))
        self.assertFalse(model.is_on)
        self.assertIsNone(model.pending)
        self.assertEqual(model.last_state_at, 2)

    def test_opposite_report_updates_observed_state_but_leaves_intent_pending(self):
        model, session = self.new()
        model.request(True, 1)
        model.apply_state(report(False), 2, session_id=session)
        self.assertFalse(model.is_on)
        self.assertTrue(model.pending['requested_is_on'])
        model.apply_state(report(True), 3, session_id=session)
        self.assertTrue(model.is_on)
        self.assertIsNone(model.pending)

    def test_every_timed_method_rejects_backwards_time_without_mutation(self):
        methods = [lambda m, s: m.connect(9), lambda m, s: m.request(True, 9),
                   lambda m, s: m.ack(9), lambda m, s: m.tick(9),
                   lambda m, s: m.apply_state(report(), 9, session_id=s)]
        for method in methods:
            model, session = self.new()
            model.apply_state(report(False), 10, session_id=session)
            before = model.snapshot()
            with self.assertRaisesRegex(state.StateModelError, 'backwards'):
                method(model, session)
            self.assertEqual(model.snapshot(), before)

    def test_every_timed_method_rejects_invalid_times(self):
        methods = [lambda m, s, t: m.connect(t), lambda m, s, t: m.request(True, t),
                   lambda m, s, t: m.ack(t), lambda m, s, t: m.tick(t),
                   lambda m, s, t: m.apply_state(report(), t, session_id=s)]
        for method in methods:
            for now in (True, False, None, '1', -1, float('nan'), float('inf'), 10 ** 1000):
                model, session = self.new()
                before = model.snapshot()
                with self.assertRaises(state.StateModelError):
                    method(model, session, now)
                self.assertEqual(model.snapshot(), before)

    def test_equal_timestamps_are_allowed(self):
        model, session = self.new()
        model.request(True, 0)
        model.ack(0)
        self.assertTrue(model.apply_state(report(), 0, session_id=session))
        self.assertTrue(model.tick(0))

    def test_pending_report_and_snapshot_are_not_mutable_model_storage(self):
        model, session = self.new()
        pending = model.request(True, 1)
        pending['requested_is_on'] = False
        self.assertTrue(model.pending['requested_is_on'])
        snapshot = model.snapshot()
        snapshot['available'] = True
        snapshot['pending']['requested_is_on'] = False
        self.assertFalse(model.available)
        self.assertTrue(model.pending['requested_is_on'])
        record = report(True)
        model.apply_state(record, 2, session_id=session)
        record['candidate_is_on'] = False
        self.assertTrue(model.is_on)

    def test_rejected_report_never_refreshes_last_report_time(self):
        model, session = self.new()
        model.apply_state(report(False), 1, session_id=session)
        self.assertFalse(model.apply_state(report(state_present=False), 10, session_id=session))
        self.assertEqual(model.last_state_at, 1)
        self.assertFalse(model.tick(11))

    def test_source_has_no_network_home_assistant_io_or_thread_dependencies(self):
        source = (ROOT / 'tools/light_state_model.py').read_text()
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        self.assertEqual(set(imports), {'__future__', 'math'})


if __name__ == '__main__':
    unittest.main()
