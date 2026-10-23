"""Pure offline single-light state kernel; no device or Home Assistant access.

``connect(now)`` starts a new software generation and returns its integer ID.
The adapter must tag each newly received state record with that generation and
pass it as ``apply_state(record, now, session_id=...)``. Old receive callbacks
must keep their old ID; they must never be retagged after reconnecting. This ID
is an adapter software generation, not a Moorgen wire session or authentication.

Requests and ACK observations only update local pending metadata. They cannot
set the observed lamp state, make it available, or refresh its independent-state
timestamp. Only a qualifying independent report from the current generation
can do that. The model trusts explicit parser context for its software decision;
it does not establish a working protocol, authentication, or physical feedback.
``physical_feedback_verified`` is always False.

Callers supply finite nonnegative monotonic seconds and call ``tick(now)`` when
they need freshness evaluated. There is no clock, timer, thread, or network I/O.
"""
from __future__ import annotations

import math


class StateModelError(ValueError):
    """Invalid explicit identifier, time, or local state-model operation."""


def _seconds(value, name):
    if type(value) not in (int, float):
        raise StateModelError(name + ' must be finite nonnegative numeric seconds')
    try:
        converted = float(value)
    except OverflowError:
        raise StateModelError(name + ' must be finite nonnegative numeric seconds') from None
    if not math.isfinite(converted) or converted < 0:
        raise StateModelError(name + ' must be finite nonnegative numeric seconds')
    return converted


class LightStateModel:
    """Observed software state for one explicitly identified ordinary light.

    The 120-second default is a configurable local freshness policy, not a
    measured Moorgen heartbeat. ``is_on`` retains the last observation while
    unavailable; consumers must check ``available`` before treating it as live.
    Reports may update a light after panel operation without any local request.
    """

    def __init__(self, target_identifier, stale_after_seconds=120):
        if not isinstance(target_identifier, (bytes, bytearray)) or len(target_identifier) != 8:
            raise StateModelError('target_identifier must be exactly 8 explicit bytes')
        self._target_identifier = bytes(target_identifier)
        self._stale_after_seconds = _seconds(stale_after_seconds, 'stale_after_seconds')
        if self._stale_after_seconds == 0:
            raise StateModelError('stale_after_seconds must be greater than zero')
        self._connected = False
        self._available = False
        self._is_on = None
        self._source = None
        self._last_state_at = None
        self._session_state_at = None
        self._last_event_at = None
        self._generation = 0
        self._session_id = None
        self._request_counter = 0
        self._pending = None

    @property
    def target_identifier(self):
        return self._target_identifier

    @property
    def connected(self):
        return self._connected

    @property
    def available(self):
        return self._available

    @property
    def is_on(self):
        return self._is_on

    @property
    def source(self):
        return self._source

    @property
    def last_state_at(self):
        """Last accepted report time, including a prior unavailable generation."""
        return self._last_state_at

    @property
    def session_id(self):
        return self._session_id

    @property
    def pending(self):
        """A copy of local intent metadata, never a command or observed state."""
        return dict(self._pending) if self._pending is not None else None

    @property
    def physical_feedback_verified(self):
        return False

    @property
    def physical_verified(self):
        return False

    def _advance(self, now):
        now = _seconds(now, 'now')
        if self._last_event_at is not None and now < self._last_event_at:
            raise StateModelError('now moved backwards; monotonic time is required')
        self._last_event_at = now
        return now

    def connect(self, now):
        """Begin a new generation; cached state and ACKs cannot make it live."""
        self._advance(now)
        self._generation += 1
        self._session_id = self._generation
        self._connected = True
        self._available = False
        self._session_state_at = None
        self._pending = None
        return self._session_id

    def disconnect(self):
        """Invalidate the generation and pending intent; preserve last-known state."""
        self._connected = False
        self._available = False
        self._session_id = None
        self._session_state_at = None
        self._pending = None

    def request(self, is_on, now):
        """Record local intent only; never construct or send protocol bytes."""
        if type(is_on) is not bool:
            raise StateModelError('is_on must be an explicit bool')
        if not self._connected:
            raise StateModelError('request requires a connected software generation')
        now = self._advance(now)
        self._request_counter += 1
        self._pending = {'request_id': self._request_counter, 'session_id': self._session_id,
                         'requested_is_on': is_on, 'requested_at': now,
                         'acknowledged_at': None}
        return self.pending

    def ack(self, now):
        """Note an ACK against pending local intent; this does not prove execution.

        No wire serial or ACK correlation is implemented. Even when this method
        returns True, independent state must arrive before intent is satisfied.
        """
        now = self._advance(now)
        if not self._connected or self._pending is None:
            return False
        self._pending['acknowledged_at'] = now
        return True

    def apply_state(self, record, now, *, session_id):
        """Accept only a qualifying newly received state from this generation.

        Returns False for another target, missing/ambiguous parser context, a
        missing status, a non-bool candidate, or a disconnected/stale generation.
        Rejected observations cannot change the last state or its freshness.
        ``now`` still participates in global monotonic event-order validation.
        """
        now = self._advance(now)
        if not self._connected or type(session_id) is not int or session_id != self._session_id:
            return False
        if not isinstance(record, dict):
            return False
        identifier = record.get('device_identifier_hex')
        if not isinstance(identifier, str) or len(identifier) != 16:
            return False
        try:
            identifier_bytes = bytes.fromhex(identifier)
        except ValueError:
            return False
        if identifier_bytes != self._target_identifier:
            return False
        if record.get('state_present') is not True or record.get('device_type_context') != 'ordinary_light':
            return False
        context = record.get('status_context')
        if not isinstance(context, dict) or context.get('device_status_context_confirmed') is not True:
            return False
        observed = record.get('candidate_is_on')
        if type(observed) is not bool:
            return False
        self._is_on = observed
        self._last_state_at = now
        self._session_state_at = now
        self._source = 'independent_report_candidate'
        self._available = True
        if self._pending is not None and self._pending['requested_is_on'] is observed:
            self._pending = None
        return True

    def tick(self, now):
        """Evaluate availability using only current-generation report freshness."""
        now = self._advance(now)
        self._available = (self._connected and self._session_state_at is not None
                           and now - self._session_state_at < self._stale_after_seconds)
        return self._available

    def snapshot(self):
        """Return independent copies of state/intention metadata for an adapter/UI."""
        return {'target_identifier_hex': self._target_identifier.hex(),
                'connected': self._connected, 'session_id': self._session_id,
                'available': self._available, 'is_on': self._is_on,
                'source': self._source, 'last_state_at': self._last_state_at,
                'session_state_at': self._session_state_at, 'last_event_at': self._last_event_at,
                'stale_after_seconds': self._stale_after_seconds,
                'pending': self.pending, 'physical_feedback_verified': False,
                'physical_verified': False}
