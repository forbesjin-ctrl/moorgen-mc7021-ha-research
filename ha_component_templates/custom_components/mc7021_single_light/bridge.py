"""HA-independent single-light bridge, tested entirely with offline fake drivers.

Driver callbacks are declarations by the approved adapter, not authenticated
physical measurements. Only an independent readback opens a new receive epoch.
"""
from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
import time
import uuid

from .const import CASES, DRIVER_TIMEOUT, QUERY_INTERVAL, RECONNECT_INTERVAL, STATE_MAX_AGE, VERSION


class SingleLightBridge:
    def __init__(self, driver_factory, binding, *, clock=time.monotonic, max_age=STATE_MAX_AGE):
        self.driver_factory, self.binding, self.clock = driver_factory, dict(binding), clock
        self.max_age = max_age
        self.generation = 0
        self.connected = False
        self.manual_pause = False
        self._closed = False
        self._driver = None
        self._power = None
        self._last_state = None
        self._needs_readback = True
        self._pending_power = None
        self._listeners = set()
        self._lock = asyncio.Lock()
        self._next_reconnect = 0.0
        self._last_query = 0.0
        self.selected_case = CASES[0]
        self.window_case = None
        self.window_id = None
        self.reset_log()

    def reset_log(self):
        self.session_id = uuid.uuid4().hex
        self.events = deque(maxlen=1000)
        self.dropped_events = 0
        self._event_id = 0
        self.window_case = None
        self.window_id = None
        self._event('session_started', 'local_marker')

    @property
    def available(self):
        return (not self._closed and self.connected and not self._needs_readback and self._last_state is not None
                and self.clock() - self._last_state <= self.max_age)

    @property
    def power(self):
        return self._power if self.available else None

    def subscribe(self, listener):
        self._listeners.add(listener)
        return lambda: self._listeners.discard(listener)

    def _notify(self):
        for listener in tuple(self._listeners):
            listener()

    def _event(self, kind, source, *, state=None, independent=False):
        self._event_id += 1
        if len(self.events) == self.events.maxlen:
            self.dropped_events += 1
        self.events.append(dict(event_id=self._event_id, kind=kind,
            step_id=self.window_case, window_case=self.window_case, window_id=self.window_id,
            generation=self.generation, state=state, source=source, independent=independent,
            pending_command=self._pending_power is not None,
            at=datetime.now(timezone.utc).isoformat()))

    def select_case(self, case):
        if case not in CASES:
            raise ValueError('Unknown acceptance case')
        self.selected_case = case
        self._notify()

    def begin_window(self):
        if self._pending_power is not None:
            raise ValueError('Wait for the outstanding HA command state feedback before changing test windows')
        self.window_case = self.selected_case
        self.window_id = uuid.uuid4().hex
        self._event('window_started', 'local_marker', state=self.power)
        self._notify()

    def _state_callback(self, generation):
        def receive(observation):
            if self._closed or generation != self.generation or not self.connected:
                return
            self.check_stale()
            if not isinstance(observation, dict):
                return
            if observation.get('identifier') != self.binding['target_identifier'] or type(observation.get('power')) is not bool:
                return
            source = observation.get('source')
            if source not in ('independent_readback', 'independent_push'):
                return
            if self._needs_readback and source != 'independent_readback':
                return
            self._needs_readback = False
            self._power = observation['power']
            self._last_state = self.clock()
            if self._pending_power is self._power:
                self._pending_power = None
            self._event('state', source, state=self._power, independent=True)
            self._notify()
        return receive

    def _disconnect_callback(self, generation):
        def disconnected():
            if self._closed or generation != self.generation or not self.connected:
                return
            self.connected = False
            self._needs_readback = True
            self._pending_power = None
            self._next_reconnect = self.clock() + RECONNECT_INTERVAL
            if getattr(self._driver, 'fatal_setup_error', False) is True:
                self.manual_pause = True
            self._event('unavailable', 'disconnected')
            self._notify()
        return disconnected

    async def _call(self, awaitable):
        return await asyncio.wait_for(awaitable, DRIVER_TIMEOUT)

    async def async_connect(self, *, _automatic=False):
        async with self._lock:
            if self._closed:
                raise ValueError('This adapter has been unloaded')
            if _automatic and (self.manual_pause or self.connected):
                return
            await self._disconnect_locked(log=False)
            if self._closed:
                raise ValueError('This adapter was unloaded while disconnecting')
            self.manual_pause = False
            self.generation += 1
            generation = self.generation
            self._needs_readback = True
            self._power = self._last_state = None
            self._pending_power = None
            driver = self.driver_factory()
            self._driver = driver
            try:
                await self._call(driver.async_connect(host=self.binding['host_ip'],
                    identifier=self.binding['target_identifier'], on_state=self._state_callback(generation),
                    on_disconnect=self._disconnect_callback(generation)))
                if self._closed:
                    raise ValueError('This adapter was unloaded while connecting')
                self.connected = True
                self._event('connected', 'connected')
                self._notify()
                await self._request_locked()
            except BaseException as error:
                await self._disconnect_locked(log=True)
                self._next_reconnect = self.clock() + RECONNECT_INTERVAL
                if getattr(error, 'fatal_setup', False) is True:
                    self.manual_pause = True
                    self._event('unavailable', 'disconnected')
                raise

    async def _disconnect_locked(self, *, log=True):
        driver = self._driver
        self._driver = None
        self.connected = False
        self._needs_readback = True
        self._power = self._last_state = None
        self._pending_power = None
        if log:
            self._event('unavailable', 'disconnected')
            self._notify()
        if driver is not None:
            try:
                await self._call(driver.async_disconnect())
            except Exception:
                # Never put arbitrary driver exceptions, credentials or bytes in logs.
                pass

    async def async_disconnect(self):
        async with self._lock:
            self.manual_pause = True
            await self._disconnect_locked()

    async def async_shutdown(self):
        # Set before acquiring the lock so an already-scheduled reconnect cannot
        # revive the adapter after HA unloads its entities/timer.
        self._closed = True
        self.manual_pause = True
        async with self._lock:
            await self._disconnect_locked()

    async def async_set_power(self, power):
        if type(power) is not bool:
            raise ValueError('Only a boolean ordinary-light command is accepted')
        async with self._lock:
            if not self.available or self._driver is None:
                raise ValueError('Current independent readback is required before sending a command')
            if self._pending_power is not None:
                raise ValueError('Wait for independent feedback from the previous command')
            self._pending_power = power
            self._event('command_requested', 'command_requested', state=power)
            self._notify()
            try:
                await self._call(self._driver.async_set_power(power))
            except BaseException:
                await self._disconnect_locked()
                raise
            # Return/ACK is intentionally not used as a state value.

    async def _request_locked(self):
        if self.connected and self._driver is not None:
            self._last_query = self.clock()
            await self._call(self._driver.async_request_state())

    async def async_request_state(self):
        async with self._lock:
            if self._closed or not self.connected:
                raise ValueError('The driver is disconnected')
            try:
                await self._request_locked()
            except BaseException:
                await self._disconnect_locked()
                raise

    def check_stale(self):
        if self.connected and self._last_state is not None and not self._needs_readback and self.clock() - self._last_state > self.max_age:
            self._needs_readback = True
            self._pending_power = None
            self._event('unavailable', 'stale')
            self._notify()

    async def async_maintain(self):
        self.check_stale()
        if self.manual_pause or self._closed:
            return
        if not self.connected:
            if self.clock() >= self._next_reconnect:
                await self.async_connect(_automatic=True)
        elif self.clock() - self._last_query >= QUERY_INTERVAL:
            await self.async_request_state()

    def diagnostics(self):
        return dict(artifact='mc7021_ha_acceptance_diagnostics', schema_version=VERSION,
            wizard_id=self.binding['wizard_id'], package_id=self.binding['package_id'],
            host_ip=self.binding['host_ip'], selected_identifier=self.binding['target_identifier'],
            driver_sha256=self.binding['driver_sha256'], baseline_review_sha256=self.binding['baseline_review_sha256'],
            simulation=False, private=True, identity_authenticated=False, physical_feedback_verified=False,
            session_id=self.session_id, generation=self.generation, dropped_events=self.dropped_events,
            state_max_age_seconds=self.max_age, events=[dict(event) for event in self.events],
            note='Private local adapter declarations and observations; not proof of physical identity or driver safety.')
