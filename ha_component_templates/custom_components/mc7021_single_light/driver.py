"""NONFUNCTIONAL EXAMPLE. Replace with an owner-reviewed single-light driver.

No protocol, port, authentication, bytes or register is guessed here. This file
must never pass package generation. The Mac tool must not import driver code.
"""
DRIVER_API_VERSION = 1
DRIVER_IS_PLACEHOLDER = True


class Driver:
    async def async_connect(self, *, host, identifier, on_state, on_disconnect):
        raise NotImplementedError('A separately reviewed real driver is required')

    async def async_set_power(self, power):
        raise NotImplementedError

    async def async_request_state(self):
        raise NotImplementedError

    async def async_disconnect(self):
        return None
