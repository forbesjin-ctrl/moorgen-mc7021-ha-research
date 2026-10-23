"""Private fixed-whitelist acceptance log; no config/driver dump or raw bytes."""
from .const import DOMAIN


async def async_get_config_entry_diagnostics(hass, entry):
    return hass.data[DOMAIN][entry.entry_id].diagnostics()
