"""The single ONOFF entity never uses optimistic state."""
from homeassistant.components.light import ColorMode, LightEntity
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([ReviewedLight(hass.data[DOMAIN][entry.entry_id], entry)])


class ReviewedLight(LightEntity):
    _attr_should_poll = False
    _attr_supported_color_modes = {ColorMode.ONOFF}
    _attr_color_mode = ColorMode.ONOFF

    def __init__(self, bridge, entry):
        self.bridge = bridge
        self._attr_name = entry.data['name']
        self._attr_unique_id = entry.unique_id
        self._attr_device_info = {'identifiers': {(DOMAIN, entry.unique_id)},
                                 'name': entry.data['name'], 'manufacturer': 'Owner-reviewed adapter'}

    @property
    def available(self):
        return self.bridge.available

    @property
    def is_on(self):
        return self.bridge.power

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        self.async_on_remove(self.bridge.subscribe(self.async_write_ha_state))

    async def async_turn_on(self, **kwargs):
        try:
            await self.bridge.async_set_power(True)
        except Exception:
            raise HomeAssistantError('Single-light command failed or independent readback is missing') from None

    async def async_turn_off(self, **kwargs):
        try:
            await self.bridge.async_set_power(False)
        except Exception:
            raise HomeAssistantError('Single-light command failed or independent readback is missing') from None
