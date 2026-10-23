"""Explicit HA buttons affect this adapter's connection or local log only."""
from homeassistant.components.button import ButtonEntity
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN

BUTTONS = (
    ('begin', '开始记录所选验收步骤', 'mdi:record-circle-outline'),
    ('read', '读取这一组灯的独立状态', 'mdi:refresh'),
    ('disconnect', '仅断开本单灯适配连接', 'mdi:lan-disconnect'),
    ('reconnect', '重连本单灯适配并读回', 'mdi:lan-connect'),
    ('reset', '清空本轮验收日志重新开始', 'mdi:playlist-remove'),
)


async def async_setup_entry(hass, entry, async_add_entities):
    bridge = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([AcceptanceButton(bridge, entry, *item) for item in BUTTONS])


class AcceptanceButton(ButtonEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_should_poll = False

    def __init__(self, bridge, entry, action, name, icon):
        self.bridge, self.action = bridge, action
        self._attr_name, self._attr_icon = name, icon
        self._attr_unique_id = entry.unique_id + '_acceptance_' + action
        self._attr_device_info = {'identifiers': {(DOMAIN, entry.unique_id)}}

    async def async_press(self):
        try:
            if self.action == 'begin':
                self.bridge.begin_window()
            elif self.action == 'read':
                await self.bridge.async_request_state()
            elif self.action == 'disconnect':
                await self.bridge.async_disconnect()
            elif self.action == 'reconnect':
                await self.bridge.async_connect()
            elif self.action == 'reset':
                self.bridge.reset_log()
        except Exception:
            raise HomeAssistantError('Single-light acceptance action could not finish; check current readback and pending command') from None
