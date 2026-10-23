"""Native HA selector: choosing a step does not begin or operate a light."""
from homeassistant.components.select import SelectEntity
from homeassistant.helpers.entity import EntityCategory

from .const import CASES, CASE_LABELS, DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([AcceptanceStep(hass.data[DOMAIN][entry.entry_id], entry)])


class AcceptanceStep(SelectEntity):
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_name = '单灯验收步骤'
    _attr_icon = 'mdi:format-list-numbered'
    _attr_options = [CASE_LABELS[case] for case in CASES]

    def __init__(self, bridge, entry):
        self.bridge = bridge
        self._attr_unique_id = entry.unique_id + '_acceptance_step'
        self._attr_device_info = {'identifiers': {(DOMAIN, entry.unique_id)}}

    @property
    def current_option(self):
        return CASE_LABELS[self.bridge.selected_case]

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        self.async_on_remove(self.bridge.subscribe(self.async_write_ha_state))

    async def async_select_option(self, option):
        self.bridge.select_case(next(case for case in CASES if CASE_LABELS[case] == option))
