"""A manual HA configuration form; it does not import or connect a driver."""
from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries

from .const import DOMAIN
from .contract import inspect_install


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        try:
            binding, _raw = await self.hass.async_add_executor_job(inspect_install)
        except Exception:
            return self.async_abort(reason='invalid_private_package')
        errors = {}
        if user_input is not None:
            if user_input.get('host') != binding['host_ip']:
                errors['host'] = 'host_mismatch'
            if not isinstance(user_input.get('name'), str) or not user_input['name'].strip() or len(user_input['name'].strip()) > 64:
                errors['name'] = 'invalid_name'
            if user_input.get('driver_approved') is not True or user_input.get('enable_single_light_control') is not True:
                errors['base'] = 'approval_required'
            if not errors:
                await self.async_set_unique_id(binding['host_ip'] + '_' + binding['target_identifier'])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=user_input['name'].strip(), data={
                    'host': binding['host_ip'], 'name': user_input['name'].strip(),
                    'package_id': binding['package_id'], 'driver_approved': True,
                    'enable_single_light_control': True,
                    **{key: binding[key] for key in ('target_identifier', 'driver_sha256', 'baseline_review_sha256')}})
        return self.async_show_form(step_id='user', data_schema=vol.Schema({
            vol.Required('host', default=binding['host_ip']): str,
            vol.Required('name', default='首组普通灯'): str,
            vol.Required('driver_approved', default=False): bool,
            vol.Required('enable_single_light_control', default=False): bool,
        }), errors=errors, description_placeholders={
            'identifier': binding['target_identifier'], 'driver_sha256': binding['driver_sha256']})
