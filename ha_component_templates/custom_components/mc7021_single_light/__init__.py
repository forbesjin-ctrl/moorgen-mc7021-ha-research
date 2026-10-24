"""An explicitly approved, owner-supplied adapter for one reviewed light."""
from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.const import Platform
from homeassistant.exceptions import ConfigEntryNotReady, ConfigEntryError
from homeassistant.helpers.event import async_track_time_interval

from .bridge import SingleLightBridge
from .const import DOMAIN
from .contract import inspect_install, load_approved_driver

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.LIGHT, Platform.SELECT, Platform.BUTTON]


async def async_setup_entry(hass, entry):
    if entry.data.get('driver_approved') is not True or entry.data.get('enable_single_light_control') is not True:
        raise ConfigEntryNotReady('Explicit owner approval of this driver and single-light test is required')
    try:
        binding, raw = await hass.async_add_executor_job(inspect_install)
        if (binding['host_ip'] != entry.data.get('host')
                or any(binding[key] != entry.data.get(key) for key in
                       ('package_id', 'target_identifier', 'driver_sha256', 'baseline_review_sha256'))
                or entry.unique_id != binding['host_ip'] + '_' + binding['target_identifier']):
            raise ValueError('Package binding changed')
        # Only after the HA owner explicitly trusts this code. The Mac never imports it.
        driver_class = await hass.async_add_executor_job(load_approved_driver, raw)
        if binding.get('builtin_profile'):
            credentials = {key: entry.data.get(key) for key in ('username', 'password')}
            factory = lambda: driver_class(profile=binding['builtin_profile'], credentials=credentials)
        else:
            factory = driver_class
        bridge = SingleLightBridge(factory, binding)
        await bridge.async_connect()
    except Exception as error:
        if getattr(error, 'fatal_setup', False) is True:
            raise ConfigEntryError('内置策略或当前认证不匹配，已停止自动重试。请保留本机日志，核对凭据/重新采样后重新配置；不尝试其它编码或参数。') from None
        raise ConfigEntryNotReady('Approved single-light adapter could not start; check private binding and driver') from None
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = bridge

    async def maintain(_now):
        try:
            await bridge.async_maintain()
        except Exception:
            # User adapter exceptions may contain credentials; never interpolate them.
            _LOGGER.warning('Single-light adapter maintenance failed; state remains unavailable')

    cancel = async_track_time_interval(hass, maintain, timedelta(seconds=5))
    entry.async_on_unload(cancel)
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        cancel()
        await bridge.async_shutdown()
        hass.data[DOMAIN].pop(entry.entry_id, None)
        raise
    return True


async def async_unload_entry(hass, entry):
    if not await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        return False
    bridge = hass.data[DOMAIN].pop(entry.entry_id)
    await bridge.async_shutdown()
    return True
