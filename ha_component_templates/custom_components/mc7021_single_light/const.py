"""One explicitly selected ordinary on/off light; no discovery."""
DOMAIN = 'mc7021_single_light'
VERSION = '0.6.0'
DRIVER_API_VERSION = 1
STATE_MAX_AGE = 60.0  # Local policy, not a measured manufacturer heartbeat.
QUERY_INTERVAL = 20.0
RECONNECT_INTERVAL = 30.0
DRIVER_TIMEOUT = 10.0
CASES = ('ha_on_1', 'ha_off_1', 'ha_on_2', 'ha_off_2',
         'panel_on', 'panel_off', 'disconnect', 'reconnect')
CASE_LABELS = {
    'ha_on_1': '1 · HA开灯（第一次）', 'ha_off_1': '2 · HA关灯（第一次）',
    'ha_on_2': '3 · HA开灯（第二次）', 'ha_off_2': '4 · HA关灯（第二次）',
    'panel_on': '5 · 面板开灯', 'panel_off': '6 · 面板关灯',
    'disconnect': '7 · 仅断开本集成，检查不可用',
    'reconnect': '8 · 面板开灯后，重连读回',
}
