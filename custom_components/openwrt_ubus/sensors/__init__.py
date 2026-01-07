"""Sensor modules for OpenWrt ubus integration."""

from . import ap_sensor, eth_sensor, qmodem_sensor, sta_sensor, system_sensor, connected_devices_sensor

__all__ = ["ap_sensor", "eth_sensor", "qmodem_sensor", "sta_sensor", "system_sensor", "connected_devices_sensor"]
