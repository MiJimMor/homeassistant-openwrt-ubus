"""Support for OpenWrt connected devices count sensor."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from ..const import (
    DOMAIN,
    CONF_STA_SENSOR_TIMEOUT,
    DEFAULT_STA_SENSOR_TIMEOUT,
)
from ..shared_data_manager import SharedDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> SharedDataUpdateCoordinator:
    """Set up the connected devices count sensor from a config entry."""

    # Get shared data manager
    data_manager_key = f"data_manager_{entry.entry_id}"
    data_manager = hass.data[DOMAIN][data_manager_key]

    # Get timeout from configuration (priority: options > data > default)
    timeout = entry.options.get(
        CONF_STA_SENSOR_TIMEOUT,
        entry.data.get(CONF_STA_SENSOR_TIMEOUT, DEFAULT_STA_SENSOR_TIMEOUT),
    )
    scan_interval = timedelta(seconds=timeout)

    # Create coordinator using shared data manager
    coordinator = SharedDataUpdateCoordinator(
        hass,
        data_manager,
        ["device_statistics"],  # Data types this coordinator needs
        f"{DOMAIN}_connected_devices_{entry.data[CONF_HOST]}",
        scan_interval,
    )

    # Perform first refresh
    await coordinator.async_config_entry_first_refresh()

    # Create the connected devices count sensor
    sensor = ConnectedDevicesSensor(coordinator)
    async_add_entities([sensor], True)
    _LOGGER.info("Set up connected devices count sensor")

    # Return the coordinator for cleanup
    return coordinator


class ConnectedDevicesSensor(CoordinatorEntity, SensorEntity):
    """Representation of a connected devices count sensor."""

    def __init__(self, coordinator: SharedDataUpdateCoordinator) -> None:
        """Initialize the connected devices sensor."""
        super().__init__(coordinator)
        self._host = coordinator.data_manager.entry.data[CONF_HOST]
        self._attr_unique_id = f"{self._host}_connected_devices_count"
        self._attr_name = "Connected Devices"
        self._attr_icon = "mdi:devices"
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = "devices"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info to link this sensor to the router device."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._host)},
        )

    @property
    def native_value(self) -> int:
        """Return the number of connected devices."""
        if not self.coordinator.data or "device_statistics" not in self.coordinator.data:
            return 0

        device_stats = self.coordinator.data["device_statistics"]
        # Count only connected devices
        connected_count = sum(
            1 for device_data in device_stats.values() if device_data.get("connected", False)
        )
        return connected_count

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes with list of connected devices."""
        if not self.coordinator.data or "device_statistics" not in self.coordinator.data:
            return {"devices": []}

        device_stats = self.coordinator.data["device_statistics"]
        devices_list = []

        # Build list of connected devices with their info
        for mac, device_data in device_stats.items():
            if device_data.get("connected", False):
                device_info = {
                    "mac": mac,
                    "hostname": device_data.get("hostname", mac.replace(":", "")),
                    "ip": device_data.get("ip_address", "Unknown"),
                    "ssid": device_data.get("ap_ssid", "Unknown"),
                    "signal": device_data.get("signal", "Unknown"),
                }
                devices_list.append(device_info)

        # Sort by hostname for consistent display
        devices_list.sort(key=lambda x: x["hostname"].lower())

        return {
            "devices": devices_list,
            "total_devices": len(devices_list),
            "router": self._host,
        }

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and "device_statistics" in self.coordinator.data
        )
