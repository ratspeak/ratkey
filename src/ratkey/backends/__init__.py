"""Hardware backend registry and auto-detection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ratkey.errors import HardwareNotFoundError

if TYPE_CHECKING:
    from ratkey.backends.base import AbstractHardwareBackend
    from ratkey.hwid import HwidConfig


def auto_detect_backend(
    config: HwidConfig,
    pin_callback=None,
) -> AbstractHardwareBackend:
    """Auto-detect and connect to the appropriate hardware backend.

    Selects the backend based on the device type in the .hwid config.
    """
    device_type = config.device_type.lower()

    if device_type in ("yubikey5", "yubikey"):
        try:
            from ratkey.backends.yubikey_piv import YubiKeyPIVBackend

            backend = YubiKeyPIVBackend(serial=config.device_serial)
            if pin_callback:
                backend.set_pin_callback(pin_callback)
            return backend
        except ImportError:
            raise HardwareNotFoundError(
                "YubiKey backend requires yubikey-manager. "
                "Install with: pip install ratkey[yubikey]"
            )
    elif device_type == "nitrokey3":
        try:
            from ratkey.backends.nitrokey_piv import NitrokeyPIVBackend

            backend = NitrokeyPIVBackend(serial=config.device_serial)
            if pin_callback:
                backend.set_pin_callback(pin_callback)
            return backend
        except ImportError:
            raise HardwareNotFoundError(
                "Nitrokey backend requires pynitrokey. "
                "Install with: pip install ratkey[nitrokey]"
            )
    else:
        raise HardwareNotFoundError(f"Unknown device type: {device_type}")
