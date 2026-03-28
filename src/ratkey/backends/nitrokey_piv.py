"""Nitrokey 3 PIV backend — placeholder for future implementation.

Nitrokey 3 supports PIV (firmware 1.8+) but does NOT yet support
PIV attestation. The PIV interface is compatible with the YubiKey
PIV backend for key generation, signing, and ECDH.

Requires: ``pip install ratkey[nitrokey]`` (installs pynitrokey)
"""

from __future__ import annotations

from ratkey.backends.base import AbstractHardwareBackend, TouchPolicy
from ratkey.errors import HardwareNotFoundError


class NitrokeyPIVBackend(AbstractHardwareBackend):
    """Nitrokey 3 PIV backend — placeholder.

    Shares the same PIV APDU interface as YubiKey but with different
    device detection and no attestation support.
    """

    def __init__(self, serial: int | None = None):
        self._serial = serial
        raise HardwareNotFoundError(
            "Nitrokey 3 PIV backend is not yet implemented. "
            "Nitrokey 3 supports PIV but requires additional testing with real hardware. "
            "Contributions welcome at https://github.com/ratspeak/ratkey"
        )

    @property
    def name(self) -> str:
        return "nitrokey-piv"

    def is_connected(self) -> bool:
        return False

    def provision(self, pin, touch_signing=TouchPolicy.ALWAYS,
                  touch_encryption=TouchPolicy.CACHED) -> dict:
        raise NotImplementedError

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError

    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        raise NotImplementedError

    def get_public_keys(self) -> tuple[bytes, bytes]:
        raise NotImplementedError
