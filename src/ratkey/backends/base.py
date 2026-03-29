"""Abstract base class for all hardware identity backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Callable, Optional


class TouchPolicy(Enum):
    """Touch policy for a PIV slot."""

    NEVER = "never"
    ALWAYS = "always"
    CACHED = "cached"


class PinPolicy(Enum):
    """PIN policy for a PIV slot."""

    ONCE = "once"
    ALWAYS = "always"
    NEVER = "never"


class AbstractHardwareBackend(ABC):
    """Base class for hardware identity backends (YubiKey, Nitrokey, Mock).

    Implementations must provide on-device key generation, Ed25519 signing,
    and X25519 key agreement. Private key material must never be returned
    to the host during normal operation.
    """

    _pin_callback: Optional[Callable[[str, Optional[int]], str]] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier (e.g., 'yubikey-piv', 'nitrokey-piv', 'mock')."""

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if the hardware device is physically present and accessible."""

    @abstractmethod
    def provision(
        self,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
        pin_policy: PinPolicy = PinPolicy.ONCE,
    ) -> dict:
        """Generate a new identity keypair on the hardware device.

        Returns a dict with:
            ed25519_public: bytes (32) — signing public key
            x25519_public: bytes (32) — encryption public key
            serial: int — device serial number
            firmware: str — firmware version string
        """

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Ed25519 sign using the hardware token's key in slot 9A.

        Returns a 64-byte Ed25519 signature per RFC 8032.
        The private key never leaves the hardware device.
        """

    @abstractmethod
    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        """X25519 ECDH key agreement using the hardware token's key in slot 9D.

        Returns a 32-byte shared secret per RFC 7748.
        The private key never leaves the hardware device.
        """

    @abstractmethod
    def get_public_keys(self) -> tuple[bytes, bytes]:
        """Return (ed25519_pub_bytes, x25519_pub_bytes)."""

    def set_pin_callback(self, callback: Callable[[str, Optional[int]], str]) -> None:
        """Register a callable that returns the PIN string.

        Args:
            callback: Function(prompt, retries_remaining) → PIN string.
                      retries_remaining may be None if unknown.
        """
        self._pin_callback = callback

    def import_key(
        self,
        ed25519_private: bytes,
        x25519_private: bytes,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
        pin_policy: PinPolicy = PinPolicy.ONCE,
    ) -> dict:
        """Import existing key material onto the device.

        Used for recoverable provisioning (seed phrase) and software→hardware migration.
        Not all backends support this operation.

        Raises:
            NotImplementedError: If the backend does not support key import.
        """
        raise NotImplementedError(f"Key import not supported by {self.name} backend")
