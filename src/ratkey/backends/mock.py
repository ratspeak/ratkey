"""Cryptographically accurate mock backend for testing.

Uses real Ed25519/X25519 keys and performs real cryptographic operations.
The ONLY difference from a real hardware backend is that keys live in
memory instead of on a hardware token.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratkey.backends.base import AbstractHardwareBackend, TouchPolicy
from ratkey.errors import (
    HardwareDisconnectedError,
    PINIncorrectError,
    PINLockedError,
    PINRequiredError,
)


class MockBackend(AbstractHardwareBackend):
    """Mock hardware backend with real cryptographic operations.

    Generates real Ed25519/X25519 keypairs and performs real signing/ECDH.
    Simulates PIN verification, touch policy, and device disconnection.
    """

    def __init__(self):
        self._ed25519_prv: Ed25519PrivateKey | None = None
        self._x25519_prv: X25519PrivateKey | None = None
        self._ed25519_pub_bytes: bytes | None = None
        self._x25519_pub_bytes: bytes | None = None
        self._pin = "123456"
        self._pin_verified = False
        self._pin_retries = 3
        self._connected = True
        self._serial = 99999999
        self._firmware = "5.7.1"

    @property
    def name(self) -> str:
        return "mock"

    def is_connected(self) -> bool:
        return self._connected

    def disconnect(self) -> None:
        """Simulate device removal."""
        self._connected = False

    def reconnect(self) -> None:
        """Simulate device re-insertion."""
        self._connected = True
        self._pin_verified = False

    def set_pin(self, pin: str) -> None:
        """Set the mock device's PIN."""
        self._pin = pin
        self._pin_verified = False

    def verify_pin(self, pin: str) -> None:
        """Verify the PIN. Simulates retry counting and lockout."""
        if not self._connected:
            raise HardwareDisconnectedError("Device disconnected")
        if self._pin_retries == 0:
            raise PINLockedError("PIN locked — device requires PUK to unlock")
        if pin != self._pin:
            self._pin_retries -= 1
            if self._pin_retries == 0:
                raise PINLockedError("PIN locked — too many failed attempts")
            raise PINIncorrectError(
                f"PIN incorrect ({self._pin_retries} attempts remaining)",
                remaining=self._pin_retries,
            )
        self._pin_verified = True
        self._pin_retries = 3

    def provision(
        self,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
    ) -> dict:
        if not self._connected:
            raise HardwareDisconnectedError("Device disconnected")
        self.verify_pin(pin)

        self._ed25519_prv = Ed25519PrivateKey.generate()
        self._x25519_prv = X25519PrivateKey.generate()

        self._ed25519_pub_bytes = self._ed25519_prv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._x25519_pub_bytes = self._x25519_prv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        return {
            "ed25519_public": self._ed25519_pub_bytes,
            "x25519_public": self._x25519_pub_bytes,
            "serial": self._serial,
            "firmware": self._firmware,
        }

    def sign(self, message: bytes) -> bytes:
        if not self._connected:
            raise HardwareDisconnectedError("Device disconnected")
        if not self._pin_verified:
            raise PINRequiredError("PIN not verified — call verify_pin() first")
        if self._ed25519_prv is None:
            raise PINRequiredError("No key provisioned in signing slot")
        return self._ed25519_prv.sign(message)

    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        if not self._connected:
            raise HardwareDisconnectedError("Device disconnected")
        if not self._pin_verified:
            raise PINRequiredError("PIN not verified — call verify_pin() first")
        if self._x25519_prv is None:
            raise PINRequiredError("No key provisioned in encryption slot")
        peer_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return self._x25519_prv.exchange(peer_key)

    def get_public_keys(self) -> tuple[bytes, bytes]:
        if self._ed25519_pub_bytes is None or self._x25519_pub_bytes is None:
            raise PINRequiredError("No keys provisioned")
        return (self._ed25519_pub_bytes, self._x25519_pub_bytes)

    def import_key(
        self,
        ed25519_private: bytes,
        x25519_private: bytes,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
    ) -> dict:
        if not self._connected:
            raise HardwareDisconnectedError("Device disconnected")
        self.verify_pin(pin)

        self._ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_private)
        self._x25519_prv = X25519PrivateKey.from_private_bytes(x25519_private)

        self._ed25519_pub_bytes = self._ed25519_prv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._x25519_pub_bytes = self._x25519_prv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        return {
            "ed25519_public": self._ed25519_pub_bytes,
            "x25519_public": self._x25519_pub_bytes,
            "serial": self._serial,
            "firmware": self._firmware,
        }

    @classmethod
    def with_keys(cls) -> MockBackend:
        """Create a mock with pre-generated keys and PIN already verified."""
        mock = cls()
        mock.provision("123456")
        return mock
