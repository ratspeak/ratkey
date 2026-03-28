"""YubiKey 5 PIV backend — delegates crypto to hardware via yubikit.

Requires: ``pip install ratkey[yubikey]`` (installs yubikey-manager)

Minimum firmware: 5.7.0 (for native Ed25519/X25519 in PIV slots)

PIV slot assignments:
    9A (Authentication) → Ed25519 signing key
    9D (Key Management) → X25519 encryption key
"""

from __future__ import annotations

from typing import Optional

from ratkey.backends.base import AbstractHardwareBackend, TouchPolicy
from ratkey.errors import (
    FirmwareVersionError,
    HardwareDisconnectedError,
    HardwareNotFoundError,
    PINIncorrectError,
    PINLockedError,
    PINRequiredError,
)

# Minimum firmware for Ed25519/X25519 in PIV
MIN_FIRMWARE = (5, 7, 0)

# Map our TouchPolicy to yubikit's
_TOUCH_MAP = {
    TouchPolicy.NEVER: "DEFAULT",
    TouchPolicy.ALWAYS: "ALWAYS",
    TouchPolicy.CACHED: "CACHED",
}


class YubiKeyPIVBackend(AbstractHardwareBackend):
    """YubiKey 5 PIV backend using yubikit.piv.

    Performs Ed25519 signing and X25519 ECDH on the hardware token.
    Private keys never leave the YubiKey.
    """

    def __init__(self, serial: Optional[int] = None):
        self._serial = serial
        self._session = None
        self._connection = None
        self._pin_verified = False
        self._ed25519_pub: Optional[bytes] = None
        self._x25519_pub: Optional[bytes] = None

    @property
    def name(self) -> str:
        return "yubikey-piv"

    def is_connected(self) -> bool:
        """Check if the YubiKey is physically present."""
        if self._connection is None:
            return False
        try:
            # Lightweight check — read metadata from attestation slot
            self._session.get_slot_metadata(0xF9)
            return True
        except Exception:
            self._connection = None
            self._session = None
            return False

    def _connect(self):
        """Establish PIV session with the YubiKey."""
        try:
            from yubikit.piv import PivSession
            from yubikit.core.smartcard import SmartCardConnection
            from ykman.device import list_all_devices
        except ImportError:
            raise HardwareNotFoundError(
                "yubikey-manager not installed. Run: pip install ratkey[yubikey]"
            )

        devices = list(list_all_devices())
        if not devices:
            raise HardwareNotFoundError("No YubiKey devices found")

        # Find matching device by serial if specified
        device = None
        for dev, dev_info in devices:
            if self._serial is None or dev_info.serial == self._serial:
                device = dev
                break

        if device is None:
            raise HardwareNotFoundError(
                f"YubiKey with serial {self._serial} not found"
            )

        connection = device.open_connection(SmartCardConnection)
        session = PivSession(connection)

        # Check firmware version
        mgmt_info = session.management_key_type  # triggers version check
        version = session.version
        if version < MIN_FIRMWARE:
            v_str = ".".join(str(x) for x in version)
            r_str = ".".join(str(x) for x in MIN_FIRMWARE)
            raise FirmwareVersionError(
                f"YubiKey firmware {v_str} does not meet minimum {r_str}. "
                f"Ed25519/X25519 PIV support requires firmware 5.7.0 or later."
            )

        self._connection = connection
        self._session = session

    def _ensure_session(self):
        """Ensure we have an active PIV session."""
        if self._session is None:
            self._connect()

    def provision(
        self,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
    ) -> dict:
        from yubikit.piv import SLOT, KEY_TYPE, PIN_POLICY, TOUCH_POLICY

        self._ensure_session()
        self._session.verify_pin(pin)
        self._pin_verified = True

        # Map touch policies
        touch_sign = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_signing])
        touch_enc = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_encryption])

        # Generate Ed25519 in slot 9A
        ed_pub = self._session.generate_key(
            SLOT.AUTHENTICATION,
            KEY_TYPE.ED25519,
            pin_policy=PIN_POLICY.ONCE,
            touch_policy=touch_sign,
        )
        ed_pub_bytes = ed_pub.public_bytes_raw()

        # Generate X25519 in slot 9D
        x_pub = self._session.generate_key(
            SLOT.KEY_MANAGEMENT,
            KEY_TYPE.X25519,
            pin_policy=PIN_POLICY.ONCE,
            touch_policy=touch_enc,
        )
        x_pub_bytes = x_pub.public_bytes_raw()

        self._ed25519_pub = ed_pub_bytes
        self._x25519_pub = x_pub_bytes

        return {
            "ed25519_public": ed_pub_bytes,
            "x25519_public": x_pub_bytes,
            "serial": self._serial or 0,
            "firmware": ".".join(str(x) for x in self._session.version),
        }

    def import_key(
        self,
        ed25519_private: bytes,
        x25519_private: bytes,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
    ) -> dict:
        from yubikit.piv import SLOT, PIN_POLICY, TOUCH_POLICY, DEFAULT_MANAGEMENT_KEY
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        self._ensure_session()
        self._session.verify_pin(pin)
        self._pin_verified = True

        # Management key auth required for put_key
        self._session.authenticate(DEFAULT_MANAGEMENT_KEY)

        touch_sign = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_signing])
        touch_enc = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_encryption])

        ed_prv = Ed25519PrivateKey.from_private_bytes(ed25519_private)
        x_prv = X25519PrivateKey.from_private_bytes(x25519_private)

        self._session.put_key(
            SLOT.AUTHENTICATION,
            ed_prv,
            pin_policy=PIN_POLICY.ONCE,
            touch_policy=touch_sign,
        )

        self._session.put_key(
            SLOT.KEY_MANAGEMENT,
            x_prv,
            pin_policy=PIN_POLICY.ONCE,
            touch_policy=touch_enc,
        )

        ed_pub_bytes = ed_prv.public_key().public_bytes_raw()
        x_pub_bytes = x_prv.public_key().public_bytes_raw()

        self._ed25519_pub = ed_pub_bytes
        self._x25519_pub = x_pub_bytes

        return {
            "ed25519_public": ed_pub_bytes,
            "x25519_public": x_pub_bytes,
            "serial": self._serial or 0,
            "firmware": ".".join(str(x) for x in self._session.version),
        }

    def sign(self, message: bytes) -> bytes:
        from yubikit.piv import SLOT, KEY_TYPE

        self._ensure_session()
        if not self._pin_verified:
            raise PINRequiredError("PIN not verified")
        return self._session.sign(
            SLOT.AUTHENTICATION,
            KEY_TYPE.ED25519,
            message,
        )

    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        from yubikit.piv import SLOT
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        self._ensure_session()
        if not self._pin_verified:
            raise PINRequiredError("PIN not verified")
        peer_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return self._session.calculate_secret(SLOT.KEY_MANAGEMENT, peer_key)

    def get_public_keys(self) -> tuple[bytes, bytes]:
        if self._ed25519_pub is None or self._x25519_pub is None:
            raise PINRequiredError("Keys not yet read from device")
        return (self._ed25519_pub, self._x25519_pub)
