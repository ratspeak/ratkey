"""YubiKey 5 PIV backend — delegates crypto to hardware via yubikit.

Requires: ``pip install ratkey[yubikey]`` (installs yubikey-manager)

Minimum firmware: 5.7.0 (for native Ed25519/X25519 in PIV slots)

PIV slot assignments:
    9A (Authentication) → Ed25519 signing key
    9D (Key Management) → X25519 encryption key
"""

from __future__ import annotations

from typing import Optional

from ratkey.backends.base import AbstractHardwareBackend, PinPolicy, TouchPolicy
from ratkey.errors import (
    FirmwareVersionError,
    HardwareNotFoundError,
    PINRequiredError,
    SlotOccupiedError,
)

# Minimum firmware for Ed25519/X25519 in PIV
MIN_FIRMWARE = (5, 7, 0)

# Factory defaults
DEFAULT_PIV_PIN = "123456"

# Map our enums to yubikit's
_TOUCH_MAP = {
    TouchPolicy.NEVER: "DEFAULT",
    TouchPolicy.ALWAYS: "ALWAYS",
    TouchPolicy.CACHED: "CACHED",
}

_PIN_MAP = {
    PinPolicy.ONCE: "ONCE",
    PinPolicy.ALWAYS: "ALWAYS",
    PinPolicy.NEVER: "NEVER",
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

        device = None
        for dev, dev_info in devices:
            if self._serial is None or dev_info.serial == self._serial:
                device = dev
                self._serial = dev_info.serial
                break

        if device is None:
            raise HardwareNotFoundError(
                f"YubiKey with serial {self._serial} not found"
            )

        connection = device.open_connection(SmartCardConnection)
        session = PivSession(connection)

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
        if self._session is None:
            self._connect()

    def _reconnect(self):
        """Close and re-establish the PIV session (needed after reset)."""
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
        self._session = None
        self._connection = None
        self._pin_verified = False
        self._connect()

    # ── Slot inspection ─────────────────────────────────────────────

    def check_slots(self) -> dict:
        """Check if PIV slots 9A and 9D have existing keys.

        Returns dict with 'signing' and 'encryption' booleans.
        """
        from yubikit.piv import SLOT

        self._ensure_session()
        result = {"signing": False, "encryption": False}
        for slot, key in [(SLOT.AUTHENTICATION, "signing"), (SLOT.KEY_MANAGEMENT, "encryption")]:
            try:
                self._session.get_slot_metadata(slot)
                result[key] = True
            except Exception:
                pass
        return result

    # ── PIV reset ───────────────────────────────────────────────────

    def reset_piv(self):
        """Factory reset the PIV application.

        Clears all keys, resets PIN to 123456, PUK to 12345678,
        and management key to default. Session is reconnected after.
        """
        self._ensure_session()
        self._session.reset()
        self._reconnect()

    # ── PIN management ──────────────────────────────────────────────

    def change_pin(self, old_pin: str, new_pin: str):
        """Change the PIV PIN."""
        self._ensure_session()
        self._session.change_pin(old_pin, new_pin)

    def verify_pin(self, pin: str):
        """Verify PIN for non-provisioning operations (test, sign, etc.)."""
        self._ensure_session()
        self._session.verify_pin(pin)
        self._pin_verified = True

    def get_pin_retries(self) -> int:
        """Return the number of PIN retries remaining."""
        self._ensure_session()
        return self._session.get_pin_attempts()

    # ── Provisioning ────────────────────────────────────────────────

    def provision(
        self,
        pin: str,
        touch_signing: TouchPolicy = TouchPolicy.ALWAYS,
        touch_encryption: TouchPolicy = TouchPolicy.CACHED,
        pin_policy: PinPolicy = PinPolicy.ONCE,
    ) -> dict:
        """Generate new keys on-device.

        Expects the PIV application is in a clean state (reset first if
        needed). Authenticates with default PIN, changes it to ``pin``,
        then generates keys.
        """
        from yubikit.piv import SLOT, KEY_TYPE, PIN_POLICY, TOUCH_POLICY, DEFAULT_MANAGEMENT_KEY

        self._ensure_session()

        # Auth with default PIN (caller should have reset if needed)
        self._session.verify_pin(DEFAULT_PIV_PIN)
        if pin != DEFAULT_PIV_PIN:
            self._session.change_pin(DEFAULT_PIV_PIN, pin)
        self._pin_verified = True

        # Management key auth for generate_key
        self._session.authenticate(DEFAULT_MANAGEMENT_KEY)

        touch_sign = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_signing])
        touch_enc = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_encryption])
        piv_pin_policy = getattr(PIN_POLICY, _PIN_MAP[pin_policy])

        ed_pub = self._session.generate_key(
            SLOT.AUTHENTICATION,
            KEY_TYPE.ED25519,
            pin_policy=piv_pin_policy,
            touch_policy=touch_sign,
        )
        ed_pub_bytes = ed_pub.public_bytes_raw()

        x_pub = self._session.generate_key(
            SLOT.KEY_MANAGEMENT,
            KEY_TYPE.X25519,
            pin_policy=piv_pin_policy,
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
        pin_policy: PinPolicy = PinPolicy.ONCE,
    ) -> dict:
        """Import key material onto the device.

        Same reset-first expectation as provision().
        """
        from yubikit.piv import SLOT, PIN_POLICY, TOUCH_POLICY, DEFAULT_MANAGEMENT_KEY
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        self._ensure_session()

        self._session.verify_pin(DEFAULT_PIV_PIN)
        if pin != DEFAULT_PIV_PIN:
            self._session.change_pin(DEFAULT_PIV_PIN, pin)
        self._pin_verified = True

        self._session.authenticate(DEFAULT_MANAGEMENT_KEY)

        touch_sign = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_signing])
        touch_enc = getattr(TOUCH_POLICY, _TOUCH_MAP[touch_encryption])
        piv_pin_policy = getattr(PIN_POLICY, _PIN_MAP[pin_policy])

        ed_prv = Ed25519PrivateKey.from_private_bytes(ed25519_private)
        x_prv = X25519PrivateKey.from_private_bytes(x25519_private)

        self._session.put_key(
            SLOT.AUTHENTICATION,
            ed_prv,
            pin_policy=piv_pin_policy,
            touch_policy=touch_sign,
        )

        self._session.put_key(
            SLOT.KEY_MANAGEMENT,
            x_prv,
            pin_policy=piv_pin_policy,
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

    # ── Crypto operations ───────────────────────────────────────────

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
