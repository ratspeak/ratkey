"""HardwareIdentity — drop-in replacement for RNS.Identity backed by hardware.

This is the core class of Ratkey. It subclasses ``RNS.Identity`` and overrides
private key operations to delegate them to a hardware security token via proxy
objects. To the rest of the Reticulum stack, it behaves identically to a
software identity — peers on the network cannot tell the difference.

Usage::

    from ratkey import HardwareIdentity

    # From a .hwid file (auto-detects backend)
    identity = HardwareIdentity.from_hwid("path/to/identity.hwid")

    # Use with RNS as normal
    destination = RNS.Destination(identity, RNS.Destination.IN,
                                  RNS.Destination.SINGLE, "myapp", "myaspect")

    # Sign messages
    signature = identity.sign(b"hello")

    # Decrypt messages addressed to this identity
    plaintext = identity.decrypt(ciphertext)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

import RNS

from ratkey.errors import HardwareNotFoundError, PrivateKeyAccessError
from ratkey.hwid import HwidConfig, load_hwid
from ratkey.proxies import HardwareEd25519PrivateKey, HardwareX25519PrivateKey

if TYPE_CHECKING:
    from ratkey.backends.base import AbstractHardwareBackend

# Sentinel value for prv_bytes/sig_prv_bytes.
# Non-None so truthiness checks in RNS code pass, but obviously invalid
# if anyone tries to use it as actual key material.
_SENTINEL_BYTES = b"\xDE\xAD" * 16


class HardwareIdentity(RNS.Identity):
    """A Reticulum Identity backed by a hardware security token.

    Compatible with the ``RNS.Identity`` API. Can be used anywhere a
    software Identity is expected: Destinations, Links, LXMF messages.

    Private keys never exist on the host machine. All signing and ECDH
    operations are performed on the hardware device.
    """

    @staticmethod
    def from_hwid(
        path: str | Path,
        backend: Optional[AbstractHardwareBackend] = None,
        pin_callback=None,
    ) -> HardwareIdentity:
        """Load a HardwareIdentity from a `.hwid` configuration file.

        If no backend is provided, auto-detects based on the device type
        in the config file.

        Args:
            path: Path to the `.hwid` TOML file.
            backend: Optional hardware backend instance. If None, auto-detected.
            pin_callback: Optional callable(prompt, retries) → PIN string.

        Returns:
            A HardwareIdentity ready for use with RNS.
        """
        config = load_hwid(path)

        if backend is None:
            from ratkey.backends import auto_detect_backend
            backend = auto_detect_backend(config, pin_callback)

        return HardwareIdentity(
            backend=backend,
            ed25519_pub=config.ed25519_pub_bytes,
            x25519_pub=config.x25519_pub_bytes,
            config=config,
        )

    @staticmethod
    def from_backend(
        backend: AbstractHardwareBackend,
    ) -> HardwareIdentity:
        """Create a HardwareIdentity from a connected backend.

        Reads the public keys from the backend. The backend must have
        provisioned keys.

        Args:
            backend: A connected hardware backend with provisioned keys.

        Returns:
            A HardwareIdentity ready for use with RNS.
        """
        ed25519_pub, x25519_pub = backend.get_public_keys()
        return HardwareIdentity(
            backend=backend,
            ed25519_pub=ed25519_pub,
            x25519_pub=x25519_pub,
        )

    def __init__(
        self,
        backend: AbstractHardwareBackend,
        ed25519_pub: bytes,
        x25519_pub: bytes,
        config: Optional[HwidConfig] = None,
    ):
        """Initialize a hardware-backed identity.

        Do not call directly — use ``from_hwid()`` or ``from_backend()``.

        Args:
            backend: Hardware backend for signing/ECDH operations.
            ed25519_pub: 32-byte Ed25519 public key.
            x25519_pub: 32-byte X25519 public key.
            config: Optional HwidConfig for metadata.
        """
        # Initialize parent WITHOUT generating keys
        super().__init__(create_keys=False)

        self._backend = backend
        self._hwid_config = config

        # Store public key bytes in the correct order for Reticulum:
        #   pub_bytes = X25519 public (32 bytes)
        #   sig_pub_bytes = Ed25519 public (32 bytes)
        self.pub_bytes = x25519_pub
        self.sig_pub_bytes = ed25519_pub

        # Create real public key objects from bytes
        from RNS.Cryptography import Ed25519PublicKey, X25519PublicKey

        self.pub = X25519PublicKey.from_public_bytes(x25519_pub)
        self.sig_pub = Ed25519PublicKey.from_public_bytes(ed25519_pub)

        # Install PROXY objects that delegate to hardware.
        # When Link.py copies identity.sig_prv and later calls .sign(),
        # the proxy intercepts and routes to the hardware token.
        self.prv = HardwareX25519PrivateKey(backend, x25519_pub)
        self.sig_prv = HardwareEd25519PrivateKey(backend, ed25519_pub)

        # Non-None sentinels so RNS truthiness checks pass.
        # Code like `if identity.prv_bytes:` will see True.
        self.prv_bytes = _SENTINEL_BYTES
        self.sig_prv_bytes = _SENTINEL_BYTES

        # Compute identity hash (same algorithm as software identity)
        self.update_hashes()

    # ── Properties ────────────────────────────────────────────────

    @property
    def is_hardware(self) -> bool:
        """True — this is a hardware-backed identity."""
        return True

    @property
    def backend_name(self) -> str:
        """Name of the hardware backend (e.g., 'yubikey-piv')."""
        return self._backend.name

    @property
    def hwid_config(self) -> Optional[HwidConfig]:
        """The .hwid configuration, if loaded from file."""
        return self._hwid_config

    # ── Overrides (block private key access) ──────────────────────

    def get_private_key(self):
        """Hardware identities cannot export private keys.

        Raises:
            PrivateKeyAccessError: Always.
        """
        raise PrivateKeyAccessError(
            f"Cannot export private key from hardware identity {self}. "
            f"Keys are held on the {self.backend_name} device."
        )

    def to_file(self, path):
        """Hardware identities cannot be saved as private key files.

        Use the `.hwid` TOML format instead.

        Raises:
            PrivateKeyAccessError: Always.
        """
        raise PrivateKeyAccessError(
            "Cannot save hardware identity as a private key file. "
            "Hardware identities use the .hwid format. "
            "Use ratkey.hwid.save_hwid() to save the public configuration."
        )

    # ── Convenience (non-overrides) ───────────────────────────────

    def sign_bytes(self, message: bytes) -> bytes:
        """Sign raw bytes using the hardware token.

        This is a convenience method that calls the backend directly.
        For normal RNS usage, the proxy objects handle signing transparently.

        Returns:
            64-byte Ed25519 signature.
        """
        return self._backend.sign(message)

    def is_connected(self) -> bool:
        """Check if the hardware token is physically present."""
        return self._backend.is_connected()
