"""Proxy objects that mimic RNS private key interfaces but delegate to hardware.

These proxies are the core trick that makes HardwareIdentity transparent to
existing Reticulum code. When RNS.Link copies ``identity.sig_prv`` and later
calls ``.sign()``, the proxy intercepts the call and routes it to the hardware
token. When ``Identity.decrypt()`` calls ``self.prv.exchange(peer_pub)``, the
proxy intercepts and performs ECDH on the hardware.

The proxies implement the exact same method signatures as the real
``Ed25519PrivateKey`` and ``X25519PrivateKey`` objects from ``RNS.Cryptography``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratkey.errors import HardwareDisconnectedError, PrivateKeyAccessError

if TYPE_CHECKING:
    from ratkey.backends.base import AbstractHardwareBackend


class HardwareEd25519PrivateKey:
    """Proxy that looks like an Ed25519PrivateKey to RNS code.

    Implements the same interface as ``RNS.Cryptography.Ed25519PrivateKey``:
    - ``.sign(message)`` → 64-byte Ed25519 signature (delegated to hardware)
    - ``.public_key()`` → Ed25519PublicKey
    - ``.private_bytes()`` → raises PrivateKeyAccessError
    """

    def __init__(self, backend: AbstractHardwareBackend, pub_key_bytes: bytes):
        self._backend = backend
        self._pub_bytes = pub_key_bytes

    def sign(self, message: bytes) -> bytes:
        """Sign a message using the hardware token's Ed25519 key.

        Returns a 64-byte Ed25519 signature per RFC 8032.
        """
        if not self._backend.is_connected():
            raise HardwareDisconnectedError(
                "Hardware device disconnected. Insert your security key to sign."
            )
        return self._backend.sign(message)

    def public_key(self):
        """Return the Ed25519 public key."""
        from RNS.Cryptography import Ed25519PublicKey

        return Ed25519PublicKey.from_public_bytes(self._pub_bytes)

    def private_bytes(self) -> bytes:
        """Raises: private key material is held on hardware and cannot be exported."""
        raise PrivateKeyAccessError(
            "Ed25519 private key is held on the hardware device and cannot be exported. "
            "Use .sign() to perform signing operations through the hardware token."
        )


class HardwareX25519PrivateKey:
    """Proxy that looks like an X25519PrivateKey to RNS code.

    Implements the same interface as ``RNS.Cryptography.X25519PrivateKey``:
    - ``.exchange(peer_public_key)`` → 32-byte shared secret (delegated to hardware)
    - ``.public_key()`` → X25519PublicKey
    - ``.private_bytes()`` → raises PrivateKeyAccessError
    """

    def __init__(self, backend: AbstractHardwareBackend, pub_key_bytes: bytes):
        self._backend = backend
        self._pub_bytes = pub_key_bytes

    def exchange(self, peer_public_key) -> bytes:
        """Perform X25519 ECDH key agreement using the hardware token.

        Accepts either an X25519PublicKey object or raw 32-byte public key.
        Returns a 32-byte shared secret per RFC 7748.
        """
        if not self._backend.is_connected():
            raise HardwareDisconnectedError(
                "Hardware device disconnected. Insert your security key for decryption."
            )
        # Extract raw bytes from various key object types
        if isinstance(peer_public_key, bytes):
            peer_bytes = peer_public_key
        elif hasattr(peer_public_key, "public_bytes"):
            peer_bytes = peer_public_key.public_bytes()
        elif hasattr(peer_public_key, "public_bytes_raw"):
            peer_bytes = peer_public_key.public_bytes_raw()
        elif hasattr(peer_public_key, "real"):
            # PyCA proxy wrapper used by RNS
            peer_bytes = peer_public_key.real.public_bytes_raw()
        else:
            raise TypeError(
                f"Cannot extract public key bytes from {type(peer_public_key).__name__}. "
                f"Expected X25519PublicKey, bytes, or compatible object."
            )
        return self._backend.exchange(peer_bytes)

    def public_key(self):
        """Return the X25519 public key."""
        from RNS.Cryptography import X25519PublicKey

        return X25519PublicKey.from_public_bytes(self._pub_bytes)

    def private_bytes(self) -> bytes:
        """Raises: private key material is held on hardware and cannot be exported."""
        raise PrivateKeyAccessError(
            "X25519 private key is held on the hardware device and cannot be exported. "
            "Use .exchange() to perform ECDH through the hardware token."
        )
