"""
Ratkey — Hardware-backed identity protection for Reticulum.

Delegates Ed25519 signing and X25519 ECDH to hardware security tokens
(YubiKey 5, Nitrokey 3) via the PIV smart card interface. Private keys
never leave the hardware device during normal operation.

Quick start:
    from ratkey import HardwareIdentity

    # Load from a .hwid config file
    identity = HardwareIdentity.from_hwid("~/.reticulum/storage/identities/abc123.hwid")

    # Use anywhere RNS.Identity is expected
    destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "app", "aspect")

For provisioning new hardware identities, use the CLI:
    $ rnid-hw provision --hardware yubikey
"""

__version__ = "0.1.0"

from ratkey.identity import HardwareIdentity
from ratkey.errors import (
    RatkeyError,
    HardwareNotFoundError,
    HardwareDisconnectedError,
    PINRequiredError,
    PINIncorrectError,
    PrivateKeyAccessError,
    SeedPhraseError,
    KeyImportError,
)
from ratkey.hwid import HwidConfig, load_hwid, save_hwid

__all__ = [
    "HardwareIdentity",
    "HwidConfig",
    "load_hwid",
    "save_hwid",
    "RatkeyError",
    "HardwareNotFoundError",
    "HardwareDisconnectedError",
    "PINRequiredError",
    "PINIncorrectError",
    "PrivateKeyAccessError",
    "SeedPhraseError",
    "KeyImportError",
]
