"""`.hwid` file format — TOML configuration for hardware-backed identities.

A `.hwid` file stores public metadata about a hardware identity: public keys,
device info, slot assignments, PIN policy, and attestation certificates.
**No private key material is ever stored in this file.**

The file format is shared between the Rust and Python implementations to
ensure interoperability.

Typical location:
    ``~/.reticulum/storage/identities/<hash>.hwid``
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import tomli_w


@dataclass
class HwidConfig:
    """Complete hardware identity configuration."""

    # Identity
    identity_hash: str = ""
    nickname: str = ""
    created_at: int = 0

    # Device
    device_type: str = ""  # "yubikey5" or "nitrokey3"
    device_serial: int = 0
    device_firmware: str = ""

    # Public keys (hex-encoded, 32 bytes each)
    ed25519_pub: str = ""
    x25519_pub: str = ""

    # PIV slots
    signing_slot: str = "9A"
    encryption_slot: str = "9D"

    # Policy
    pin_policy: str = "once"
    pin_cache_timeout: int = 300
    touch_signing: str = "always"
    touch_encryption: str = "cached"

    # Attestation (base64-encoded DER)
    attestation_ed25519_cert: str = ""
    attestation_x25519_cert: str = ""
    attestation_verified: bool = False

    # LXMF
    lxmf_hash: str = ""

    # Provisioning method: "hardware-only" or "recoverable"
    provisioning_method: str = ""

    @property
    def ed25519_pub_bytes(self) -> bytes:
        """Decode the Ed25519 public key from hex."""
        return bytes.fromhex(self.ed25519_pub)

    @property
    def x25519_pub_bytes(self) -> bytes:
        """Decode the X25519 public key from hex."""
        return bytes.fromhex(self.x25519_pub)

    @property
    def signing_slot_byte(self) -> int:
        """Parse the signing slot as an integer (e.g., '9A' → 0x9A)."""
        return int(self.signing_slot, 16)

    @property
    def encryption_slot_byte(self) -> int:
        """Parse the encryption slot as an integer (e.g., '9D' → 0x9D)."""
        return int(self.encryption_slot, 16)


def load_hwid(path: str | Path) -> HwidConfig:
    """Load a `.hwid` TOML file and return an HwidConfig."""
    path = Path(path).expanduser()
    with open(path, "rb") as f:
        data = tomllib.load(f)

    config = HwidConfig()

    # Identity section
    if "identity" in data:
        sec = data["identity"]
        config.identity_hash = sec.get("hash", "")
        config.nickname = sec.get("nickname", "")
        config.created_at = sec.get("created_at", 0)

    # Device section
    if "device" in data:
        sec = data["device"]
        config.device_type = sec.get("type", "")
        config.device_serial = sec.get("serial", 0)
        config.device_firmware = sec.get("firmware", "")

    # Keys section
    if "keys" in data:
        sec = data["keys"]
        config.ed25519_pub = sec.get("ed25519_pub", "")
        config.x25519_pub = sec.get("x25519_pub", "")

    # Slots section
    if "slots" in data:
        sec = data["slots"]
        config.signing_slot = sec.get("signing", "9A")
        config.encryption_slot = sec.get("encryption", "9D")

    # Policy section
    if "policy" in data:
        sec = data["policy"]
        config.pin_policy = sec.get("pin_policy", "once")
        config.pin_cache_timeout = sec.get("pin_cache_timeout", 300)
        config.touch_signing = sec.get("touch_signing", "always")
        config.touch_encryption = sec.get("touch_encryption", "cached")

    # Attestation section
    if "attestation" in data:
        sec = data["attestation"]
        config.attestation_ed25519_cert = sec.get("ed25519_cert", "")
        config.attestation_x25519_cert = sec.get("x25519_cert", "")
        config.attestation_verified = sec.get("verified", False)

    # LXMF section
    if "lxmf" in data:
        config.lxmf_hash = data["lxmf"].get("lxmf_hash", "")

    # Provisioning method (new format)
    if "provisioning" in data:
        config.provisioning_method = data["provisioning"].get("method", "")
    elif "backup" in data:
        # Backward compat: old tier-based format
        tier = data["backup"].get("tier", 0)
        config.provisioning_method = "recoverable" if tier > 0 else "hardware-only"

    return config


def save_hwid(config: HwidConfig, path: str | Path) -> None:
    """Write an HwidConfig to a `.hwid` TOML file.

    Uses atomic write (write to .tmp, then rename) to prevent corruption.
    """
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "identity": {
            "hash": config.identity_hash,
            "nickname": config.nickname,
            "created_at": config.created_at,
        },
        "device": {
            "type": config.device_type,
            "serial": config.device_serial,
            "firmware": config.device_firmware,
        },
        "keys": {
            "ed25519_pub": config.ed25519_pub,
            "x25519_pub": config.x25519_pub,
        },
        "slots": {
            "signing": config.signing_slot,
            "encryption": config.encryption_slot,
        },
        "policy": {
            "pin_policy": config.pin_policy,
            "pin_cache_timeout": config.pin_cache_timeout,
            "touch_signing": config.touch_signing,
            "touch_encryption": config.touch_encryption,
        },
        "attestation": {
            "ed25519_cert": config.attestation_ed25519_cert,
            "x25519_cert": config.attestation_x25519_cert,
            "verified": config.attestation_verified,
        },
        "lxmf": {
            "lxmf_hash": config.lxmf_hash,
        },
        "provisioning": {
            "method": config.provisioning_method,
        },
    }

    header = (
        "# Ratkey Hardware Identity \u2014 DO NOT EDIT MANUALLY\n"
        "# Private keys exist ONLY on the hardware device.\n\n"
    )

    # Atomic write
    tmp_path = path.with_suffix(".hwid.tmp")
    with open(tmp_path, "wb") as f:
        f.write(header.encode("utf-8"))
        tomli_w.dump(data, f)
    os.replace(tmp_path, path)
