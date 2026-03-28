"""Ratkey CLI — Hardware identity management for Reticulum.

Entry point: ``rnid-hw`` (installed via pip)
"""

from __future__ import annotations

import hashlib
import random
import time
from pathlib import Path

import click


@click.group()
@click.version_option(package_name="ratkey")
def cli():
    """Ratkey — Hardware-backed identity management for Reticulum.

    Manage Reticulum identities stored on YubiKey 5 hardware security
    tokens via the PIV smart card interface.
    """


# ── Provision ────────────────────────────────────────────────────────


@cli.command()
@click.option("--pin", prompt="PIV PIN", hide_input=True, confirmation_prompt=True,
              help="6-8 character PIV PIN for the YubiKey")
@click.option("--method", type=click.Choice(["hardware-only", "recoverable"]),
              help="Provisioning method (prompted if not provided)")
@click.option("--touch-signing", type=click.Choice(["never", "cached", "always"]),
              default="never", show_default=True,
              help="Touch policy for signing operations")
@click.option("--touch-encryption", type=click.Choice(["never", "cached", "always"]),
              default="never", show_default=True,
              help="Touch policy for decryption operations")
@click.option("--nickname", "-n", default="", help="Human-readable name for this identity")
@click.option("--output", "-o", type=click.Path(), required=True,
              help="Directory to save the .hwid file")
def provision(pin, method, touch_signing, touch_encryption, nickname, output):
    """Provision a new hardware-backed Reticulum identity.

    You'll choose between two provisioning methods:

    \b
    Hardware-only: Keys generated on the YubiKey. No backup possible.
    Recoverable:   Keys derived from a 24-word seed phrase. Write down
                   the words as your backup.
    """
    if len(pin) < 6 or len(pin) > 8:
        raise click.BadParameter("PIN must be 6-8 characters", param_hint="--pin")

    # Method selection
    if method is None:
        method = _prompt_method()

    if method == "recoverable":
        _provision_recoverable(pin, touch_signing, touch_encryption, nickname, output)
    else:
        _provision_hardware_only(pin, touch_signing, touch_encryption, nickname, output)


def _prompt_method() -> str:
    """Interactive provisioning method selection."""
    click.echo()
    click.echo("Choose a provisioning method:")
    click.echo()
    click.echo("  [1] Hardware-only")
    click.echo("      Keys are generated directly on the YubiKey's secure element.")
    click.echo("      No backup is possible. If you lose this YubiKey, this identity")
    click.echo("      is gone forever. This is the most secure option.")
    click.echo()
    click.echo("  [2] Recoverable (seed phrase)")
    click.echo("      Keys are derived from a 24-word seed phrase and imported to the")
    click.echo("      YubiKey. Write down the words as your backup. If you lose the")
    click.echo("      YubiKey, you can restore the identity to a new one using the words.")
    click.echo()
    choice = click.prompt("Choose", type=click.Choice(["1", "2"]))
    return "hardware-only" if choice == "1" else "recoverable"


def _confirm_policies(touch_signing: str, touch_encryption: str) -> bool:
    """Display policy summary and get confirmation."""
    click.echo()
    click.echo("Touch policy summary:")
    click.echo(f"  Signing:    {touch_signing}")
    click.echo(f"  Encryption: {touch_encryption}")
    click.echo()
    click.echo("WARNING: These policies are permanently burned into the YubiKey's")
    click.echo("hardware. They CANNOT be changed after provisioning — not by software,")
    click.echo("not by firmware update, not by factory reset. If you choose wrong,")
    click.echo("your only option is to generate a new identity (new address, start over).")
    click.echo()
    return click.confirm("Proceed with these policies?")


def _get_backend():
    """Connect to a YubiKey hardware backend."""
    try:
        from ratkey.backends.yubikey_piv import YubiKeyPIVBackend
    except ImportError:
        click.echo("Error: YubiKey backend not installed.", err=True)
        click.echo("Install with: pip install ratkey[yubikey]", err=True)
        raise SystemExit(1)

    try:
        backend = YubiKeyPIVBackend()
        click.echo("Connected to YubiKey.")
        return backend
    except Exception as e:
        click.echo(f"Error: could not connect to YubiKey — {e}", err=True)
        click.echo("", err=True)
        click.echo("Make sure your YubiKey is plugged in.", err=True)
        click.echo("On Linux, check that pcscd is running: sudo systemctl start pcscd", err=True)
        raise SystemExit(1)


def _save_hwid(ed_pub, x_pub, backend, nickname, touch_signing, touch_encryption,
               output, provisioning_method):
    """Compute identity hash and save .hwid file."""
    pub_bytes = x_pub + ed_pub
    identity_hash = hashlib.sha256(pub_bytes).digest()[:16]
    hash_hex = identity_hash.hex()

    from ratkey.hwid import HwidConfig, save_hwid

    config = HwidConfig(
        identity_hash=hash_hex,
        nickname=nickname,
        created_at=int(time.time()),
        device_type=backend.name.replace("-piv", ""),
        device_serial=0,
        device_firmware="",
        ed25519_pub=ed_pub.hex(),
        x25519_pub=x_pub.hex(),
        touch_signing=touch_signing,
        touch_encryption=touch_encryption,
        provisioning_method=provisioning_method,
    )

    path = Path(output) / hash_hex / "identity.hwid"
    save_hwid(config, path)

    click.echo()
    click.echo("Hardware identity provisioned:")
    click.echo(f"  Identity hash:  {hash_hex}")
    click.echo(f"  Ed25519 public: {ed_pub.hex()}")
    click.echo(f"  X25519 public:  {x_pub.hex()}")
    click.echo(f"  Method:         {provisioning_method}")
    click.echo(f"  Saved to:       {path}")
    return hash_hex


def _provision_hardware_only(pin, touch_signing, touch_encryption, nickname, output):
    """Provision with keys generated on-device."""
    if not _confirm_policies(touch_signing, touch_encryption):
        click.echo("Cancelled.")
        return

    from ratkey.backends.base import TouchPolicy
    touch_map = {"never": TouchPolicy.NEVER, "cached": TouchPolicy.CACHED, "always": TouchPolicy.ALWAYS}

    backend = _get_backend()
    try:
        result = backend.provision(pin, touch_map[touch_signing], touch_map[touch_encryption])
    except Exception as e:
        click.echo(f"Provisioning failed: {e}", err=True)
        raise SystemExit(1)

    _save_hwid(result["ed25519_public"], result["x25519_public"],
               backend, nickname, touch_signing, touch_encryption,
               output, "hardware-only")

    click.echo()
    click.echo("WARNING: No backup exists. If you lose this YubiKey, this identity")
    click.echo("is gone forever. There is no recovery.")


def _provision_recoverable(pin, touch_signing, touch_encryption, nickname, output):
    """Provision with keys derived from a BIP-39 seed phrase."""
    click.echo()
    click.echo("SECURITY NOTICE")
    click.echo()
    click.echo("Your private keys will be derived from a 24-word seed phrase and")
    click.echo("imported to the YubiKey. This means:")
    click.echo()
    click.echo("  * The seed phrase IS your identity — anyone who sees these words")
    click.echo("    can reconstruct your private keys and impersonate you")
    click.echo("  * The seed phrase is NOT protected by your YubiKey PIN")
    click.echo("  * The keys briefly exist in this computer's memory during import")
    click.echo("  * You get recoverability: lose the YubiKey, restore from words")
    click.echo()

    if not click.confirm("Continue with recoverable provisioning?"):
        click.echo("Cancelled.")
        return

    if not _confirm_policies(touch_signing, touch_encryption):
        click.echo("Cancelled.")
        return

    # Generate seed phrase
    from ratkey.backup.seed_phrase import generate_mnemonic, derive_keys

    mnemonic = generate_mnemonic()
    words = mnemonic.split()

    click.echo()
    click.echo("Your seed phrase (24 words):")
    click.echo()
    for i in range(0, 24, 4):
        row = "  ".join(f"{i+j+1:>2}. {words[i+j]:<12}" for j in range(4))
        click.echo(f"  {row}")
    click.echo()
    click.echo("WRITE THESE WORDS DOWN NOW on physical paper.")
    click.echo()
    click.echo("  * Do NOT photograph them")
    click.echo("  * Do NOT store them digitally (no notes apps, no cloud, no screenshots)")
    click.echo("  * Store the paper in a physically secure location")
    click.echo("  * These words will NOT be shown again")
    click.echo()

    # Spot-check: verify user wrote them down
    check_indices = random.sample(range(24), 2)
    for idx in sorted(check_indices):
        answer = click.prompt(f"Confirm — enter word #{idx + 1}").strip().lower()
        if answer != words[idx]:
            click.echo(f"Incorrect. Expected word #{idx + 1} to be '{words[idx]}'.")
            click.echo("Please write down your seed phrase carefully and try again.")
            raise SystemExit(1)

    click.echo("Confirmed.")
    click.echo()

    # Derive keys
    ed_prv, ed_pub, x_prv, x_pub = derive_keys(mnemonic)

    # Import to hardware
    from ratkey.backends.base import TouchPolicy
    touch_map = {"never": TouchPolicy.NEVER, "cached": TouchPolicy.CACHED, "always": TouchPolicy.ALWAYS}

    backend = _get_backend()
    try:
        result = backend.import_key(
            ed_prv, x_prv, pin,
            touch_map[touch_signing], touch_map[touch_encryption],
        )
    except Exception as e:
        click.echo(f"Key import failed: {e}", err=True)
        raise SystemExit(1)

    _save_hwid(result["ed25519_public"], result["x25519_public"],
               backend, nickname, touch_signing, touch_encryption,
               output, "recoverable")

    click.echo()
    click.echo("Close this terminal window after confirming you have your seed phrase written down.")


# ── List ─────────────────────────────────────────────────────────────


@cli.command("list")
@click.option("--dir", "-d", type=click.Path(exists=True), required=True,
              help="Directory to scan for .hwid files")
def list_identities(dir):
    """List hardware identities in a directory."""
    from ratkey.hwid import load_hwid

    found = 0
    for entry in sorted(Path(dir).iterdir()):
        hwid_path = entry / "identity.hwid"
        if hwid_path.exists():
            try:
                config = load_hwid(hwid_path)
                nick = config.nickname or "(unnamed)"
                method = config.provisioning_method or "unknown"
                click.echo(f"  {config.identity_hash}  {config.device_type}  {method}  {nick}")
                found += 1
            except Exception as e:
                click.echo(f"  Error reading {hwid_path}: {e}", err=True)

    if found == 0:
        click.echo("No hardware identities found.")
    else:
        click.echo(f"\n{found} hardware identity(s) found.")


# ── Info ─────────────────────────────────────────────────────────────


@cli.command()
@click.argument("hwid", type=click.Path(exists=True))
def info(hwid):
    """Show detailed hardware identity information."""
    from ratkey.hwid import load_hwid

    config = load_hwid(hwid)

    click.echo("Hardware Identity Information:")
    click.echo(f"  Hash:            {config.identity_hash}")
    click.echo(f"  Nickname:        {config.nickname or '(none)'}")
    click.echo(f"  Created:         {config.created_at} (Unix timestamp)")
    click.echo()
    click.echo("Device:")
    click.echo(f"  Type:            {config.device_type}")
    click.echo(f"  Serial:          {config.device_serial}")
    click.echo(f"  Firmware:        {config.device_firmware}")
    click.echo()
    click.echo("Keys:")
    click.echo(f"  Ed25519 public:  {config.ed25519_pub}")
    click.echo(f"  X25519 public:   {config.x25519_pub}")
    click.echo()
    click.echo("Policy (permanent — set at provisioning):")
    click.echo(f"  Touch (sign):    {config.touch_signing}")
    click.echo(f"  Touch (encrypt): {config.touch_encryption}")
    click.echo(f"  PIN cache:       {config.pin_cache_timeout}s (editable in .hwid file)")
    click.echo()
    click.echo(f"Provisioning:      {config.provisioning_method or 'unknown'}")
    if config.attestation_verified:
        click.echo("Attestation:       verified")
    else:
        click.echo("Attestation:       (not verified)")


# ── Verify ───────────────────────────────────────────────────────────


@cli.command()
@click.argument("hwid", type=click.Path(exists=True))
def verify(hwid):
    """Verify that a connected YubiKey matches a .hwid file."""
    from ratkey.hwid import load_hwid

    config = load_hwid(hwid)
    click.echo(f"Verifying identity {config.identity_hash}...")

    try:
        from ratkey.backends.yubikey_piv import YubiKeyPIVBackend
        backend = YubiKeyPIVBackend(serial=config.device_serial)
        ed_pub, x_pub = backend.get_public_keys()

        if ed_pub.hex() == config.ed25519_pub and x_pub.hex() == config.x25519_pub:
            click.echo("PASS: YubiKey public keys match .hwid file.")
        else:
            click.echo("FAIL: Public keys do not match.", err=True)
            raise SystemExit(1)
    except ImportError:
        click.echo("YubiKey backend not installed. Run: pip install ratkey[yubikey]", err=True)
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"Verification failed: {e}", err=True)
        raise SystemExit(1)


# ── Test ─────────────────────────────────────────────────────────────


@cli.command()
@click.argument("hwid", type=click.Path(exists=True))
@click.option("--pin", prompt="PIV PIN", hide_input=True, help="YubiKey PIV PIN")
def test(hwid, pin):
    """Test signing and decryption with a connected YubiKey."""
    from ratkey.hwid import load_hwid

    config = load_hwid(hwid)
    click.echo(f"Testing identity {config.identity_hash}...\n")

    try:
        from ratkey.backends.yubikey_piv import YubiKeyPIVBackend
        backend = YubiKeyPIVBackend(serial=config.device_serial)
    except ImportError:
        click.echo("YubiKey backend not installed. Run: pip install ratkey[yubikey]", err=True)
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"Cannot connect to YubiKey: {e}", err=True)
        raise SystemExit(1)

    try:
        backend.verify_pin(pin)
    except Exception as e:
        click.echo(f"PIN verification failed: {e}", err=True)
        raise SystemExit(1)

    # Test 1: Sign and verify
    click.echo("1. Signing test message...")
    test_msg = b"Ratkey hardware identity test"
    try:
        sig = backend.sign(test_msg)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_key = Ed25519PublicKey.from_public_bytes(config.ed25519_pub_bytes)
        pub_key.verify(sig, test_msg)
        click.echo("   PASS: signature verified")
    except Exception as e:
        click.echo(f"   FAIL: {e}", err=True)
        raise SystemExit(1)

    # Test 2: ECDH
    click.echo("2. Key agreement test...")
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        peer_prv = X25519PrivateKey.generate()
        peer_pub = peer_prv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        hw_secret = backend.exchange(peer_pub)
        peer_secret = peer_prv.exchange(
            X25519PublicKey.from_public_bytes(config.x25519_pub_bytes)
        )

        if hw_secret == peer_secret:
            click.echo("   PASS: ECDH shared secrets match")
        else:
            click.echo("   FAIL: shared secrets don't match", err=True)
            raise SystemExit(1)
    except Exception as e:
        click.echo(f"   FAIL: {e}", err=True)
        raise SystemExit(1)

    click.echo("\nAll tests passed.")


# ── Restore ──────────────────────────────────────────────────────────


@cli.command()
@click.option("--output", "-o", type=click.Path(), required=True,
              help="Directory to save the restored .hwid file")
@click.option("--touch-signing", type=click.Choice(["never", "cached", "always"]),
              default="cached", show_default=True)
@click.option("--touch-encryption", type=click.Choice(["never", "cached", "always"]),
              default="cached", show_default=True)
@click.option("--nickname", "-n", default="", help="Nickname for the restored identity")
def restore(output, touch_signing, touch_encryption, nickname):
    """Restore an identity from a 24-word seed phrase.

    Enter the seed phrase you wrote down during provisioning. The same
    keys will be derived and imported onto the connected YubiKey.
    """
    click.echo("Enter your 24-word seed phrase (space-separated):")
    words_input = click.prompt("Seed phrase").strip()

    from ratkey.backup.seed_phrase import validate_mnemonic, derive_keys, compute_identity_hash

    if not validate_mnemonic(words_input):
        click.echo("Invalid seed phrase. Must be 24 valid BIP-39 English words.", err=True)
        raise SystemExit(1)

    # Derive keys and show expected identity
    ed_prv, ed_pub, x_prv, x_pub = derive_keys(words_input)
    identity_hash = compute_identity_hash(ed_pub, x_pub)
    hash_hex = identity_hash.hex()

    click.echo(f"\nDerived identity hash: {hash_hex}")
    if not click.confirm("Is this the identity you want to restore?"):
        click.echo("Cancelled.")
        return

    pin = click.prompt("PIV PIN for the target YubiKey", hide_input=True)
    if len(pin) < 6 or len(pin) > 8:
        click.echo("PIN must be 6-8 characters.", err=True)
        raise SystemExit(1)

    from ratkey.backends.base import TouchPolicy
    touch_map = {"never": TouchPolicy.NEVER, "cached": TouchPolicy.CACHED, "always": TouchPolicy.ALWAYS}

    backend = _get_backend()
    try:
        result = backend.import_key(
            ed_prv, x_prv, pin,
            touch_map[touch_signing], touch_map[touch_encryption],
        )
    except Exception as e:
        click.echo(f"Key import failed: {e}", err=True)
        raise SystemExit(1)

    # Verify the imported keys match
    if result["ed25519_public"] != ed_pub or result["x25519_public"] != x_pub:
        click.echo("ERROR: Imported keys don't match derived keys.", err=True)
        raise SystemExit(1)

    _save_hwid(ed_pub, x_pub, backend, nickname,
               touch_signing, touch_encryption, output, "recoverable")

    click.echo("\nIdentity restored successfully.")


# ── Migrate ──────────────────────────────────────────────────────────


@cli.command()
@click.argument("identity", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), required=True,
              help="Directory to save the .hwid file")
@click.option("--touch-signing", type=click.Choice(["never", "cached", "always"]),
              default="cached", show_default=True)
@click.option("--touch-encryption", type=click.Choice(["never", "cached", "always"]),
              default="cached", show_default=True)
@click.option("--nickname", "-n", default="", help="Nickname for the migrated identity")
def migrate(identity, output, touch_signing, touch_encryption, nickname):
    """Move an existing software identity onto a YubiKey.

    Reads a Reticulum identity file (64-byte private key), imports the
    keys onto the connected YubiKey, and writes a .hwid config file.
    Same identity, same address -- now hardware-backed.
    """
    # Read the identity file
    key_data = Path(identity).read_bytes()

    # Handle both raw 64-byte format and msgpack-wrapped format
    if len(key_data) == 64:
        prv_bytes = key_data
    else:
        try:
            import rmp_serde
        except ImportError:
            pass
        # Try msgpack unwrap (ratspeak format: {"private_key": bytes})
        try:
            import msgpack
            unpacked = msgpack.unpackb(key_data)
            if isinstance(unpacked, dict) and b"private_key" in unpacked:
                prv_bytes = unpacked[b"private_key"]
            elif isinstance(unpacked, dict) and "private_key" in unpacked:
                prv_bytes = unpacked["private_key"]
            elif isinstance(unpacked, bytes) and len(unpacked) == 64:
                prv_bytes = unpacked
            else:
                prv_bytes = key_data
        except Exception:
            prv_bytes = key_data

    if len(prv_bytes) != 64:
        click.echo(f"Error: identity file must contain 64 bytes of key material, got {len(prv_bytes)}.", err=True)
        raise SystemExit(1)

    x25519_prv = prv_bytes[:32]
    ed25519_prv = prv_bytes[32:64]

    # Compute and display the identity hash so user can confirm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ed_pub = Ed25519PrivateKey.from_private_bytes(ed25519_prv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_pub = X25519PrivateKey.from_private_bytes(x25519_prv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    identity_hash = hashlib.sha256(x_pub + ed_pub).digest()[:16]
    hash_hex = identity_hash.hex()

    click.echo(f"\nIdentity to migrate: {hash_hex}")
    click.echo(f"  Ed25519 public: {ed_pub.hex()}")
    click.echo(f"  X25519 public:  {x_pub.hex()}")
    click.echo()

    if not click.confirm("Is this the identity you want to move to hardware?"):
        click.echo("Cancelled.")
        return

    pin = click.prompt("PIV PIN for the YubiKey", hide_input=True)
    if len(pin) < 6 or len(pin) > 8:
        click.echo("PIN must be 6-8 characters.", err=True)
        raise SystemExit(1)

    from ratkey.backends.base import TouchPolicy
    touch_map = {"never": TouchPolicy.NEVER, "cached": TouchPolicy.CACHED, "always": TouchPolicy.ALWAYS}

    backend = _get_backend()
    try:
        result = backend.import_key(
            ed25519_prv, x25519_prv, pin,
            touch_map[touch_signing], touch_map[touch_encryption],
        )
    except Exception as e:
        click.echo(f"Key import failed: {e}", err=True)
        raise SystemExit(1)

    # Verify
    if result["ed25519_public"] != ed_pub or result["x25519_public"] != x_pub:
        click.echo("ERROR: Imported keys don't match source identity.", err=True)
        raise SystemExit(1)

    _save_hwid(ed_pub, x_pub, backend, nickname,
               touch_signing, touch_encryption, output, "migrated")

    click.echo()
    if click.confirm("Delete the software identity file? (Keys now live on the YubiKey)"):
        Path(identity).unlink()
        click.echo(f"Deleted {identity}")
    else:
        click.echo(f"Software key file kept at {identity}")
        click.echo("Consider deleting it manually once you've confirmed the hardware identity works.")


if __name__ == "__main__":
    cli()
