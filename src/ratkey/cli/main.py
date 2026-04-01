"""Ratkey CLI — Hardware identity management for Reticulum.

Entry point: ``rnid-hw`` (installed via pip)

Running ``rnid-hw`` with no arguments launches an interactive wizard.
All subcommands also work directly for scripting.
"""

from __future__ import annotations

import hashlib
import random
import sys
import time
from pathlib import Path

import click


DEFAULT_IDENTITY_DIR = str(Path.home() / ".reticulum" / "identities")


# ── Shared helpers ──────────────────────────────────────────────────


def _default_dir() -> str:
    return DEFAULT_IDENTITY_DIR


def _compute_lxmf_hash(identity_hash: bytes) -> bytes:
    """Compute the LXMF delivery destination hash from an identity hash.

    This mirrors Reticulum's Destination.hash(identity, "lxmf", "delivery"):
      name_hash = SHA-256("lxmf.delivery")[:10]
      dest_hash = SHA-256(name_hash + identity_hash)[:16]
    """
    name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]
    return hashlib.sha256(name_hash + identity_hash).digest()[:16]


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
        return backend
    except Exception as e:
        click.echo(f"Error: could not connect to YubiKey — {e}", err=True)
        click.echo("", err=True)
        click.echo("Make sure your YubiKey is plugged in.", err=True)
        click.echo("On Linux, check that pcscd is running: sudo systemctl start pcscd", err=True)
        raise SystemExit(1)


def _touch_map():
    from ratkey.backends.base import TouchPolicy
    return {"never": TouchPolicy.NEVER, "cached": TouchPolicy.CACHED, "always": TouchPolicy.ALWAYS}


def _wipe(data):
    """Best-effort zeroing of sensitive data in memory.

    Python strings and bytes are immutable so this is not guaranteed —
    the interpreter may keep copies. This is defense-in-depth.
    """
    import ctypes
    if isinstance(data, bytearray):
        ctypes.memset(
            ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data)),
            0, len(data),
        )
    elif isinstance(data, (bytes, str)):
        # Can't truly zero immutable objects, but we can try to overwrite
        # the buffer. This works on CPython but is not portable.
        try:
            buf = ctypes.cast(id(data) + (sys.getsizeof(data) - len(data)),
                              ctypes.POINTER(ctypes.c_char * len(data)))
            ctypes.memset(buf, 0, len(data))
        except Exception:
            pass


def _pin_policy_map():
    from ratkey.backends.base import PinPolicy
    return {"once": PinPolicy.ONCE, "always": PinPolicy.ALWAYS, "never": PinPolicy.NEVER}


def _save_hwid(ed_pub, x_pub, backend, nickname, touch_signing, touch_encryption,
               pin_policy, output, provisioning_method):
    """Compute identity hash and save .hwid file."""
    pub_bytes = x_pub + ed_pub
    identity_hash = hashlib.sha256(pub_bytes).digest()[:16]
    hash_hex = identity_hash.hex()
    lxmf_hash = _compute_lxmf_hash(identity_hash)
    lxmf_hex = lxmf_hash.hex()

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
        pin_policy=pin_policy,
        touch_signing=touch_signing,
        touch_encryption=touch_encryption,
        lxmf_hash=lxmf_hex,
        provisioning_method=provisioning_method,
    )

    path = Path(output) / hash_hex / "identity.hwid"
    save_hwid(config, path)

    click.echo()
    click.echo("Done. Hardware identity provisioned:")
    click.echo()
    click.echo(f"  LXMF address:   {lxmf_hex}")
    click.echo(f"  Identity hash:  {hash_hex}")
    click.echo(f"  Ed25519 public: {ed_pub.hex()}")
    click.echo(f"  X25519 public:  {x_pub.hex()}")
    click.echo(f"  Method:         {provisioning_method}")
    click.echo(f"  Saved to:       {path}")
    click.echo()
    click.echo("  Your LXMF address is what you share with others")
    click.echo("  so they can message you.")
    return hash_hex


# ── Interactive prompts ─────────────────────────────────────────────


def _prompt_pin() -> str:
    """Prompt for PIV PIN with validation and confirmation."""
    while True:
        pin = click.prompt("PIV PIN (6-8 characters)", hide_input=True)
        if len(pin) < 6 or len(pin) > 8:
            click.echo("PIN must be 6-8 characters. Try again.")
            continue
        confirm = click.prompt("Confirm PIN", hide_input=True)
        if pin != confirm:
            click.echo("PINs don't match. Try again.")
            continue
        return pin


def _prompt_pin_policy() -> str:
    """Prompt for PIN policy."""
    click.echo()
    click.echo("PIN policy:")
    click.echo()
    click.echo("  [1] once   — Enter PIN once per session. Cached until you unplug. (recommended)")
    click.echo("  [2] always — Enter PIN for every single operation.")
    click.echo("  [3] never  — No PIN required. Anyone with the YubiKey can use it.")
    click.echo()
    choice = click.prompt("Choice", type=click.Choice(["1", "2", "3"]), default="1", show_default=True)
    return {"1": "once", "2": "always", "3": "never"}[choice]


def _prompt_touch(operation: str) -> str:
    """Prompt for touch policy for a given operation."""
    click.echo()
    click.echo(f"Touch policy for {operation}:")
    click.echo()
    click.echo("  [1] never  — No touch required. Best for messaging and servers.")
    click.echo("  [2] cached — Touch once, then free for 15 seconds.")
    click.echo("  [3] always — Touch every single operation. Maximum security.")
    click.echo()
    choice = click.prompt("Choice", type=click.Choice(["1", "2", "3"]), default="1", show_default=True)
    return {"1": "never", "2": "cached", "3": "always"}[choice]


def _prompt_nickname() -> str:
    """Prompt for an optional nickname."""
    return click.prompt("Nickname (optional, Enter to skip)", default="", show_default=False)


def _prompt_output() -> str:
    """Prompt for output directory with default."""
    return click.prompt("Save location", default=_default_dir(), show_default=True)


def _show_summary(method: str, pin_policy: str, touch_signing: str,
                  touch_encryption: str, nickname: str, output: str) -> bool:
    """Show a summary of what's about to happen and confirm."""
    click.echo()
    click.echo("─── Summary ───────────────────────────────────────")
    click.echo(f"  Method:         {method}")
    click.echo(f"  PIN policy:     {pin_policy}")
    click.echo(f"  Touch (sign):   {touch_signing}")
    click.echo(f"  Touch (crypt):  {touch_encryption}")
    click.echo(f"  Nickname:       {nickname or '(none)'}")
    click.echo(f"  Output:         {output}")
    click.echo()
    click.echo("  Touch and PIN policies are permanently burned into the")
    click.echo("  YubiKey. They CANNOT be changed after provisioning.")
    click.echo("───────────────────────────────────────────────────")
    click.echo()
    return click.confirm("Proceed?")


# ── Flows ───────────────────────────────────────────────────────────


def _connect_and_prepare(backend):
    """Connect to YubiKey, check for existing keys, reset if user agrees.

    Returns True if ready to proceed, False if user cancelled.
    """
    slots = backend.check_slots()
    has_keys = slots["signing"] or slots["encryption"]

    if has_keys:
        click.echo()
        occupied = []
        if slots["signing"]:
            occupied.append("9A (signing)")
        if slots["encryption"]:
            occupied.append("9D (encryption)")
        click.echo(f"This YubiKey already has keys in slot(s): {', '.join(occupied)}")
        click.echo("Provisioning will reset the PIV application, clearing ALL existing")
        click.echo("PIV keys, PIN, and PUK back to factory defaults.")
        click.echo()
        if not click.confirm("Reset and overwrite?"):
            click.echo("Cancelled.")
            return False
        backend.reset_piv()
        click.echo("PIV application reset.")
    return True


def _do_provision_hardware_only(pin, pin_policy, touch_signing, touch_encryption, nickname, output):
    """Provision with keys generated on-device."""
    backend = _get_backend()
    click.echo("Connected to YubiKey.")

    if not _connect_and_prepare(backend):
        return

    try:
        result = backend.provision(
            pin, _touch_map()[touch_signing], _touch_map()[touch_encryption],
            _pin_policy_map()[pin_policy],
        )
    except Exception as e:
        click.echo(f"Provisioning failed: {e}", err=True)
        raise SystemExit(1)

    _save_hwid(result["ed25519_public"], result["x25519_public"],
               backend, nickname, touch_signing, touch_encryption,
               pin_policy, output, "hardware-only")

    click.echo()
    click.echo("WARNING: No backup exists. If you lose this YubiKey, this identity")
    click.echo("is gone forever. There is no recovery.")


def _do_provision_recoverable(pin, pin_policy, touch_signing, touch_encryption, nickname, output):
    """Provision with keys derived from a BIP-39 seed phrase."""
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
    click.echo("  * Do NOT store them digitally")
    click.echo("  * Store the paper in a physically secure location")
    click.echo("  * These words will NOT be shown again")
    click.echo()

    # Spot-check
    check_indices = random.sample(range(24), 2)
    for idx in sorted(check_indices):
        answer = click.prompt(f"Confirm — enter word #{idx + 1}").strip().lower()
        if answer != words[idx]:
            click.echo(f"Incorrect. Expected word #{idx + 1} to be '{words[idx]}'.")
            click.echo("Please write down your seed phrase carefully and try again.")
            raise SystemExit(1)

    click.echo("Confirmed.")

    ed_prv, ed_pub, x_prv, x_pub = derive_keys(mnemonic)

    backend = _get_backend()
    click.echo("Connected to YubiKey.")

    if not _connect_and_prepare(backend):
        _wipe(mnemonic)
        _wipe(ed_prv)
        _wipe(x_prv)
        del mnemonic, words, ed_prv, x_prv
        return

    try:
        result = backend.import_key(
            ed_prv, x_prv, pin,
            _touch_map()[touch_signing], _touch_map()[touch_encryption],
            _pin_policy_map()[pin_policy],
        )
    except Exception as e:
        click.echo(f"Key import failed: {e}", err=True)
        _wipe(mnemonic)
        _wipe(ed_prv)
        _wipe(x_prv)
        del mnemonic, words, ed_prv, x_prv
        raise SystemExit(1)

    # Wipe sensitive material from memory
    _wipe(mnemonic)
    _wipe(ed_prv)
    _wipe(x_prv)
    for i in range(len(words)):
        _wipe(words[i])
    del mnemonic, words, ed_prv, x_prv

    _save_hwid(result["ed25519_public"], result["x25519_public"],
               backend, nickname, touch_signing, touch_encryption,
               pin_policy, output, "recoverable")

    click.echo()
    click.echo("Seed phrase and private keys have been wiped from memory.")
    click.echo("Close this terminal to clear scrollback history.")


def _do_restore(pin_policy, touch_signing, touch_encryption, nickname, output):
    """Restore from seed phrase flow."""
    click.echo("Enter your 24-word seed phrase (space-separated):")
    words_input = click.prompt("Seed phrase").strip()

    from ratkey.backup.seed_phrase import validate_mnemonic, derive_keys, compute_identity_hash

    if not validate_mnemonic(words_input):
        click.echo("Invalid seed phrase. Must be 24 valid BIP-39 English words.", err=True)
        raise SystemExit(1)

    ed_prv, ed_pub, x_prv, x_pub = derive_keys(words_input)
    identity_hash = compute_identity_hash(ed_pub, x_pub)
    hash_hex = identity_hash.hex()
    lxmf_hex = _compute_lxmf_hash(identity_hash).hex()

    click.echo(f"\nDerived identity:")
    click.echo(f"  LXMF address:   {lxmf_hex}")
    click.echo(f"  Identity hash:  {hash_hex}")
    if not click.confirm("\nIs this the identity you want to restore?"):
        click.echo("Cancelled.")
        _wipe(words_input)
        _wipe(ed_prv)
        _wipe(x_prv)
        del words_input, ed_prv, x_prv
        return

    backend = _get_backend()
    click.echo("Connected to YubiKey.")

    if not _connect_and_prepare(backend):
        _wipe(words_input)
        _wipe(ed_prv)
        _wipe(x_prv)
        del words_input, ed_prv, x_prv
        return

    pin = _prompt_pin()

    try:
        result = backend.import_key(
            ed_prv, x_prv, pin,
            _touch_map()[touch_signing], _touch_map()[touch_encryption],
            _pin_policy_map()[pin_policy],
        )
    except Exception as e:
        click.echo(f"Key import failed: {e}", err=True)
        _wipe(words_input)
        _wipe(ed_prv)
        _wipe(x_prv)
        del words_input, ed_prv, x_prv
        raise SystemExit(1)

    if result["ed25519_public"] != ed_pub or result["x25519_public"] != x_pub:
        click.echo("ERROR: Imported keys don't match derived keys.", err=True)
        _wipe(words_input)
        _wipe(ed_prv)
        _wipe(x_prv)
        del words_input, ed_prv, x_prv
        raise SystemExit(1)

    # Wipe sensitive material
    _wipe(words_input)
    _wipe(ed_prv)
    _wipe(x_prv)
    del words_input, ed_prv, x_prv

    _save_hwid(ed_pub, x_pub, backend, nickname,
               touch_signing, touch_encryption, pin_policy, output, "recoverable")

    click.echo()
    click.echo("Identity restored successfully.")
    click.echo("Seed phrase and private keys have been wiped from memory.")
    click.echo("Close this terminal to clear scrollback history.")


def _do_migrate(identity_path, pin_policy, touch_signing, touch_encryption, nickname, output):
    """Migrate a software identity to hardware."""
    key_data = Path(identity_path).read_bytes()

    # Handle both raw 64-byte format and msgpack-wrapped format
    if len(key_data) == 64:
        prv_bytes = key_data
    else:
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

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ed_pub = Ed25519PrivateKey.from_private_bytes(ed25519_prv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_pub = X25519PrivateKey.from_private_bytes(x25519_prv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    identity_hash = hashlib.sha256(x_pub + ed_pub).digest()[:16]
    hash_hex = identity_hash.hex()
    lxmf_hex = _compute_lxmf_hash(identity_hash).hex()

    click.echo(f"\nIdentity to migrate:")
    click.echo(f"  LXMF address:   {lxmf_hex}")
    click.echo(f"  Identity hash:  {hash_hex}")
    click.echo(f"  Ed25519 public: {ed_pub.hex()}")
    click.echo(f"  X25519 public:  {x_pub.hex()}")
    click.echo()

    if not click.confirm("Is this the identity you want to move to hardware?"):
        click.echo("Cancelled.")
        return

    backend = _get_backend()
    click.echo("Connected to YubiKey.")

    if not _connect_and_prepare(backend):
        return

    pin = _prompt_pin()

    try:
        result = backend.import_key(
            ed25519_prv, x25519_prv, pin,
            _touch_map()[touch_signing], _touch_map()[touch_encryption],
            _pin_policy_map()[pin_policy],
        )
    except Exception as e:
        click.echo(f"Key import failed: {e}", err=True)
        raise SystemExit(1)

    if result["ed25519_public"] != ed_pub or result["x25519_public"] != x_pub:
        click.echo("ERROR: Imported keys don't match source identity.", err=True)
        raise SystemExit(1)

    _save_hwid(ed_pub, x_pub, backend, nickname,
               touch_signing, touch_encryption, pin_policy, output, "migrated")

    click.echo()
    if click.confirm("Delete the software identity file? (Keys now live on the YubiKey)"):
        Path(identity_path).unlink()
        click.echo(f"Deleted {identity_path}")
    else:
        click.echo(f"Software key file kept at {identity_path}")
        click.echo("Consider deleting it manually once you've confirmed the hardware identity works.")


def _do_list(directory):
    """List hardware identities."""
    dir_path = Path(directory)
    if not dir_path.exists():
        click.echo("No hardware identities have been provisioned yet.")
        return

    from ratkey.hwid import load_hwid

    found = 0
    for entry in sorted(dir_path.iterdir()):
        hwid_path = entry / "identity.hwid"
        if hwid_path.exists():
            try:
                config = load_hwid(hwid_path)
                nick = config.nickname or "(unnamed)"
                method = config.provisioning_method or "unknown"
                lxmf_hex = config.lxmf_hash or _compute_lxmf_hash(bytes.fromhex(config.identity_hash)).hex()
                click.echo(f"  LXMF: {lxmf_hex}  Identity: {config.identity_hash}  {config.device_type}  {method}  {nick}")
                found += 1
            except Exception as e:
                click.echo(f"  Error reading {hwid_path}: {e}", err=True)

    if found == 0:
        click.echo("No hardware identities found.")
    else:
        click.echo(f"\n{found} hardware identity(s) found.")


def _do_test(hwid_path):
    """Test signing and key agreement against hardware."""
    from ratkey.hwid import load_hwid

    config = load_hwid(hwid_path)
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

    pin = click.prompt("PIV PIN", hide_input=True)
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


# ── Interactive wizard ──────────────────────────────────────────────


def _wizard():
    """Main interactive menu."""
    click.echo()
    click.echo("Ratkey — Hardware-backed Reticulum identity management")
    click.echo()
    click.echo("  [1] Provision new identity")
    click.echo("  [2] Restore identity from seed phrase")
    click.echo("  [3] Migrate software identity to hardware")
    click.echo("  [4] Test a hardware identity")
    click.echo("  [5] List hardware identities")
    click.echo("  [6] Exit")
    click.echo()
    choice = click.prompt("Choose", type=click.Choice(["1", "2", "3", "4", "5", "6"]))

    if choice == "1":
        _wizard_provision()
    elif choice == "2":
        _wizard_restore()
    elif choice == "3":
        _wizard_migrate()
    elif choice == "4":
        _wizard_test()
    elif choice == "5":
        _do_list(_default_dir())
    else:
        return


def _wizard_provision():
    """Interactive provisioning walkthrough."""
    click.echo()
    click.echo("─── Provision New Identity ─────────────────────────")
    click.echo()
    click.echo("Choose a provisioning method:")
    click.echo()
    click.echo("  [1] Hardware-only")
    click.echo("      Keys generated on the YubiKey's secure element.")
    click.echo("      No backup possible. Lose the key, lose the identity.")
    click.echo()
    click.echo("  [2] Recoverable (seed phrase)")
    click.echo("      Keys derived from a 24-word seed phrase.")
    click.echo("      Write down the words — that's your backup.")
    click.echo()
    method_choice = click.prompt("Method", type=click.Choice(["1", "2"]))
    method = "hardware-only" if method_choice == "1" else "recoverable"

    if method == "recoverable":
        click.echo()
        click.echo("SECURITY NOTICE: Your keys will be derived from a seed phrase and")
        click.echo("imported to the YubiKey. The seed phrase IS your identity — anyone")
        click.echo("who sees those words can reconstruct your keys. The keys briefly")
        click.echo("exist in host memory during import.")
        click.echo()
        if not click.confirm("Continue with recoverable provisioning?"):
            click.echo("Cancelled.")
            return

    click.echo()
    pin = _prompt_pin()
    pin_policy = _prompt_pin_policy()
    touch_signing = _prompt_touch("signing (Ed25519, slot 9A)")
    touch_encryption = _prompt_touch("encryption (X25519, slot 9D)")
    click.echo()
    nickname = _prompt_nickname()
    output = _prompt_output()

    if not _show_summary(method, pin_policy, touch_signing, touch_encryption, nickname, output):
        click.echo("Cancelled.")
        return

    if method == "recoverable":
        _do_provision_recoverable(pin, pin_policy, touch_signing, touch_encryption, nickname, output)
    else:
        _do_provision_hardware_only(pin, pin_policy, touch_signing, touch_encryption, nickname, output)


def _wizard_restore():
    """Interactive restore walkthrough."""
    click.echo()
    click.echo("─── Restore Identity from Seed Phrase ──────────────")
    click.echo()

    pin_policy = _prompt_pin_policy()
    touch_signing = _prompt_touch("signing (Ed25519, slot 9A)")
    touch_encryption = _prompt_touch("encryption (X25519, slot 9D)")
    click.echo()
    nickname = _prompt_nickname()
    output = _prompt_output()

    click.echo()
    _do_restore(pin_policy, touch_signing, touch_encryption, nickname, output)


def _wizard_migrate():
    """Interactive migrate walkthrough."""
    click.echo()
    click.echo("─── Migrate Software Identity to Hardware ──────────")
    click.echo()

    identity_path = click.prompt("Path to Reticulum identity file",
                                 type=click.Path(exists=True))

    pin_policy = _prompt_pin_policy()
    touch_signing = _prompt_touch("signing (Ed25519, slot 9A)")
    touch_encryption = _prompt_touch("encryption (X25519, slot 9D)")
    click.echo()
    nickname = _prompt_nickname()
    output = _prompt_output()

    click.echo()
    _do_migrate(identity_path, pin_policy, touch_signing, touch_encryption, nickname, output)


def _wizard_test():
    """Interactive test walkthrough."""
    click.echo()
    click.echo("─── Test Hardware Identity ─────────────────────────")
    click.echo()

    # Auto-discover identities
    id_dir = Path(_default_dir())
    hwid_files = []
    if id_dir.exists():
        for entry in sorted(id_dir.iterdir()):
            hwid_path = entry / "identity.hwid"
            if hwid_path.exists():
                hwid_files.append(hwid_path)

    if not hwid_files:
        path = click.prompt("Path to .hwid file", type=click.Path(exists=True))
        _do_test(path)
        return

    click.echo("Found identities:")
    click.echo()
    from ratkey.hwid import load_hwid
    for i, path in enumerate(hwid_files, 1):
        try:
            config = load_hwid(path)
            nick = config.nickname or "(unnamed)"
            click.echo(f"  [{i}] {config.identity_hash[:16]}...  {nick}")
        except Exception:
            click.echo(f"  [{i}] {path}")

    click.echo()
    choice = click.prompt("Choose identity", type=click.IntRange(1, len(hwid_files)))
    _do_test(str(hwid_files[choice - 1]))


# ── CLI group + subcommands ─────────────────────────────────────────


@click.group(invoke_without_command=True)
@click.version_option(package_name="ratkey")
@click.pass_context
def cli(ctx):
    """Ratkey — Hardware-backed identity management for Reticulum.

    Run with no arguments for an interactive setup wizard.
    """
    if ctx.invoked_subcommand is None:
        _wizard()


# Subcommands below are kept for scripting / direct invocation.


@cli.command()
@click.option("--pin", default=None, help="6-8 character PIV PIN for the YubiKey")
@click.option("--method", type=click.Choice(["hardware-only", "recoverable"]),
              default=None, help="Provisioning method")
@click.option("--pin-policy", type=click.Choice(["once", "always", "never"]),
              default=None, help="PIN policy (once, always, never)")
@click.option("--touch-signing", type=click.Choice(["never", "cached", "always"]),
              default=None, help="Touch policy for signing")
@click.option("--touch-encryption", type=click.Choice(["never", "cached", "always"]),
              default=None, help="Touch policy for encryption")
@click.option("--nickname", "-n", default=None, help="Human-readable name")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Save directory [default: ~/.reticulum/identities]")
def provision(pin, method, pin_policy, touch_signing, touch_encryption, nickname, output):
    """Provision a new hardware-backed Reticulum identity.

    All options are prompted interactively if not provided.
    """
    # Prompt for anything not supplied via CLI
    if method is None:
        click.echo()
        click.echo("Choose a provisioning method:")
        click.echo()
        click.echo("  [1] Hardware-only — keys generated on YubiKey, no backup")
        click.echo("  [2] Recoverable  — keys from seed phrase, write down as backup")
        click.echo()
        c = click.prompt("Method", type=click.Choice(["1", "2"]))
        method = "hardware-only" if c == "1" else "recoverable"

    if method == "recoverable":
        click.echo()
        click.echo("SECURITY NOTICE: Keys derived from a seed phrase and imported.")
        click.echo("The seed phrase IS your identity. Keys briefly exist in host memory.")
        click.echo()
        if not click.confirm("Continue?"):
            click.echo("Cancelled.")
            return

    if pin is None:
        pin = _prompt_pin()
    elif len(pin) < 6 or len(pin) > 8:
        raise click.BadParameter("PIN must be 6-8 characters", param_hint="--pin")

    if pin_policy is None:
        pin_policy = _prompt_pin_policy()
    if touch_signing is None:
        touch_signing = _prompt_touch("signing (Ed25519, slot 9A)")
    if touch_encryption is None:
        touch_encryption = _prompt_touch("encryption (X25519, slot 9D)")
    if nickname is None:
        nickname = _prompt_nickname()
    if output is None:
        output = _prompt_output()

    if not _show_summary(method, pin_policy, touch_signing, touch_encryption, nickname, output):
        click.echo("Cancelled.")
        return

    if method == "recoverable":
        _do_provision_recoverable(pin, pin_policy, touch_signing, touch_encryption, nickname, output)
    else:
        _do_provision_hardware_only(pin, pin_policy, touch_signing, touch_encryption, nickname, output)


@cli.command()
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Save directory [default: ~/.reticulum/identities]")
@click.option("--pin-policy", type=click.Choice(["once", "always", "never"]),
              default=None, help="PIN policy (once, always, never)")
@click.option("--touch-signing", type=click.Choice(["never", "cached", "always"]),
              default=None, help="Touch policy for signing")
@click.option("--touch-encryption", type=click.Choice(["never", "cached", "always"]),
              default=None, help="Touch policy for encryption")
@click.option("--nickname", "-n", default=None, help="Nickname for the restored identity")
def restore(output, pin_policy, touch_signing, touch_encryption, nickname):
    """Restore an identity from a 24-word seed phrase."""
    if pin_policy is None:
        pin_policy = _prompt_pin_policy()
    if touch_signing is None:
        touch_signing = _prompt_touch("signing (Ed25519, slot 9A)")
    if touch_encryption is None:
        touch_encryption = _prompt_touch("encryption (X25519, slot 9D)")
    if nickname is None:
        nickname = _prompt_nickname()
    if output is None:
        output = _prompt_output()

    _do_restore(pin_policy, touch_signing, touch_encryption, nickname, output)


@cli.command()
@click.argument("identity", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Save directory [default: ~/.reticulum/identities]")
@click.option("--pin-policy", type=click.Choice(["once", "always", "never"]),
              default=None, help="PIN policy (once, always, never)")
@click.option("--touch-signing", type=click.Choice(["never", "cached", "always"]),
              default=None, help="Touch policy for signing")
@click.option("--touch-encryption", type=click.Choice(["never", "cached", "always"]),
              default=None, help="Touch policy for encryption")
@click.option("--nickname", "-n", default=None, help="Nickname for the migrated identity")
def migrate(identity, output, pin_policy, touch_signing, touch_encryption, nickname):
    """Move an existing software identity onto a YubiKey."""
    if pin_policy is None:
        pin_policy = _prompt_pin_policy()
    if touch_signing is None:
        touch_signing = _prompt_touch("signing (Ed25519, slot 9A)")
    if touch_encryption is None:
        touch_encryption = _prompt_touch("encryption (X25519, slot 9D)")
    if nickname is None:
        nickname = _prompt_nickname()
    if output is None:
        output = _prompt_output()

    _do_migrate(identity, pin_policy, touch_signing, touch_encryption, nickname, output)


@cli.command("list")
@click.option("--dir", "-d", type=click.Path(), default=None,
              help="Directory to scan [default: ~/.reticulum/identities]")
def list_identities(dir):
    """List hardware identities."""
    _do_list(dir or _default_dir())


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
    click.echo(f"  PIN policy:      {config.pin_policy}")
    click.echo(f"  Touch (sign):    {config.touch_signing}")
    click.echo(f"  Touch (encrypt): {config.touch_encryption}")
    click.echo(f"  PIN cache:       {config.pin_cache_timeout}s (editable in .hwid file)")
    click.echo()
    click.echo(f"Provisioning:      {config.provisioning_method or 'unknown'}")
    if config.attestation_verified:
        click.echo("Attestation:       verified")
    else:
        click.echo("Attestation:       (not verified)")


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


@cli.command()
@click.argument("hwid", type=click.Path(exists=True))
def test(hwid):
    """Test signing and decryption with a connected YubiKey."""
    _do_test(hwid)


if __name__ == "__main__":
    cli()
