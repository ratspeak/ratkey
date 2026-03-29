<div align="center">

# Ratkey

**Hardware-backed identity protection built for [Reticulum](https://reticulum.network) and [Ratspeak](https://ratspeak.org).**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-3776AB.svg)](https://python.org)
[![YubiKey 5](https://img.shields.io/badge/YubiKey_5-fw_5.7%2B-84BD00.svg)](https://www.yubico.com/products/yubikey-5-overview/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/ratspeak/ratkey/issues)

> **NOTE:** YubiKey integration was written against the official Yubico SDK but has not been validated against physical hardware. Looking for early testers with a YubiKey 5 (firmware 5.7.0+) -- [open an issue](https://github.com/ratspeak/ratkey/issues) if you can help.

</div>

---

Your Reticulum identity is a pair of cryptographic keys. Today those keys sit as plaintext files on disk. Any malware, bad backup, or stolen laptop can take them. This tool moves them onto a YubiKey 5 hardware token via PIV. Ed25519 signing and X25519 key agreement happen on-chip. Private keys never leave the Yubikey.


## Install

```
pip install "ratkey[yubikey] @ git+https://github.com/ratspeak/ratkey.git"
```

macOS and Windows work out of the box. Linux needs the smart card daemon:

```
sudo apt install pcscd libpcsclite-dev
```

Requires Python 3.9+, the `rns` package, and a YubiKey 5 with firmware 5.7.0 or later.

## Provisioning

Plug in your YubiKey and run:

```
rnid-hw
```

An interactive wizard walks you through everything: provisioning method, PIN, PIN policy, touch policies, and where to save the identity file. You can also jump straight to a specific action with `rnid-hw provision`, `rnid-hw restore`, etc.

You pick a PIN (6-8 characters, 3 wrong attempts locks it) and choose one of the following two provisioning methods:

1. `Hardware-only` generates keys directly on the YubiKey's secure element. No backup exists, nor are they possible. The private keys never exist outside the hardware, not even for a moment. Lose the YubiKey, lose the identity forever.

2. `Recoverable` derives keys from a 24-word BIP-39 seed phrase and imports them to the YubiKey. Same concept as a Trezor or Ledger recovery phrase -- you write the words on paper, and that paper is your backup. If you lose the YubiKey, run `rnid-hw restore` with your seed phrase onto a new one.

The trade-off: the seed phrase is a second attack surface. Anyone who sees those 24 words can reconstruct your private keys. The seed phrase is not protected by your YubiKey PIN. The keys also briefly exist in host memory during first creation.

We do not recommend one over the other - though `recoverable` is much less prone to human and hardware error.

## Policies -- READ BEFORE PROVISIONING

We highly recommend using `never` for your touch policy, and `once` for your PIN policy for the best experience.

**Unless you provision it as recoverable**, touch and PIN policies are burned into the YubiKey's hardware at provisioning. They cannot be changed afterward, and yes, I mean it. If you pick wrong, your only option is to generate a new identity with a new address and start over. Recoverable identities can choose a new policy on import.

### Touch

Controls whether you physically tap the YubiKey for each operation.

| Policy | Behavior |
|--------|----------|
| `never` | No touch required. Operations happen automatically when plugged in. Good for messaging, servers, and unattended nodes. |
| `cached` | Touch once, then no touch for 15 seconds (not configurable). More secure, more hassle. |
| `always` | Touch for every single operation. Maximum security, but expect frequent tapping. **NOT RECOMMENDED** |

Touch is set separately for signing (slot 9A) and encryption (slot 9D). Both default to `never`.

When touch is enabled, the YubiKey's LED blinks to signal it's waiting. You tap, the operation proceeds.

### PIN

| Policy | Behavior |
|--------|----------|
| `once` | Enter PIN once when the app starts. Cached until you unplug. **Recommended.** |
| `always` | Enter PIN for every operation. **NOT RECOMMENDED.** |
| `never` | No PIN ever. Anyone with physical access can use your identity. |

## When the YubiKey is needed

Sending messages, receiving messages, announcing your identity, and establishing links all require the YubiKey to be plugged in. These operations need your private key.

If the YubiKey is unplugged mid-session, operations that need it will block until you plug it back in. No data is lost.

## PIV slot usage

The tool writes to PIV slots 9A (Authentication, used for Ed25519 signing) and 9D (Key Management, used for X25519 encryption). If you already have keys in those slots — SSH login, S/MIME, or anything else — provisioning will detect them and ask if you want to reset the PIV application. Resetting clears all existing PIV keys and resets the PIN/PUK to factory defaults before proceeding.

## Security model

Protects against disk exfiltration (no private key on disk), remote compromise (crypto operations require physical USB presence), and identity cloning (keys cannot be copied off the hardware).

Does not protect against physical YubiKey theft (PIN and lockout help, but aren't bulletproof), or a compromised device requesting signatures while the key is plugged in (touch policy mitigates this).

## CLI

```
rnid-hw                        Interactive wizard (start here)
rnid-hw provision              Provision a new hardware identity
rnid-hw restore                Restore an identity from a 24-word seed phrase
rnid-hw migrate <identity>     Move an existing software identity onto a YubiKey
rnid-hw list                   List hardware identities
rnid-hw info <hwid-file>       Show detailed identity information
rnid-hw verify <hwid-file>     Check that a connected YubiKey matches a .hwid file
rnid-hw test <hwid-file>       Run signing and decryption tests against hardware
```

All commands prompt interactively for any options not provided via flags. Identities are saved to `~/.reticulum/identities/` by default.

## For developers

Adding support to a Reticulum application is a small change. Find where your app loads its identity, have it search for `RNS.Identity.from_file` and check for a `.hwid` file before it, something like:

```python
def load_identity(identity_dir):
    hwid_path = Path(identity_dir) / "identity.hwid"
    key_path = Path(identity_dir) / "identity"

    if hwid_path.exists():
        try:
            from ratkey import HardwareIdentity
            return HardwareIdentity.from_hwid(hwid_path)
        except ImportError:
            print("Hardware identity found but ratkey is not installed.")
            print("Install with: pip install ratkey[yubikey]")
            return None
    elif key_path.exists():
        return RNS.Identity.from_file(str(key_path))
    else:
        return RNS.Identity()
```

That's the whole change. `HardwareIdentity` is a subclass of `RNS.Identity`. Destinations, links, LXMF, signing, encryption -- everything works the same. The `try/except ImportError` means your app still works for users who don't have the library installed.

If the YubiKey isn't plugged in during a private key operation, a `HardwareDisconnectedError` is raised. Catch it to show a "plug in your key" prompt if you want.

## Troubleshooting

**YubiKey not detected.** On Linux, make sure `pcscd` is running: `sudo systemctl start pcscd`. On all platforms, try unplugging and re-inserting the key.

**PIN locked after 3 wrong attempts.** The YubiKey PIV PIN locks after 3 failures. You can reset it with the PUK (PIN Unblocking Key) if you set one during setup. After 10 wrong PUK attempts, the PIV application locks permanently and all keys are destroyed. A factory reset is your only option.

**Touch timeout.** If the YubiKey blinks and you don't tap within ~30 seconds, the operation times out. Just try again.

**Slot conflict during provisioning.** If slots 9A or 9D already contain keys, provisioning refuses to overwrite. Use `--force` if you want to replace them, or use a dedicated YubiKey.

## License

MIT -- [Ratspeak Project](https://ratspeak.org)
