"""BIP-39 seed phrase generation and deterministic key derivation.

Generates a 24-word mnemonic (256-bit entropy) and derives Ed25519 + X25519
keypairs from it using HKDF-SHA256. The derivation is deterministic — the
same seed phrase always produces the same Reticulum identity.

Derivation scheme (v1):
    BIP-39 mnemonic (24 words)
        → PBKDF2-SHA512 (BIP-39 standard, passphrase="") → 64-byte seed
        → HKDF-SHA256(seed, salt="ratkey-ed25519-v1") → 32-byte Ed25519 private key
        → HKDF-SHA256(seed, salt="ratkey-x25519-v1")  → 32-byte X25519 private key
"""

from __future__ import annotations

import ctypes
import hashlib

from ratkey.errors import SeedPhraseError

# HKDF salts — versioned to allow future scheme changes without breaking old backups
_ED25519_SALT = b"ratkey-ed25519-v1"
_X25519_SALT = b"ratkey-x25519-v1"
_HKDF_INFO = b"ratkey identity key derivation"


def generate_mnemonic() -> str:
    """Generate a new 24-word BIP-39 mnemonic (256-bit entropy).

    Requires: ``pip install ratkey[backup]``

    Returns:
        Space-separated string of 24 English words.
    """
    try:
        from mnemonic import Mnemonic
    except ImportError:
        raise ImportError(
            "Seed phrase support requires the mnemonic library. "
            "Install with: pip install ratkey[backup]"
        )
    m = Mnemonic("english")
    return m.generate(strength=256)


def validate_mnemonic(words: str) -> bool:
    """Check if a mnemonic string is valid BIP-39.

    Validates word count (24), that all words are in the BIP-39 English
    wordlist, and that the checksum is correct.

    Returns:
        True if valid, False otherwise.
    """
    try:
        from mnemonic import Mnemonic
    except ImportError:
        raise ImportError(
            "Seed phrase validation requires the mnemonic library. "
            "Install with: pip install ratkey[backup]"
        )
    m = Mnemonic("english")
    word_list = words.strip().split()
    if len(word_list) != 24:
        return False
    return m.check(words.strip())


def derive_keys(mnemonic_words: str) -> tuple[bytes, bytes, bytes, bytes]:
    """Derive Ed25519 and X25519 keypairs from a BIP-39 mnemonic.

    The derivation is deterministic — the same mnemonic always produces
    the same keys, and therefore the same Reticulum identity.

    Args:
        mnemonic_words: Space-separated 24-word BIP-39 mnemonic.

    Returns:
        Tuple of (ed25519_private, ed25519_public, x25519_private, x25519_public),
        each as raw bytes (32 bytes per key).

    Raises:
        SeedPhraseError: If the mnemonic is invalid.
    """
    if not validate_mnemonic(mnemonic_words):
        raise SeedPhraseError(
            "Invalid seed phrase. Must be 24 valid BIP-39 English words "
            "with a correct checksum."
        )

    try:
        from mnemonic import Mnemonic
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        raise ImportError(
            "Key derivation requires cryptography and mnemonic libraries. "
            "Install with: pip install ratkey[backup]"
        )

    # Step 1: Mnemonic → 64-byte seed (BIP-39 standard PBKDF2-SHA512)
    seed_bytes = Mnemonic.to_seed(mnemonic_words.strip(), passphrase="")

    # Step 2: Derive Ed25519 private key via HKDF-SHA256
    ed25519_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_ED25519_SALT,
        info=_HKDF_INFO,
    ).derive(seed_bytes)

    # Step 3: Derive X25519 private key via HKDF-SHA256
    x25519_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_X25519_SALT,
        info=_HKDF_INFO,
    ).derive(seed_bytes)

    # Step 4: Construct key objects to get public keys
    ed_prv = Ed25519PrivateKey.from_private_bytes(ed25519_secret)
    x_prv = X25519PrivateKey.from_private_bytes(x25519_secret)

    ed_pub = ed_prv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_pub = x_prv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Best-effort memory cleanup of intermediate secrets
    _zero_bytes(seed_bytes)

    return (ed25519_secret, ed_pub, x25519_secret, x_pub)


def compute_identity_hash(ed25519_pub: bytes, x25519_pub: bytes) -> bytes:
    """Compute the Reticulum identity hash from public keys.

    Hash = SHA-256(X25519_pub || Ed25519_pub)[:16]

    This matches the standard Reticulum identity hash computation.
    """
    pub_bytes = x25519_pub + ed25519_pub
    return hashlib.sha256(pub_bytes).digest()[:16]


def _zero_bytes(data: bytes) -> None:
    """Best-effort zeroing of a bytes object in memory.

    Python bytes are immutable, so this is not guaranteed to work —
    the interpreter may have copies elsewhere. This is a defense-in-depth
    measure, not a security guarantee.
    """
    try:
        if isinstance(data, (bytearray, memoryview)):
            ctypes.memset(
                ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data)),
                0,
                len(data),
            )
    except (TypeError, ValueError):
        pass
