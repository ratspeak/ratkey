"""Exception hierarchy for Ratkey hardware identity operations."""


class RatkeyError(Exception):
    """Base exception for all Ratkey errors."""


class HardwareNotFoundError(RatkeyError):
    """No compatible hardware device is connected."""


class HardwareDisconnectedError(RatkeyError):
    """Hardware device was disconnected during an operation."""


class PINRequiredError(RatkeyError):
    """A PIN is required but no callback is registered or PIN was not provided."""


class PINIncorrectError(RatkeyError):
    """The supplied PIN was rejected by the device.

    Attributes:
        remaining: Number of PIN attempts remaining before lockout.
    """

    def __init__(self, message: str = "PIN incorrect", remaining: int | None = None):
        super().__init__(message)
        self.remaining = remaining


class PINLockedError(RatkeyError):
    """The PIN has been locked after too many failed attempts.
    The PUK is required to unlock, or the device must be factory reset."""


class TouchRequiredError(RatkeyError):
    """Physical touch on the hardware token is required to authorize this operation."""


class ProvisioningError(RatkeyError):
    """Key generation or provisioning on the hardware device failed."""


class SlotOccupiedError(RatkeyError):
    """The target PIV slot already contains a key. Use --force to overwrite."""


class FirmwareVersionError(RatkeyError):
    """Device firmware does not meet minimum version requirements."""


class BackupError(RatkeyError):
    """Backup creation or restoration failed."""


class SeedPhraseError(RatkeyError):
    """Invalid or malformed BIP-39 seed phrase.

    Raised when a mnemonic has the wrong word count, contains unknown words,
    or fails the BIP-39 checksum validation.
    """


class KeyImportError(RatkeyError):
    """Failed to import key material onto the hardware device."""


class PrivateKeyAccessError(RatkeyError):
    """Attempted to access raw private key material from a hardware-backed identity.

    Hardware identities hold private keys exclusively on the hardware token.
    They cannot be exported, serialized, or accessed in raw form.
    """
