"""PIN callback protocols for different application contexts.

Applications register their own PIN callback to handle PIN entry in a way
appropriate to their UI: CLI apps use getpass, GUI apps show a dialog,
headless daemons read from environment variables.
"""

from __future__ import annotations

import getpass
import os
from typing import Optional

from ratkey.errors import PINRequiredError


def cli_pin_callback(prompt: str, retries_remaining: Optional[int] = None) -> str:
    """Default PIN callback for CLI applications.

    Uses ``getpass`` to securely read the PIN from the terminal without
    echoing characters.
    """
    if retries_remaining is not None:
        prompt = f"{prompt} ({retries_remaining} attempts remaining)"
    return getpass.getpass(prompt + ": ")


def env_pin_callback(prompt: str, retries_remaining: Optional[int] = None) -> str:
    """PIN callback that reads from the ``RATKEY_PIN`` environment variable.

    Useful for headless daemons and CI environments.
    """
    pin = os.environ.get("RATKEY_PIN")
    if pin is None:
        raise PINRequiredError(
            "RATKEY_PIN environment variable not set. "
            "Set it to your PIV PIN or use a different PIN callback."
        )
    return pin
