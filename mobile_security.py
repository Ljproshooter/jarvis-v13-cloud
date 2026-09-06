"""Dependency-free security policy shared by production mobile routes and tests."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any


PAIRING_ALPHABET = "0123456789"
ALLOWED_ACTIONS = {
    "show_notification": False,
    "media_play_pause": False,
    "media_next": False,
    "volume_mute": False,
    "lock_pc": True,
    "open_lj_ai": False,
    "run_diagnostic": True,
}

NOTIFICATION_PAYLOAD_FIELDS = frozenset({"title", "message"})
NOTIFICATION_TITLE_MAX_LENGTH = 100
NOTIFICATION_MESSAGE_MAX_LENGTH = 500


class PairingConfigurationError(RuntimeError):
    """Raised when the server cannot securely hash a pairing code."""


def normalize_pairing_code(value: str) -> str:
    return "".join(str(value).upper().split())


def is_valid_pairing_code(value: str) -> bool:
    clean = normalize_pairing_code(value)
    return len(clean) == 6 and all(char in PAIRING_ALPHABET for char in clean)


def pairing_digest(user_id: str, code: str, secret: str) -> str:
    if len(secret) < 32:
        raise PairingConfigurationError("LJ_PAIRING_HMAC_SECRET must contain at least 32 characters.")
    message = f"{user_id}:{normalize_pairing_code(code)}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sanitize_remote_command_payload(action: str, payload: dict[str, Any]) -> dict[str, str]:
    """Return the small, action-specific payload that a Windows client may consume.

    Every action except ``show_notification`` is deliberately parameterless. This
    prevents a future or modified client from smuggling executable text, paths or
    other arbitrary data through the remote-command queue.
    """

    if action not in ALLOWED_ACTIONS:
        raise ValueError("Unsupported remote command action.")
    if action != "show_notification":
        if payload:
            raise ValueError("This remote command does not accept details.")
        return {}

    unknown_fields = set(payload).difference(NOTIFICATION_PAYLOAD_FIELDS)
    if unknown_fields:
        raise ValueError("A notification accepts only title and message details.")

    clean: dict[str, str] = {}
    for field, maximum in (
        ("title", NOTIFICATION_TITLE_MAX_LENGTH),
        ("message", NOTIFICATION_MESSAGE_MAX_LENGTH),
    ):
        if field not in payload:
            continue
        value = payload[field]
        if not isinstance(value, str):
            raise ValueError(f"Notification {field} must be text.")
        clean[field] = value.strip()[:maximum]
    return clean
