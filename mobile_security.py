"""Dependency-free security policy shared by production mobile routes and tests."""

from __future__ import annotations

import hashlib
import hmac
import re
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
    "open_app": False,
}

ANDROID_ALLOWED_ACTIONS = {
    "open_lj_ai": False,
    "open_app": False,
    "media_play_pause": False,
    "volume_mute": False,
}

NOTIFICATION_PAYLOAD_FIELDS = frozenset({"title", "message"})
NOTIFICATION_TITLE_MAX_LENGTH = 100
NOTIFICATION_MESSAGE_MAX_LENGTH = 500
APP_NAME_MAX_LENGTH = 80
SAFE_APP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+&'()-]{0,79}$")
BLOCKED_APP_SUFFIXES = (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".lnk")
BLOCKED_COMMAND_HOSTS = {
    "cmd", "command prompt", "powershell", "pwsh", "windows powershell",
    "wscript", "cscript", "mshta", "rundll32", "regsvr32", "windows terminal",
}


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

    Every action except ``show_notification`` and ``open_app`` is deliberately
    parameterless. ``open_app`` accepts only a friendly installed-app name; paths,
    URLs, switches and shell punctuation are rejected.
    """

    if action not in ALLOWED_ACTIONS:
        raise ValueError("Unsupported remote command action.")
    if action == "open_app":
        if set(payload) != {"app_name"}:
            raise ValueError("Open app accepts exactly one app_name value.")
        app_name = payload.get("app_name")
        if not isinstance(app_name, str):
            raise ValueError("App name must be text.")
        app_name = " ".join(app_name.split())[:APP_NAME_MAX_LENGTH]
        folded = app_name.casefold()
        if (
            not app_name
            or not SAFE_APP_NAME.fullmatch(app_name)
            or folded.endswith(BLOCKED_APP_SUFFIXES)
            or folded in BLOCKED_COMMAND_HOSTS
            or any(part.startswith("-") for part in app_name.split())
        ):
            raise ValueError("Use only the installed app's normal display name, without a path, URL or command.")
        return {"app_name": app_name}

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
