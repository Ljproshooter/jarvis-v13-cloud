"""Dependency-free security policy shared by staged mobile backend tests."""

from __future__ import annotations

import hashlib
import hmac


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


def normalize_pairing_code(value: str) -> str:
    return "".join(str(value).upper().split())


def is_valid_pairing_code(value: str) -> bool:
    clean = normalize_pairing_code(value)
    return len(clean) == 6 and all(char in PAIRING_ALPHABET for char in clean)


def pairing_digest(user_id: str, code: str, secret: str) -> str:
    if len(secret) < 32:
        raise RuntimeError("LJ_PAIRING_HMAC_SECRET must contain at least 32 characters.")
    message = f"{user_id}:{normalize_pairing_code(code)}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
