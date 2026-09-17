"""Cross-device preferences, conversations and leased voice handover.

All database access uses the server's service credential, so every read and
write in this module must explicitly scope itself to the authenticated user.
Client supplied identifiers are treated as idempotency keys, never as proof of
ownership.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SAFE_PREFERENCE_KEYS = {
    "theme",
    "voice_speed",
    "voice_output",
    "allow_interruptions",
    "auto_voice_handover",
    "sync_preferences",
    "sign_in_briefing",
    "screen_monitoring",
    "mouse_control",
    "messaging_access",
    "file_access",
    "weather_location",
    "personality",
    "ai_mode",
    "memory_enabled",
    "automatic_memory_enabled",
    # V15.9.7 Android stores these separately: one controls whether history
    # synchronises and the other controls whether prior turns are referenced
    # when answering. Keep the V15.9.6 key for older clients.
    "sync_chat_history",
    "reference_chat_history",
    "chat_history_enabled",
}
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,100}$")
SENSITIVE_MEMORY_PATTERN = re.compile(
    r"\b(?:password|passcode|api[ _-]?key|access[ _-]?token|auth(?:entication)?[ _-]?token|"
    r"private[ _-]?key|recovery[ _-]?code|verification[ _-]?code|security[ _-]?code|"
    r"one[ -]?time[ -]?(?:password|code)|otp|[2m]fa[ _-]?(?:code|token)|cvv|"
    r"card[ _-]?number|bank[ _-]?account|routing[ _-]?number|social[ _-]?security|ssn|"
    r"tax[ _-]?id|medical[ _-]?(?:record|diagnosis)|medical|diagnos(?:is|ed)|medication|medicine|prescri(?:be|bed|ption)|"
    r"dosage|health[ _-]?condition|disease|disorder|biometric|home[ _-]?address|sexual[ _-]?(?:orientation|health)|"
    r"gay|lesbian|bisexual|transgender|non[ -]?binary|sex[ _-]?life|std|sti|"
    r"pregnan(?:cy|t)|abortion|fertility|reproductive[ _-]?health|lawsuit|court[ _-]?case|criminal[ _-]?record|"
    r"charged[ _-]?with|arrest(?:ed)?|felony|conviction|parole|probation|iban|swift[ _-]?code|account[ _-]?number|"
    r"credit[ _-]?card|debit[ _-]?card|seed[ _-]?phrase)\b",
    re.IGNORECASE,
)
SECRET_SHAPE_PATTERN = re.compile(
    r"(?:\b(?:sk-|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_-]{16,}\b|"
    r"\bAKIA[A-Z0-9]{16}\b|\bAIza[A-Za-z0-9_-]{20,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]{16,}\b)",
    re.IGNORECASE,
)
CARD_NUMBER_CANDIDATE_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
PRECISE_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,6}\s+[A-Za-z][A-Za-z .'-]{1,80}\s(?:street|st|road|rd|avenue|ave|lane|ln|"
    r"drive|dr|boulevard|blvd|court|ct|place|pl|terrace|highway|hwy)\b",
    re.IGNORECASE,
)
VOICE_LEASE_SECONDS = 90
VOICE_RECONNECT_GRACE_SECONDS = 5 * 60
MAX_TRANSCRIPT_BYTES = 32 * 1024
MAX_MEMORIES = 200


def _identity_value(identity: Any, key: str) -> str:
    value = identity.get(key) if isinstance(identity, dict) else getattr(identity, key)
    return str(value)


def _user_id(identity: Any) -> str:
    return _identity_value(identity, "user_id")


def _device_id(identity: Any) -> str:
    return _identity_value(identity, "device_id")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _validate_identifier(value: str, label: str) -> str:
    clean = value.strip()
    if not IDENTIFIER_PATTERN.fullmatch(clean):
        raise HTTPException(status_code=422, detail=f"The supplied {label} is invalid.")
    return clean


def _encode_cursor(row: dict[str, Any], timestamp_key: str) -> str:
    raw = json.dumps(
        {"timestamp": str(row.get(timestamp_key) or ""), "id": str(row.get("id") or "")},
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    try:
        padded = value.strip() + "=" * (-len(value.strip()) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        timestamp = str(payload.get("timestamp") or "")
        item_id = str(payload.get("id") or "")
        if _parse_timestamp(timestamp) is None or not IDENTIFIER_PATTERN.fullmatch(item_id):
            raise ValueError
        return timestamp, item_id
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=422, detail="The page cursor is invalid.") from None


def _normalise_memory_fact(value: str) -> str:
    return " ".join(value.casefold().split()).strip(" .,!?:;")[:500]


def _passes_luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if len(digits) not in range(13, 20) or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def memory_fact_is_safe(value: str) -> bool:
    fact = " ".join(str(value).split()).strip()
    return (
        bool(fact)
        and not SENSITIVE_MEMORY_PATTERN.search(fact)
        and not SECRET_SHAPE_PATTERN.search(fact)
        and not PRECISE_ADDRESS_PATTERN.search(fact)
        and not any(_passes_luhn(match.group(0)) for match in CARD_NUMBER_CANDIDATE_PATTERN.finditer(fact))
    )


def validate_memory_fact(value: str) -> str:
    fact = " ".join(str(value).split()).strip()[:500]
    if not fact:
        raise ValueError("Memory cannot be empty.")
    if not memory_fact_is_safe(fact):
        raise ValueError(
            "For safety, passwords, payment details, security codes and other sensitive records cannot be saved to memory."
        )
    return fact


def _clean_transcript_tail(value: Any) -> list[dict[str, str]]:
    """Keep only compact user/assistant text needed for seamless handover."""
    if not isinstance(value, list):
        return []
    clean: list[dict[str, str]] = []
    total_bytes = 0
    for item in value[-20:]:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip().lower()
        content = str(item.get("content") or "").strip()[:2000]
        if role not in {"user", "assistant"} or not content:
            continue
        item_bytes = len(content.encode("utf-8"))
        if total_bytes + item_bytes > MAX_TRANSCRIPT_BYTES:
            break
        clean.append({"role": role, "content": content})
        total_bytes += item_bytes
    return clean


def _lease_expiry() -> str:
    return (_now() + timedelta(seconds=VOICE_LEASE_SECONDS)).isoformat()


def _reconnect_deadline(row: dict[str, Any]) -> datetime:
    expiry = _parse_timestamp(row.get("lease_expires_at"))
    if expiry is None:
        updated = _parse_timestamp(row.get("updated_at")) or _now()
        expiry = updated + timedelta(seconds=VOICE_LEASE_SECONDS)
    return expiry + timedelta(seconds=VOICE_RECONNECT_GRACE_SECONDS)


def _is_reconnectable(row: dict[str, Any]) -> bool:
    return _now() <= _reconnect_deadline(row)


class PreferenceUpdate(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict, max_length=50)
    base_revision: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def limit_serialised_values(self) -> "PreferenceUpdate":
        if len(str(self.values).encode("utf-8")) > 16 * 1024:
            raise ValueError("The preference update is too large.")
        return self


class ConversationRequest(BaseModel):
    conversation_id: str | None = Field(default=None, min_length=8, max_length=100)
    title: str = Field(default="New conversation", max_length=120)

    @field_validator("conversation_id")
    @classmethod
    def validate_conversation_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not IDENTIFIER_PATTERN.fullmatch(clean):
            raise ValueError("The conversation identity is invalid.")
        return clean


class ConversationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, max_length=120)
    pinned: bool | None = None
    archived: bool | None = None

    @model_validator(mode="after")
    def require_change(self) -> "ConversationUpdate":
        if self.title is None and self.pinned is None and self.archived is None:
            raise ValueError("At least one conversation change is required.")
        return self


class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=20_000)
    message_id: str | None = Field(default=None, min_length=8, max_length=100)
    images: list[str] = Field(default_factory=list, max_length=6)

    @field_validator("message_id")
    @classmethod
    def validate_message_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not IDENTIFIER_PATTERN.fullmatch(clean):
            raise ValueError("The message identity is invalid.")
        return clean

    @field_validator("images")
    @classmethod
    def clean_images(cls, value: list[str]) -> list[str]:
        if value:
            raise ValueError(
                "Chat photos are request-only in V15.9.7 and cannot be saved as arbitrary image references."
            )
        return []


class MemoryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fact: str = Field(min_length=1, max_length=500)
    category: Literal["PREFERENCE", "PROFILE", "PROJECT", "OTHER"] = "OTHER"
    enabled: bool = True

    @field_validator("fact")
    @classmethod
    def clean_fact(cls, value: str) -> str:
        return validate_memory_fact(value)


class MemoryUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fact: str | None = Field(default=None, min_length=1, max_length=500)
    category: Literal["PREFERENCE", "PROFILE", "PROJECT", "OTHER"] | None = None
    enabled: bool | None = None

    @field_validator("fact")
    @classmethod
    def clean_fact(cls, value: str | None) -> str | None:
        return validate_memory_fact(value) if value is not None else None

    @model_validator(mode="after")
    def require_change(self) -> "MemoryUpdate":
        if self.fact is None and self.category is None and self.enabled is None:
            raise ValueError("At least one memory change is required.")
        return self


class MemorySettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class VoiceStartRequest(BaseModel):
    platform: Literal["WINDOWS", "ANDROID"]
    conversation_id: str | None = Field(default=None, min_length=8, max_length=100)
    transcript_tail: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    auto_handover: bool = False

    @field_validator("conversation_id")
    @classmethod
    def validate_conversation_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not IDENTIFIER_PATTERN.fullmatch(clean):
            raise ValueError("The conversation identity is invalid.")
        return clean

    @field_validator("transcript_tail")
    @classmethod
    def clean_transcript(cls, value: list[dict[str, Any]]) -> list[dict[str, str]]:
        return _clean_transcript_tail(value)


class VoiceClaimRequest(BaseModel):
    platform: Literal["WINDOWS", "ANDROID"]


class VoiceOfferRequest(BaseModel):
    target_platform: Literal["WINDOWS", "ANDROID"]


class VoiceHeartbeatRequest(BaseModel):
    transcript_tail: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    state: Literal["LISTENING", "SPEAKING", "IDLE"] = "IDLE"

    @field_validator("transcript_tail")
    @classmethod
    def clean_transcript(cls, value: list[dict[str, Any]]) -> list[dict[str, str]]:
        return _clean_transcript_tail(value)


def create_sync_router(
    *,
    current_identity: Callable[..., Any],
    rest_request: Callable[..., Any],
    insert_audit: Callable[..., Any],
    consume_voice_usage: Callable[..., Any],
    learn_memory: Callable[..., Any] | None = None,
) -> APIRouter:
    router = APIRouter(tags=["sync"])

    @router.get("/v1/sync/preferences")
    async def get_preferences(identity: Any = Depends(current_identity)) -> dict[str, Any]:
        rows = await rest_request(
            "GET",
            "lj_user_preferences",
            params={
                "user_id": f"eq.{_user_id(identity)}",
                "select": "values,revision,updated_at",
                "limit": "1",
            },
        ) or []
        return rows[0] if rows else {"values": {}, "revision": 0}

    @router.put("/v1/sync/preferences")
    async def put_preferences(
        body: PreferenceUpdate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        rows = await rest_request(
            "GET",
            "lj_user_preferences",
            params={"user_id": f"eq.{user_id}", "select": "values,revision", "limit": "1"},
        ) or []
        old = rows[0] if rows else {"values": {}, "revision": 0}
        revision = int(old.get("revision") or 0)
        if rows and body.base_revision != revision:
            raise HTTPException(
                status_code=409,
                detail={"message": "Preferences changed on another device.", **old},
            )
        clean: dict[str, str | bool | int | float] = {}
        for key, value in body.values.items():
            if key not in SAFE_PREFERENCE_KEYS or not isinstance(value, (str, bool, int, float)):
                continue
            clean[key] = value[:200] if isinstance(value, str) else value
        row = {
            "user_id": user_id,
            "values": {**(old.get("values") or {}), **clean},
            "revision": revision + 1,
            "updated_at": _now().isoformat(),
        }
        await rest_request(
            "POST",
            "lj_user_preferences",
            payload=row,
            prefer="resolution=merge-duplicates,return=minimal",
        )
        return row

    @router.get("/v1/sync/conversations")
    async def list_conversations(
        limit: int = 30,
        identity: Any = Depends(current_identity),
    ) -> list[dict[str, Any]]:
        return await rest_request(
            "GET",
            "lj_conversations",
            params={
                "user_id": f"eq.{_user_id(identity)}",
                "select": "*",
                "order": "updated_at.desc",
                "limit": str(max(1, min(100, limit))),
            },
        ) or []

    @router.post("/v1/sync/conversations")
    async def create_conversation(
        body: ConversationRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        conversation_id = body.conversation_id or secrets.token_urlsafe(24)
        title = body.title.strip() or "New conversation"
        existing = await rest_request(
            "GET",
            "lj_conversations",
            params={"id": f"eq.{conversation_id}", "select": "id,user_id,created_at", "limit": "1"},
        ) or []
        timestamp = _now().isoformat()
        if existing:
            if str(existing[0].get("user_id")) != user_id:
                raise HTTPException(status_code=409, detail="That conversation identity is unavailable.")
            await rest_request(
                "PATCH",
                "lj_conversations",
                params={"id": f"eq.{conversation_id}", "user_id": f"eq.{user_id}"},
                payload={"title": title, "updated_at": timestamp},
                prefer="return=minimal",
            )
            return {
                "id": conversation_id,
                "user_id": user_id,
                "title": title,
                "created_at": existing[0].get("created_at") or timestamp,
                "updated_at": timestamp,
            }
        saved = await rest_request(
            "GET",
            "lj_conversations",
            params={"user_id": f"eq.{user_id}", "select": "id", "limit": "500"},
        ) or []
        if len(saved) >= 500:
            raise HTTPException(
                status_code=409,
                detail="You can keep up to 500 saved conversations. Delete one before creating another.",
            )
        active = await rest_request(
            "GET",
            "lj_conversations",
            params={
                "user_id": f"eq.{user_id}",
                "archived_at": "is.null",
                "select": "id",
                "limit": "100",
            },
        ) or []
        if len(active) >= 100:
            raise HTTPException(
                status_code=409,
                detail="You can keep up to 100 active conversations. Archive or delete one before creating another.",
            )
        row = {
            "id": conversation_id,
            "user_id": user_id,
            "title": title,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        await rest_request("POST", "lj_conversations", payload=row, prefer="return=minimal")
        return row

    async def require_owned_conversation(conversation_id: str, identity: Any) -> str:
        clean_id = _validate_identifier(conversation_id, "conversation identity")
        rows = await rest_request(
            "GET",
            "lj_conversations",
            params={
                "id": f"eq.{clean_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "select": "id",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="Conversation not found.")
        return clean_id

    @router.get("/v1/sync/conversations/{conversation_id}/messages")
    async def list_messages(
        conversation_id: str,
        limit: int = 100,
        identity: Any = Depends(current_identity),
    ) -> list[dict[str, Any]]:
        conversation_id = await require_owned_conversation(conversation_id, identity)
        rows = await rest_request(
            "GET",
            "lj_conversation_messages",
            params={
                "conversation_id": f"eq.{conversation_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "select": "*",
                "order": "created_at.desc,id.desc",
                "limit": str(max(1, min(200, limit))),
            },
        ) or []
        # Legacy clients expect a plain chronological list. Querying newest
        # first prevents a long chat from silently returning its oldest page.
        return list(reversed(rows))

    # Deprecated V15.9.6 compatibility path. It temporarily accepts assistant
    # rows, but those rows lack unspoofable server markers and are excluded
    # from every canonical model context. New clients must use /v1/chat.
    @router.post("/v1/sync/conversations/{conversation_id}/messages")
    async def add_message(
        conversation_id: str,
        body: MessageRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        conversation_id = await require_owned_conversation(conversation_id, identity)
        message_id = body.message_id or secrets.token_urlsafe(20)
        existing = await rest_request(
            "GET",
            "lj_conversation_messages",
            params={"id": f"eq.{message_id}", "select": "*", "limit": "1"},
        ) or []
        if existing:
            item = existing[0]
            if str(item.get("user_id")) != user_id or str(item.get("conversation_id")) != conversation_id:
                raise HTTPException(status_code=409, detail="That message identity is unavailable.")
            return item
        message_rows = await rest_request(
            "GET",
            "lj_conversation_messages",
            params={
                "conversation_id": f"eq.{conversation_id}",
                "user_id": f"eq.{user_id}",
                "select": "id",
                "limit": "2000",
            },
        ) or []
        if len(message_rows) >= 2000:
            raise HTTPException(
                status_code=409,
                detail="This conversation reached its 2,000-message sync limit. Start a new conversation.",
            )
        row = {
            "id": message_id,
            "conversation_id": conversation_id,
            "user_id": user_id,
            "role": body.role,
            "content": body.content,
            "images": body.images,
            "source_device_id": _device_id(identity),
            "created_at": _now().isoformat(),
        }
        await rest_request("POST", "lj_conversation_messages", payload=row, prefer="return=minimal")
        await rest_request(
            "PATCH",
            "lj_conversations",
            params={"id": f"eq.{conversation_id}", "user_id": f"eq.{user_id}"},
            payload={"updated_at": _now().isoformat()},
            prefer="return=minimal",
        )
        return row

    def public_conversation(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "title": row.get("title") or "New conversation",
            "pinned": bool(row.get("pinned")),
            "archived": bool(row.get("archived_at")),
            "archived_at": row.get("archived_at"),
            "last_message_preview": row.get("last_message_preview"),
            "message_count": int(row.get("message_count") or 0),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    def public_message(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "conversation_id": row.get("conversation_id"),
            "role": row.get("role"),
            "content": row.get("content") or "",
            "request_id": row.get("request_id"),
            "model": row.get("model"),
            "source_device_id": row.get("source_device_id"),
            "created_at": row.get("created_at"),
        }

    def public_memory(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "fact": row.get("fact") or "",
            "category": row.get("category") or "OTHER",
            "enabled": bool(row.get("enabled")),
            "source_conversation_id": row.get("source_conversation_id"),
            "source_kind": row.get("source_kind", "MANUAL"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    async def memory_enabled(user_id: str) -> bool:
        rows = await rest_request(
            "GET",
            "lj_user_preferences",
            params={"user_id": f"eq.{user_id}", "select": "values", "limit": "1"},
        ) or []
        values = rows[0].get("values") if rows and isinstance(rows[0].get("values"), dict) else {}
        return values.get("memory_enabled", True) is not False

    # V15.9.7 canonical thread API. The older /v1/sync paths above remain for
    # installed clients, while new clients receive stable pagination metadata.
    @router.get("/v1/conversations")
    async def canonical_list_conversations(
        limit: int = 30,
        cursor: str | None = None,
        archived: bool = False,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        page_size = max(1, min(100, limit))
        params = {
            "user_id": f"eq.{_user_id(identity)}",
            "archived_at": "not.is.null" if archived else "is.null",
            "select": (
                "id,title,pinned,archived_at,last_message_preview,message_count,created_at,updated_at"
            ),
            "order": "updated_at.desc,id.desc",
            "limit": str(page_size + 1),
        }
        decoded = _decode_cursor(cursor)
        if decoded:
            timestamp, item_id = decoded
            params["or"] = (
                f"(updated_at.lt.{timestamp},and(updated_at.eq.{timestamp},id.lt.{item_id}))"
            )
        rows = await rest_request("GET", "lj_conversations", params=params) or []
        has_more = len(rows) > page_size
        page = rows[:page_size]
        return {
            "conversations": [public_conversation(row) for row in page],
            "next_cursor": _encode_cursor(page[-1], "updated_at") if has_more and page else None,
            "has_more": has_more,
        }

    @router.post("/v1/conversations")
    async def canonical_create_conversation(
        body: ConversationRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        row = await create_conversation(body, identity)
        return public_conversation(row)

    @router.get("/v1/conversations/{conversation_id}")
    async def canonical_get_conversation(
        conversation_id: str,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        conversation_id = await require_owned_conversation(conversation_id, identity)
        rows = await rest_request(
            "GET",
            "lj_conversations",
            params={
                "id": f"eq.{conversation_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="Conversation not found.")
        return public_conversation(rows[0])

    @router.patch("/v1/conversations/{conversation_id}")
    async def canonical_update_conversation(
        conversation_id: str,
        body: ConversationUpdate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        conversation_id = await require_owned_conversation(conversation_id, identity)
        changes: dict[str, Any] = {"updated_at": _now().isoformat()}
        if body.title is not None:
            title = " ".join(body.title.split()).strip()
            if not title:
                raise HTTPException(status_code=422, detail="Conversation title cannot be empty.")
            changes["title"] = title[:120]
        if body.pinned is not None:
            changes["pinned"] = body.pinned
        if body.archived is not None:
            changes["archived_at"] = _now().isoformat() if body.archived else None
        rows = await rest_request(
            "PATCH",
            "lj_conversations",
            params={"id": f"eq.{conversation_id}", "user_id": f"eq.{user_id}"},
            payload=changes,
            prefer="return=representation",
        ) or []
        if not rows:
            raise HTTPException(status_code=409, detail="Conversation changed on another device.")
        return public_conversation(rows[0])

    @router.delete("/v1/conversations/{conversation_id}", status_code=204)
    async def canonical_delete_conversation(
        conversation_id: str,
        identity: Any = Depends(current_identity),
    ) -> None:
        conversation_id = await require_owned_conversation(conversation_id, identity)
        deleted = await rest_request(
            "POST",
            "rpc/delete_lj_conversation",
            payload={"p_user_id": _user_id(identity), "p_conversation_id": conversation_id},
        )
        value = deleted[0] if isinstance(deleted, list) and deleted else deleted
        if isinstance(value, dict):
            value = next(iter(value.values()), False)
        if value is not True:
            raise HTTPException(status_code=409, detail="Stop any coding job in this chat, then refresh and delete the conversation.")
        return None

    @router.get("/v1/conversations/{conversation_id}/messages")
    async def canonical_list_messages(
        conversation_id: str,
        limit: int = 50,
        cursor: str | None = None,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        conversation_id = await require_owned_conversation(conversation_id, identity)
        page_size = max(1, min(100, limit))
        params = {
            "conversation_id": f"eq.{conversation_id}",
            "user_id": f"eq.{user_id}",
            "select": "id,conversation_id,role,content,request_id,model,source_device_id,created_at",
            "order": "created_at.desc,id.desc",
            "limit": str(page_size + 1),
        }
        decoded = _decode_cursor(cursor)
        if decoded:
            timestamp, item_id = decoded
            params["or"] = (
                f"(created_at.lt.{timestamp},and(created_at.eq.{timestamp},id.lt.{item_id}))"
            )
        rows = await rest_request("GET", "lj_conversation_messages", params=params) or []
        has_more = len(rows) > page_size
        newest_first = rows[:page_size]
        page = list(reversed(newest_first))
        return {
            "messages": [public_message(row) for row in page],
            "next_cursor": (
                _encode_cursor(newest_first[-1], "created_at") if has_more and newest_first else None
            ),
            "has_more": has_more,
        }

    @router.post("/v1/conversations/{conversation_id}/messages")
    async def canonical_add_user_message(
        conversation_id: str,
        body: MessageRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        if body.role != "user":
            raise HTTPException(
                status_code=403,
                detail="Assistant messages can only be written by the LJ AI server.",
            )
        row = await add_message(conversation_id, body, identity)
        return public_message(row)

    @router.get("/v1/memories")
    async def list_memories(
        limit: int = MAX_MEMORIES,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        rows = await rest_request(
            "GET",
            "lj_memories",
            params={
                "user_id": f"eq.{user_id}",
                "select": "id,fact,category,enabled,source_conversation_id,source_kind,created_at,updated_at",
                "order": "updated_at.desc,id.desc",
                "limit": str(max(1, min(MAX_MEMORIES, limit))),
            },
        ) or []
        return {
            "memories": [public_memory(row) for row in rows],
            "memory_enabled": await memory_enabled(user_id),
        }

    @router.delete("/v1/memories", status_code=204)
    async def clear_memories(identity: Any = Depends(current_identity)) -> None:
        await rest_request(
            "POST", "rpc/forget_lj_memory",
            payload={"p_user_id": _user_id(identity), "p_all": True},
        )
        return None

    @router.post("/v1/memories")
    async def create_memory(
        body: MemoryCreate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        normalized = _normalise_memory_fact(body.fact)
        existing = await rest_request(
            "GET",
            "lj_memories",
            params={
                "user_id": f"eq.{user_id}",
                "normalized_fact": f"eq.{normalized}",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if existing:
            return public_memory(existing[0])
        memories = await rest_request(
            "GET",
            "lj_memories",
            params={"user_id": f"eq.{user_id}", "select": "id", "limit": str(MAX_MEMORIES)},
        ) or []
        if len(memories) >= MAX_MEMORIES:
            raise HTTPException(status_code=409, detail="Delete an old memory before saving another one.")
        timestamp = _now().isoformat()
        rows = await rest_request(
            "POST",
            "lj_memories",
            payload={
                "user_id": user_id,
                "fact": body.fact,
                "normalized_fact": normalized,
                "category": body.category,
                "enabled": body.enabled,
                "created_at": timestamp,
                "updated_at": timestamp,
            },
            prefer="return=representation",
        ) or []
        if not rows:
            raise HTTPException(status_code=502, detail="Memory could not be saved.")
        return public_memory(rows[0])

    async def require_owned_memory(memory_id: str, identity: Any) -> dict[str, Any]:
        try:
            clean_id = str(uuid.UUID(memory_id))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(status_code=404, detail="Memory not found.") from None
        rows = await rest_request(
            "GET",
            "lj_memories",
            params={
                "id": f"eq.{clean_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="Memory not found.")
        return rows[0]

    @router.patch("/v1/memories/{memory_id}")
    async def update_memory(
        memory_id: str,
        body: MemoryUpdate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        current = await require_owned_memory(memory_id, identity)
        changes: dict[str, Any] = {"updated_at": _now().isoformat()}
        if body.fact is not None:
            changes["fact"] = body.fact
            changes["normalized_fact"] = _normalise_memory_fact(body.fact)
            changes["source_kind"] = "MANUAL"
        if body.category is not None:
            changes["category"] = body.category
        if body.enabled is not None:
            changes["enabled"] = body.enabled
        try:
            updated = await rest_request(
                "POST", "rpc/edit_lj_memory",
                payload={"p_user_id": _user_id(identity), "p_memory_id": current["id"], "p_changes": changes})
            rows = updated if isinstance(updated, list) else ([updated] if updated else [])
        except HTTPException as error:
            raise HTTPException(status_code=409, detail="That memory already exists.") from error
        if not rows:
            raise HTTPException(status_code=409, detail="Memory changed on another device.")
        return public_memory(rows[0])

    @router.delete("/v1/memories/{memory_id}", status_code=204)
    async def delete_memory(
        memory_id: str,
        identity: Any = Depends(current_identity),
    ) -> None:
        current = await require_owned_memory(memory_id, identity)
        await rest_request(
            "POST", "rpc/forget_lj_memory",
            payload={"p_user_id": _user_id(identity), "p_memory_id": current["id"]},
        )
        return None

    @router.put("/v1/memory/settings")
    async def update_memory_settings(
        body: MemorySettingsUpdate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, bool]:
        result = await rest_request(
            "POST",
            "rpc/set_lj_memory_enabled",
            payload={
                "p_user_id": _user_id(identity),
                "p_enabled": body.enabled,
            },
        )
        row = result[0] if isinstance(result, list) and result else result
        return {"enabled": bool(row.get("enabled")) if isinstance(row, dict) else body.enabled}

    async def require_voice_session(session_id: str, identity: Any) -> dict[str, Any]:
        clean_id = _validate_identifier(session_id, "voice session identity")
        rows = await rest_request(
            "GET",
            "lj_voice_sessions",
            params={
                "id": f"eq.{clean_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="Voice session not found.")
        return rows[0]

    def require_voice_lease(row: dict[str, Any], token: str, identity: Any) -> None:
        expected_hash = str(row.get("lease_token_hash") or "")
        valid_token = bool(token) and secrets.compare_digest(expected_hash, _hash_token(token))
        valid_device = str(row.get("active_device_id") or "") == _device_id(identity)
        valid_status = str(row.get("status") or "") in {"ACTIVE", "HANDOVER_REQUESTED"}
        if not valid_token or not valid_device or not valid_status or not _is_reconnectable(row):
            raise HTTPException(status_code=409, detail="This device no longer owns the voice session.")

    async def apply_voice_action(
        row: dict[str, Any],
        identity: Any,
        action: str,
        *,
        lease_hash: str,
        active_device_id: str,
        transcript_tail: list[dict[str, str]] | None = None,
        voice_state: str | None = None,
        target_platform: str | None = None,
        new_device_id: str | None = None,
        new_platform: str | None = None,
        new_lease_hash: str | None = None,
    ) -> dict[str, Any]:
        result = await rest_request(
            "POST",
            "rpc/apply_lj_voice_session",
            payload={
                "p_user_id": _user_id(identity),
                "p_session_id": str(row.get("id") or ""),
                "p_device_id": active_device_id,
                "p_lease_token_hash": lease_hash,
                "p_action": action,
                "p_transcript_tail": transcript_tail,
                "p_voice_state": voice_state,
                "p_target_platform": target_platform,
                "p_new_device_id": new_device_id,
                "p_new_platform": new_platform,
                "p_new_lease_token_hash": new_lease_hash,
            },
        )
        outcome = result[0] if isinstance(result, list) and result else result or {}
        if not outcome.get("applied"):
            reason = str(outcome.get("denial_reason") or "VOICE_STATE_CHANGED")
            status_code = 429 if reason == "ALLOWANCE_EXHAUSTED" else 409
            raise HTTPException(
                status_code=status_code,
                detail=(
                    "Your voice allowance is used up for this billing cycle."
                    if status_code == 429
                    else "This device no longer owns the voice session."
                ),
            )
        return outcome

    async def end_voice_row(row: dict[str, Any], identity: Any, reason: str) -> dict[str, Any]:
        action = (
            "ABORT"
            if bool(row.get("issuance_pending"))
            and int(row.get("prepaid_seconds") or 0) == 0
            else "END"
        )
        outcome = await apply_voice_action(
            row,
            identity,
            action,
            lease_hash=str(row.get("lease_token_hash") or ""),
            active_device_id=str(row.get("active_device_id") or ""),
        )
        if not outcome.get("already_ended"):
            await insert_audit(
                _user_id(identity),
                "VOICE_SESSION_ENDED",
                {"session_id": str(row.get("id") or ""), "reason": reason},
            )
        return outcome

    @router.post("/v1/sync/voice/start")
    async def start_voice(
        body: VoiceStartRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
        owned_conversation_id = None
        if body.conversation_id:
            owned_conversation_id = await require_owned_conversation(body.conversation_id, identity)
        active_rows = await rest_request(
            "GET",
            "lj_voice_sessions",
            params={
                "user_id": f"eq.{user_id}",
                "status": "in.(ACTIVE,HANDOVER_REQUESTED)",
                "select": "*",
                "order": "updated_at.desc",
                "limit": "4",
            },
        ) or []
        inherited_tail = body.transcript_tail
        inherited_prepaid = 0
        for old in active_rows:
            other_device = str(old.get("active_device_id") or "") != _device_id(identity)
            reconnectable = _is_reconnectable(old)
            if (
                other_device
                and reconnectable
                and not (body.auto_handover or bool(old.get("auto_handover")))
            ):
                raise HTTPException(
                    status_code=409,
                    detail="Voice is active on another linked device. Offer or claim a handover first.",
                )
            ended = await end_voice_row(old, identity, "replaced" if reconnectable else "lease_expired")
            inherited_prepaid += max(0, int(ended.get("prepaid_seconds") or 0))
            if other_device and not inherited_tail:
                inherited_tail = _clean_transcript_tail(old.get("transcript_tail"))

        token = secrets.token_urlsafe(40)
        timestamp = _now().isoformat()
        row = {
            "id": secrets.token_urlsafe(28),
            "user_id": user_id,
            "conversation_id": owned_conversation_id,
            "active_device_id": _device_id(identity),
            "active_platform": body.platform,
            "status": "ACTIVE",
            "auto_handover": body.auto_handover,
            "transcript_tail": inherited_tail,
            "lease_token_hash": _hash_token(token),
            "lease_expires_at": _lease_expiry(),
            "metered_at": timestamp,
            "prepaid_seconds": min(86400, inherited_prepaid),
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        await rest_request("POST", "lj_voice_sessions", payload=row, prefer="return=minimal")
        await insert_audit(
            user_id,
            "VOICE_SESSION_STARTED",
            {"session_id": row["id"], "platform": body.platform, "device_id": _device_id(identity)},
        )
        public_row = {key: value for key, value in row.items() if key != "lease_token_hash"}
        return {**public_row, "lease_token": token}

    @router.get("/v1/sync/voice/active")
    async def active_voice(identity: Any = Depends(current_identity)) -> dict[str, Any]:
        rows = await rest_request(
            "GET",
            "lj_voice_sessions",
            params={
                "user_id": f"eq.{_user_id(identity)}",
                "status": "in.(ACTIVE,HANDOVER_REQUESTED)",
                "select": (
                    "id,active_device_id,active_platform,status,handover_target,auto_handover,"
                    "transcript_tail,lease_token_hash,lease_expires_at,updated_at,"
                    "issuance_pending,prepaid_seconds"
                ),
                "order": "updated_at.desc",
                "limit": "1",
            },
        ) or []
        if not rows:
            return {"status": "NONE"}
        row = rows[0]
        if not _is_reconnectable(row):
            try:
                await end_voice_row(row, identity, "lease_expired")
            except HTTPException:
                pass
            return {"status": "NONE"}
        row["transcript_tail"] = _clean_transcript_tail(row.get("transcript_tail"))
        row.pop("lease_token_hash", None)
        return row

    @router.post("/v1/sync/voice/{session_id}/handover")
    async def offer_handover(
        session_id: str,
        body: VoiceOfferRequest,
        x_lj_voice_lease: str = Header(default=""),
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        row = await require_voice_session(session_id, identity)
        require_voice_lease(row, x_lj_voice_lease, identity)
        if row.get("status") != "ACTIVE":
            raise HTTPException(status_code=409, detail="A handover is already pending for this voice session.")
        usage = await apply_voice_action(
            row,
            identity,
            "OFFER",
            lease_hash=_hash_token(x_lj_voice_lease),
            active_device_id=_device_id(identity),
            target_platform=body.target_platform,
        )
        await insert_audit(
            _user_id(identity),
            "VOICE_HANDOVER_OFFERED",
            {"session_id": session_id, "target_platform": body.target_platform},
        )
        return {
            "status": "HANDOVER_REQUESTED",
            "voice_seconds_remaining": usage.get("voice_seconds_remaining"),
        }

    @router.post("/v1/sync/voice/{session_id}/claim")
    async def claim_handover(
        session_id: str,
        body: VoiceClaimRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        row = await require_voice_session(session_id, identity)
        if not _is_reconnectable(row):
            await end_voice_row(row, identity, "lease_expired")
            raise HTTPException(status_code=409, detail="That voice handover has expired.")
        target = str(row.get("handover_target") or "")
        if row.get("status") not in {"ACTIVE", "HANDOVER_REQUESTED"}:
            raise HTTPException(status_code=409, detail="That voice session has already ended.")
        if row.get("status") != "HANDOVER_REQUESTED" and not row.get("auto_handover"):
            raise HTTPException(status_code=409, detail="The active device has not offered a handover.")
        if target and target != body.platform:
            raise HTTPException(status_code=409, detail="That handover was offered to a different platform.")
        token = secrets.token_urlsafe(40)
        updated = await apply_voice_action(
            row,
            identity,
            "CLAIM",
            lease_hash=str(row.get("lease_token_hash") or ""),
            active_device_id=str(row.get("active_device_id") or ""),
            new_device_id=_device_id(identity),
            new_platform=body.platform,
            new_lease_hash=_hash_token(token),
        )
        await insert_audit(
            _user_id(identity),
            "VOICE_HANDOVER_CLAIMED",
            {"session_id": session_id, "platform": body.platform, "device_id": _device_id(identity)},
        )
        return {
            "id": session_id,
            "active_device_id": _device_id(identity),
            "active_platform": body.platform,
            "status": str(updated.get("session_state") or "ACTIVE"),
            "handover_target": None,
            "lease_expires_at": updated.get("lease_expires_at"),
            "lease_token": token,
            "transcript_tail": _clean_transcript_tail(row.get("transcript_tail")),
        }

    @router.post("/v1/sync/voice/{session_id}/heartbeat")
    async def voice_heartbeat(
        session_id: str,
        body: VoiceHeartbeatRequest,
        x_lj_voice_lease: str = Header(default=""),
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        row = await require_voice_session(session_id, identity)
        require_voice_lease(row, x_lj_voice_lease, identity)
        usage = await apply_voice_action(
            row,
            identity,
            "HEARTBEAT",
            lease_hash=_hash_token(x_lj_voice_lease),
            active_device_id=_device_id(identity),
            transcript_tail=body.transcript_tail,
            voice_state=body.state,
        )
        remaining = usage.get("voice_seconds_remaining")
        exhausted = bool(usage.get("allowance_exhausted"))
        expiry = usage.get("lease_expires_at")
        status = str(usage.get("session_state") or "ACTIVE")
        if learn_memory is not None and status == "ACTIVE":
            from automatic_memory import new_voice_memory_turns
            previous_tail = _clean_transcript_tail(row.get("transcript_tail"))
            for index, turn in new_voice_memory_turns(previous_tail, body.transcript_tail):
                if turn.get("role") == "user":
                    text = str(turn.get("content") or "")
                    occurrence = json.dumps([previous_tail[-2:], body.transcript_tail[:index+1]], sort_keys=True)
                    turn_id = "voice-memory-" + hashlib.sha256((session_id + "\0" + occurrence).encode()).hexdigest()[:40]
                    await learn_memory(identity, text, row.get("conversation_id"), turn_id)
        return {
            "status": status,
            "lease_expires_at": expiry,
            "voice_seconds_remaining": remaining,
            "allowance_exhausted": exhausted,
        }

    @router.post("/v1/sync/voice/{session_id}/end")
    async def end_voice(
        session_id: str,
        x_lj_voice_lease: str = Header(default=""),
        identity: Any = Depends(current_identity),
    ) -> dict[str, bool]:
        row = await require_voice_session(session_id, identity)
        outcome = await apply_voice_action(
            row,
            identity,
            "END",
            lease_hash=_hash_token(x_lj_voice_lease),
            active_device_id=_device_id(identity),
        )
        if not outcome.get("already_ended"):
            await insert_audit(
                _user_id(identity),
                "VOICE_SESSION_ENDED",
                {"session_id": session_id, "reason": "user_request"},
            )
        return {"ended": True}

    return router
