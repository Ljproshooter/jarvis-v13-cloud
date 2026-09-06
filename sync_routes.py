"""Cross-device preferences, conversations and leased voice handover.

All database access uses the server's service credential, so every read and
write in this module must explicitly scope itself to the authenticated user.
Client supplied identifiers are treated as idempotency keys, never as proof of
ownership.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator


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
}
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,100}$")
VOICE_LEASE_SECONDS = 90
VOICE_RECONNECT_GRACE_SECONDS = 5 * 60
MAX_TRANSCRIPT_BYTES = 32 * 1024


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


class MessageRequest(BaseModel):
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
        clean: list[str] = []
        for item in value:
            reference = str(item).strip()
            if not reference or len(reference) > 2048:
                raise ValueError("An image reference is invalid.")
            clean.append(reference)
        return clean


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
        return await rest_request(
            "GET",
            "lj_conversation_messages",
            params={
                "conversation_id": f"eq.{conversation_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "select": "*",
                "order": "created_at.asc",
                "limit": str(max(1, min(200, limit))),
            },
        ) or []

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

    async def meter_since(row: dict[str, Any], identity: Any) -> dict[str, Any]:
        stamp = _parse_timestamp(row.get("updated_at") or row.get("created_at")) or _now()
        seconds = max(0, min(VOICE_LEASE_SECONDS, int((_now() - stamp).total_seconds())))
        if seconds <= 0:
            return {"voice_seconds_remaining": None}
        return await consume_voice_usage(identity, seconds)

    async def end_voice_row(row: dict[str, Any], identity: Any, reason: str) -> bool:
        timestamp = _now().isoformat()
        updated = await rest_request(
            "PATCH",
            "lj_voice_sessions",
            params={
                "id": f"eq.{row.get('id')}",
                "user_id": f"eq.{_user_id(identity)}",
                "active_device_id": f"eq.{row.get('active_device_id')}",
                "lease_token_hash": f"eq.{row.get('lease_token_hash')}",
                "status": "in.(ACTIVE,HANDOVER_REQUESTED)",
            },
            payload={"status": "ENDED", "lease_expires_at": timestamp, "updated_at": timestamp},
            prefer="return=representation",
        ) or []
        if not updated:
            return False
        await insert_audit(
            _user_id(identity),
            "VOICE_SESSION_ENDED",
            {"session_id": str(row.get("id") or ""), "reason": reason},
        )
        return True

    @router.post("/v1/sync/voice/start")
    async def start_voice(
        body: VoiceStartRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = _user_id(identity)
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
            if reconnectable:
                try:
                    await meter_since(old, identity)
                except HTTPException as error:
                    if error.status_code != 429:
                        raise
            ended = await end_voice_row(old, identity, "replaced" if reconnectable else "lease_expired")
            if not ended:
                raise HTTPException(
                    status_code=409,
                    detail="Voice state changed on another device. Try starting voice again.",
                )
            if other_device and not inherited_tail:
                inherited_tail = _clean_transcript_tail(old.get("transcript_tail"))

        token = secrets.token_urlsafe(40)
        timestamp = _now().isoformat()
        row = {
            "id": secrets.token_urlsafe(28),
            "user_id": user_id,
            "conversation_id": body.conversation_id,
            "active_device_id": _device_id(identity),
            "active_platform": body.platform,
            "status": "ACTIVE",
            "auto_handover": body.auto_handover,
            "transcript_tail": inherited_tail,
            "lease_token_hash": _hash_token(token),
            "lease_expires_at": _lease_expiry(),
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
                    "transcript_tail,lease_token_hash,lease_expires_at,updated_at"
                ),
                "order": "updated_at.desc",
                "limit": "1",
            },
        ) or []
        if not rows:
            return {"status": "NONE"}
        row = rows[0]
        if not _is_reconnectable(row):
            await end_voice_row(row, identity, "lease_expired")
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
        usage = await meter_since(row, identity)
        timestamp = _now().isoformat()
        updated = await rest_request(
            "PATCH",
            "lj_voice_sessions",
            params={
                "id": f"eq.{session_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "active_device_id": f"eq.{_device_id(identity)}",
                "lease_token_hash": f"eq.{row.get('lease_token_hash')}",
                "status": "eq.ACTIVE",
            },
            payload={
                "status": "HANDOVER_REQUESTED",
                "handover_target": body.target_platform,
                "lease_expires_at": _lease_expiry(),
                "updated_at": timestamp,
            },
            prefer="return=representation",
        ) or []
        if not updated:
            raise HTTPException(status_code=409, detail="Voice state changed before the handover was offered.")
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
        timestamp = _now().isoformat()
        patch = {
            "active_device_id": _device_id(identity),
            "active_platform": body.platform,
            "status": "ACTIVE",
            "handover_target": None,
            "lease_token_hash": _hash_token(token),
            "lease_expires_at": _lease_expiry(),
            "updated_at": timestamp,
        }
        updated = await rest_request(
            "PATCH",
            "lj_voice_sessions",
            params={
                "id": f"eq.{session_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "active_device_id": f"eq.{row.get('active_device_id')}",
                "lease_token_hash": f"eq.{row.get('lease_token_hash')}",
                "status": f"eq.{row.get('status')}",
            },
            payload=patch,
            prefer="return=representation",
        ) or []
        if not updated:
            raise HTTPException(status_code=409, detail="That voice handover was claimed on another device.")
        await insert_audit(
            _user_id(identity),
            "VOICE_HANDOVER_CLAIMED",
            {"session_id": session_id, "platform": body.platform, "device_id": _device_id(identity)},
        )
        public_patch = {key: value for key, value in patch.items() if key != "lease_token_hash"}
        return {
            **public_patch,
            "id": session_id,
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
        usage = await meter_since(row, identity)
        remaining = usage.get("voice_seconds_remaining")
        exhausted = remaining is not None and int(remaining) <= 0
        expiry = _lease_expiry()
        timestamp = _now().isoformat()
        status = "ENDED" if exhausted else str(row.get("status") or "ACTIVE")
        updated = await rest_request(
            "PATCH",
            "lj_voice_sessions",
            params={
                "id": f"eq.{session_id}",
                "user_id": f"eq.{_user_id(identity)}",
                "active_device_id": f"eq.{_device_id(identity)}",
                "lease_token_hash": f"eq.{row.get('lease_token_hash')}",
                "status": "in.(ACTIVE,HANDOVER_REQUESTED)",
            },
            payload={
                "transcript_tail": body.transcript_tail,
                "last_voice_state": body.state,
                "lease_expires_at": expiry,
                "updated_at": timestamp,
                "status": status,
            },
            prefer="return=representation",
        ) or []
        if not updated:
            raise HTTPException(status_code=409, detail="This device no longer owns the voice session.")
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
        require_voice_lease(row, x_lj_voice_lease, identity)
        try:
            await meter_since(row, identity)
        except HTTPException as error:
            if error.status_code != 429:
                raise
        ended = await end_voice_row(row, identity, "user_request")
        if not ended:
            raise HTTPException(status_code=409, detail="This device no longer owns the voice session.")
        return {"ended": True}

    return router
