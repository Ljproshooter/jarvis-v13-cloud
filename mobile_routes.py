"""Staged LJ AI phone-to-Windows routes.

Copy beside the cloud main.py and include only after running the staging SQL and
setting LJ_PAIRING_HMAC_SECRET to at least 32 random characters. This module
never accepts arbitrary commands or shell text.
"""

from __future__ import annotations

import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from mobile_security import ALLOWED_ACTIONS, is_valid_pairing_code, normalize_pairing_code, pairing_digest


PAIRING_TTL_SECONDS = 300
COMMAND_TTL_SECONDS = 45


class PairingClaim(BaseModel):
    code: str = Field(min_length=6, max_length=12)
    mobile_device_name: str = Field(default="Android phone", min_length=1, max_length=80)

    @field_validator("code")
    @classmethod
    def clean_code(cls, value: str) -> str:
        clean = normalize_pairing_code(value)
        if not is_valid_pairing_code(clean):
            raise ValueError("Enter the six-digit pairing code shown by LJ AI on Windows.")
        return clean


class RemoteCommandRequest(BaseModel):
    action: Literal[
        "show_notification",
        "media_play_pause",
        "media_next",
        "volume_mute",
        "lock_pc",
        "open_lj_ai",
        "run_diagnostic",
    ]
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def small_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 4096:
            raise ValueError("Remote command details are too large.")
        return value


class CommandResult(BaseModel):
    status: Literal["SUCCEEDED", "FAILED"]
    message: str = Field(default="", max_length=500)


def create_mobile_router(
    *,
    current_identity: Callable[..., Awaitable[Any]],
    rest_request: Callable[..., Awaitable[Any]],
    rpc: Callable[..., Awaitable[Any]],
    insert_audit: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    limiter: Any,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["mobile-link"])

    async def current_device(identity: Any) -> dict[str, Any]:
        rows = await rest_request(
            "GET",
            "account_devices",
            params={
                "user_id": f"eq.{identity.user_id}",
                "device_id": f"eq.{identity.device_id}",
                "is_active": "eq.true",
                "select": "device_id,device_name,platform",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=401, detail="This device is no longer signed in.")
        return rows[0]

    @router.post("/pc-links/pairing-code")
    async def issue_pairing_code(identity: Any = Depends(current_identity)) -> dict[str, Any]:
        await limiter.enforce(f"pc-pair-create:{identity.user_id}", 10, 600)
        device = await current_device(identity)
        if not str(device.get("platform") or "").casefold().startswith("windows"):
            raise HTTPException(status_code=403, detail="Pairing codes must be created by LJ AI on Windows.")
        secret = os.getenv("LJ_PAIRING_HMAC_SECRET", "")
        code = f"{secrets.randbelow(1_000_000):06d}"
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=PAIRING_TTL_SECONDS)
        await rest_request(
            "POST",
            "device_pairing_codes",
            payload={
                "user_id": identity.user_id,
                "windows_device_id": identity.device_id,
                "windows_device_name": str(device.get("device_name") or "Windows PC")[:80],
                "code_hash": pairing_digest(identity.user_id, code, secret),
                "expires_at": expires.isoformat(),
            },
            prefer="return=minimal",
        )
        await insert_audit(identity.user_id, "PC_PAIRING_CODE_CREATED", {"device_id": identity.device_id})
        return {
            "code": code,
            "qr_payload": f"ljai://pair?code={code}",
            "expires_at": expires.isoformat(),
        }

    @router.post("/pc-links/claim")
    async def claim_pairing_code(body: PairingClaim, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        await limiter.enforce(f"pc-pair-claim:{identity.user_id}", 10, 300)
        device = await current_device(identity)
        if not str(device.get("platform") or "").casefold().startswith("android"):
            raise HTTPException(status_code=403, detail="Use LJ AI Mobile on Android to claim this code.")
        secret = os.getenv("LJ_PAIRING_HMAC_SECRET", "")
        result = await rpc(
            "claim_lj_pairing_code",
            {
                "p_user_id": identity.user_id,
                "p_code_hash": pairing_digest(identity.user_id, body.code, secret),
                "p_mobile_device_id": identity.device_id,
                "p_mobile_device_name": body.mobile_device_name,
            },
        )
        row = result[0] if isinstance(result, list) and result else result or {}
        if not row.get("allowed") or not row.get("link_id"):
            raise HTTPException(status_code=400, detail="That pairing code is invalid, expired or belongs to another account.")
        await insert_audit(identity.user_id, "PC_LINK_CREATED", {"link_id": row["link_id"]})
        return {
            "paired": True,
            "link_id": row["link_id"],
            "windows_device_name": row.get("windows_device_name"),
        }

    @router.get("/pc-links")
    async def list_links(identity: Any = Depends(current_identity)) -> list[dict[str, Any]]:
        rows = await rest_request(
            "GET",
            "device_links",
            params={
                "user_id": f"eq.{identity.user_id}",
                "is_active": "eq.true",
                "select": "id,windows_device_id,windows_device_name,mobile_device_id,mobile_device_name,created_at,last_used_at",
                "order": "last_used_at.desc",
                "limit": "20",
            },
        ) or []
        return rows

    @router.post("/pc-links/{link_id}/commands", status_code=202)
    async def enqueue_command(
        link_id: str,
        body: RemoteCommandRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        await limiter.enforce(f"pc-command:{identity.user_id}", 30, 60)
        try:
            link_id = str(uuid.UUID(link_id))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=404, detail="That PC link is unavailable.") from None
        rows = await rest_request(
            "GET",
            "device_links",
            params={
                "id": f"eq.{link_id}",
                "user_id": f"eq.{identity.user_id}",
                "mobile_device_id": f"eq.{identity.device_id}",
                "is_active": "eq.true",
                "select": "id,windows_device_id",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="That PC link is not active for this phone.")
        now = datetime.now(timezone.utc)
        created = await rest_request(
            "POST",
            "device_remote_commands",
            payload={
                "user_id": identity.user_id,
                "link_id": link_id,
                "source_device_id": identity.device_id,
                "target_device_id": rows[0]["windows_device_id"],
                "action": body.action,
                "payload": body.payload,
                "requires_pc_confirmation": ALLOWED_ACTIONS[body.action],
                "expires_at": (now + timedelta(seconds=COMMAND_TTL_SECONDS)).isoformat(),
            },
            prefer="return=representation",
        ) or []
        if not created:
            raise HTTPException(status_code=502, detail="The PC command could not be queued.")
        await insert_audit(identity.user_id, "PC_COMMAND_QUEUED", {"link_id": link_id, "action": body.action})
        return {
            "command_id": created[0]["id"],
            "status": "PENDING",
            "requires_pc_confirmation": ALLOWED_ACTIONS[body.action],
        }

    @router.get("/pc-links/{link_id}/commands/{command_id}")
    async def command_status(
        link_id: str,
        command_id: str,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        await limiter.enforce(f"pc-command-status:{identity.user_id}:{identity.device_id}", 60, 60)
        try:
            link_id = str(uuid.UUID(link_id))
            command_id = str(uuid.UUID(command_id))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=404, detail="That PC command is unavailable.") from None
        rows = await rest_request(
            "GET",
            "device_remote_commands",
            params={
                "id": f"eq.{command_id}",
                "link_id": f"eq.{link_id}",
                "user_id": f"eq.{identity.user_id}",
                "source_device_id": f"eq.{identity.device_id}",
                "select": "id,status,result,created_at,delivered_at,completed_at,expires_at",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="That PC command is unavailable.")
        row = rows[0]
        if row.get("status") in {"PENDING", "DELIVERED"}:
            expiry = datetime.fromisoformat(str(row.get("expires_at") or "").replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                await rest_request(
                    "PATCH",
                    "device_remote_commands",
                    params={"id": f"eq.{command_id}", "status": "in.(PENDING,DELIVERED)"},
                    payload={"status": "EXPIRED", "completed_at": datetime.now(timezone.utc).isoformat()},
                    prefer="return=minimal",
                )
                row["status"] = "EXPIRED"
        result = row.get("result") if isinstance(row.get("result"), dict) else {}
        return {
            "command_id": command_id,
            "status": row.get("status"),
            "message": str(result.get("message") or "")[:500],
        }

    @router.get("/pc-links/commands/pending")
    async def pending_commands(identity: Any = Depends(current_identity)) -> list[dict[str, Any]]:
        await limiter.enforce(f"pc-poll:{identity.user_id}:{identity.device_id}", 120, 60)
        rows = await rest_request(
            "GET",
            "device_remote_commands",
            params={
                "user_id": f"eq.{identity.user_id}",
                "target_device_id": f"eq.{identity.device_id}",
                "status": "in.(PENDING,DELIVERED)",
                "expires_at": f"gt.{datetime.now(timezone.utc).isoformat()}",
                "select": "id,link_id,action,payload,requires_pc_confirmation,created_at,expires_at",
                "order": "created_at.asc",
                "limit": "20",
            },
        ) or []
        if rows:
            ids = ",".join(str(row["id"]) for row in rows)
            await rest_request(
                "PATCH",
                "device_remote_commands",
                params={"id": f"in.({ids})", "status": "eq.PENDING"},
                payload={"status": "DELIVERED", "delivered_at": datetime.now(timezone.utc).isoformat()},
                prefer="return=minimal",
            )
        return rows

    @router.post("/pc-links/commands/{command_id}/result")
    async def complete_command(
        command_id: str,
        body: CommandResult,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        await limiter.enforce(f"pc-result:{identity.user_id}:{identity.device_id}", 120, 60)
        try:
            command_id = str(uuid.UUID(command_id))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=404, detail="That remote command is unavailable.") from None
        rows = await rest_request(
            "GET",
            "device_remote_commands",
            params={
                "id": f"eq.{command_id}",
                "user_id": f"eq.{identity.user_id}",
                "target_device_id": f"eq.{identity.device_id}",
                "status": "in.(PENDING,DELIVERED)",
                "expires_at": f"gt.{datetime.now(timezone.utc).isoformat()}",
                "select": "id,link_id,action",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="That remote command is unavailable or already completed.")
        now = datetime.now(timezone.utc).isoformat()
        await rest_request(
            "PATCH",
            "device_remote_commands",
            params={"id": f"eq.{command_id}"},
            payload={"status": body.status, "result": {"message": body.message}, "completed_at": now},
            prefer="return=minimal",
        )
        await rest_request(
            "PATCH",
            "device_links",
            params={"id": f"eq.{rows[0]['link_id']}"},
            payload={"last_used_at": now},
            prefer="return=minimal",
        )
        await insert_audit(identity.user_id, "PC_COMMAND_COMPLETED", {"command_id": command_id, "status": body.status})
        return {"completed": True}

    return router
