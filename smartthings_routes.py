"""Staged SmartThings OAuth and allowlisted device/scene controls.

Samsung credentials and tokens stay on the server. The Android app receives
only LJ AI responses and never the SmartThings client secret or access token.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator


SMARTTHINGS_API = "https://api.smartthings.com/v1"
SMARTTHINGS_AUTHORIZE = "https://api.smartthings.com/oauth/authorize"
SMARTTHINGS_TOKEN = "https://api.smartthings.com/oauth/token"
OAUTH_TTL_SECONDS = 600
DEFAULT_SCOPES = "r:locations:* r:devices:* x:devices:* r:scenes:* x:scenes:*"
NORMAL_COMMANDS = {
    ("switch", "on"),
    ("switch", "off"),
    ("switchLevel", "setLevel"),
    ("colorControl", "setColor"),
    ("thermostatCoolingSetpoint", "setCoolingSetpoint"),
    ("thermostatHeatingSetpoint", "setHeatingSetpoint"),
    ("windowShade", "open"),
    ("windowShade", "close"),
    ("windowShade", "pause"),
    ("mediaPlayback", "play"),
    ("mediaPlayback", "pause"),
    ("mediaPlayback", "stop"),
    ("audioVolume", "setVolume"),
    ("audioMute", "mute"),
    ("audioMute", "unmute"),
    ("lock", "lock"),
    ("doorControl", "close"),
    ("garageDoorControl", "close"),
}


class SmartThingsCommand(BaseModel):
    capability: str = Field(min_length=1, max_length=80)
    command: str = Field(min_length=1, max_length=80)
    arguments: list[Any] = Field(default_factory=list, max_length=8)

    @field_validator("arguments")
    @classmethod
    def safe_arguments(cls, value: list[Any]) -> list[Any]:
        if len(str(value).encode("utf-8")) > 2048:
            raise ValueError("SmartThings command arguments are too large.")
        return value


def create_smartthings_router(
    *,
    current_identity: Callable[..., Awaitable[Any]],
    rest_request: Callable[..., Awaitable[Any]],
    insert_audit: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    limiter: Any,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["smartthings"])

    def config() -> tuple[str, str, str, Fernet]:
        client_id = os.getenv("SMARTTHINGS_CLIENT_ID", "").strip()
        client_secret = os.getenv("SMARTTHINGS_CLIENT_SECRET", "").strip()
        redirect_uri = os.getenv("SMARTTHINGS_REDIRECT_URI", "").strip()
        encryption_key = os.getenv("SMARTTHINGS_TOKEN_ENCRYPTION_KEY", "").strip()
        if not all((client_id, client_secret, redirect_uri, encryption_key)):
            raise HTTPException(status_code=503, detail="SmartThings OAuth is not configured on LJ AI Cloud yet.")
        try:
            cipher = Fernet(encryption_key.encode("ascii"))
        except (ValueError, TypeError):
            raise HTTPException(status_code=503, detail="SmartThings token encryption is misconfigured.") from None
        return client_id, client_secret, redirect_uri, cipher

    async def connection(identity: Any) -> tuple[dict[str, Any], str]:
        client_id, client_secret, _, cipher = config()
        rows = await rest_request(
            "GET",
            "smartthings_connections",
            params={
                "user_id": f"eq.{identity.user_id}",
                "is_active": "eq.true",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=409, detail="Connect SmartThings first.")
        row = rows[0]
        try:
            token = cipher.decrypt(str(row["access_token_ciphertext"]).encode("ascii")).decode("utf-8")
        except (InvalidToken, KeyError, ValueError):
            raise HTTPException(status_code=503, detail="The stored SmartThings connection needs to be linked again.") from None
        expires_text = str(row.get("token_expires_at") or "")
        try:
            expires_at = datetime.fromisoformat(expires_text.replace("Z", "+00:00"))
        except ValueError:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        if expires_at <= datetime.now(timezone.utc) + timedelta(seconds=60):
            encrypted_refresh = str(row.get("refresh_token_ciphertext") or "")
            try:
                refresh_token = cipher.decrypt(encrypted_refresh.encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError):
                raise HTTPException(status_code=409, detail="Reconnect SmartThings to renew Samsung approval.") from None
            basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
            async with httpx.AsyncClient(timeout=30) as client:
                try:
                    response = await client.post(
                        SMARTTHINGS_TOKEN,
                        headers={"Authorization": f"Basic {basic}", "Accept": "application/json"},
                        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                    )
                except httpx.RequestError as exc:
                    raise HTTPException(status_code=503, detail="Samsung token renewal is currently unavailable.") from exc
            if response.status_code >= 400:
                raise HTTPException(status_code=409, detail="Reconnect SmartThings to renew Samsung approval.")
            renewed = response.json()
            token = str(renewed.get("access_token") or "")
            if not token:
                raise HTTPException(status_code=409, detail="Reconnect SmartThings to renew Samsung approval.")
            new_refresh = str(renewed.get("refresh_token") or refresh_token)
            expires_in = max(60, int(renewed.get("expires_in") or 86400))
            now = datetime.now(timezone.utc)
            await rest_request(
                "PATCH",
                "smartthings_connections",
                params={"id": f"eq.{row['id']}"},
                payload={
                    "access_token_ciphertext": cipher.encrypt(token.encode("utf-8")).decode("ascii"),
                    "refresh_token_ciphertext": cipher.encrypt(new_refresh.encode("utf-8")).decode("ascii"),
                    "token_expires_at": (now + timedelta(seconds=expires_in)).isoformat(),
                    "updated_at": now.isoformat(),
                },
                prefer="return=minimal",
            )
        return row, token

    async def smartthings_request(method: str, path: str, token: str, payload: dict[str, Any] | None = None) -> Any:
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                response = await client.request(
                    method,
                    SMARTTHINGS_API + path,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    json=payload,
                )
            except httpx.RequestError as exc:
                raise HTTPException(status_code=503, detail="Samsung SmartThings is currently unreachable.") from exc
        if response.status_code == 401:
            raise HTTPException(status_code=409, detail="Reconnect SmartThings to renew Samsung approval.")
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="SmartThings could not complete that request.")
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()

    @router.post("/smartthings/connect")
    async def connect(identity: Any = Depends(current_identity)) -> dict[str, Any]:
        await limiter.enforce(f"smartthings-connect:{identity.user_id}", 10, 600)
        client_id, _, redirect_uri, _ = config()
        state = secrets.token_urlsafe(32)
        state_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(seconds=OAUTH_TTL_SECONDS)
        await rest_request(
            "POST",
            "smartthings_oauth_states",
            payload={
                "user_id": identity.user_id,
                "mobile_device_id": identity.device_id,
                "state_hash": state_hash,
                "expires_at": expires.isoformat(),
            },
            prefer="return=minimal",
        )
        scopes = os.getenv("SMARTTHINGS_SCOPES", DEFAULT_SCOPES).strip()
        query = urlencode({
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scopes,
            "state": state,
        })
        return {"authorize_url": f"{SMARTTHINGS_AUTHORIZE}?{query}", "expires_at": expires.isoformat()}

    @router.get("/smartthings/oauth/callback")
    async def oauth_callback(
        code: str = Query(min_length=8, max_length=2048),
        state: str = Query(min_length=20, max_length=512),
    ) -> RedirectResponse:
        client_id, client_secret, redirect_uri, cipher = config()
        state_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
        rows = await rest_request(
            "GET",
            "smartthings_oauth_states",
            params={
                "state_hash": f"eq.{state_hash}",
                "completed_at": "is.null",
                "expires_at": f"gt.{datetime.now(timezone.utc).isoformat()}",
                "select": "id,user_id,mobile_device_id",
                "limit": "1",
            },
        ) or []
        if not rows:
            return RedirectResponse("ljai://smartthings-connected?success=0&reason=expired")
        oauth_state = rows[0]
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                response = await client.post(
                    SMARTTHINGS_TOKEN,
                    headers={"Authorization": f"Basic {basic}", "Accept": "application/json"},
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                    },
                )
            except httpx.RequestError:
                return RedirectResponse("ljai://smartthings-connected?success=0&reason=network")
        if response.status_code >= 400:
            return RedirectResponse("ljai://smartthings-connected?success=0&reason=denied")
        tokens = response.json()
        access_token = str(tokens.get("access_token") or "")
        if not access_token:
            return RedirectResponse("ljai://smartthings-connected?success=0&reason=token")
        refresh_token = str(tokens.get("refresh_token") or "")
        expires_in = max(60, int(tokens.get("expires_in") or 86400))
        scopes = str(tokens.get("scope") or "").split()
        now = datetime.now(timezone.utc)
        await rest_request(
            "POST",
            "smartthings_connections",
            params={"on_conflict": "user_id"},
            payload={
                "user_id": oauth_state["user_id"],
                "access_token_ciphertext": cipher.encrypt(access_token.encode("utf-8")).decode("ascii"),
                "refresh_token_ciphertext": cipher.encrypt(refresh_token.encode("utf-8")).decode("ascii") if refresh_token else None,
                "token_expires_at": (now + timedelta(seconds=expires_in)).isoformat(),
                "scopes": scopes,
                "is_active": True,
                "updated_at": now.isoformat(),
                "revoked_at": None,
            },
            prefer="resolution=merge-duplicates,return=minimal",
        )
        await rest_request(
            "PATCH",
            "smartthings_oauth_states",
            params={"id": f"eq.{oauth_state['id']}"},
            payload={"completed_at": now.isoformat()},
            prefer="return=minimal",
        )
        await insert_audit(oauth_state["user_id"], "SMARTTHINGS_CONNECTED", {"device_id": oauth_state["mobile_device_id"]})
        return RedirectResponse("ljai://smartthings-connected?success=1")

    @router.get("/smartthings/status")
    async def status(identity: Any = Depends(current_identity)) -> dict[str, Any]:
        config()
        rows = await rest_request(
            "GET",
            "smartthings_connections",
            params={
                "user_id": f"eq.{identity.user_id}",
                "is_active": "eq.true",
                "select": "connected_at,updated_at,scopes",
                "limit": "1",
            },
        ) or []
        return {
            "connected": bool(rows),
            "display_name": "Samsung SmartThings",
            "detail": "Connected securely" if rows else "Not connected",
        }

    @router.get("/smartthings/devices")
    async def devices(identity: Any = Depends(current_identity)) -> list[dict[str, Any]]:
        await limiter.enforce(f"smartthings-read:{identity.user_id}", 60, 60)
        _, token = await connection(identity)
        data = await smartthings_request("GET", "/devices", token)
        result: list[dict[str, Any]] = []
        for item in (data.get("items") or [])[:100]:
            capabilities = {
                str(capability.get("id") or "")
                for component in item.get("components") or []
                for capability in component.get("capabilities") or []
            }
            switch_state = None
            if "switch" in capabilities:
                status_data = await smartthings_request("GET", f"/devices/{item.get('deviceId')}/status", token)
                switch_state = (
                    status_data.get("components", {})
                    .get("main", {})
                    .get("switch", {})
                    .get("switch", {})
                    .get("value")
                )
            result.append({
                "device_id": item.get("deviceId"),
                "name": item.get("name"),
                "label": item.get("label") or item.get("name"),
                "location_id": item.get("locationId"),
                "switch_state": switch_state,
                "capabilities": sorted(capabilities),
            })
        return result

    @router.post("/smartthings/devices/{device_id}/commands", status_code=202)
    async def command(
        device_id: str,
        body: SmartThingsCommand,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        await limiter.enforce(f"smartthings-command:{identity.user_id}", 30, 60)
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", device_id):
            raise HTTPException(status_code=404, detail="That SmartThings device is unavailable.")
        if (body.capability, body.command) not in NORMAL_COMMANDS:
            raise HTTPException(
                status_code=403,
                detail="That SmartThings action is blocked or requires a later biometric-confirmation flow.",
            )
        _, token = await connection(identity)
        result = await smartthings_request(
            "POST",
            f"/devices/{device_id}/commands",
            token,
            {"commands": [{
                "component": "main",
                "capability": body.capability,
                "command": body.command,
                "arguments": body.arguments,
            }]},
        )
        await insert_audit(identity.user_id, "SMARTTHINGS_COMMAND", {
            "device_id": device_id,
            "capability": body.capability,
            "command": body.command,
        })
        return {"accepted": True, "smartthings": result}

    @router.get("/smartthings/scenes")
    async def scenes(identity: Any = Depends(current_identity)) -> list[dict[str, Any]]:
        await limiter.enforce(f"smartthings-read:{identity.user_id}", 60, 60)
        _, token = await connection(identity)
        data = await smartthings_request("GET", "/scenes", token)
        return [{
            "scene_id": item.get("sceneId"),
            "name": item.get("sceneName") or item.get("name") or "SmartThings scene",
            "location_id": item.get("locationId"),
        } for item in (data.get("items") or [])[:100]]

    @router.post("/smartthings/scenes/{scene_id}/execute", status_code=202)
    async def execute_scene(scene_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        await limiter.enforce(f"smartthings-scene:{identity.user_id}", 20, 60)
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", scene_id):
            raise HTTPException(status_code=404, detail="That SmartThings scene is unavailable.")
        _, token = await connection(identity)
        result = await smartthings_request("POST", f"/scenes/{scene_id}/execute", token, {})
        await insert_audit(identity.user_id, "SMARTTHINGS_SCENE", {"scene_id": scene_id})
        return {"accepted": True, "smartthings": result}

    return router
