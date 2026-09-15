"""Production SmartThings OAuth and allowlisted device/scene controls.

Samsung credentials and tokens stay on the server. The Android app receives
only LJ AI responses and never the SmartThings client secret or access token.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import logging
import math
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
    ("mediaPlayback", "rewind"),
    ("mediaPlayback", "fastForward"),
    ("audioVolume", "setVolume"),
    ("audioVolume", "volumeUp"),
    ("audioVolume", "volumeDown"),
    ("audioMute", "mute"),
    ("audioMute", "unmute"),
    ("tvChannel", "setTvChannel"),
    ("tvChannel", "channelUp"),
    ("tvChannel", "channelDown"),
    ("mediaInputSource", "setInputSource"),
    ("custom.launchapp", "launchApp"),
    ("lock", "lock"),
    ("doorControl", "close"),
    ("garageDoorControl", "close"),
}


class SmartThingsCommand(BaseModel):
    component: str = Field(default="main", pattern=r"^[A-Za-z0-9_-]{1,80}$")
    capability: str = Field(min_length=1, max_length=80)
    command: str = Field(min_length=1, max_length=80)
    arguments: list[Any] = Field(default_factory=list, max_length=8)

    @field_validator("arguments")
    @classmethod
    def safe_arguments(cls, value: list[Any]) -> list[Any]:
        if len(str(value).encode("utf-8")) > 2048:
            raise ValueError("SmartThings command arguments are too large.")
        return value


class SmartThingsRemoteRequest(BaseModel):
    action: str = Field(min_length=1, max_length=40)
    value: str = Field(default="", max_length=300)


_REMOTE_COMMANDS = {
    "SWITCH_ON": ("switch", "on"), "SWITCH_OFF": ("switch", "off"),
    "VOLUME_UP": ("audioVolume", "volumeUp"), "VOLUME_DOWN": ("audioVolume", "volumeDown"),
    "SET_VOLUME": ("audioVolume", "setVolume"),
    "MUTE": ("audioMute", "mute"), "UNMUTE": ("audioMute", "unmute"),
    "PLAY": ("mediaPlayback", "play"), "PAUSE": ("mediaPlayback", "pause"),
    "STOP": ("mediaPlayback", "stop"),
    "REWIND": ("mediaPlayback", "rewind"), "FAST_FORWARD": ("mediaPlayback", "fastForward"),
    "CHANNEL_UP": ("tvChannel", "channelUp"), "CHANNEL_DOWN": ("tvChannel", "channelDown"),
    "SET_CHANNEL": ("tvChannel", "setTvChannel"), "SET_INPUT": ("mediaInputSource", "setInputSource"),
    "LAUNCH_APP": ("custom.launchapp", "launchApp"),
}
# SmartThings Developer Support's TV launchApp example uses this Netflix ID.
# IDs vary across TV generations; an advertised app list always takes precedence.
# https://community.smartthings.com/t/api-call-tv-app/247068/2
_TV_APP_IDS = {"netflix": "3201907018807", "youtube": "111299001912"}
_MAX_REMOTE_PRESSES = 20
_REMOTE_DEADLINE_SECONDS = 60
_LOG = logging.getLogger(__name__)


def _normal(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def _repeat_count(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*(?:x|times?|press(?:es)?|steps?)?\s*", value, re.I)
    if not value.strip():
        return 1
    if not match or not 1 <= int(match[1]) <= _MAX_REMOTE_PRESSES:
        raise HTTPException(422, f"Use between 1 and {_MAX_REMOTE_PRESSES} volume button presses.")
    return int(match[1])


def _duration_seconds(value: str) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)?\s*", value, re.I)
    if not match:
        raise HTTPException(422, "Give an exact rewind or fast-forward duration, such as 5 seconds or 15 minutes.")
    unit = (match[2] or "s").lower()
    seconds = float(match[1]) * (3600 if unit.startswith("h") else 60 if unit.startswith("m") else 1)
    if not math.isfinite(seconds) or not 0 < seconds <= 86400:
        raise HTTPException(422, "Choose a playback duration greater than zero and no longer than 24 hours.")
    return seconds


def _provider_outcome(data: Any, expected: int = 1) -> tuple[bool, bool]:
    """HTTP success only acknowledges transport; ACCEPTED is not execution."""
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != expected:
        return False, False
    statuses = [str(item.get("status", "")).upper() for item in results if isinstance(item, dict)]
    accepted = len(statuses) == expected and all(status in {"ACCEPTED", "COMPLETED"} for status in statuses)
    return accepted, accepted and all(status == "COMPLETED" for status in statuses)


def _capability_component(device: dict[str, Any], capability: str) -> tuple[str, int] | None:
    matches = [
        (str(component.get("id") or "main"), int(cap.get("version") or 1))
        for component in device.get("components") or []
        for cap in component.get("capabilities") or []
        if cap.get("id") == capability
    ]
    if len(matches) == 1:
        return matches[0]
    return next((item for item in matches if item[0] == "main"), None)


def _attribute(status: dict[str, Any], component: str, capability: str, name: str) -> dict[str, Any]:
    value = status.get("components", {}).get(component, {}).get(capability, {}).get(name, {})
    return value if isinstance(value, dict) else {}


def _number_for_schema(value: float, schema: dict[str, Any]) -> int | float | None:
    if schema.get("type") not in {"number", "integer"} or not math.isfinite(value):
        return None
    if schema["type"] == "integer" and not value.is_integer():
        return None
    if value < schema.get("minimum", -math.inf) or value > schema.get("maximum", math.inf):
        return None
    return int(value) if schema["type"] == "integer" else value


def _time_multiplier(name: str, schema: dict[str, Any], attribute: dict[str, Any] | None = None) -> float | None:
    text = _normal(name + " " + str(schema.get("description") or ""))
    unit = str((attribute or {}).get("unit") or schema.get("unit") or "").lower()
    if unit in {"ms", "millisecond", "milliseconds"} or "milliseconds" in text:
        return 1000.0
    if unit in {"s", "sec", "second", "seconds"} or "seconds" in text:
        return 1.0
    return None


def _fresh_position(attribute: dict[str, Any]) -> bool:
    # SmartThings status is cached. An old playback position cannot anchor an exact seek.
    try:
        timestamp = datetime.fromisoformat(str(attribute.get("timestamp") or "").replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        return 0 <= age <= 2 and not isinstance(attribute.get("value"), bool)
    except (ValueError, TypeError):
        return False


def _reported_after(attribute: dict[str, Any], command_started: datetime) -> bool:
    """A status GET can return cached attributes; require a post-command report."""
    try:
        reported_at = datetime.fromisoformat(str(attribute.get("timestamp") or "").replace("Z", "+00:00"))
        return command_started <= reported_at <= datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def create_smartthings_router(
    *,
    current_identity: Callable[..., Awaitable[Any]],
    rest_request: Callable[..., Awaitable[Any]],
    insert_audit: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    limiter: Any,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["smartthings"])

    async def audit_device_outcome(user_id: str, event: str, details: dict[str, Any]) -> None:
        # The device action has already happened; a later audit outage must not
        # turn its known result into a generic failure that encourages a retry.
        try:
            await insert_audit(user_id, event, details)
        except Exception as exc:
            _LOG.warning("SmartThings outcome audit unavailable (%s)", type(exc).__name__)

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

    async def read_status(device_id: str, token: str) -> dict[str, Any]:
        try:
            data = await smartthings_request("GET", f"/devices/{device_id}/status", token)
            return data if isinstance(data, dict) else {}
        except HTTPException:
            # A failed status read must never turn an already-sent action into a retry.
            return {}

    async def command_definition(device: dict[str, Any], capability: str, command: str, token: str) -> tuple[str, dict[str, Any]]:
        match = _capability_component(device, capability)
        if match is None:
            raise HTTPException(422, f"This device does not expose {capability} through SmartThings.")
        component, version = match
        definition = await smartthings_request("GET", f"/capabilities/{capability}/{version}", token)
        commands = definition.get("commands") or {}
        if command not in commands:
            raise HTTPException(422, f"This device's {capability} capability does not support {command}.")
        return component, commands[command]

    async def timed_seek(device: dict[str, Any], status: dict[str, Any], token: str, action: str, seconds: float) -> dict[str, Any]:
        """Only use a declared time argument with known units, never timed key presses."""
        backwards = action == "REWIND"
        relative_names = {"skipBackward", "rewind"} if backwards else {"skipForward", "fastForward"}
        for component in (device.get("components") or [])[:16]:
            component_id = str(component.get("id") or "main")
            for capability in (component.get("capabilities") or [])[:64]:
                capability_id = str(capability.get("id") or "")
                if not any(word in capability_id.lower() for word in ("media", "playback", "player", "transport")):
                    continue
                try:
                    definition = await smartthings_request("GET", f"/capabilities/{capability_id}/{int(capability.get('version') or 1)}", token)
                except HTTPException:
                    continue
                for name, spec in (definition.get("commands") or {}).items():
                    arguments = spec.get("arguments") or []
                    if len(arguments) != 1 or name not in relative_names | {"seek", "setPlaybackPosition"}:
                        continue
                    argument = arguments[0]
                    schema = argument.get("schema") or {}
                    if name in relative_names:
                        multiplier = _time_multiplier(str(argument.get("name") or ""), schema)
                        raw_value = seconds * multiplier if multiplier else None
                    else:
                        # An absolute seek needs a current position and its explicit units.
                        position = next((
                            _attribute(status, component_id, capability_id, attribute)
                            for attribute in ("playbackPosition", "position", "currentPosition", "elapsedTime")
                            if isinstance(_attribute(status, component_id, capability_id, attribute).get("value"), (float, int))
                        ), {})
                        position_multiplier = _time_multiplier("", {}, position)
                        multiplier = _time_multiplier(str(argument.get("name") or ""), schema)
                        if not position_multiplier or not multiplier or not _fresh_position(position):
                            continue
                        position_seconds = float(position["value"]) / position_multiplier
                        target_seconds = position_seconds + (-seconds if backwards else seconds)
                        if target_seconds < 0:
                            raise HTTPException(422, "The requested rewind would go before the start of this video. Choose a shorter duration.")
                        raw_value = target_seconds * multiplier
                    if raw_value is None:
                        continue
                    value = _number_for_schema(float(raw_value), schema)
                    if value is not None:
                        return {"component": component_id, "capability": capability_id, "command": name, "arguments": [value]}
        raise HTTPException(422, "This TV/app does not expose exact timed seeking through SmartThings. I cannot reliably rewind or fast-forward that duration with its available remote commands.")

    def advertised_app_id(status: dict[str, Any], wanted: str) -> str | None:
        matches: set[str] = set()
        for component in status.get("components", {}).values():
            for capability in component.values():
                for attribute in ("supportedApps", "installedApps", "applications", "appList"):
                    entries = capability.get(attribute, {}).get("value")
                    if not isinstance(entries, list):
                        continue
                    for item in entries:
                        if isinstance(item, dict) and _normal(item.get("name") or item.get("label")) == _normal(wanted):
                            app_id = str(item.get("appId") or item.get("id") or "")
                            if re.fullmatch(r"[A-Za-z0-9._-]{1,150}", app_id):
                                matches.add(app_id)
        return next(iter(matches)) if len(matches) == 1 else None

    def observed_target(status: dict[str, Any], command: dict[str, Any], action: str = "", value: str = "", *, since: datetime) -> bool:
        component, capability, name = command["component"], command["capability"], command["command"]
        arguments = command["arguments"]
        target = {
            ("switch", "on"): ("switch", "on"), ("switch", "off"): ("switch", "off"),
            ("audioMute", "mute"): ("mute", "muted"), ("audioMute", "unmute"): ("mute", "unmuted"),
            ("mediaPlayback", "play"): ("playbackStatus", "playing"),
            ("mediaPlayback", "pause"): ("playbackStatus", "paused"),
            ("mediaPlayback", "stop"): ("playbackStatus", "stopped"),
            ("mediaPlayback", "rewind"): ("playbackStatus", "rewinding"),
            ("mediaPlayback", "fastForward"): ("playbackStatus", "fast forwarding"),
        }.get((capability, name))
        if arguments:
            target = {
                ("audioVolume", "setVolume"): ("volume", arguments[0]),
                ("tvChannel", "setTvChannel"): ("tvChannel", arguments[0]),
                ("mediaInputSource", "setInputSource"): ("inputSource", arguments[0]),
            }.get((capability, name), target)
        if target:
            reported = _attribute(status, component, capability, target[0])
            actual = reported.get("value")
            return actual is not None and _normal(actual) == _normal(target[1]) and _reported_after(reported, since)
        if action == "LAUNCH_APP":
            wanted = {_normal(value), _normal(arguments[0])}
            for attributes in status.get("components", {}).get(component, {}).values():
                for attribute in ("appId", "applicationId", "currentApp", "runningApp", "appName", "tvChannelName"):
                    reported = attributes.get(attribute, {})
                    if not isinstance(reported, dict):
                        continue
                    actual = reported.get("value")
                    if actual is not None and _normal(actual) in wanted and _reported_after(reported, since):
                        return True
        return False

    @router.post("/smartthings/devices/{device_id}/remote")
    async def remote(device_id: str, body: SmartThingsRemoteRequest, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        progress = {"requested_count": 1, "sent_count": 0, "acknowledged_count": 0}
        try:
            return await asyncio.wait_for(execute_remote(device_id, body, identity, progress), timeout=_REMOTE_DEADLINE_SECONDS)
        except asyncio.TimeoutError:
            sent, acknowledged = progress["sent_count"], progress["acknowledged_count"]
            message = (
                f"The TV request timed out after {sent} attempted commands ({acknowledged} acknowledged). "
                "The last command may have reached the TV. I stopped the sequence and did not retry it."
                if sent else "SmartThings did not respond in time to prepare this action. No TV command was sent."
            )
            return {"ok": False, "accepted": acknowledged > 0, "confirmed": False,
                    "status": "unknown" if sent else "timeout", "message": message, **progress}

    async def execute_remote(device_id: str, body: SmartThingsRemoteRequest, identity: Any, progress: dict[str, int]) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", device_id):
            raise HTTPException(404, "That SmartThings device is unavailable.")
        action, value = body.action.upper().strip(), body.value.strip()
        if action not in _REMOTE_COMMANDS:
            raise HTTPException(422, "That SmartThings remote action is not supported.")
        count = _repeat_count(value) if action in {"VOLUME_UP", "VOLUME_DOWN"} else 1
        progress["requested_count"] = count
        # Charge each requested press so a count cannot bypass the command budget.
        for _ in range(count):
            await limiter.enforce(f"smartthings-command:{identity.user_id}", 60, 60)
        _, token = await connection(identity)
        device = await smartthings_request("GET", f"/devices/{device_id}", token)
        status = await read_status(device_id, token)
        capability, command_name = _REMOTE_COMMANDS[action]
        arguments: list[Any] = []
        if action in {"REWIND", "FAST_FORWARD"} and value:
            seconds = _duration_seconds(value)
            planned = await timed_seek(device, status, token, action, seconds)
            description = f"{'rewind' if action == 'REWIND' else 'fast-forward'} {seconds:g} seconds"
        else:
            component, definition = await command_definition(device, capability, command_name, token)
            if action == "SET_VOLUME":
                if not re.fullmatch(r"\d{1,3}", value) or not 0 <= int(value) <= 100:
                    raise HTTPException(422, "Set TV volume to a whole number from 0 to 100.")
                arguments = [int(value)]
            elif action in {"SET_CHANNEL", "SET_INPUT", "LAUNCH_APP"}:
                if not re.fullmatch(r"[A-Za-z0-9 ._/-]{1,150}", value):
                    raise HTTPException(422, "Give a valid TV app, channel, or input name.")
                if action == "LAUNCH_APP":
                    arguments = [advertised_app_id(status, value) or _TV_APP_IDS.get(_normal(value), value)]
                elif action == "SET_INPUT":
                    compact = re.sub(r"\s+", "", value).lower()
                    arguments = [compact.upper() if re.fullmatch(r"hdmi[1-4]?", compact) else "digitalTv" if compact in {"tv", "digitaltv", "dtv"} else value]
                else:
                    arguments = [value]
            elif value and action not in {"VOLUME_UP", "VOLUME_DOWN"}:
                raise HTTPException(422, "This remote button does not accept an extra value.")
            if len(definition.get("arguments") or []) != len(arguments):
                raise HTTPException(422, "This TV exposes a different command format, so I cannot safely use that remote action.")
            # A device may expose mediaPlayback but omit individual playback buttons.
            supported = _attribute(status, component, capability, "supportedPlaybackCommands").get("value")
            if capability == "mediaPlayback" and isinstance(supported, list) and command_name not in supported:
                raise HTTPException(422, f"The current TV/app does not support {command_name} through SmartThings.")
            planned = {"component": component, "capability": capability, "command": command_name, "arguments": arguments}
            description = f"{count} volume-{'up' if action == 'VOLUME_UP' else 'down'} press{'es' if count != 1 else ''}" if action in {"VOLUME_UP", "VOLUME_DOWN"} else f"{action.lower().replace('_', ' ')}{(' ' + value) if value else ''}"
        sent = accepted_count = 0
        provider_completed = True
        command_started = datetime.now(timezone.utc)
        for index in range(count):
            if index:
                await asyncio.sleep(0.12)
            sent += 1
            progress["sent_count"] = sent
            try:
                result = await smartthings_request("POST", f"/devices/{device_id}/commands", token, {"commands": [planned]})
            except HTTPException:
                return {"ok": False, "accepted": accepted_count > 0, "confirmed": False, "status": "unknown",
                        "requested_count": count, "sent_count": sent,
                        "message": f"The {description} request could not be fully verified; {accepted_count} of {count} commands were acknowledged. The last command may have reached the TV. I did not retry it."}
            accepted, completed = _provider_outcome(result)
            if not accepted:
                return {"ok": False, "accepted": accepted_count > 0, "confirmed": False, "status": "partial" if accepted_count else "rejected",
                        "requested_count": count, "sent_count": sent,
                        "message": f"SmartThings did not accept all of the {description} request ({accepted_count} of {count} acknowledged)."}
            accepted_count += 1
            progress["acknowledged_count"] = accepted_count
            provider_completed = provider_completed and completed
        confirmed = False
        for attempt in range(3):
            if attempt:
                await asyncio.sleep(0.35)
            latest = await read_status(device_id, token)
            # 'rewinding' only confirms direction, not a requested duration.
            if not (action in {"REWIND", "FAST_FORWARD"} and value) and observed_target(latest, planned, action, value, since=command_started):
                confirmed = True
                break
        # COMPLETED confirms a key press, but cannot prove which application opened.
        if action != "LAUNCH_APP" and provider_completed:
            confirmed = True
        label = str(device.get("label") or device.get("name") or "TV")
        if confirmed:
            message = f"{label} reports {value} is open." if action == "LAUNCH_APP" else f"{label} confirmed the {description} command."
        else:
            message = f"Sent {description} to {label}. SmartThings accepted it, but the TV has not confirmed the change."
        await audit_device_outcome(identity.user_id, "SMARTTHINGS_REMOTE", {"device_id": device_id, "action": action, "requested_count": count, "sent_count": sent, "confirmed": confirmed})
        return {"ok": True, "accepted": True, "confirmed": confirmed, "status": "confirmed" if confirmed else "accepted",
                "requested_count": count, "sent_count": sent, "message": message}

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
        code: str = Query(min_length=1, max_length=2048),
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
        device = await smartthings_request("GET", f"/devices/{device_id}", token)
        if not any(
            component.get("id") == body.component and any(cap.get("id") == body.capability for cap in component.get("capabilities") or [])
            for component in device.get("components") or []
        ):
            raise HTTPException(422, "That device component does not expose the requested SmartThings capability.")
        command_started = datetime.now(timezone.utc)
        result = await smartthings_request(
            "POST",
            f"/devices/{device_id}/commands",
            token,
            {"commands": [{
                "component": body.component,
                "capability": body.capability,
                "command": body.command,
                "arguments": body.arguments,
            }]},
        )
        await audit_device_outcome(identity.user_id, "SMARTTHINGS_COMMAND", {
            "device_id": device_id,
            "capability": body.capability,
            "command": body.command,
        })
        accepted, completed = _provider_outcome(result)
        if not accepted:
            raise HTTPException(502, "SmartThings did not acknowledge that command. Its device outcome is unconfirmed; it was not retried.")
        observed = await read_status(device_id, token)
        confirmed = observed_target(observed, {"component": body.component, "capability": body.capability, "command": body.command, "arguments": body.arguments}, since=command_started)
        if body.capability != "custom.launchapp":
            confirmed = confirmed or completed
        return {"ok": True, "accepted": True, "confirmed": confirmed,
                "status": "confirmed" if confirmed else "accepted",
                "message": "The device confirmed the command." if confirmed else "SmartThings accepted the command; the device has not confirmed the change.",
                "smartthings": result}

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
        await audit_device_outcome(identity.user_id, "SMARTTHINGS_SCENE", {"scene_id": scene_id})
        return {"ok": True, "accepted": True, "confirmed": False, "status": "accepted",
                "message": "SmartThings accepted the scene request; its device changes have not been verified.", "smartthings": result}

    return router
