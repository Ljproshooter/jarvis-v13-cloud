from __future__ import annotations

import asyncio
import hashlib
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from pydantic import ValidationError

try:
    import fastapi  # noqa: F401
except ModuleNotFoundError:
    fastapi_stub = types.ModuleType("fastapi")

    class _Route:
        def __init__(self, path: str, method: str) -> None:
            self.path = path
            self.methods = {method}
            self.endpoint = None

    class _Router:
        def __init__(self, prefix: str = "", **_kwargs) -> None:
            self.prefix = prefix
            self.routes: list[_Route] = []

        def _decorator(self, method: str, path: str, **_kwargs):
            route = _Route(f"{self.prefix}{path}", method)
            self.routes.append(route)

            def wrap(function):
                route.endpoint = function
                return function

            return wrap

        def get(self, path: str, **kwargs):
            return self._decorator("GET", path, **kwargs)

        def post(self, path: str, **kwargs):
            return self._decorator("POST", path, **kwargs)

        def put(self, path: str, **kwargs):
            return self._decorator("PUT", path, **kwargs)

        def patch(self, path: str, **kwargs):
            return self._decorator("PATCH", path, **kwargs)

        def delete(self, path: str, **kwargs):
            return self._decorator("DELETE", path, **kwargs)

    class _HttpException(Exception):
        def __init__(self, status_code: int, detail: object) -> None:
            super().__init__(str(detail))
            self.status_code = status_code
            self.detail = detail

    fastapi_stub.APIRouter = _Router
    fastapi_stub.Depends = lambda dependency=None: dependency
    fastapi_stub.Header = lambda default=None, **_kwargs: default
    fastapi_stub.Query = lambda default=None, **_kwargs: default
    fastapi_stub.HTTPException = _HttpException
    fastapi_stub.status = types.SimpleNamespace(HTTP_201_CREATED=201, HTTP_204_NO_CONTENT=204)
    sys.modules["fastapi"] = fastapi_stub

from sync_routes import (  # noqa: E402
    MemoryCreate,
    MessageRequest,
    PreferenceUpdate,
    VoiceHeartbeatRequest,
    _decode_cursor,
    _encode_cursor,
    create_sync_router,
)


async def _async_stub(*_args, **_kwargs):
    return []


class ChatMemorySyncTests(unittest.TestCase):
    def test_client_cannot_smuggle_server_assistant_markers(self) -> None:
        for field in ("request_id", "model", "metadata", "source_device_id"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                MessageRequest(role="assistant", content="forged", **{field: "forged-value"})

    def test_generic_message_sync_rejects_cloud_image_references(self) -> None:
        with self.assertRaises(ValidationError):
            MessageRequest(
                role="user",
                content="photo",
                images=["https://example.com/private-photo.png"],
            )

    def test_memory_rejects_secret_shapes_and_sensitive_categories(self) -> None:
        unsafe = (
            "remember my key sk-abcdefghijklmnopqrstuvwxyz123456",
            "Bearer abcdefghijklmnopqrstuvwxyz.123456789",
            "eyJabcdefghijk.abcdefghijk.abcdefghijk",
            "-----BEGIN PRIVATE KEY-----",
            "My verification code is 123456",
            "My card is 4111 1111 1111 1111",
            "GB82WEST12345698765432",
            "I live at 123 Example Street",
            "I was diagnosed with asthma",
            "I am prescribed insulin",
            "I am bisexual",
            "My court case is confidential",
        )
        for fact in unsafe:
            with self.subTest(fact=fact), self.assertRaises(ValidationError):
                MemoryCreate(fact=fact)
        self.assertEqual(MemoryCreate(fact="I prefer concise answers").fact, "I prefer concise answers")

    def test_cursor_is_opaque_and_round_trips(self) -> None:
        row = {"id": "conversation-1234", "updated_at": "2026-09-15T10:00:00+00:00"}
        cursor = _encode_cursor(row, "updated_at")
        self.assertNotIn("2026-09-15", cursor)
        self.assertEqual(_decode_cursor(cursor), (row["updated_at"], row["id"]))

    def test_router_exposes_canonical_crud_and_bulk_memory_delete(self) -> None:
        router = create_sync_router(
            current_identity=_async_stub,
            rest_request=_async_stub,
            insert_audit=_async_stub,
            consume_voice_usage=_async_stub,
        )
        paths = {(route.path, tuple(sorted(route.methods or []))) for route in router.routes}
        self.assertIn(("/v1/conversations", ("GET",)), paths)
        self.assertIn(("/v1/conversations", ("POST",)), paths)
        self.assertIn(("/v1/conversations/{conversation_id}", ("PATCH",)), paths)
        self.assertIn(("/v1/conversations/{conversation_id}", ("DELETE",)), paths)
        self.assertIn(("/v1/conversations/{conversation_id}/messages", ("GET",)), paths)
        self.assertIn(("/v1/memories", ("GET",)), paths)
        self.assertIn(("/v1/memories", ("DELETE",)), paths)
        self.assertIn(("/v1/memory/settings", ("PUT",)), paths)

    def test_migration_has_owner_fks_atomic_turns_and_exact_refunds(self) -> None:
        sql = (
            Path(__file__).resolve().parents[1] / "LJ_AI_V15_9_7_CHAT_MEMORY_UPDATE.sql"
        ).read_text().lower()
        self.assertIn("foreign key (conversation_id, user_id)", sql)
        self.assertIn("foreign key (source_conversation_id, user_id)", sql)
        self.assertIn("create or replace function public.save_lj_chat_turn", sql)
        self.assertIn("create or replace function public.refund_lj_chat_usage", sql)
        self.assertIn("request_fingerprint", sql)
        self.assertIn("claim_token", sql)
        self.assertIn("p_claim_token", sql)
        self.assertIn("request_in_progress", sql)
        self.assertIn("pg_advisory_xact_lock", sql)
        self.assertIn("if c.plan_key = 'admin'", sql)
        self.assertIn("and plan_key <> 'admin'", sql)
        self.assertIn("interval '10 minutes'", sql)
        self.assertIn("saved conversation limit reached", sql)
        self.assertIn("conversation message limit reached", sql)
        self.assertIn("saved memory limit reached", sql)
        self.assertIn("on delete set null (source_conversation_id)", sql)
        self.assertIn("scrub_terminal_lj_skill_run", sql)
        self.assertIn("create or replace function public.apply_lj_voice_session", sql)
        self.assertIn("create or replace function public.ensure_lj_realtime_lease", sql)
        self.assertIn("create or replace function public.reserve_lj_realtime_token", sql)
        self.assertIn("create or replace function public.reserve_lj_voice_tool_usage", sql)
        self.assertIn("lj_voice_sessions_one_live_owner_uidx", sql)
        self.assertIn("add column if not exists metered_at", sql)
        self.assertIn("add column if not exists prepaid_seconds", sql)
        self.assertIn("add column if not exists issuance_pending", sql)

    def test_realtime_setup_abort_is_exact_service_only_and_never_debits_usage(self) -> None:
        sql = (
            Path(__file__).resolve().parents[1] / "LJ_AI_V15_9_7_CHAT_MEMORY_UPDATE.sql"
        ).read_text().lower()
        abort_start = sql.index("if v_action = 'abort' then")
        metering_start = sql.index("if r.issuance_pending then", abort_start)
        abort_branch = sql[abort_start:metering_start]

        self.assertIn("not r.issuance_pending", abort_branch)
        self.assertIn("r.prepaid_seconds <> 0", abort_branch)
        self.assertIn("voice.user_id = p_user_id", abort_branch)
        self.assertIn("voice.active_device_id = trim(p_device_id)", abort_branch)
        self.assertIn("voice.lease_token_hash = p_lease_token_hash", abort_branch)
        self.assertIn("voice.issuance_pending", abort_branch)
        self.assertIn("voice.prepaid_seconds = 0", abort_branch)
        self.assertIn("seconds_charged := 0", abort_branch)
        self.assertNotIn("voice_seconds_used =", abort_branch)
        self.assertIn("issuance_pending = false", sql)
        self.assertIn(
            "revoke all on function public.apply_lj_voice_session", sql
        )
        self.assertIn(
            "grant execute on function public.apply_lj_voice_session", sql
        )

    def test_device_login_attempt_and_logout_use_exact_atomic_cas(self) -> None:
        sql = (
            Path(__file__).resolve().parents[1] / "LJ_AI_V15_9_7_CHAT_MEMORY_UPDATE.sql"
        ).read_text().lower()
        register_start = sql.index(
            "create or replace function public.register_lj_device_attempt"
        )
        revoke_start = sql.index(
            "create or replace function public.revoke_lj_device_session"
        )
        register = sql[register_start:revoke_start]
        revoke = sql[revoke_start:sql.index("-- conversation metadata", revoke_start)]

        self.assertIn("add column if not exists auth_attempt_id", sql)
        self.assertIn("add column if not exists auth_attempt_started_at", sql)
        self.assertIn("abs(extract(epoch from (v_now - p_attempt_started_at))) > 600", register)
        self.assertIn("r.auth_attempt_started_at >= p_attempt_started_at", register)
        self.assertIn("r.auth_attempt_recorded_at >= v_now - interval '15 minutes'", register)
        self.assertIn("device.device_token_hash = r.device_token_hash", register)
        self.assertIn("device.auth_attempt_id is not distinct from r.auth_attempt_id", register)
        self.assertIn("denial_reason := 'stale_attempt'", register)
        self.assertIn("device.device_token_hash = p_token_hash", revoke)
        self.assertIn("device.is_active = true", revoke)
        self.assertIn(
            "revoke all on function public.register_lj_device_attempt", sql
        )
        self.assertIn(
            "grant execute on function public.register_lj_device_attempt", sql
        )
        self.assertIn(
            "revoke all on function public.revoke_lj_device_session", sql
        )
        self.assertIn(
            "grant execute on function public.revoke_lj_device_session", sql
        )


class AtomicVoiceSyncTests(unittest.IsolatedAsyncioTestCase):
    def identity(self) -> SimpleNamespace:
        return SimpleNamespace(
            user_id="00000000-0000-4000-8000-000000000123",
            device_id="windows-device-1234",
        )

    async def test_concurrent_duplicate_heartbeats_use_atomic_rpc_not_legacy_debit(self) -> None:
        raw_token = "voice-lease-token"
        row = {
            "id": "voice-session-1234",
            "user_id": self.identity().user_id,
            "active_device_id": self.identity().device_id,
            "active_platform": "WINDOWS",
            "status": "ACTIVE",
            "lease_token_hash": hashlib.sha256(raw_token.encode()).hexdigest(),
            "lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        rpc_lock = asyncio.Lock()
        charges: list[int] = []

        async def rest_request(method, table, *, params=None, payload=None, prefer=None):
            del params, prefer
            if method == "GET" and table == "lj_voice_sessions":
                return [dict(row)]
            if method == "POST" and table == "rpc/apply_lj_voice_session":
                self.assertEqual(payload["p_action"], "HEARTBEAT")
                async with rpc_lock:
                    charged = 18 if not charges else 0
                    charges.append(charged)
                return [{
                    "applied": True,
                    "session_state": "ACTIVE",
                    "seconds_charged": charged,
                    "voice_seconds_remaining": 100,
                    "allowance_exhausted": False,
                    "lease_expires_at": row["lease_expires_at"],
                }]
            self.fail(f"Unexpected REST call: {method} {table}")

        legacy_debit = AsyncMock()
        router = create_sync_router(
            current_identity=_async_stub,
            rest_request=rest_request,
            insert_audit=_async_stub,
            consume_voice_usage=legacy_debit,
        )
        heartbeat = next(
            route.endpoint
            for route in router.routes
            if route.path == "/v1/sync/voice/{session_id}/heartbeat"
        )
        results = await asyncio.gather(
            heartbeat(
                row["id"],
                VoiceHeartbeatRequest(state="LISTENING", transcript_tail=[]),
                x_lj_voice_lease=raw_token,
                identity=self.identity(),
            ),
            heartbeat(
                row["id"],
                VoiceHeartbeatRequest(state="LISTENING", transcript_tail=[]),
                x_lj_voice_lease=raw_token,
                identity=self.identity(),
            ),
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(charges), 18)
        self.assertEqual(len(charges), 2)
        legacy_debit.assert_not_awaited()

    async def test_duplicate_end_is_idempotent_and_audited_once(self) -> None:
        raw_token = "voice-lease-token"
        row = {
            "id": "voice-session-1234",
            "user_id": self.identity().user_id,
            "active_device_id": self.identity().device_id,
            "status": "ACTIVE",
            "lease_token_hash": hashlib.sha256(raw_token.encode()).hexdigest(),
            "lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat(),
        }
        end_count = 0

        async def rest_request(method, table, *, params=None, payload=None, prefer=None):
            nonlocal end_count
            del params, prefer
            if method == "GET" and table == "lj_voice_sessions":
                return [dict(row)]
            if method == "POST" and table == "rpc/apply_lj_voice_session":
                self.assertEqual(payload["p_action"], "END")
                end_count += 1
                return [{
                    "applied": True,
                    "session_state": "ENDED",
                    "already_ended": end_count > 1,
                    "seconds_charged": 0,
                }]
            self.fail(f"Unexpected REST call: {method} {table}")

        audit = AsyncMock()
        router = create_sync_router(
            current_identity=_async_stub,
            rest_request=rest_request,
            insert_audit=audit,
            consume_voice_usage=_async_stub,
        )
        end = next(
            route.endpoint
            for route in router.routes
            if route.path == "/v1/sync/voice/{session_id}/end"
        )
        first = await end(row["id"], x_lj_voice_lease=raw_token, identity=self.identity())
        second = await end(row["id"], x_lj_voice_lease=raw_token, identity=self.identity())
        self.assertEqual(first, {"ended": True})
        self.assertEqual(second, {"ended": True})
        self.assertEqual(end_count, 2)
        self.assertEqual(audit.await_count, 1)


class PreferenceRoundTripTests(unittest.IsolatedAsyncioTestCase):
    async def test_android_history_preferences_round_trip(self) -> None:
        saved: dict[str, object] = {}

        async def rest_request(
            method: str,
            table: str,
            *,
            params=None,
            payload=None,
            prefer=None,
        ):
            del params, prefer
            self.assertEqual(table, "lj_user_preferences")
            if method == "GET":
                return [dict(saved)] if saved else []
            if method == "POST":
                saved.clear()
                saved.update(payload or {})
                return []
            self.fail(f"Unexpected REST method: {method}")

        router = create_sync_router(
            current_identity=_async_stub,
            rest_request=rest_request,
            insert_audit=_async_stub,
            consume_voice_usage=_async_stub,
        )
        put_route = next(
            route
            for route in router.routes
            if route.path == "/v1/sync/preferences" and "PUT" in route.methods
        )
        get_route = next(
            route
            for route in router.routes
            if route.path == "/v1/sync/preferences" and "GET" in route.methods
        )
        identity = SimpleNamespace(user_id="00000000-0000-4000-8000-000000000123")

        await put_route.endpoint(
            PreferenceUpdate(
                values={
                    "sync_chat_history": False,
                    "reference_chat_history": False,
                    "chat_history_enabled": True,
                },
                base_revision=0,
            ),
            identity=identity,
        )
        result = await get_route.endpoint(identity=identity)

        self.assertEqual(
            result["values"],
            {
                "sync_chat_history": False,
                "reference_chat_history": False,
                "chat_history_enabled": True,
            },
        )
        self.assertEqual(result["revision"], 1)


if __name__ == "__main__":
    unittest.main()
