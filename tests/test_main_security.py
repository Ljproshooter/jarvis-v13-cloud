import asyncio
import base64
import json
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch

from fastapi import HTTPException
from pydantic import ValidationError

import main


class SensitiveRequest:
    def __init__(self, payload: dict[str, object], *, origin: str = main.AUTH_PUBLIC_ORIGIN) -> None:
        self._raw = json.dumps(payload).encode("utf-8")
        self.headers = {
            "content-type": "application/json",
            "content-length": str(len(self._raw)),
            "origin": origin,
        }
        self.client = SimpleNamespace(host="198.51.100.12")

    async def body(self) -> bytes:
        return self._raw


def otp_token(user_id: str, issued_at: int | None = None) -> str:
    now = issued_at or int(time.time())
    claims = {
        "sub": user_id,
        "iat": now,
        "session_id": "00000000-0000-4000-8000-000000000099",
        "amr": [{"method": "otp", "timestamp": now}],
    }
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


class OwnerRecoverySecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_signup_requires_eight_characters_but_login_remains_compatible(self) -> None:
        common = {
            "email": "new@example.com",
            "username": "new_user",
            "device_id": "device-12345678",
        }
        with self.assertRaises(ValidationError):
            main.SignUpRequest(password="short7", **common)
        signup = main.SignUpRequest(password="eight888", **common)
        self.assertEqual(signup.password, "eight888")

        legacy_login = main.LoginRequest(
            identifier="legacy@example.com",
            password="old6pw",
            device_id="device-12345678",
        )
        self.assertEqual(legacy_login.password, "old6pw")

    async def test_owner_recovery_create_is_indistinguishable_and_creates_nothing(self) -> None:
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_profile_for_identifier", new=AsyncMock()) as resolve_profile,
            patch.object(main, "_rest_request", new=AsyncMock()) as rest_request,
        ):
            existing = await main._create_owner_recovery(
                "real-user@example.com", "Please reset me", "198.51.100.8"
            )
            missing = await main._create_owner_recovery(
                "missing-user@example.com", "Please reset me", "198.51.100.8"
            )

        self.assertEqual(existing, missing)
        self.assertEqual(existing.get("created"), False)
        self.assertNotIn("request_id", existing)
        self.assertNotIn("secret", existing)
        resolve_profile.assert_not_awaited()
        rest_request.assert_not_awaited()

    async def test_owner_recovery_completion_is_blocked_before_secret_or_admin_auth(self) -> None:
        body = main.RecoveryCompleteRequest(
            secret="s" * 32,
            new_password="a-new-secure-password",
        )
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.9"))

        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_recovery_request_with_secret", new=AsyncMock()) as lookup,
            patch.object(main, "_auth_admin_request", new=AsyncMock()) as admin_auth,
        ):
            with self.assertRaises(HTTPException) as raised:
                await main.complete_recovery_request(
                    "00000000-0000-0000-0000-000000000000", body, request
                )

        self.assertEqual(raised.exception.status_code, 410)
        lookup.assert_not_awaited()
        admin_auth.assert_not_awaited()

    async def test_password_reset_always_returns_generic_public_response(self) -> None:
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.10"))
        auth_request = AsyncMock(side_effect=[{}, HTTPException(status_code=429, detail="rate limited")])
        user_id = "00000000-0000-4000-8000-000000000123"

        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(
                main,
                "_profile_for_identifier",
                new=AsyncMock(
                    side_effect=[
                        {
                            "id": user_id,
                            "email": "real-user@example.com",
                            "account_status": "ACTIVE",
                        },
                        None,
                    ]
                ),
            ),
            patch.object(main, "_verified_email_proof", new=AsyncMock(return_value=True)),
            patch.object(main, "_begin_recovery_challenge", new=AsyncMock(return_value=True)) as begin,
            patch.object(main, "_auth_request", new=auth_request),
        ):
            accepted = await main.password_reset(
                main.PasswordResetRequest(identifier="real-user@example.com"), request
            )
            upstream_failure = await main.password_reset(
                main.PasswordResetRequest(identifier="missing-user@example.com"), request
            )

        self.assertEqual(accepted, upstream_failure)
        self.assertEqual(accepted, {"message": main.PASSWORD_RESET_GENERIC_MESSAGE})
        self.assertEqual(auth_request.await_count, 2)
        first = auth_request.await_args_list[0]
        self.assertEqual(first.args, ("POST", "recover"))
        self.assertEqual(first.kwargs["payload"], {"email": "real-user@example.com"})
        self.assertEqual(
            first.kwargs["params"],
            {"redirect_to": main.DEFAULT_PASSWORD_RESET_REDIRECT_URL},
        )
        self.assertTrue(
            auth_request.await_args_list[1].kwargs["payload"]["email"].endswith("@example.invalid")
        )
        begin.assert_awaited_once_with(user_id, "real-user@example.com")

    async def test_legacy_account_without_new_proof_never_receives_recovery_mail(self) -> None:
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.11"))
        auth_request = AsyncMock(return_value={})
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(
                main,
                "_profile_for_identifier",
                new=AsyncMock(return_value={
                    "id": "00000000-0000-4000-8000-000000000123",
                    "email": "legacy@example.com",
                    "account_status": "ACTIVE",
                }),
            ),
            patch.object(main, "_verified_email_proof", new=AsyncMock(return_value=False)),
            patch.object(main, "_auth_request", new=auth_request),
        ):
            response = await main.password_reset(
                main.PasswordResetRequest(identifier="legacy@example.com"), request
            )
        self.assertEqual(response, {"message": main.PASSWORD_RESET_GENERIC_MESSAGE})
        sent_email = auth_request.await_args.kwargs["payload"]["email"]
        self.assertNotEqual(sent_email, "legacy@example.com")
        self.assertTrue(sent_email.endswith("@example.invalid"))

    async def test_signup_uses_real_confirmation_and_never_creates_a_device_session(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        auth_request = AsyncMock(return_value={
            "id": user_id,
            "email": "new@example.com",
            "identities": [{"id": "identity"}],
            "user_metadata": {"lj_signup_nonce": "fixed-signup-nonce"},
        })
        body = main.SignUpRequest(
            email="new@example.com",
            password="secure-password",
            username="new_user",
            device_id="device-12345678",
        )
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.20"))
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main.secrets, "token_urlsafe", return_value="fixed-signup-nonce"),
            patch.object(main, "_auth_request", new=auth_request),
            patch.object(main, "_begin_email_proof", new=AsyncMock(return_value=True)) as begin,
            patch.object(main, "_register_device", new=AsyncMock()) as register,
            patch.object(main, "_auth_admin_request", new=AsyncMock()) as admin,
        ):
            response = await main.signup(body, request)
        self.assertEqual(response, {
            "created": True,
            "confirmation_required": True,
            "message": main.SIGNUP_CONFIRMATION_MESSAGE,
            "session": None,
        })
        auth_request.assert_awaited_once()
        self.assertEqual(auth_request.await_args.args, ("POST", "signup"))
        self.assertEqual(
            auth_request.await_args.kwargs["params"],
            {"redirect_to": main.DEFAULT_EMAIL_VERIFICATION_REDIRECT_URL},
        )
        begin.assert_awaited_once_with(
            user_id,
            "new@example.com",
            main.EMAIL_PROOF_SOURCE_SIGNUP,
            ttl_seconds=86_400,
        )
        register.assert_not_awaited()
        admin.assert_not_awaited()

    async def test_duplicate_signup_has_same_non_enumerating_contract(self) -> None:
        body = main.SignUpRequest(
            email="existing@example.com",
            password="secure-password",
            username="existing",
            device_id="device-12345678",
        )
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.21"))
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(
                main,
                "_auth_request",
                new=AsyncMock(side_effect=HTTPException(status_code=400, detail="already registered")),
            ),
            patch.object(main, "_begin_email_proof", new=AsyncMock()) as begin,
        ):
            response = await main.signup(body, request)
        self.assertTrue(response["confirmation_required"])
        self.assertIsNone(response["session"])
        self.assertNotIn("existing", response["message"].casefold())
        begin.assert_not_awaited()

    async def test_signup_fails_closed_if_supabase_auto_confirms(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        created = {
            "access_token": "validated-access-token-value",
            "user": {
                "id": user_id,
                "email": "new@example.com",
                "identities": [{"id": "identity"}],
                "user_metadata": {"lj_signup_nonce": "fixed-signup-nonce"},
            },
        }
        auth_request = AsyncMock(side_effect=[created, {}])
        admin = AsyncMock(return_value={})
        body = main.SignUpRequest(
            email="new@example.com",
            password="secure-password",
            username="new_user",
            device_id="device-12345678",
        )
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main.secrets, "token_urlsafe", return_value="fixed-signup-nonce"),
            patch.object(main, "_auth_request", new=auth_request),
            patch.object(main, "_auth_admin_request", new=admin),
        ):
            with self.assertRaises(HTTPException) as raised:
                await main.signup(body, SimpleNamespace(client=SimpleNamespace(host="198.51.100.22")))
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(auth_request.await_args_list[1].args, ("POST", "logout?scope=local"))
        admin.assert_awaited_once_with("DELETE", f"admin/users/{user_id}")

    def test_completion_pages_are_same_origin_fragment_only_and_non_persistent(self) -> None:
        reset = main._password_reset_page()
        verification = main._email_verification_page()
        for response in (reset, verification):
            html = response.body.decode("utf-8")
            self.assertIn("window.location.hash", html)
            self.assertIn("window.history.replaceState", html)
            self.assertNotIn("localStorage", html)
            self.assertNotIn("sessionStorage", html)
            self.assertNotIn("<script src=", html)
            self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
            self.assertIn("default-src 'none'", response.headers["content-security-policy"])
        self.assertIn("new_password", reset.body.decode())
        self.assertNotIn("new_password", verification.body.decode())

    def test_auth_redirects_accept_only_exact_fixed_https_cloud_pages(self) -> None:
        self.assertTrue(
            main._redirect_url_is_exact(
                main.DEFAULT_PASSWORD_RESET_REDIRECT_URL,
                main.PASSWORD_RESET_COMPLETION_PATH,
            )
        )
        for unsafe in (
            "http://jarvis-v13-cloud.onrender.com/v1/auth/password-reset/complete",
            "https://jarvis-v13-cloud.onrender.com:443/v1/auth/password-reset/complete",
            "https://jarvis-v13-cloud.onrender.com/v1/auth/password-reset/complete?token=x",
            "https://jarvis-v13-cloud.onrender.com/v1/auth/password-reset/complete#token=x",
            "https://jarvis-v13-cloud.onrender.com:bad/v1/auth/password-reset/complete",
            "https://evil.example/v1/auth/password-reset/complete",
        ):
            self.assertFalse(
                main._redirect_url_is_exact(unsafe, main.PASSWORD_RESET_COMPLETION_PATH),
                unsafe,
            )

    async def test_password_completion_uses_authenticated_user_update_only(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        challenge_id = "00000000-0000-4000-8000-000000000077"
        now = int(time.time())
        token = otp_token(user_id, now)
        password = "new-secure-password"
        challenge = {
            "challenge_id": challenge_id,
            "user_id": user_id,
            "email_hash": main._email_proof_hash("verified@example.com"),
            "requested_at": main.datetime.fromtimestamp(
                now - 10, tz=main.timezone.utc
            ).isoformat(),
            "expires_at": main.datetime.fromtimestamp(
                now + 3500, tz=main.timezone.utc
            ).isoformat(),
            "consumed_at": None,
        }
        auth_request = AsyncMock(side_effect=[
            {"id": user_id, "email": "verified@example.com"},
            {"id": user_id, "email": "verified@example.com"},
            {},
        ])
        request = SensitiveRequest({"access_token": token, "new_password": password})
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_auth_request", new=auth_request),
            patch.object(main, "_verified_email_proof", new=AsyncMock(return_value=True)),
            patch.object(main, "_recovery_challenge_row", new=AsyncMock(return_value=challenge)),
            patch.object(main, "_claim_recovery_challenge", new=AsyncMock(return_value=True)) as claim,
            patch.object(main, "_finish_recovery_challenge", new=AsyncMock(return_value=True)) as finish,
            patch.object(main, "_insert_audit", new=AsyncMock()),
            patch.object(main, "_auth_admin_request", new=AsyncMock()) as admin,
        ):
            response = await main.complete_password_reset(request)
        self.assertTrue(response["updated"])
        self.assertNotIn(token, json.dumps(response))
        self.assertNotIn(password, json.dumps(response))
        self.assertEqual(
            auth_request.await_args_list[:2],
            [
                call("GET", "user", access_token=token),
                call("PUT", "user", payload={"password": password}, access_token=token),
            ],
        )
        self.assertEqual(
            claim.await_args.args[0:3],
            (user_id, challenge_id, "verified@example.com"),
        )
        self.assertEqual(claim.await_args.args[4], "00000000-0000-4000-8000-000000000099")
        finish.assert_awaited_once_with(
            user_id, challenge_id, "00000000-0000-4000-8000-000000000099"
        )
        admin.assert_not_awaited()

    async def test_password_completion_rejects_non_recovery_session_before_update(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        challenge_id = "00000000-0000-4000-8000-000000000077"
        now = int(time.time())
        claims = {
            "sub": user_id,
            "iat": now,
            "session_id": "00000000-0000-4000-8000-000000000099",
            "amr": [{"method": "password", "timestamp": now}],
        }
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        token = f"header.{encoded}.signature"
        challenge = {
            "challenge_id": challenge_id,
            "email_hash": main._email_proof_hash("verified@example.com"),
            "requested_at": main.datetime.fromtimestamp(
                now - 10, tz=main.timezone.utc
            ).isoformat(),
            "expires_at": main.datetime.fromtimestamp(
                now + 3500, tz=main.timezone.utc
            ).isoformat(),
            "consumed_at": None,
        }
        auth_request = AsyncMock(return_value={"id": user_id, "email": "verified@example.com"})
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_auth_request", new=auth_request),
            patch.object(main, "_verified_email_proof", new=AsyncMock(return_value=True)),
            patch.object(main, "_recovery_challenge_row", new=AsyncMock(return_value=challenge)),
            patch.object(main, "_claim_recovery_challenge", new=AsyncMock()) as claim,
        ):
            with self.assertRaises(HTTPException) as raised:
                await main.complete_password_reset(
                    SensitiveRequest({"access_token": token, "new_password": "new-secure-password"})
                )
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(auth_request.await_count, 1)
        claim.assert_not_awaited()

    async def test_reset_request_cannot_replace_challenge_during_claimed_password_put(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        challenge_id = "00000000-0000-4000-8000-000000000077"
        now = int(time.time())
        token = otp_token(user_id, now)
        challenge = {
            "challenge_id": challenge_id,
            "user_id": user_id,
            "email_hash": main._email_proof_hash("verified@example.com"),
            "requested_at": main.datetime.fromtimestamp(
                now - 10, tz=main.timezone.utc
            ).isoformat(),
            "expires_at": main.datetime.fromtimestamp(
                now + 3500, tz=main.timezone.utc
            ).isoformat(),
            "consumed_at": None,
        }
        put_started = asyncio.Event()
        allow_put = asyncio.Event()
        recover_payloads: list[dict[str, object]] = []

        async def auth_request(method: str, path: str, **kwargs: object) -> dict[str, object]:
            if (method, path) == ("GET", "user"):
                return {"id": user_id, "email": "verified@example.com"}
            if (method, path) == ("PUT", "user"):
                put_started.set()
                await allow_put.wait()
                return {"id": user_id, "email": "verified@example.com"}
            if (method, path) == ("POST", "recover"):
                recover_payloads.append(dict(kwargs.get("payload") or {}))
                return {}
            if (method, path) == ("POST", "logout?scope=local"):
                return {}
            raise AssertionError((method, path))

        begin = AsyncMock(return_value=False)
        claim = AsyncMock(return_value=True)
        finish = AsyncMock(return_value=True)
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_auth_request", new=auth_request),
            patch.object(main, "_verified_email_proof", new=AsyncMock(return_value=True)),
            patch.object(main, "_recovery_challenge_row", new=AsyncMock(return_value=challenge)),
            patch.object(main, "_claim_recovery_challenge", new=claim),
            patch.object(main, "_finish_recovery_challenge", new=finish),
            patch.object(main, "_begin_recovery_challenge", new=begin),
            patch.object(
                main,
                "_profile_for_identifier",
                new=AsyncMock(return_value={
                    "id": user_id,
                    "email": "verified@example.com",
                    "account_status": "ACTIVE",
                }),
            ),
            patch.object(main, "_insert_audit", new=AsyncMock()),
        ):
            completion = asyncio.create_task(
                main.complete_password_reset(
                    SensitiveRequest({
                        "access_token": token,
                        "new_password": "new-secure-password",
                    })
                )
            )
            await asyncio.wait_for(put_started.wait(), timeout=1)
            reset_response = await main.password_reset(
                main.PasswordResetRequest(identifier="verified@example.com"),
                SimpleNamespace(client=SimpleNamespace(host="198.51.100.25")),
            )
            allow_put.set()
            completed = await asyncio.wait_for(completion, timeout=1)

        self.assertEqual(reset_response, {"message": main.PASSWORD_RESET_GENERIC_MESSAGE})
        self.assertTrue(completed["updated"])
        begin.assert_awaited_once_with(user_id, "verified@example.com")
        self.assertEqual(len(recover_payloads), 1)
        self.assertTrue(str(recover_payloads[0]["email"]).endswith("@example.invalid"))
        claim.assert_awaited_once()
        finish.assert_awaited_once_with(
            user_id, challenge_id, "00000000-0000-4000-8000-000000000099"
        )

    async def test_successful_password_put_logs_out_even_when_finalize_fails(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        challenge_id = "00000000-0000-4000-8000-000000000077"
        now = int(time.time())
        token = otp_token(user_id, now)
        auth_request = AsyncMock(side_effect=[
            {"id": user_id, "email": "verified@example.com"},
            {"id": user_id, "email": "verified@example.com"},
            {},
        ])
        challenge = {
            "challenge_id": challenge_id,
            "email_hash": main._email_proof_hash("verified@example.com"),
            "requested_at": main.datetime.fromtimestamp(
                now - 10, tz=main.timezone.utc
            ).isoformat(),
            "expires_at": main.datetime.fromtimestamp(
                now + 3500, tz=main.timezone.utc
            ).isoformat(),
            "consumed_at": None,
        }
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_auth_request", new=auth_request),
            patch.object(main, "_verified_email_proof", new=AsyncMock(return_value=True)),
            patch.object(main, "_recovery_challenge_row", new=AsyncMock(return_value=challenge)),
            patch.object(main, "_claim_recovery_challenge", new=AsyncMock(return_value=True)),
            patch.object(main, "_finish_recovery_challenge", new=AsyncMock(return_value=False)),
        ):
            with self.assertRaises(HTTPException) as raised:
                await main.complete_password_reset(
                    SensitiveRequest({
                        "access_token": token,
                        "new_password": "new-secure-password",
                    })
                )
        self.assertEqual(raised.exception.status_code, 502)
        self.assertEqual(
            auth_request.await_args_list[-1],
            call("POST", "logout?scope=local", access_token=token),
        )

    async def test_email_reverification_requires_fresh_otp_session(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        now = int(time.time())
        token = otp_token(user_id, now)
        row = {
            "user_id": user_id,
            "email_hash": main._email_proof_hash("legacy@example.com"),
            "proof_source": main.EMAIL_PROOF_SOURCE_LEGACY,
            "initiated_at": main.datetime.fromtimestamp(now - 10, tz=main.timezone.utc).isoformat(),
            "challenge_expires_at": main.datetime.fromtimestamp(now + 3500, tz=main.timezone.utc).isoformat(),
            "verified_at": None,
            "invalidated_at": None,
        }
        request = SensitiveRequest({"access_token": token})
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(
                main,
                "_auth_request",
                new=AsyncMock(side_effect=[{"id": user_id, "email": "legacy@example.com"}, {}]),
            ),
            patch.object(main, "_email_proof_row", new=AsyncMock(return_value=row)),
            patch.object(main, "_complete_email_proof", new=AsyncMock(return_value=True)) as complete,
            patch.object(main, "_insert_audit", new=AsyncMock()),
        ):
            response = await main.complete_email_verification(request)
        self.assertTrue(response["verified"])
        self.assertEqual(complete.await_args.args[0:3], (
            user_id, "legacy@example.com", main.EMAIL_PROOF_SOURCE_LEGACY
        ))
        self.assertEqual(complete.await_args.args[4], "00000000-0000-4000-8000-000000000099")

    def test_auth_security_migration_is_service_only_and_legacy_safe(self) -> None:
        sql = (
            Path(__file__).resolve().parents[1] / "LJ_AI_AUTH_SECURITY_UPDATE.sql"
        ).read_text()
        lowered = sql.lower()
        self.assertIn("lj_auth_email_proofs", sql)
        self.assertIn("legacy_reverification", lowered)
        self.assertIn("signup_confirmation", lowered)
        self.assertIn("coalesce(auth.role(), '') <> 'service_role'", lowered)
        self.assertIn("revoke all on public.lj_auth_email_proofs from public, anon, authenticated", lowered)
        self.assertIn("invalidate_lj_email_proof_on_auth_email_change", lowered)
        self.assertIn("lj_auth_recovery_challenges", lowered)
        self.assertIn("claim_lj_recovery_challenge", lowered)
        self.assertIn("finish_lj_recovery_challenge", lowered)
        self.assertIn("challenge.claimed_session_id is not null", lowered)
        self.assertIn("claim_expires_at = now() + interval '5 minutes'", lowered)
        self.assertIn("challenge.challenge_id <> p_challenge_id", lowered)
        self.assertIn("lj_auth_recovery_session_uses", lowered)
        self.assertIn("where used.session_id = p_session_id", lowered)
        self.assertIn("existing.claimed_session_id is not null", lowered)
        self.assertIn("return false;", lowered)

    def test_openai_voice_entitlement_message_matches_plan_gate(self) -> None:
        self.assertEqual(main.CEDAR_PLANS, {"BASIC", "PREMIUM", "VIP", "ADMIN"})
        source = Path(main.__file__).read_text()
        self.assertIn(
            "OpenAI voices require Basic, Premium, VIP or Administrator access.",
            source,
        )


class MobileUpdateMetadataTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_newer_android_release_is_advertised(self) -> None:
        with (
            patch.object(main, "ANDROID_LATEST_VERSION_NAME", "15.9.6"),
            patch.object(main, "ANDROID_LATEST_VERSION_CODE", "15907"),
            patch.object(
                main,
                "ANDROID_UPDATE_URL",
                "https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v15.9.6/LJ_AI_Mobile_V15.9.6.apk",
            ),
            patch.object(main, "ANDROID_UPDATE_SHA256", "a" * 64),
            patch.object(main, "ANDROID_UPDATE_NOTES", "Verified Android update."),
        ):
            response = await main.mobile_update(installed_code=15906)

        payload = json.loads(response.body)
        self.assertTrue(payload["configured"])
        self.assertTrue(payload["available"])
        self.assertEqual(payload["version_code"], 15907)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")

    async def test_android_update_is_not_offered_to_same_or_newer_install(self) -> None:
        with (
            patch.object(main, "ANDROID_LATEST_VERSION_NAME", "15.9.5"),
            patch.object(main, "ANDROID_LATEST_VERSION_CODE", "15906"),
            patch.object(
                main,
                "ANDROID_UPDATE_URL",
                "https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v15.9.5/LJ_AI_Mobile_V15.9.5.apk",
            ),
            patch.object(main, "ANDROID_UPDATE_SHA256", "b" * 64),
        ):
            response = await main.mobile_update(installed_code=15906)

        payload = json.loads(response.body)
        self.assertTrue(payload["configured"])
        self.assertFalse(payload["available"])

    async def test_untrusted_or_incomplete_android_metadata_fails_closed(self) -> None:
        with (
            patch.object(main, "ANDROID_LATEST_VERSION_NAME", "15.9.6"),
            patch.object(main, "ANDROID_LATEST_VERSION_CODE", "15907"),
            patch.object(main, "ANDROID_UPDATE_URL", "https://example.com/update.apk"),
            patch.object(main, "ANDROID_UPDATE_SHA256", "not-a-checksum"),
        ):
            response = await main.mobile_update(installed_code=15906)

        payload = json.loads(response.body)
        self.assertFalse(payload["configured"])
        self.assertFalse(payload["available"])
        self.assertEqual(payload["download_url"], "")
        self.assertEqual(payload["sha256"], "")

    def test_android_release_url_rejects_lookalikes(self) -> None:
        self.assertTrue(
            main._trusted_android_release_url(
                "https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v15.9.5/LJ_AI_Mobile_V15.9.5.apk"
            )
        )
        self.assertFalse(main._trusted_android_release_url("http://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v15.9.5/app.apk"))
        self.assertFalse(main._trusted_android_release_url("https://github.com.evil.example/Ljproshooter/jarvis-v13-cloud/releases/download/v15.9.5/app.apk"))
        self.assertFalse(main._trusted_android_release_url("https://github.com/other/repo/releases/download/v15.9.5/app.apk"))


if __name__ == "__main__":
    unittest.main()
