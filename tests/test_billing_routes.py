from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import billing_routes as billing


class BillingConfigurationTests(unittest.TestCase):
    def test_legacy_and_regional_price_configuration(self) -> None:
        values = {
            "STRIPE_DEFAULT_CURRENCY": "USD",
            "STRIPE_PRICE_BASIC_MONTHLY": "price_basic_usd",
            "STRIPE_PRICE_BASIC_MONTHLY_AUD": "price_basic_aud",
            "STRIPE_PRICE_MAP_JSON": json.dumps(
                {"VIP.YEARLY.GBP": "price_vip_gbp"}
            ),
        }
        with patch.dict(os.environ, values, clear=True):
            configured = billing._configured_prices()
        self.assertEqual(configured[("BASIC", "MONTHLY", "USD")], "price_basic_usd")
        self.assertEqual(configured[("BASIC", "MONTHLY", "AUD")], "price_basic_aud")
        self.assertEqual(configured[("VIP", "YEARLY", "GBP")], "price_vip_gbp")

    def test_one_price_id_cannot_grant_two_plans(self) -> None:
        values = {
            "STRIPE_PRICE_BASIC_MONTHLY": "price_shared",
            "STRIPE_PRICE_VIP_MONTHLY": "price_shared",
        }
        with patch.dict(os.environ, values, clear=True):
            with self.assertRaises(ValueError):
                billing._configured_prices()

    def test_recurring_intervals_match_periods(self) -> None:
        monthly = {"recurring": {"interval": "month", "interval_count": 1}}
        quarterly = {"recurring": {"interval": "month", "interval_count": 3}}
        yearly = {"recurring": {"interval": "year", "interval_count": 1}}
        self.assertTrue(billing._price_period_matches(monthly, "MONTHLY"))
        self.assertTrue(billing._price_period_matches(quarterly, "3_MONTHS"))
        self.assertTrue(billing._price_period_matches(yearly, "YEARLY"))
        self.assertFalse(billing._price_period_matches(monthly, "YEARLY"))


class BillingWebhookTests(unittest.IsolatedAsyncioTestCase):
    def test_signature_uses_raw_body_and_rejects_tampering(self) -> None:
        raw = b'{"id":"evt_test"}'
        timestamp = int(time.time())
        secret = "whsec_test"
        signature = hmac.new(
            secret.encode(),
            str(timestamp).encode() + b"." + raw,
            hashlib.sha256,
        ).hexdigest()
        header = f"t={timestamp},v1={signature}"
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": secret}, clear=True):
            self.assertTrue(billing._webhook_signature_valid(raw, header))
            self.assertFalse(billing._webhook_signature_valid(raw + b" ", header))

    def test_invoice_subscription_id_supports_current_stripe_shape(self) -> None:
        invoice = {
            "parent": {
                "subscription_details": {"subscription": "sub_current"}
            }
        }
        self.assertEqual(billing._invoice_subscription_id(invoice), "sub_current")

    async def test_configured_price_controls_plan_activation(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        sync_payload: dict[str, object] = {}

        async def rest_request(method: str, path: str, **kwargs):
            params = kwargs.get("params") or {}
            if method == "GET" and path == "lj_subscriptions":
                return [
                    {
                        "user_id": user_id,
                        "plan_key": "FREE",
                        "billing_period": "MONTHLY",
                        "status": "free",
                        "stripe_customer_id": "cus_test",
                        "stripe_subscription_id": None,
                        "stripe_price_id": None,
                        "currency": None,
                        "current_period_start": None,
                        "current_period_end": None,
                    }
                ] if "stripe_customer_id" in params else []
            if method == "GET" and path == "profiles":
                return [{"id": user_id, "role": "USER"}]
            if method == "POST" and path == "rpc/sync_lj_stripe_subscription_v2":
                sync_payload.update(kwargs["payload"])
                return True
            raise AssertionError((method, path, kwargs))

        now = int(time.time())
        event = {"id": "evt_test", "type": "customer.subscription.updated", "created": now}
        subscription = {
            "id": "sub_test",
            "customer": "cus_test",
            # Deliberately false metadata: configured Price ID must win.
            "metadata": {"user_id": user_id, "lj_plan": "VIP"},
            "status": "active",
            "current_period_start": now,
            "current_period_end": now + 2_592_000,
            "items": {
                "data": [
                    {"price": {"id": "price_basic", "currency": "usd"}}
                ]
            },
        }
        with patch.dict(
            os.environ,
            {"STRIPE_PRICE_BASIC_MONTHLY": "price_basic"},
            clear=True,
        ):
            await billing._sync_subscription(
                rest_request, event, subscription, reconcile_sequence=17
            )

        self.assertEqual(sync_payload["p_plan_key"], "BASIC")
        self.assertEqual(sync_payload["p_billing_period"], "MONTHLY")
        self.assertEqual(sync_payload["p_user_id"], user_id)
        self.assertEqual(sync_payload["p_reconcile_sequence"], 17)

    async def test_unconfigured_price_cannot_activate_metadata_plan(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"

        async def rest_request(method: str, path: str, **kwargs):
            params = kwargs.get("params") or {}
            if method == "GET" and path == "lj_subscriptions":
                return [
                    {
                        "user_id": user_id,
                        "plan_key": "FREE",
                        "billing_period": "MONTHLY",
                        "status": "free",
                        "stripe_customer_id": "cus_test",
                        "stripe_subscription_id": None,
                        "stripe_price_id": None,
                        "currency": None,
                        "current_period_start": None,
                        "current_period_end": None,
                    }
                ] if "stripe_customer_id" in params else []
            if method == "GET" and path == "profiles":
                return [{"id": user_id, "role": "USER"}]
            raise AssertionError((method, path, kwargs))

        now = int(time.time())
        event = {"id": "evt_test", "type": "customer.subscription.updated", "created": now}
        subscription = {
            "id": "sub_test",
            "customer": "cus_test",
            "metadata": {"user_id": user_id, "lj_plan": "VIP"},
            "status": "active",
            "current_period_start": now,
            "current_period_end": now + 2_592_000,
            "items": {"data": [{"price": {"id": "price_unknown", "currency": "usd"}}]},
        }
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                await billing._sync_subscription(
                    rest_request, event, subscription, reconcile_sequence=18
                )

    def test_subscription_requires_one_item_at_quantity_one(self) -> None:
        good = {
            "items": {
                "data": [
                    {"quantity": 1, "price": {"id": "price_basic", "currency": "usd"}}
                ]
            }
        }
        self.assertEqual(billing._subscription_price_id(good), ("price_basic", "USD"))
        doubled = {
            "items": {
                "data": [
                    {"quantity": 2, "price": {"id": "price_basic", "currency": "usd"}}
                ]
            }
        }
        self.assertEqual(billing._subscription_price_id(doubled), (None, None))
        multiple = {
            "items": {
                "data": [
                    {"quantity": 1, "price": {"id": "price_basic", "currency": "usd"}},
                    {"quantity": 1, "price": {"id": "price_other", "currency": "usd"}},
                ]
            }
        }
        self.assertEqual(billing._subscription_price_id(multiple), (None, None))

    async def test_open_checkout_is_reused_only_for_exact_server_choice(self) -> None:
        session = {
            "id": "cs_test",
            "url": "https://checkout.stripe.com/c/pay/cs_test",
            "mode": "subscription",
            "status": "open",
            "customer": "cus_test",
            "client_reference_id": "00000000-0000-4000-8000-000000000123",
            "metadata": {
                "lj_plan": "BASIC",
                "lj_period": "MONTHLY",
                "lj_currency": "USD",
                "lj_price_id": "price_basic",
            },
        }

        async def stripe_request(method: str, path: str, **_kwargs):
            self.assertEqual((method, path), ("GET", "checkout/sessions/cs_test"))
            return session

        with patch.object(billing, "_stripe_request", stripe_request):
            reused = await billing._reuse_or_retire_checkout(
                existing={"checkout_session_id": "cs_test"},
                user_id=session["client_reference_id"],
                customer_id="cus_test",
                plan="BASIC",
                period="MONTHLY",
                currency="USD",
                price_id="price_basic",
            )
        self.assertEqual(reused, {"checkout_url": session["url"], "session_id": "cs_test"})

    def test_checkout_generation_does_not_trust_client_request_ids(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        first = billing._checkout_generation_key(user_id, None)
        self.assertEqual(first, billing._checkout_generation_key(user_id, None))
        self.assertNotEqual(first, billing._checkout_generation_key(user_id, "cs_previous"))

    async def test_reconcile_lease_is_claimed_before_stripe_snapshot(self) -> None:
        calls: list[str] = []

        async def rest_request(method: str, path: str, **kwargs):
            self.assertEqual(
                (method, path),
                ("POST", "rpc/claim_lj_billing_reconcile_lease"),
            )
            self.assertEqual(kwargs["payload"]["p_subscription_id"], "sub_test")
            self.assertRegex(kwargs["payload"]["p_lock_token"], r"^[0-9a-f]{64}$")
            calls.append("claim")
            return [{"acquired": True, "reconcile_sequence": 42}]

        async def stripe_request(method: str, path: str, **_kwargs):
            self.assertEqual((method, path), ("GET", "subscriptions/sub_test"))
            calls.append("fetch")
            return {"id": "sub_test", "customer": "cus_test"}

        with patch.object(billing, "_stripe_request", stripe_request):
            lock_token, sequence, snapshot = await billing._retrieve_subscription_for_sync(
                rest_request, "sub_test"
            )
        self.assertEqual(calls, ["claim", "fetch"])
        self.assertRegex(lock_token, r"^[0-9a-f]{64}$")
        self.assertEqual(sequence, 42)
        self.assertEqual(snapshot["id"], "sub_test")

    async def test_busy_reconcile_lease_fails_closed(self) -> None:
        async def rest_request(_method: str, _path: str, **_kwargs):
            return [{"acquired": False, "reconcile_sequence": 0}]

        with self.assertRaises(billing.HTTPException) as raised:
            await billing._claim_reconcile_lease(rest_request, "sub_test")
        self.assertEqual(raised.exception.status_code, 503)

    async def test_reconcile_lease_wraps_entitlement_sync(self) -> None:
        calls: list[str] = []

        async def rest_request(*_args, **_kwargs):
            raise AssertionError("raw REST should be mocked by the lease helpers")

        async def retrieve(_rest, subscription_id):
            self.assertEqual(subscription_id, "sub_test")
            calls.append("claim-and-fetch")
            return "a" * 64, 51, {"id": "sub_test", "customer": "cus_test"}

        async def sync(_rest, event, subscription, *, reconcile_sequence, fallback_user_id=None):
            self.assertEqual(event["id"], "evt_test")
            self.assertEqual(subscription["id"], "sub_test")
            self.assertEqual(reconcile_sequence, 51)
            self.assertIsNone(fallback_user_id)
            calls.append("sync")

        async def finish(_rest, subscription_id, token):
            self.assertEqual((subscription_id, token), ("sub_test", "a" * 64))
            calls.append("release")

        with (
            patch.object(billing, "_retrieve_subscription_for_sync", retrieve),
            patch.object(billing, "_sync_subscription", sync),
            patch.object(billing, "_finish_reconcile_lease", finish),
        ):
            await billing._sync_subscription_with_lease(
                rest_request,
                {"id": "evt_test", "type": "invoice.paid"},
                "sub_test",
            )
        self.assertEqual(calls, ["claim-and-fetch", "sync", "release"])

    async def test_webhook_never_grants_from_unbound_metadata(self) -> None:
        async def rest_request(method: str, path: str, **_kwargs):
            if method == "GET" and path == "lj_subscriptions":
                return []
            raise AssertionError((method, path, _kwargs))

        with self.assertRaises(RuntimeError):
            await billing._resolve_webhook_user(
                rest_request,
                {
                    "id": "sub_unbound",
                    "customer": "cus_unbound",
                    "metadata": {"user_id": "00000000-0000-4000-8000-000000000123"},
                },
            )

    def test_sql_migration_contains_ordering_leases_and_profile_guard(self) -> None:
        sql = (Path(__file__).resolve().parents[1] / "LJ_AI_STRIPE_BILLING_UPDATE.sql").read_text()
        self.assertIn("next_lj_billing_reconcile_sequence", sql)
        self.assertIn("last_reconcile_sequence", sql)
        self.assertIn("lj_billing_reconcile_locks", sql)
        self.assertIn("claim_lj_billing_reconcile_lease", sql)
        self.assertIn("finish_lj_billing_reconcile_lease", sql)
        self.assertIn("an active billing reconciliation lease is required", sql.lower())
        self.assertIn("claim_lj_checkout_lease", sql)
        self.assertIn("finish_lj_checkout_lease", sql)
        self.assertIn("before insert or update on public.profiles", sql.lower())
        self.assertIn("new lj ai profiles cannot assign a role or paid plan", sql.lower())
        self.assertIn("lj ai role and plan fields are server managed", sql.lower())
        self.assertIn("sync_lj_stripe_subscription_v2", sql)


class BillingSubscriptionPrivacyTests(unittest.IsolatedAsyncioTestCase):
    async def test_subscription_response_exposes_only_user_facing_fields(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"

        async def rest_request(method: str, path: str, **kwargs):
            self.assertEqual((method, path), ("GET", "lj_subscriptions"))
            selected = set(str(kwargs["params"]["select"]).split(","))
            self.assertNotIn("*", selected)
            self.assertNotIn("stripe_subscription_id", selected)
            self.assertNotIn("checkout_session_id", selected)
            self.assertNotIn("checkout_lock_token", selected)
            return [{
                "plan_key": "VIP",
                "billing_period": "YEARLY",
                "status": "active",
                "currency": "usd",
                "current_period_start": "2099-01-01T00:00:00+00:00",
                "current_period_end": "2099-12-31T00:00:00+00:00",
                "cancel_at_period_end": False,
                "canceled_at": None,
                "ended_at": None,
                "stripe_customer_id": "cus_private",
                # Even a permissive/misbehaving REST wrapper must not leak these.
                "stripe_subscription_id": "sub_private",
                "stripe_price_id": "price_private",
                "checkout_session_id": "cs_private",
                "latest_invoice_id": "in_private",
                "checkout_lock_token": "secret-lock",
                "last_reconcile_sequence": 99,
            }]

        async def unused(*_args, **_kwargs):
            return None

        router = billing.create_billing_router(
            current_identity=unused,
            rest_request=rest_request,
            insert_audit=unused,
            require_verified_email=unused,
        )
        endpoint = next(
            route.endpoint for route in router.routes
            if route.path == "/v1/billing/subscription"
        )
        response = await endpoint({"user_id": user_id, "role": "USER"})

        self.assertEqual(response["effective_plan"], "VIP")
        self.assertEqual(response["currency"], "USD")
        self.assertTrue(response["managed_by_stripe"])
        self.assertTrue(response["can_manage"])
        private_fields = {
            "user_id", "stripe_customer_id", "stripe_subscription_id",
            "stripe_price_id", "checkout_session_id", "latest_invoice_id",
            "checkout_lock_token", "checkout_lock_expires_at",
            "last_stripe_event_created", "last_reconcile_sequence",
        }
        self.assertTrue(private_fields.isdisjoint(response))


class BillingCheckoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_checkout_uses_lease_and_server_price_with_stable_idempotency(self) -> None:
        user_id = "00000000-0000-4000-8000-000000000123"
        captured: dict[str, object] = {}

        async def unused(*_args, **_kwargs):
            return None

        async def validated(*_args, **_kwargs):
            return {}

        async def ensure_customer(*_args, **_kwargs):
            return "cus_test", {
                "stripe_customer_id": "cus_test",
                "status": "free",
                "checkout_session_id": None,
            }

        async def claim(*_args, **_kwargs):
            captured["leased"] = True
            return {
                "acquired": True,
                "stripe_customer_id": "cus_test",
                "status": "free",
                "checkout_session_id": None,
            }

        async def reuse(**_kwargs):
            return None

        async def stripe_request(method: str, path: str, **kwargs):
            self.assertEqual((method, path), ("POST", "checkout/sessions"))
            captured["form"] = kwargs["data"]
            captured["idempotency_key"] = kwargs["idempotency_key"]
            return {
                "id": "cs_new",
                "url": "https://checkout.stripe.com/c/pay/cs_new",
            }

        async def finish(_rest, _user, _token, *, checkout_session_id=None):
            captured["finished"] = checkout_session_id

        router = billing.create_billing_router(
            current_identity=unused,
            rest_request=unused,
            insert_audit=unused,
            require_verified_email=unused,
        )
        endpoint = next(
            route.endpoint for route in router.routes
            if route.path == "/v1/billing/checkout"
        )
        environment = {
            "STRIPE_SECRET_KEY": "sk_test_example",
            "STRIPE_PRICE_BASIC_MONTHLY": "price_basic",
            "STRIPE_DEFAULT_CURRENCY": "USD",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(billing, "_validated_price", validated),
            patch.object(billing, "_ensure_customer", ensure_customer),
            patch.object(billing, "_claim_checkout_lease", claim),
            patch.object(billing, "_reuse_or_retire_checkout", reuse),
            patch.object(billing, "_stripe_request", stripe_request),
            patch.object(billing, "_finish_checkout_lease", finish),
        ):
            response = await endpoint(
                billing.CheckoutRequest(
                    plan="BASIC",
                    period="MONTHLY",
                    request_id="attacker_can_change_this",
                ),
                {"user_id": user_id, "email": "user@example.com", "role": "USER"},
            )

        self.assertTrue(captured["leased"])
        self.assertEqual(captured["finished"], "cs_new")
        form = captured["form"]
        self.assertEqual(form["line_items[0][price]"], "price_basic")
        self.assertNotIn("amount", form)
        self.assertEqual(
            captured["idempotency_key"],
            billing._checkout_generation_key(user_id, None),
        )
        self.assertEqual(response["session_id"], "cs_new")

    async def test_checkout_requires_verified_email_before_stripe(self) -> None:
        calls: list[str] = []

        async def unused(*_args, **_kwargs):
            raise AssertionError("checkout must stop before downstream work")

        async def require_verified_email(identity):
            self.assertEqual(identity["user_id"], "00000000-0000-4000-8000-000000000123")
            calls.append("proof")
            raise billing.HTTPException(
                status_code=403,
                detail={"code": "verification_required"},
            )

        router = billing.create_billing_router(
            current_identity=unused,
            rest_request=unused,
            insert_audit=unused,
            require_verified_email=require_verified_email,
        )
        endpoint = next(
            route.endpoint for route in router.routes
            if route.path == "/v1/billing/checkout"
        )
        with self.assertRaises(billing.HTTPException) as raised:
            await endpoint(
                billing.CheckoutRequest(plan="BASIC", period="MONTHLY"),
                {
                    "user_id": "00000000-0000-4000-8000-000000000123",
                    "email": "legacy@example.com",
                    "role": "USER",
                },
            )
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "verification_required")
        self.assertEqual(calls, ["proof"])


if __name__ == "__main__":
    unittest.main()
