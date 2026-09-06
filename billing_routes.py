"""Server-controlled Stripe Billing for LJ AI.

The clients choose only a catalog plan, billing period, and optional display
currency. They never submit an amount or grant themselves an entitlement.
Stripe Price IDs configured on the server are the source of truth, and a
verified Stripe webhook is the only path that activates a paid plan.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator


PAID_PLANS = {"BASIC", "PREMIUM", "VIP"}
BILLING_PERIODS = {"MONTHLY", "3_MONTHS", "YEARLY"}
ENTITLED_STATUSES = {"active", "trialing"}
SUBSCRIPTION_EVENTS = {
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.paused",
    "customer.subscription.resumed",
    "customer.subscription.pending_update_applied",
    "customer.subscription.pending_update_expired",
}
INVOICE_EVENTS = {
    "invoice.paid",
    "invoice.payment_succeeded",
    "invoice.payment_failed",
    "invoice.voided",
    "invoice.marked_uncollectible",
}
CHECKOUT_EVENTS = {
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "checkout.session.async_payment_failed",
}
PRICE_ENV = {
    (plan, period): f"STRIPE_PRICE_{plan}_{period}"
    for plan in sorted(PAID_PLANS)
    for period in sorted(BILLING_PERIODS)
}
PRICE_ENV_PATTERN = re.compile(
    r"^STRIPE_PRICE_(BASIC|PREMIUM|VIP)_(MONTHLY|3_MONTHS|YEARLY)_([A-Z]{3})$"
)

PLAN_CATALOG: dict[str, dict[str, Any]] = {
    "FREE": {
        "name": "Free",
        "periods": {"MONTHLY": 0.0},
        "text": 25,
        "images": 3,
        "voice_seconds": 0,
        "refills": 0,
    },
    "BASIC": {
        "name": "Basic",
        "periods": {"MONTHLY": 15.0, "3_MONTHS": 45.0, "YEARLY": 171.0},
        "text": {"MONTHLY": 1500, "3_MONTHS": 4500, "YEARLY": 18250},
        "images": {"MONTHLY": 60, "3_MONTHS": 180, "YEARLY": 730},
        "voice_seconds": {"MONTHLY": 5400, "3_MONTHS": 16200, "YEARLY": 74100},
        "refills": {"MONTHLY": 0, "3_MONTHS": 0, "YEARLY": 1},
    },
    "PREMIUM": {
        "name": "Premium",
        "periods": {"MONTHLY": 24.99, "3_MONTHS": 74.97, "YEARLY": 284.89},
        "text": {"MONTHLY": 3000, "3_MONTHS": 9000, "YEARLY": 36500},
        "images": {"MONTHLY": 150, "3_MONTHS": 450, "YEARLY": 1825},
        "voice_seconds": {"MONTHLY": 18000, "3_MONTHS": 108000, "YEARLY": 219000},
        "refills": {"MONTHLY": 0, "3_MONTHS": 0, "YEARLY": 2},
    },
    "VIP": {
        "name": "VIP",
        "periods": {"MONTHLY": 59.99, "3_MONTHS": 179.97, "YEARLY": 683.89},
        "text": {"MONTHLY": 3000, "3_MONTHS": 9000, "YEARLY": 36500},
        "images": {"MONTHLY": 300, "3_MONTHS": 900, "YEARLY": 3650},
        "voice_seconds": {"MONTHLY": 36000, "3_MONTHS": 108000, "YEARLY": 438000},
        "refills": {"MONTHLY": 0, "3_MONTHS": 0, "YEARLY": 5},
        "three_month_refills_on_request": True,
    },
}

# Stripe Price amounts are immutable. Checking the configured USD Prices here
# catches a swapped or mistyped Price ID before a customer can be charged the
# wrong amount for an LJ AI entitlement. Regional Prices are merchant-managed
# and are still checked for currency, recurrence, and licensed (not metered)
# usage below.
EXPECTED_USD_CENTS: dict[tuple[str, str], int] = {
    ("BASIC", "MONTHLY"): 1_500,
    ("BASIC", "3_MONTHS"): 4_500,
    ("BASIC", "YEARLY"): 17_100,
    ("PREMIUM", "MONTHLY"): 2_499,
    ("PREMIUM", "3_MONTHS"): 7_497,
    ("PREMIUM", "YEARLY"): 28_489,
    ("VIP", "MONTHLY"): 5_999,
    ("VIP", "3_MONTHS"): 17_997,
    ("VIP", "YEARLY"): 68_389,
}

TERMINAL_SUBSCRIPTION_STATUSES = {"canceled", "incomplete_expired"}
FREE_SUBSCRIPTION_STATUSES = {"", "free"}


class CheckoutRequest(BaseModel):
    plan: str = Field(min_length=3, max_length=20)
    period: str = Field(min_length=3, max_length=20)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    request_id: str | None = Field(default=None, min_length=8, max_length=100)

    @field_validator("plan", "period")
    @classmethod
    def normalise_choice(cls, value: str) -> str:
        return _normalise(value)

    @field_validator("currency")
    @classmethod
    def normalise_currency(cls, value: str | None) -> str | None:
        if value is None:
            return None
        result = value.strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", result):
            raise ValueError("Currency must be a three-letter ISO currency code.")
        return result

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        result = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,100}", result):
            raise ValueError("request_id contains unsupported characters.")
        return result


def _identity_value(identity: Any, key: str, default: Any = "") -> Any:
    return identity.get(key, default) if isinstance(identity, dict) else getattr(identity, key, default)


def _normalise(value: str) -> str:
    cleaned = value.strip().upper().replace("-", "_").replace(" ", "_")
    return {
        "PREMIUM_PLUS": "PREMIUM",
        "1_MONTH": "MONTHLY",
        "3_MONTH": "3_MONTHS",
        "12_MONTHS": "YEARLY",
    }.get(cleaned, cleaned)


def _truthy_environment(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _default_currency() -> str:
    value = os.getenv("STRIPE_DEFAULT_CURRENCY", "USD").strip().upper()
    return value if re.fullmatch(r"[A-Z]{3}", value) else "USD"


def _add_nested_price_map(
    output: dict[tuple[str, str, str], str],
    raw: dict[str, Any],
) -> None:
    """Accept PLAN.PERIOD.CURRENCY keys or PLAN -> PERIOD -> CURRENCY maps."""
    for key, value in raw.items():
        if isinstance(value, str):
            parts = re.split(r"[.:/]", str(key).strip().upper())
            if len(parts) != 3:
                raise ValueError("Flat Stripe price-map keys must be PLAN.PERIOD.CURRENCY.")
            plan, period, currency = parts
            _store_price(output, plan, period, currency, value)
            continue
        plan = _normalise(str(key))
        if not isinstance(value, dict):
            raise ValueError("Stripe price-map values must be Price IDs or nested objects.")
        for period_key, currencies in value.items():
            period = _normalise(str(period_key))
            if not isinstance(currencies, dict):
                raise ValueError("Each billing period must map currencies to Stripe Price IDs.")
            for currency, price_id in currencies.items():
                _store_price(output, plan, period, str(currency), str(price_id))


def _store_price(
    output: dict[tuple[str, str, str], str],
    plan: str,
    period: str,
    currency: str,
    price_id: str,
) -> None:
    normalised_plan = _normalise(plan)
    normalised_period = _normalise(period)
    normalised_currency = currency.strip().upper()
    clean_price_id = price_id.strip()
    if normalised_plan not in PAID_PLANS or normalised_period not in BILLING_PERIODS:
        raise ValueError("Stripe price map contains an unsupported plan or period.")
    if not re.fullmatch(r"[A-Z]{3}", normalised_currency):
        raise ValueError("Stripe price map contains an invalid currency.")
    if not clean_price_id.startswith("price_"):
        raise ValueError("Every Stripe price configuration value must be a price_ ID.")
    output[(normalised_plan, normalised_period, normalised_currency)] = clean_price_id


def _configured_prices() -> dict[tuple[str, str, str], str]:
    """Load server-side Price IDs without ever accepting an amount from a client."""
    output: dict[tuple[str, str, str], str] = {}
    default_currency = _default_currency()

    for (plan, period), env_name in PRICE_ENV.items():
        value = os.getenv(env_name, "").strip()
        if value:
            _store_price(output, plan, period, default_currency, value)

    for env_name, value in os.environ.items():
        match = PRICE_ENV_PATTERN.fullmatch(env_name.upper())
        if match and value.strip():
            _store_price(output, match.group(1), match.group(2), match.group(3), value)

    raw_json = os.getenv("STRIPE_PRICE_MAP_JSON", "").strip()
    if raw_json:
        parsed = json.loads(raw_json)
        if not isinstance(parsed, dict):
            raise ValueError("STRIPE_PRICE_MAP_JSON must be a JSON object.")
        _add_nested_price_map(output, parsed)

    reverse: dict[str, tuple[str, str, str]] = {}
    for key, price_id in output.items():
        other = reverse.get(price_id)
        if other is not None and other != key:
            raise ValueError(f"Stripe Price ID {price_id} is mapped to more than one plan.")
        reverse[price_id] = key
    return output


def _public_price_availability() -> dict[str, dict[str, list[str]]]:
    try:
        configured = _configured_prices()
    except (ValueError, json.JSONDecodeError):
        return {}
    result: dict[str, dict[str, list[str]]] = {}
    for plan, period, currency in configured:
        result.setdefault(plan, {}).setdefault(period, []).append(currency)
    for periods in result.values():
        for currencies in periods.values():
            currencies.sort()
    return result


def public_plan_catalog() -> list[dict[str, Any]]:
    availability = _public_price_availability()
    output: list[dict[str, Any]] = []
    for key, value in PLAN_CATALOG.items():
        periods = value["periods"]
        text = value["text"]
        output.append(
            {
                "plan_key": key,
                "display_name": value["name"],
                "monthly_price_usd": float(periods.get("MONTHLY", 0)),
                "daily_message_limit": text if isinstance(text, int) else int(text.get("MONTHLY", 0)),
                "ai_voice_enabled": key != "FREE",
                "cedar_voice_enabled": key != "FREE",
                "checkout_url": "",
                "billing_periods_usd": periods,
                "text_allowance": value["text"],
                "image_allowance": value["images"],
                "voice_seconds": value["voice_seconds"],
                "refills": value["refills"],
                "refill_on_request": bool(value.get("three_month_refills_on_request")),
                "screen_monitoring": True,
                "local_currency_at_checkout": True,
                "configured_currencies": availability.get(key, {}),
                "price_source": "stripe_price" if key != "FREE" else "free",
            }
        )
    return output


def _stripe_headers(idempotency_key: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    api_version = os.getenv("STRIPE_API_VERSION", "").strip()
    if api_version:
        headers["Stripe-Version"] = api_version
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key[:255]
    return headers


async def _stripe_request(
    method: str,
    path: str,
    *,
    data: Any = None,
    params: Any = None,
    idempotency_key: str | None = None,
    allow_missing: bool = False,
) -> dict[str, Any]:
    secret = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="Stripe billing has not been configured yet.")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.request(
                method,
                f"https://api.stripe.com/v1/{path.lstrip('/')}",
                auth=(secret, ""),
                headers=_stripe_headers(idempotency_key),
                data=data,
                params=params,
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="Stripe is temporarily unreachable.") from exc
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code >= 400:
        error = payload.get("error") if isinstance(payload, dict) else None
        code = str((error or {}).get("code") or "stripe_error")
        if allow_missing and response.status_code == 404 and code == "resource_missing":
            return {}
        if response.status_code == 429:
            raise HTTPException(status_code=503, detail="Stripe is busy. Please try again shortly.")
        raise HTTPException(status_code=502, detail=f"Stripe rejected the billing request ({code}).")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Stripe returned an invalid response.")
    return payload


def _webhook_signature_valid(raw: bytes, header: str) -> bool:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
    if not secret or not header:
        return False
    parts: dict[str, list[str]] = {}
    for item in header.split(","):
        key, separator, value = item.partition("=")
        if separator:
            parts.setdefault(key.strip(), []).append(value.strip())
    try:
        timestamp = int((parts.get("t") or [""])[0])
        tolerance = int(os.getenv("STRIPE_WEBHOOK_TOLERANCE_SECONDS", "300"))
    except ValueError:
        return False
    tolerance = min(900, max(30, tolerance))
    if abs(int(time.time()) - timestamp) > tolerance:
        return False
    digest = hmac.new(
        secret.encode("utf-8"),
        str(timestamp).encode("ascii") + b"." + raw,
        hashlib.sha256,
    ).hexdigest()
    return any(hmac.compare_digest(digest, candidate) for candidate in parts.get("v1", []))


def _safe_https_url(name: str, default: str, *, allow_session_template: bool = False) -> str:
    value = os.getenv(name, default).strip()
    parsed_value = value.replace("{CHECKOUT_SESSION_ID}", "session") if allow_session_template else value
    parsed = urlparse(parsed_value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=503, detail=f"{name} must be configured as a public HTTPS URL.")
    return value


def _price_period_matches(price: dict[str, Any], period: str) -> bool:
    recurring = price.get("recurring") or {}
    interval = str(recurring.get("interval") or "")
    try:
        count = int(recurring.get("interval_count") or 1)
    except (TypeError, ValueError):
        return False
    expected = {
        "MONTHLY": {("month", 1)},
        "3_MONTHS": {("month", 3)},
        "YEARLY": {("year", 1), ("month", 12)},
    }
    return (interval, count) in expected.get(period, set())


async def _validated_price(
    price_id: str,
    plan: str,
    period: str,
    configured_currency: str,
) -> dict[str, Any]:
    price = await _stripe_request("GET", f"prices/{price_id}")
    if price.get("id") != price_id or not price.get("active"):
        raise HTTPException(status_code=503, detail="That billing option is not currently available.")
    if str(price.get("type") or "") != "recurring" or not _price_period_matches(price, period):
        raise HTTPException(status_code=503, detail="That Stripe Price has the wrong recurring interval.")
    if str((price.get("recurring") or {}).get("usage_type") or "licensed") == "metered":
        raise HTTPException(status_code=503, detail="Metered Stripe Prices cannot be used for LJ AI plans.")
    base_currency = str(price.get("currency") or "").upper()
    if configured_currency != base_currency:
        raise HTTPException(status_code=503, detail="That Stripe Price uses a different base currency.")
    if str(price.get("billing_scheme") or "per_unit") != "per_unit":
        raise HTTPException(status_code=503, detail="Tiered Stripe Prices cannot be used for LJ AI plans.")
    if price.get("transform_quantity") or price.get("custom_unit_amount"):
        raise HTTPException(status_code=503, detail="That Stripe Price has unsupported quantity or custom pricing.")
    if configured_currency == "USD":
        expected_amount = EXPECTED_USD_CENTS.get((plan, period))
        try:
            actual_amount = int(price.get("unit_amount"))
        except (TypeError, ValueError):
            actual_amount = -1
        if expected_amount is None or actual_amount != expected_amount:
            raise HTTPException(
                status_code=503,
                detail="That Stripe Price amount does not match the LJ AI plan catalogue.",
            )
    return price


def _unix_to_iso(value: Any) -> str | None:
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return None
    if timestamp <= 0:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _clean_stripe_id(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("id")
    cleaned = str(value or "").strip()
    return cleaned or None


def _subscription_items(subscription: dict[str, Any]) -> list[dict[str, Any]]:
    items = subscription.get("items") or {}
    data = items.get("data") if isinstance(items, dict) else []
    return [item for item in (data or []) if isinstance(item, dict)]


def _subscription_period(subscription: dict[str, Any]) -> tuple[str | None, str | None]:
    starts = [subscription.get("current_period_start")]
    ends = [subscription.get("current_period_end")]
    for item in _subscription_items(subscription):
        starts.append(item.get("current_period_start"))
        ends.append(item.get("current_period_end"))
    start_values = [int(value) for value in starts if str(value or "").isdigit() and int(value) > 0]
    end_values = [int(value) for value in ends if str(value or "").isdigit() and int(value) > 0]
    return (
        _unix_to_iso(min(start_values)) if start_values else None,
        _unix_to_iso(max(end_values)) if end_values else None,
    )


def _subscription_price_id(subscription: dict[str, Any]) -> tuple[str | None, str | None]:
    items = _subscription_items(subscription)
    # Checkout creates exactly one licensed item at quantity one. Refuse to
    # translate a manually altered, duplicated, or multi-product Subscription
    # into an LJ AI entitlement: the customer must repair it in Stripe first.
    if len(items) != 1:
        return None, None
    found: list[tuple[str, str | None]] = []
    for item in items:
        try:
            quantity = int(item.get("quantity") or 1)
        except (TypeError, ValueError):
            return None, None
        if quantity != 1:
            return None, None
        price = item.get("price") or {}
        price_id = _clean_stripe_id(price)
        if price_id:
            currency = None
            if isinstance(price, dict):
                currency = str(price.get("currency") or "").upper() or None
            found.append((price_id, currency))
    unique = list(dict.fromkeys(found))
    if len(unique) != 1:
        return None, None
    return unique[0]


def _invoice_subscription_id(invoice: dict[str, Any]) -> str | None:
    direct = _clean_stripe_id(invoice.get("subscription"))
    if direct:
        return direct
    parent = invoice.get("parent") or {}
    details = parent.get("subscription_details") if isinstance(parent, dict) else {}
    return _clean_stripe_id((details or {}).get("subscription"))


async def _billing_rpc(
    rest_request: Callable[..., Any],
    function: str,
    payload: dict[str, Any],
) -> Any:
    return await rest_request("POST", f"rpc/{function}", payload=payload)


async def _claim_reconcile_lease(
    rest_request: Callable[..., Any],
    subscription_id: str,
) -> tuple[str, int]:
    """Serialize Stripe retrieval + database sync for one Subscription."""
    if not re.fullmatch(r"sub_[A-Za-z0-9]+", subscription_id):
        raise RuntimeError("Stripe Subscription ID is invalid.")
    token = os.urandom(32).hex()
    result = await _billing_rpc(
        rest_request,
        "claim_lj_billing_reconcile_lease",
        {"p_subscription_id": subscription_id, "p_lock_token": token},
    )
    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict) or not row.get("acquired"):
        raise HTTPException(
            status_code=503,
            detail="That Stripe subscription is already being reconciled.",
        )
    try:
        sequence = int(row.get("reconcile_sequence") or 0)
    except (TypeError, ValueError):
        sequence = 0
    if sequence <= 0:
        raise RuntimeError("Billing reconciliation sequence is unavailable.")
    return token, sequence


async def _finish_reconcile_lease(
    rest_request: Callable[..., Any],
    subscription_id: str,
    token: str,
    reconcile_sequence: int,
) -> None:
    result = await _billing_rpc(
        rest_request,
        "finish_lj_billing_reconcile_lease",
        {
            "p_subscription_id": subscription_id,
            "p_lock_token": token,
            "p_reconcile_sequence": reconcile_sequence,
        },
    )
    value = result[0] if isinstance(result, list) and result else result
    if isinstance(value, dict):
        value = next(iter(value.values()), False)
    if value is not True:
        raise RuntimeError("Billing reconciliation lease was lost.")


async def _find_subscription_binding(
    rest_request: Callable[..., Any],
    *,
    subscription_id: str | None,
    customer_id: str | None,
) -> dict[str, Any]:
    fields = (
        "user_id,plan_key,billing_period,status,stripe_customer_id,stripe_subscription_id,"
        "stripe_subscription_created,stripe_price_id,currency,current_period_start,current_period_end"
    )
    by_subscription: list[dict[str, Any]] = []
    if subscription_id:
        by_subscription = await rest_request(
            "GET",
            "lj_subscriptions",
            params={"stripe_subscription_id": f"eq.{subscription_id}", "select": fields, "limit": "2"},
        ) or []
    by_customer: list[dict[str, Any]] = []
    if customer_id:
        by_customer = await rest_request(
            "GET",
            "lj_subscriptions",
            params={"stripe_customer_id": f"eq.{customer_id}", "select": fields, "limit": "2"},
        ) or []
    if len(by_subscription) > 1 or len(by_customer) > 1:
        raise RuntimeError("Stripe identifier is linked to multiple LJ AI users.")
    if by_subscription and by_customer:
        if (
            str(by_subscription[0].get("user_id")) != str(by_customer[0].get("user_id"))
            or str(by_subscription[0].get("stripe_customer_id") or "") != str(customer_id or "")
            or str(by_customer[0].get("stripe_subscription_id") or "") not in {"", str(subscription_id or "")}
        ):
            raise RuntimeError("Stripe customer and subscription ownership do not match.")
    elif by_subscription:
        if customer_id and str(by_subscription[0].get("stripe_customer_id") or "") != customer_id:
            raise RuntimeError("Stripe subscription is linked to a different customer.")
    return (by_subscription or by_customer or [{}])[0]


async def _validated_profile_user(rest_request: Callable[..., Any], candidate: str) -> str | None:
    try:
        user_id = str(UUID(candidate))
    except (ValueError, TypeError, AttributeError):
        return None
    rows = await rest_request(
        "GET",
        "profiles",
        params={"id": f"eq.{user_id}", "select": "id,role", "limit": "1"},
    ) or []
    if not rows or str(rows[0].get("role") or "USER").upper() == "ADMIN":
        return None
    return user_id


async def _resolve_webhook_user(
    rest_request: Callable[..., Any],
    subscription: dict[str, Any],
    fallback_user_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    subscription_id = _clean_stripe_id(subscription.get("id"))
    customer_id = _clean_stripe_id(subscription.get("customer"))
    binding = await _find_subscription_binding(
        rest_request,
        subscription_id=subscription_id,
        customer_id=customer_id,
    )
    if not binding:
        # Every Checkout path persists the Customer-to-user binding before it
        # creates a payable Session. Never grant from mutable Stripe metadata
        # alone, even if somebody edits it in the Dashboard.
        raise RuntimeError("Stripe customer is not bound to an LJ AI account.")
    metadata = subscription.get("metadata") or {}
    candidate = str(binding.get("user_id") or "")
    user_id = await _validated_profile_user(rest_request, candidate)
    if not user_id:
        raise RuntimeError("Stripe subscription is not linked to an eligible LJ AI user.")
    if binding and str(binding.get("user_id")) != user_id:
        raise RuntimeError("Stripe subscription ownership mismatch.")
    for asserted_user in (metadata.get("user_id"), fallback_user_id):
        if asserted_user and str(asserted_user) != user_id:
            raise RuntimeError("Stripe metadata does not match the bound LJ AI account.")
    return user_id, binding


async def _retrieve_subscription_for_sync(
    rest_request: Callable[..., Any],
    subscription_id: str,
) -> tuple[str, int, dict[str, Any]]:
    """Claim serialization and then fetch authoritative Stripe state."""
    lock_token, reconcile_sequence = await _claim_reconcile_lease(
        rest_request, subscription_id
    )
    try:
        subscription = await _stripe_request(
            "GET",
            f"subscriptions/{subscription_id}",
            allow_missing=True,
        )
        if subscription:
            return lock_token, reconcile_sequence, subscription

        # A late invoice/update event can arrive after Stripe has deleted the
        # Subscription. Treat a previously bound missing Subscription as
        # terminal; never replay its stale snapshot and restore access.
        binding = await _find_subscription_binding(
            rest_request,
            subscription_id=subscription_id,
            customer_id=None,
        )
        if not binding:
            raise RuntimeError("Missing Stripe subscription has no LJ AI binding.")
        customer_id = _clean_stripe_id(binding.get("stripe_customer_id"))
        price_id = _clean_stripe_id(binding.get("stripe_price_id"))
        if not customer_id or not price_id:
            raise RuntimeError("Missing Stripe subscription has an incomplete LJ AI binding.")
        return lock_token, reconcile_sequence, {
            "id": subscription_id,
            "customer": customer_id,
            "created": int(binding.get("stripe_subscription_created") or 0),
            "status": "canceled",
            "ended_at": int(time.time()),
            "items": {
                "data": [
                    {
                        "quantity": 1,
                        "price": {
                            "id": price_id,
                            "currency": binding.get("currency"),
                        },
                    }
                ]
            },
        }
    except Exception:
        try:
            await _finish_reconcile_lease(
                rest_request, subscription_id, lock_token, reconcile_sequence
            )
        except Exception:
            pass
        raise


def _configured_identity_for_price(
    price_id: str | None,
    actual_currency: str | None,
    binding: dict[str, Any],
) -> tuple[str, str, str, str]:
    configured = _configured_prices()
    reverse = {configured_id: key for key, configured_id in configured.items()}
    if price_id and price_id in reverse:
        plan, period, configured_currency = reverse[price_id]
        if actual_currency and actual_currency != configured_currency:
            raise RuntimeError("Subscription Price currency does not match server configuration.")
        return plan, period, configured_currency, price_id
    bound_price = str(binding.get("stripe_price_id") or "")
    if price_id and bound_price == price_id:
        plan = _normalise(str(binding.get("plan_key") or ""))
        period = _normalise(str(binding.get("billing_period") or ""))
        currency = actual_currency or str(binding.get("currency") or _default_currency()).upper()
        if plan in PAID_PLANS and period in BILLING_PERIODS:
            return plan, period, currency, price_id
    raise RuntimeError("Subscription uses a Stripe Price that is not mapped to an LJ AI plan.")


async def _sync_subscription(
    rest_request: Callable[..., Any],
    event: dict[str, Any],
    subscription: dict[str, Any],
    *,
    reconcile_sequence: int,
    lock_token: str,
    fallback_user_id: str | None = None,
) -> None:
    user_id, binding = await _resolve_webhook_user(rest_request, subscription, fallback_user_id)
    price_id, actual_currency = _subscription_price_id(subscription)
    event_type = str(event.get("type") or "")
    status = str(subscription.get("status") or "").lower()
    if event_type == "customer.subscription.deleted":
        status = "canceled"

    try:
        plan, period, currency, bound_price_id = _configured_identity_for_price(
            price_id, actual_currency, binding
        )
    except RuntimeError:
        plan = _normalise(str(binding.get("plan_key") or ""))
        period = _normalise(str(binding.get("billing_period") or ""))
        bound_price_id = str(binding.get("stripe_price_id") or "")
        currency = str(binding.get("currency") or _default_currency()).upper()
        if not (
            status not in ENTITLED_STATUSES
            and plan in PAID_PLANS
            and period in BILLING_PERIODS
            and bound_price_id
        ):
            raise

    current_period_start, current_period_end = _subscription_period(subscription)
    current_period_start = current_period_start or binding.get("current_period_start")
    current_period_end = current_period_end or binding.get("current_period_end")
    subscription_id = _clean_stripe_id(subscription.get("id"))
    customer_id = _clean_stripe_id(subscription.get("customer")) or _clean_stripe_id(
        binding.get("stripe_customer_id")
    )
    if not subscription_id or not customer_id:
        raise RuntimeError("Stripe subscription is missing its customer or subscription ID.")
    try:
        subscription_created = int(
            subscription.get("created") or binding.get("stripe_subscription_created") or 0
        )
    except (TypeError, ValueError):
        subscription_created = 0

    await _billing_rpc(
        rest_request,
        "sync_lj_stripe_subscription_v2",
        {
            "p_user_id": user_id,
            "p_plan_key": plan,
            "p_billing_period": period,
            "p_status": status or "unknown",
            "p_customer_id": customer_id,
            "p_subscription_id": subscription_id,
            "p_subscription_created": subscription_created,
            "p_price_id": bound_price_id,
            "p_currency": currency,
            "p_period_start": current_period_start,
            "p_period_end": current_period_end,
            "p_cancel_at_period_end": bool(subscription.get("cancel_at_period_end")),
            "p_canceled_at": _unix_to_iso(subscription.get("canceled_at")),
            "p_ended_at": _unix_to_iso(subscription.get("ended_at")),
            "p_latest_invoice_id": _clean_stripe_id(subscription.get("latest_invoice")),
            "p_event_created": int(event.get("created") or 0),
            "p_reconcile_sequence": reconcile_sequence,
            "p_lock_token": lock_token,
        },
    )


async def _sync_subscription_with_lease(
    rest_request: Callable[..., Any],
    event: dict[str, Any],
    subscription_id: str,
    *,
    supplied_subscription: dict[str, Any] | None = None,
    fallback_user_id: str | None = None,
) -> None:
    if supplied_subscription is None:
        lock_token, reconcile_sequence, subscription = await _retrieve_subscription_for_sync(
            rest_request, subscription_id
        )
    else:
        lock_token, reconcile_sequence = await _claim_reconcile_lease(
            rest_request, subscription_id
        )
        subscription = supplied_subscription
    try:
        await _sync_subscription(
            rest_request,
            event,
            subscription,
            reconcile_sequence=reconcile_sequence,
            lock_token=lock_token,
            fallback_user_id=fallback_user_id,
        )
    except Exception:
        # A successful sync consumes its lease atomically in PostgreSQL. If the
        # sync transaction rolls back, release the restored lease so a Stripe
        # retry can claim it immediately instead of waiting for expiration.
        try:
            await _finish_reconcile_lease(
                rest_request, subscription_id, lock_token, reconcile_sequence
            )
        except Exception:
            pass
        raise


async def _claim_event(
    rest_request: Callable[..., Any], event: dict[str, Any]
) -> tuple[str, str]:
    processing_token = os.urandom(32).hex()
    result = await _billing_rpc(
        rest_request,
        "claim_lj_billing_webhook_event_v2",
        {
            "p_event_id": str(event.get("id") or ""),
            "p_event_type": str(event.get("type") or ""),
            "p_processing_token": processing_token,
            "p_stripe_created_at": int(event.get("created") or 0),
        },
    )
    state = result[0] if isinstance(result, list) and result else result
    if isinstance(state, dict):
        state = next(iter(state.values()), "")
    normalised = str(state or "").strip().upper()
    if normalised not in {"CLAIMED", "PROCESSED", "BUSY"}:
        raise RuntimeError("Billing event claim returned an invalid state.")
    return normalised, processing_token


async def _finish_event(
    rest_request: Callable[..., Any],
    event_id: str,
    processing_token: str,
    *,
    error: str | None = None,
) -> None:
    function = "fail_lj_billing_webhook_event" if error else "complete_lj_billing_webhook_event"
    payload: dict[str, Any] = {
        "p_event_id": event_id,
        "p_processing_token": processing_token,
    }
    if error:
        payload["p_error"] = error[:500]
    result = await _billing_rpc(rest_request, function, payload)
    value = result[0] if isinstance(result, list) and result else result
    if isinstance(value, dict):
        value = next(iter(value.values()), False)
    if value is not True:
        raise RuntimeError("Billing event claim was lost before completion.")


async def _handle_webhook_event(rest_request: Callable[..., Any], event: dict[str, Any]) -> None:
    event_type = str(event.get("type") or "")
    obj = ((event.get("data") or {}).get("object") or {})
    if not isinstance(obj, dict):
        return

    if event_type in SUBSCRIPTION_EVENTS:
        # Stripe doesn't guarantee event delivery order, and snapshot Event
        # `created` values have only one-second precision. Reconcile against the
        # current Subscription instead of allowing a late snapshot to restore a
        # canceled plan or an old Price. A deleted subscription event is itself
        # terminal and remains usable even if retrieval is no longer available.
        subscription_id = _clean_stripe_id(obj.get("id"))
        if not subscription_id:
            raise RuntimeError("Stripe subscription event has no subscription ID.")
        await _sync_subscription_with_lease(
            rest_request,
            event,
            subscription_id,
            supplied_subscription=obj if event_type == "customer.subscription.deleted" else None,
        )
        return

    if event_type in CHECKOUT_EVENTS:
        if event_type == "checkout.session.async_payment_failed":
            return
        if str(obj.get("mode") or "") != "subscription":
            return
        subscription_id = _clean_stripe_id(obj.get("subscription"))
        if not subscription_id:
            raise RuntimeError("Completed Checkout Session has no subscription.")
        metadata = obj.get("metadata") or {}
        fallback_user_id = str(obj.get("client_reference_id") or metadata.get("user_id") or "")
        await _sync_subscription_with_lease(
            rest_request,
            event,
            subscription_id,
            fallback_user_id=fallback_user_id,
        )
        return

    if event_type in INVOICE_EVENTS:
        subscription_id = _invoice_subscription_id(obj)
        if not subscription_id:
            return
        await _sync_subscription_with_lease(
            rest_request, event, subscription_id
        )
        return

    if event_type == "customer.deleted":
        customer_id = _clean_stripe_id(obj.get("id"))
        binding = await _find_subscription_binding(
            rest_request, subscription_id=None, customer_id=customer_id
        )
        if not binding or not binding.get("stripe_subscription_id"):
            return
        synthetic = {
            "id": binding["stripe_subscription_id"],
            "customer": customer_id,
            "created": int(binding.get("stripe_subscription_created") or 0),
            "status": "canceled",
            "items": {
                "data": [
                    {
                        "price": {
                            "id": binding.get("stripe_price_id"),
                            "currency": binding.get("currency"),
                        }
                    }
                ]
            },
        }
        await _sync_subscription_with_lease(
            rest_request,
            event,
            str(binding["stripe_subscription_id"]),
            supplied_subscription=synthetic,
        )


async def _ensure_customer(
    rest_request: Callable[..., Any],
    user_id: str,
    email: str,
) -> tuple[str, dict[str, Any]]:
    rows = await rest_request(
        "GET",
        "lj_subscriptions",
        params={"user_id": f"eq.{user_id}", "select": "*", "limit": "1"},
    ) or []
    existing = rows[0] if rows else {}
    customer_id = _clean_stripe_id(existing.get("stripe_customer_id"))
    if customer_id:
        return customer_id, existing

    stable_key = hashlib.sha256(f"lj-ai-customer:{user_id}".encode("utf-8")).hexdigest()
    customer = await _stripe_request(
        "POST",
        "customers",
        data={
            "email": email,
            "metadata[user_id]": user_id,
            "description": "LJ AI subscriber",
        },
        idempotency_key=f"lj-ai-customer-{stable_key}",
    )
    customer_id = _clean_stripe_id(customer.get("id"))
    if not customer_id:
        raise HTTPException(status_code=502, detail="Stripe did not create a billing customer.")
    now = datetime.now(timezone.utc).isoformat()
    await rest_request(
        "POST",
        "lj_subscriptions",
        payload={
            "user_id": user_id,
            "plan_key": existing.get("plan_key") or "FREE",
            "billing_period": existing.get("billing_period") or "MONTHLY",
            "status": existing.get("status") or "free",
            "stripe_customer_id": customer_id,
            "updated_at": now,
        },
        prefer="resolution=merge-duplicates,return=minimal",
    )
    existing["stripe_customer_id"] = customer_id
    return customer_id, existing


async def _claim_checkout_lease(
    rest_request: Callable[..., Any],
    user_id: str,
    token: str,
) -> dict[str, Any]:
    result = await _billing_rpc(
        rest_request,
        "claim_lj_checkout_lease",
        {"p_user_id": user_id, "p_lock_token": token},
    )
    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict) or not row.get("acquired"):
        raise HTTPException(
            status_code=409,
            detail="A checkout is already being prepared for this account. Try again in a moment.",
        )
    return row


async def _finish_checkout_lease(
    rest_request: Callable[..., Any],
    user_id: str,
    token: str,
    *,
    checkout_session_id: str | None = None,
) -> None:
    result = await _billing_rpc(
        rest_request,
        "finish_lj_checkout_lease",
        {
            "p_user_id": user_id,
            "p_lock_token": token,
            "p_checkout_session_id": checkout_session_id,
        },
    )
    value = result[0] if isinstance(result, list) and result else result
    if isinstance(value, dict):
        value = next(iter(value.values()), False)
    if value is not True:
        raise RuntimeError("Checkout lease was lost before it could be committed.")


def _checkout_generation_key(user_id: str, previous_session_id: str | None) -> str:
    """Use one Stripe idempotency generation for every concurrent user request.

    The selected plan is deliberately not part of the key. If two different
    plan buttons race, Stripe creates one Session and rejects the conflicting
    parameters instead of creating two payable subscriptions. Once that Session
    is expired or completed, its ID becomes the next generation seed.
    """
    generation = previous_session_id or "first-checkout"
    digest = hashlib.sha256(f"lj-ai-checkout:{user_id}:{generation}".encode("utf-8")).hexdigest()
    return f"lj-ai-checkout-{digest}"


def _valid_stripe_checkout_url(value: Any) -> str | None:
    candidate = str(value or "").strip()
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.netloc:
        return None
    return candidate


async def _reuse_or_retire_checkout(
    *,
    existing: dict[str, Any],
    user_id: str,
    customer_id: str,
    plan: str,
    period: str,
    currency: str,
    price_id: str,
) -> dict[str, str] | None:
    """Reuse one open Session or retire it before a replacement is created."""
    session_id = _clean_stripe_id(existing.get("checkout_session_id"))
    if not session_id or not session_id.startswith("cs_"):
        return None
    session = await _stripe_request(
        "GET",
        f"checkout/sessions/{session_id}",
        allow_missing=True,
    )
    if not session:
        return None
    if (
        str(session.get("mode") or "") != "subscription"
        or _clean_stripe_id(session.get("customer")) != customer_id
        or str(session.get("client_reference_id") or "") != user_id
    ):
        raise HTTPException(
            status_code=409,
            detail="The saved Stripe checkout does not match this LJ AI account. Contact support.",
        )
    state = str(session.get("status") or "").lower()
    metadata = session.get("metadata") or {}
    same_choice = (
        _normalise(str(metadata.get("lj_plan") or "")) == plan
        and _normalise(str(metadata.get("lj_period") or "")) == period
        and str(metadata.get("lj_currency") or "").upper() == currency
        and str(metadata.get("lj_price_id") or "") == price_id
    )
    if state == "open" and same_choice:
        checkout_url = _valid_stripe_checkout_url(session.get("url"))
        if checkout_url:
            return {"checkout_url": checkout_url, "session_id": session_id}
    if state == "open":
        await _stripe_request(
            "POST",
            f"checkout/sessions/{session_id}/expire",
            idempotency_key=f"lj-ai-expire-{hashlib.sha256(session_id.encode()).hexdigest()}",
        )
        return None
    if state == "complete":
        bound_subscription = _clean_stripe_id(existing.get("stripe_subscription_id"))
        session_subscription = _clean_stripe_id(session.get("subscription"))
        existing_status = str(existing.get("status") or "").lower()
        if not (
            existing_status in TERMINAL_SUBSCRIPTION_STATUSES
            and bound_subscription
            and bound_subscription == session_subscription
        ):
            raise HTTPException(
                status_code=409,
                detail="A Stripe payment was already submitted and is still being processed. Refresh your plan shortly.",
            )
    return None


def create_billing_router(
    *,
    current_identity: Callable[..., Any],
    rest_request: Callable[..., Any],
    insert_audit: Callable[..., Any],
    require_verified_email: Callable[[Any], Any],
) -> APIRouter:
    router = APIRouter(tags=["billing"])

    @router.get("/v1/billing/catalog")
    async def catalog() -> dict[str, Any]:
        availability = _public_price_availability()
        return {
            "currency": _default_currency(),
            "local_currency_at_checkout": True,
            "billing_available": bool(availability and os.getenv("STRIPE_SECRET_KEY", "").strip()),
            "price_source": "stripe_price",
            "plans": [
                {
                    "plan": key,
                    **value,
                    "screen_monitoring": True,
                    "annual_discount_percent": 5 if key != "FREE" else 0,
                    "configured_currencies": availability.get(key, {}),
                }
                for key, value in PLAN_CATALOG.items()
            ],
        }

    @router.get("/v1/billing/subscription")
    async def subscription(identity: Any = Depends(current_identity)) -> dict[str, Any]:
        if str(_identity_value(identity, "role", "USER")).upper() == "ADMIN":
            return {
                "status": "admin",
                "plan_key": "ADMIN",
                "effective_plan": "ADMIN",
                "managed_by_stripe": False,
            }
        rows = await rest_request(
            "GET",
            "lj_subscriptions",
            params={
                "user_id": f"eq.{_identity_value(identity, 'user_id')}",
                "select": (
                    "plan_key,billing_period,status,currency,current_period_start,"
                    "current_period_end,cancel_at_period_end,canceled_at,ended_at,"
                    "stripe_customer_id"
                ),
                "limit": "1",
            },
        ) or []
        if not rows:
            return {
                "status": "free",
                "plan_key": "FREE",
                "effective_plan": "FREE",
                "managed_by_stripe": False,
            }
        row = dict(rows[0])
        status = str(row.get("status") or "free").lower()
        end = row.get("current_period_end")
        expired = False
        if end:
            try:
                expired = datetime.fromisoformat(str(end).replace("Z", "+00:00")) <= datetime.now(timezone.utc)
            except ValueError:
                expired = True
        managed_by_stripe = bool(row.get("stripe_customer_id"))
        return {
            "status": status,
            "plan_key": str(row.get("plan_key") or "FREE").upper(),
            "billing_period": str(row.get("billing_period") or "MONTHLY").upper(),
            "currency": str(row.get("currency") or "").upper() or None,
            "current_period_start": row.get("current_period_start"),
            "current_period_end": end,
            "cancel_at_period_end": bool(row.get("cancel_at_period_end")),
            "canceled_at": row.get("canceled_at"),
            "ended_at": row.get("ended_at"),
            "effective_plan": (
                str(row.get("plan_key") or "FREE").upper()
                if status in ENTITLED_STATUSES and not expired
                else "FREE"
            ),
            "managed_by_stripe": managed_by_stripe,
            "can_manage": managed_by_stripe,
        }

    @router.post("/v1/billing/checkout")
    async def checkout(body: CheckoutRequest, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        if str(_identity_value(identity, "role", "USER")).upper() == "ADMIN":
            raise HTTPException(
                status_code=403,
                detail="Administrator accounts already have full access and cannot buy a plan.",
            )
        # Profiles created by historical app versions were marked confirmed by
        # an admin API without mailbox proof. Never create a payable Stripe
        # Session until the cloud's additive proof gate verifies this exact
        # user's current email address.
        await require_verified_email(identity)
        plan, period = _normalise(body.plan), _normalise(body.period)
        if plan not in PAID_PLANS or period not in BILLING_PERIODS:
            raise HTTPException(status_code=400, detail="Choose a valid LJ AI plan and billing period.")
        try:
            configured = _configured_prices()
        except (ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=503, detail="Stripe Price configuration is invalid.") from exc
        currency = body.currency or _default_currency()
        price_id = configured.get((plan, period, currency))
        if not price_id:
            available = sorted(key[2] for key in configured if key[:2] == (plan, period))
            if body.currency:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "That currency is not configured for this plan.",
                        "available_currencies": available,
                    },
                )
            raise HTTPException(status_code=503, detail="That Stripe billing option is not configured yet.")
        await _validated_price(price_id, plan, period, currency)

        user_id = str(_identity_value(identity, "user_id"))
        email = str(_identity_value(identity, "email")).strip().lower()
        customer_id, existing = await _ensure_customer(rest_request, user_id, email)
        lock_token = os.urandom(32).hex()
        lease_finished = False
        leased = await _claim_checkout_lease(rest_request, user_id, lock_token)
        try:
            # The lease row is the authoritative re-check after acquiring the
            # per-user lock. It closes the race where a webhook activates a
            # subscription between the first read and Checkout creation.
            existing = {**existing, **leased}
            if _clean_stripe_id(existing.get("stripe_customer_id")) != customer_id:
                raise HTTPException(
                    status_code=409,
                    detail="The Stripe billing profile does not match this LJ AI account.",
                )
            existing_status = str(existing.get("status") or "").lower()
            existing_end = existing.get("current_period_end")
            existing_active = existing_status in ENTITLED_STATUSES
            if existing_active and existing_end:
                try:
                    existing_active = (
                        datetime.fromisoformat(str(existing_end).replace("Z", "+00:00"))
                        > datetime.now(timezone.utc)
                    )
                except ValueError:
                    existing_active = True
            existing_subscription = _clean_stripe_id(existing.get("stripe_subscription_id"))
            if existing_active or (
                existing_subscription
                and existing_status not in TERMINAL_SUBSCRIPTION_STATUSES | FREE_SUBSCRIPTION_STATUSES
            ):
                raise HTTPException(
                    status_code=409,
                    detail="Manage, repair, or cancel your existing plan through Billing Management.",
                )

            reused = await _reuse_or_retire_checkout(
                existing=existing,
                user_id=user_id,
                customer_id=customer_id,
                plan=plan,
                period=period,
                currency=currency,
                price_id=price_id,
            )
            if reused:
                await _finish_checkout_lease(
                    rest_request,
                    user_id,
                    lock_token,
                    checkout_session_id=reused["session_id"],
                )
                lease_finished = True
                await insert_audit(
                    user_id,
                    "BILLING_CHECKOUT_REUSED",
                    {"plan": plan, "period": period, "currency": currency, "session_id": reused["session_id"]},
                )
                return {**reused, "plan": plan, "period": period, "currency": currency}

            success_url = _safe_https_url(
                "STRIPE_SUCCESS_URL",
                "https://jarvis-v13-cloud.onrender.com/v1/billing/success?session_id={CHECKOUT_SESSION_ID}",
                allow_session_template=True,
            )
            cancel_url = _safe_https_url(
                "STRIPE_CANCEL_URL", "https://jarvis-v13-cloud.onrender.com/v1/billing/cancel"
            )
            form: dict[str, str] = {
                "mode": "subscription",
                "line_items[0][price]": price_id,
                "line_items[0][quantity]": "1",
                "client_reference_id": user_id,
                "customer": customer_id,
                "success_url": success_url,
                "cancel_url": cancel_url,
                "metadata[user_id]": user_id,
                "metadata[lj_plan]": plan,
                "metadata[lj_period]": period,
                "metadata[lj_currency]": currency,
                "metadata[lj_price_id]": price_id,
                "subscription_data[metadata][user_id]": user_id,
                "subscription_data[metadata][lj_plan]": plan,
                "subscription_data[metadata][lj_period]": period,
            }
            if _truthy_environment("STRIPE_ALLOW_PROMOTION_CODES"):
                form["allow_promotion_codes"] = "true"
            if _truthy_environment("STRIPE_ENABLE_AUTOMATIC_TAX"):
                form["automatic_tax[enabled]"] = "true"
                form["customer_update[address]"] = "auto"
            if _truthy_environment("STRIPE_ENABLE_ADAPTIVE_PRICING", default=True):
                form["adaptive_pricing[enabled]"] = "true"

            # One deterministic generation per previous Session makes Stripe's
            # own idempotency layer a second guard behind the database lease.
            # A user-supplied request ID is never allowed to create a parallel
            # payable generation.
            idempotency_key = _checkout_generation_key(
                user_id,
                _clean_stripe_id(existing.get("checkout_session_id")),
            )
            output = await _stripe_request(
                "POST",
                "checkout/sessions",
                data=form,
                idempotency_key=idempotency_key,
            )
            checkout_url = _valid_stripe_checkout_url(output.get("url"))
            session_id = _clean_stripe_id(output.get("id"))
            if not checkout_url or not session_id or not session_id.startswith("cs_"):
                raise HTTPException(status_code=502, detail="Stripe did not return a valid Checkout Session.")
            await _finish_checkout_lease(
                rest_request,
                user_id,
                lock_token,
                checkout_session_id=session_id,
            )
            lease_finished = True
            await insert_audit(
                user_id,
                "BILLING_CHECKOUT_CREATED",
                {"plan": plan, "period": period, "currency": currency, "session_id": session_id},
            )
            return {
                "checkout_url": checkout_url,
                "session_id": session_id,
                "plan": plan,
                "period": period,
                "currency": currency,
            }
        finally:
            if not lease_finished:
                try:
                    await _finish_checkout_lease(rest_request, user_id, lock_token)
                except Exception:
                    # The short database lease expires automatically. Preserve
                    # the original error instead of hiding it behind cleanup.
                    pass

    @router.post("/v1/billing/portal")
    async def portal(identity: Any = Depends(current_identity)) -> dict[str, str]:
        if str(_identity_value(identity, "role", "USER")).upper() == "ADMIN":
            raise HTTPException(status_code=403, detail="Administrator accounts do not use Stripe billing.")
        rows = await rest_request(
            "GET",
            "lj_subscriptions",
            params={
                "user_id": f"eq.{_identity_value(identity, 'user_id')}",
                "select": "stripe_customer_id",
                "limit": "1",
            },
        ) or []
        customer = _clean_stripe_id(rows[0].get("stripe_customer_id")) if rows else None
        if not customer:
            raise HTTPException(status_code=404, detail="No Stripe billing profile is linked to this account yet.")
        form = {
            "customer": customer,
            "return_url": _safe_https_url(
                "STRIPE_PORTAL_RETURN_URL", "https://lj-ai-official-site.pages.dev/"
            ),
        }
        configuration = os.getenv("STRIPE_PORTAL_CONFIGURATION_ID", "").strip()
        if configuration:
            form["configuration"] = configuration
        output = await _stripe_request("POST", "billing_portal/sessions", data=form)
        portal_url = str(output.get("url") or "")
        if not portal_url.startswith("https://"):
            raise HTTPException(status_code=502, detail="Stripe did not return a valid Billing Portal URL.")
        await insert_audit(
            str(_identity_value(identity, "user_id")), "BILLING_PORTAL_CREATED", {}
        )
        return {"portal_url": portal_url}

    @router.post("/v1/billing/webhook")
    async def webhook(request: Request) -> dict[str, bool]:
        raw = await request.body()
        if len(raw) > 2_000_000:
            raise HTTPException(status_code=413, detail="Stripe webhook payload is too large.")
        if not _webhook_signature_valid(raw, request.headers.get("stripe-signature", "")):
            raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature.")
        try:
            event = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Invalid Stripe webhook payload.") from exc
        if not isinstance(event, dict) or not str(event.get("id") or "").startswith("evt_"):
            raise HTTPException(status_code=400, detail="Stripe webhook event ID is missing.")
        event_id = str(event["id"])
        claimed, processing_token = await _claim_event(rest_request, event)
        if claimed == "PROCESSED":
            # This exact Event already committed successfully.
            return {"received": True}
        if claimed == "BUSY":
            # Never acknowledge a still-processing retry: if its first worker
            # crashed, Stripe must retry again after the database lease expires.
            raise HTTPException(status_code=503, detail="Stripe event is still being processed.")
        try:
            await _handle_webhook_event(rest_request, event)
            await _finish_event(rest_request, event_id, processing_token)
        except Exception as exc:
            try:
                await _finish_event(
                    rest_request,
                    event_id,
                    processing_token,
                    error=type(exc).__name__,
                )
            except Exception:
                pass
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(status_code=500, detail="Stripe billing event could not be processed.") from exc
        return {"received": True}

    @router.get("/v1/billing/success", response_class=HTMLResponse)
    async def success() -> HTMLResponse:
        return HTMLResponse(
            "<body style='background:#03101f;color:#58dcff;font:18px sans-serif;padding:48px'>"
            "<h1>Payment complete</h1><p>Return to LJ AI. Your plan activates automatically after "
            "Stripe confirms the subscription.</p>"
            "<p><a style='color:#58dcff' href='https://lj-ai-official-site.pages.dev/'>LJ AI website</a></p>"
            "</body>"
        )

    @router.get("/v1/billing/cancel", response_class=HTMLResponse)
    async def cancel() -> HTMLResponse:
        return HTMLResponse(
            "<body style='background:#03101f;color:white;font:18px sans-serif;padding:48px'>"
            "<h1>Checkout cancelled</h1><p>No payment was made.</p>"
            "<p><a style='color:#58dcff' href='https://lj-ai-official-site.pages.dev/'>Return to LJ AI</a></p>"
            "</body>"
        )

    return router
