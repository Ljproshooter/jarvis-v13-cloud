# LJ AI V15.9.5 Stripe Billing setup

Use Stripe test mode first. Do not enter live keys until a complete test purchase,
renewal, cancellation, and failed-payment test all behave correctly.

Complete `AUTH_SECURITY_SETUP.md` and run
`LJ_AI_AUTH_SECURITY_UPDATE.sql` before this guide. Checkout requires a fresh LJ
AI mailbox-proof record for the account's current email. A legacy account may
still sign in, but paid checkout remains blocked until re-verification succeeds.

## 1. Apply the database migration

Open the production LJ AI Supabase project, choose **SQL Editor → New query**,
and run the complete updated contents of:

`LJ_AI_STRIPE_BILLING_UPDATE.sql`

Run it again even if an earlier copy was already applied; the V15.9.5 migration
contains the latest event-ordering, idempotency and pending-checkout safeguards.
It is additive and safe to rerun. This must finish successfully before deploying
the matching `billing_routes.py`.

## 2. Create the recurring Stripe Prices in test mode

Turn on **Test mode** in Stripe Dashboard. Create Basic, Premium, and VIP
products. Create three
recurring Prices for each product. A 3-month Price must recur every 3 months; it
must not be a one-time payment.

| Plan | Monthly (every 1 month) | 3 months (every 3 months) | Yearly (every 1 year) |
| --- | ---: | ---: | ---: |
| Basic | USD 15.00 | USD 45.00 | USD 171.00 |
| Premium | USD 24.99 | USD 74.97 | USD 284.89 |
| VIP | USD 59.99 | USD 179.97 | USD 683.89 |

Copy each `price_...` ID. Never put an amount, Product ID (`prod_...`), Payment
Link, or Checkout URL in a Price environment variable.

## 3. Add Render test environment values

Add these to the production `jarvis-v13-cloud` Render service:

```text
STRIPE_SECRET_KEY=sk_test_...
STRIPE_DEFAULT_CURRENCY=USD
STRIPE_PRICE_BASIC_MONTHLY=price_...
STRIPE_PRICE_BASIC_3_MONTHS=price_...
STRIPE_PRICE_BASIC_YEARLY=price_...
STRIPE_PRICE_PREMIUM_MONTHLY=price_...
STRIPE_PRICE_PREMIUM_3_MONTHS=price_...
STRIPE_PRICE_PREMIUM_YEARLY=price_...
STRIPE_PRICE_VIP_MONTHLY=price_...
STRIPE_PRICE_VIP_3_MONTHS=price_...
STRIPE_PRICE_VIP_YEARLY=price_...
STRIPE_ENABLE_ADAPTIVE_PRICING=true
STRIPE_ENABLE_AUTOMATIC_TAX=false
STRIPE_ALLOW_PROMOTION_CODES=false
STRIPE_WEBHOOK_TOLERANCE_SECONDS=300
STRIPE_SUCCESS_URL=https://jarvis-v13-cloud.onrender.com/v1/billing/success?session_id={CHECKOUT_SESSION_ID}
STRIPE_CANCEL_URL=https://jarvis-v13-cloud.onrender.com/v1/billing/cancel
STRIPE_PORTAL_RETURN_URL=https://lj-ai-official-site.pages.dev/
```

Leave `STRIPE_API_VERSION` empty unless the entire integration has been tested
against a specific pinned Stripe API version. Enable Automatic Tax only after
configuring Stripe Tax registrations and business tax settings.

For manually priced regional currencies, add variables such as:

```text
STRIPE_PRICE_BASIC_MONTHLY_AUD=price_...
STRIPE_PRICE_BASIC_3_MONTHS_AUD=price_...
STRIPE_PRICE_BASIC_YEARLY_AUD=price_...
```

Repeat for Premium and VIP. Alternatively use one flat JSON object in
`STRIPE_PRICE_MAP_JSON`, for example:

```json
{"BASIC.MONTHLY.AUD":"price_...","PREMIUM.MONTHLY.AUD":"price_...","VIP.YEARLY.GBP":"price_..."}
```

The server verifies the recurring interval and base currency of every Price.
The Android and Windows clients never submit a charge amount.

## 4. Configure the test-mode Stripe webhook

In Stripe Workbench/Webhooks, add this HTTPS destination:

```text
https://jarvis-v13-cloud.onrender.com/v1/billing/webhook
```

Subscribe it to:

- `checkout.session.completed`
- `checkout.session.async_payment_succeeded`
- `checkout.session.async_payment_failed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `customer.subscription.paused`
- `customer.subscription.resumed`
- `customer.subscription.pending_update_applied`
- `customer.subscription.pending_update_expired`
- `invoice.paid`
- `invoice.payment_succeeded`
- `invoice.payment_failed`
- `invoice.voided`
- `invoice.marked_uncollectible`
- `customer.deleted`

Reveal that destination's signing secret and add it to Render:

```text
STRIPE_WEBHOOK_SECRET=whsec_...
```

The test-mode and live-mode webhook destinations have different signing
secrets. Never reuse one for the other.

## 5. Enable the Customer Portal

Open Stripe Customer Portal settings. Enable payment-method updates,
subscription cancellation, and plan switching only among the nine LJ AI Prices.
Save the configuration. If Stripe supplies a `bpc_...` configuration ID, add:

```text
STRIPE_PORTAL_CONFIGURATION_ID=bpc_...
```

The app creates a new short-lived portal URL only after authenticating the LJ AI
user.

## 6. Test before going live

1. Redeploy Render and confirm `/health` is healthy.
2. Sign in with a newly mailbox-verified, non-admin LJ AI test account.
3. Buy Basic monthly with Stripe test mode.
4. Return to the app and refresh the account. It should activate automatically.
5. Confirm the Stripe Customer and Subscription IDs appear on the same user's
   `lj_subscriptions` row in Supabase.
6. Use the Customer Portal to schedule cancellation. Access should remain until
   the paid period ends and then expire automatically.
7. Test renewal, failed payment, cancellation and expiry with Stripe test clocks.
8. Confirm duplicate and out-of-order webhook deliveries do not duplicate or
   incorrectly restore an entitlement.
9. Confirm a repeated/pending checkout does not create two subscriptions.

After all tests pass, finish Stripe business verification and payout-bank setup.
Switch Stripe Dashboard to live mode, create/copy the same nine recurring Prices
and create a separate live webhook. Replace every `sk_test_`, test `price_...`
and test `whsec_...` value with values from that same live-mode account. Do not
mix test and live values. Redeploy, then make one controlled real purchase and
refund/cancel it before advertising billing publicly.

The webhook—not the browser success page—is the source of paid entitlement.
Never manually grant a plan merely because a user shows a checkout receipt.

Official references: [Stripe subscription Checkout](https://docs.stripe.com/payments/checkout/build-subscriptions),
[webhook signatures](https://docs.stripe.com/webhooks),
[subscription webhook lifecycle](https://docs.stripe.com/billing/subscriptions/webhooks),
and [Customer Portal](https://docs.stripe.com/customer-management).

If the Android app is later distributed through Google Play, check the current
Google Play payments policy before exposing Stripe checkout for digital plans.
