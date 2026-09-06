# LJ AI verified-email and password-recovery setup

This release replaces the historical admin-created, auto-confirmed signup with
Supabase's normal email-confirmation flow. It also makes recovery and Stripe
checkout depend on an LJ AI proof record for the account's current email.
`auth.users.email_confirmed_at` alone is deliberately **not** accepted because
older LJ AI releases populated it without proving mailbox ownership.

## Required deployment order

1. Run `LJ_AI_AUTH_SECURITY_UPDATE.sql` in the production Supabase SQL Editor.
2. In Supabase **Authentication -> Providers -> Email**, enable email/password
   signup and **Confirm email**. Do not enable automatic confirmation.
3. Configure production custom SMTP. Supabase's trial mailer is rate-limited
   and is not suitable for paid-account confirmation or recovery.
4. In Supabase **Authentication -> URL Configuration**, add these exact
   redirect URLs:

   - `https://jarvis-v13-cloud.onrender.com/v1/auth/email-verification/complete`
   - `https://jarvis-v13-cloud.onrender.com/v1/auth/password-reset/complete`

5. Keep the default Supabase confirmation, magic-link, and recovery templates
   using `{{ .ConfirmationURL }}`. These cloud pages intentionally consume the
   implicit-flow URL fragment in the browser and immediately erase it from the
   address bar. Do not switch these templates to a PKCE `?code=` link unless the
   cloud completion implementation is upgraded at the same time.
6. Deploy the cloud with both fixed redirect environment variables from
   `.env.example`. `/health` fails with `configuration_required` if either URL
   is changed, downgraded from HTTPS, or given query/fragment credentials.
7. Test signup, the verification email, legacy re-verification, recovery, and a
   Stripe checkout with a real test mailbox before enabling live prices.

The cloud cannot inspect the Supabase dashboard to prove that Confirm email,
the redirect allowlist, or SMTP delivery are enabled. Completing steps 2-5 and
the real-mailbox test in step 7 is therefore a mandatory release gate.

## Client contracts

`POST /v1/auth/signup` returns HTTP 201 after any accepted signup or duplicate
request, without revealing whether the email already exists:

```json
{
  "created": true,
  "confirmation_required": true,
  "message": "Check your email and confirm your LJ AI account, then return here and sign in.",
  "session": null
}
```

The client must not save a session or register a device from this response. It
should return to Sign In with the email prefilled. After the user opens the
email link, normal password login creates the device session.

Legacy users can continue to sign in, but recovery and paid checkout remain
blocked until a fresh mailbox proof is completed. A signed-in registered device
starts that challenge with:

```http
POST /v1/auth/email-verification
Authorization: Bearer <user access token>
X-LJ-Device-ID: <registered device id>
X-LJ-Device-Token: <registered device token>
```

The response tells the client to ask the user to open the email. The one-time
magic-link session is completed only by the cloud-hosted page. Checkout returns
HTTP 403 with `detail.code = "verification_required"` and the same start
endpoint until proof succeeds.

Password-reset requests use `POST /v1/auth/password-reset` and always return the
same generic message. Only eligible accounts receive mail. The recovery email
opens the cloud-hosted GET page at `/v1/auth/password-reset/complete`; that page
POSTs the fragment access token and new password back to the same path. The
server authenticates the token with Supabase and calls authenticated
`PUT /auth/v1/user`. It never uses an owner/admin password-reset API.

Each eligible request also creates a one-hour, one-time server recovery
challenge with an immutable generation ID. Completion requires a fresh
recovery-email session issued after that challenge, claims the exact generation
transactionally before the password update, and consumes it immediately
afterward. A new public reset request cannot replace a live claim. Every claimed
Auth session ID is retained as used across later generations, so an ambiguous
upstream attempt cannot be replayed against a replacement challenge. The server
also attempts local Supabase logout after every successful password update even
if database finalization fails. Ordinary password sessions, stale links,
parallel claims, and replayed links fail closed.

Tokens and passwords are never placed in query strings, database proof rows,
audit details, or server responses. Completion pages do not use local storage
or third-party scripts and erase URL fragments before making a request.
