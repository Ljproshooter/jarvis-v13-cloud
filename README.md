# JARVIS V13 Cloud Server

Private FastAPI server for the JARVIS V13 Windows application.

## What it protects

- The OpenAI API key remains only in Render environment variables.
- The Supabase service-role key remains only in Render environment variables.
- Plans and daily message limits are enforced by the server and database.
- Administrator broadcasts, tickets, account status, plan expiry and usage logs
  are stored centrally in Supabase.
- Cedar is limited to VIP and administrator accounts.

Never put real keys in this repository, the Windows client, screenshots, chat
messages or support tickets.

## Plan limits preserved from V12.3

| Plan | AI messages per day | Voice |
| --- | ---: | --- |
| Free | 5 | Text only |
| Premium | 100 | Windows voice |
| Premium Plus | 250 | Windows voice |
| VIP | 1,000 | Cedar and Windows voice |
| Administrator | Unlimited | Cedar and Windows voice |

## Deployment order

1. Run `JARVIS_V13_DATABASE_SETUP.sql` in the Supabase SQL Editor.
2. Run `JARVIS_V13_SERVER_UPDATE.sql` in the Supabase SQL Editor.
3. Upload these repository files to a private GitHub repository.
4. In Render, create a Blueprint from the repository.
5. Add the four secret environment values when Render asks for them:
   `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`,
   `SUPABASE_SERVICE_ROLE_KEY`, and `OPENAI_API_KEY`.
6. Wait for `/health` to report `healthy`.

The `.env.example` file contains names only. It must never contain real keys.

