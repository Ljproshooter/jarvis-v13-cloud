# LJ AI 16.0.1 cloud update

This update supports the matching Android and Windows source releases while
retaining the legacy 15.9.9/16.0.0 client paths. It does not change published
CLIENT_* / ANDROID_* Render settings or client_update.json.

## Deployment sequence

1. In the existing Supabase project's SQL Editor, apply
   `LJ_AI_V16_0_1_TEACH_RUN_MODE_UPDATE.sql`. This additive, idempotent migration
   adds the saved run control mode and a service-role-only RPC wrapper around
   the existing owner/device/version-validated start routine.
2. Merge the reviewed cloud pull request to main. Wait for jarvis-v13-cloud to
   finish deploying; keep the existing client update environment values until
   the new signed installers are uploaded.
3. Build the 16.0.1 signed Android APK and Windows installer, upload both to
   GitHub release v16.0.1, then apply their newly generated Render values/hashes.

If the new RPC is missing, skill runs fall back to SAFE_MODE with an explicit
notice. Other SQL/network/mutation failures are not retried as new skill runs.
Rollback can restore the previous cloud commit without dropping the added column.
A reverted legacy server simply ignores the new run-mode field.

## Behavior

- Three concurrent signed-in devices per account using the existing locked RPC.
- Owner-scoped device listing/revocation remains usable by either platform.
- Admin-only DELETE /v1/admin/tickets/{ticket_id}.
- 16.0.1 voice tools expose saved Skills and their variable inputs, native phone
  actions, and improved capability-checked SmartThings controls.
- Saved run mode is persisted atomically; old clients default to SAFE_MODE.
- Repeated rewind/fast-forward means remote presses, bounded to 20. Timed seeking
  requires an exposed seek capability and known units. Back/navigation and newer
  Samsung app launch use advertised command schemas. Mutation retries/fallbacks
  are not guessed after an uncertain command result.
- Camera advice uses provided fresh screen frames rather than inventing unseen
  settings. Actual audio/device/app behavior requires client/hardware checks.
- Windows /v1/client/download selects the versioned LJ_AI_Setup.exe using the
  validated CLIENT_LATEST_VERSION, not GitHub's global latest-release redirect.

## Validation

193 Python cloud tests passed. The suite uses the unchanged operational-guide
fixture from the complete source distribution in its expected parent folder.
SQL syntax was parsed; this migration has not been executed against production.
No real TV commands, phone calls, live database changes or deployments were
performed while preparing this update.
