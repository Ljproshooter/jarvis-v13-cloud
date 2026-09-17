# LJ AI V16.0.2 — reconnect, coding and typed actions

Prepared from the published V16.0.1 Windows/Android sources and cloud main commit 9b865f093b265b5e1e4b26f5ca354e35b0521459.

## What changes

- Saved sign-in: `/v1/auth/refresh` accepts nonblank opaque refresh tokens shorter than 20 characters. Registered-device verification and Supabase authentication remain required. Temporary connection failures preserve the saved login. Windows performs one bounded refresh attempt instead of a multi-minute retry chain; a later request can recover normally.
- Game/coding requests: Windows matches complete local questions instead of isolated words. The supplied cops-and-runners request cannot become a clock command through “take your time” and “give”. Coding requests bypass device shortcuts.
- Developer mode: default and release configuration use `gpt-6-astra`, `reasoning.effort=max`, Responses background generation, and a 65,536-token output budget including reasoning. Short display preferences no longer reduce that budget. Instructions ask for complete runnable implementations and separate HTML/CSS/JavaScript panels for JS Bin. Incomplete output is labelled. This is the API Developer mode, not an embedded ChatGPT Work environment; execution is claimed only when a tool actually ran.
- Text actions: `/v1/actions/plan` shares the voice tool catalogue. Windows and Android dispatch supported typed commands through existing voice permission handlers, including local apps, linked devices, SmartThings, saved Skills and app information. Android phone commands are parsed from the actual typed message, never from model-provided recipients or messages. Safe mode approvals, Full Access settings, OS permissions and supported-device limits still apply.
- Action turns are bounded to eight sequential calls, with at most one side-effect tool call per typed request, matching the fresh-turn authority used by phone voice. Read-only discovery can precede the action. Account/device/request-bound continuations and client duplicate guards prevent silent action replay. A lost connection after execution reports the known result without retrying it. Successful final replies use canonical conversation storage. The final action reply uses one existing NORMAL text allowance unit. Intermediate tool steps and NO_ACTION preflights release their temporary reservations, so they are not billed as extra user messages.

## Apply in this order

1. Review and merge the V16.0.2 cloud PR into `main`, then verify the Render deployment succeeds. No new Supabase migration is required. Do not rerun completed V16.0.1 setup.
2. Keep `OPENAI_TEXT_DEVELOPER_MODEL=gpt-6-astra` on Render. The repository already specifies this. A live authenticated request is still needed to confirm the deployed override and actual model response.
3. Test an existing V16.0.1 login after its access token expires. The cloud refresh fix is backward compatible, so this can be tested before building new clients. A genuinely revoked/expired refresh token still needs a new sign-in.
4. Windows: extract the complete Windows source folder and run `BUILD_LJ_AI_V15_PUBLIC.bat` (the existing filename is intentional). It runs all three Windows regression modules and produces `release/LJ_AI_Setup.exe`. Install over the existing version.
5. Android: open the full project in Android Studio, use JDK 17 and the project's SDK 37/Gradle 9.5 configuration, run `testDebugUnitTest`, and build a signed release APK using the same signing key as V16.0.1. Package name remains `com.ljai.mobile`; version is 16.0.2 / 16002. Install as an update rather than clearing app data.
6. After both new binaries pass the device checks below, publish their release assets and generate fresh SHA-256 updater values using the supplied existing release helpers. The cloud PR intentionally retains the published V16.0.1 manifest and defaults until those new assets exist. Never reuse the old installer hash.

## Checks already completed

- Cloud: 204 tests passed, plus 90 subtests. Includes short refresh tokens, revoked-device rejection, action continuation binding, shared voice/text catalogues, no-action refunds, confirmation stops and incomplete-model rejection.
- Windows: 128 tests passed. Includes the supplied game prompt, clock-question boundaries, temporary refresh failure followed by recovery, action-result return, logout during planning, mismatched targets and duplicate action calls.
- Python sources compile successfully and the patch passes whitespace validation.
- Android: source changes and four new policy tests are included. The full Android build and JUnit suite could not run here: the Gradle 9.5.0 distribution download failed with “Network is unreachable”, and no Android SDK/compiler was installed. This package is not a verified APK.
- No live OpenAI request, production deployment, Windows installer build or signed Android APK build was performed in this environment.

## Device acceptance checks before publishing

- Leave each client idle beyond access-token expiry; resume text and voice without logging out. Repeat after a temporary network outage, Wi-Fi/mobile-data change and app restart. Confirm Online returns and the 20-character validation error does not appear.
- On Windows, send the original game prompt in Developer mode. Expect game code rather than a clock reply. Paste the returned HTML/CSS/JavaScript into JS Bin and check movement, jump, bot abilities, rewind uses, sprint, obstacles, coins and shop purchases. Generated game correctness still requires this live check.
- On both clients try opening a local app, operating an explicitly named paired device, and controlling the connected TV (power, volume, app launch and bounded rewind). Check Safe mode approval and Full Access behaviour. Use only commands supported by the OS/device, as in voice.
- Start an action and sign out before its response returns; it must not execute under another account. Interrupt the connection after an action; it must not repeat silently.
- Check Teach LJ, photo analysis, screen analysis, chat-history sync and existing local shortcuts remain usable. New typed-action clients require the cloud PR to be deployed first.
