# LJ AI V16.0.3 — saved coding projects and automatic memory

This update builds on the already merged V16.0.2 cloud release. Windows becomes **16.0.3**. Continue the Android **16.0.2 / 16002** release you are already finishing; a new Android build is not required for the server memory improvements.

## Install in this order

1. In the existing Supabase project's SQL Editor, run **LJ_AI_V16_0_3_CODING_MEMORY_UPDATE.sql** once. It is safe to rerun. Do not repeat old migrations or reset your database.
2. Review and merge the V16.0.3 cloud pull request, then wait for Render to show **Live**.
3. Keep **OPENAI_TEXT_DEVELOPER_MODEL=gpt-6-astra**. The coding worker explicitly requests maximum reasoning and uses your existing server OpenAI key. There is no API key to add to Windows.
4. Extract the complete **LJ_AI_WINDOWS_V16.0.3_SOURCE.zip** into a new folder on Windows. Run **BUILD_LJ_AI_V15_PUBLIC.bat** with Python 3.12 x64. The familiar batch filename is intentional.
5. Install **release/LJ_AI_Setup.exe** over the existing Windows app and perform the live checks below.
6. Only after that installer works, create GitHub release **v16.0.3** and upload **LJ_AI_Setup.exe**. Save/publish the release and wait for the asset upload to finish.
7. Put the newly generated **release/client_update.json** into the repository's root **client_update.json**, replacing the old file. Put the values from **release/RENDER_UPDATE_VALUES.txt** into Render's environment settings. These two metadata files are not release assets. The builder calculates the new installer's SHA-256; do not reuse V16.0.2's hash.

The cloud PR keeps the published V16.0.2 Windows manifest. The cloud version and the advertised installer version are deliberately separate during rollout. Leave Android's update environment values on the Android build you publish.

## What the coding change does

Windows coding requests from VIP/Admin accounts create a durable job and return a job ID promptly. Short requests then retrieve progress. Closing Windows or losing a connection does not delete the saved job.

The worker uses the Responses API in background mode and an OpenAI hosted shell. It creates actual files in an isolated container, runs available checks, fixes failures, saves project ZIP checkpoints, and starts another response when a response reaches its token budget. LJ AI imposes no overall elapsed-time deadline on a coding job.

A separate review step checks the requirements. Completion requires a current checkpoint and test commands whose successful exit results are present in the provider response. A stale report or a prose-only claim of passing tests cannot complete the job.

In **AI Chat → CODING PROJECTS** you can:

- See progress and the model reported by the provider.
- Stop, resume, or let a job run in the background.
- Save the latest complete source ZIP, with SHA-256 verification.
- Import a source ZIP into the current chat and ask for changes.
- Open the project's conversation or delete a stopped saved job.

Follow-up requests in the same chat start from the saved files and previous request/progress. The agent maintains **REQUIREMENTS.md** and **PROJECT_STATE.md** for requirements, decisions, completed work and remaining issues. A JS Bin request asks the agent for a runnable **index.html** and separate **JSBIN_HTML.txt**, **JSBIN_CSS.txt** and **JSBIN_JS.txt** panels with paste instructions.

Jobs may pause for missing user input, repeated steps without progress, unavailable permissions, or an uncertain model-request submission. An uncertain submission is not silently replayed: Resume starts a fresh workspace from the durable checkpoint. OpenAI API/tool usage still incurs normal charges. One coding job uses one existing Developer allowance unit; its continuation/review rounds do not consume additional LJ AI message units.

## What the memory change does

Ordinary clear statements such as **“My favourite colour is purple”** are saved automatically when memory and automatic learning are enabled. Common facts are handled immediately; other lasting non-sensitive first-person facts use a durable extraction queue. Facts are private to the signed-in account and are recalled across supported text and voice clients.

Clear corrections update the same remembered preference. Retrieval ranks relevant facts instead of taking only the most recent entries. Existing manual memories remain available.

Windows' Memory page includes an **automatic learning** switch plus the existing edit, pause/use, forget and clear-all controls. **“Forget my favourite colour”** removes the automatically learned preference. Queued older learning is invalidated on a forget/edit/pause so it cannot restore a forgotten fact later. Repeated voice heartbeats do not count as new personal statements.

Turning automatic learning off stops new automatic saves; turning Memory off also stops recall. Existing saved items stay available to inspect or delete. Forgetting saved memory does not erase the original statement from an existing chat; delete that conversation separately if desired.

## Live checks before releasing Windows

1. In a new chat, say “My favourite colour is purple”. In another chat, ask for it. Then change it to green and check again.
2. Forget the preference, wait briefly, reopen the app and confirm it stays out of Memory. Test automatic learning off and the existing Memory pause switch.
3. Send the original cops-and-runners game request. Confirm the job starts, shows its actual model, produces source files and reaches review. Download and run the game: check controls, bots, rewind, sprint, coins and purchases.
4. Interrupt the network, reconnect, and reopen Coding Projects. Then close/reopen the app during a job and resume a stopped job.
5. Import a small existing source ZIP; ask for a change and check that existing files/features are preserved.
6. Check existing sign-in, voice, typed app/device actions, chat sync and Android V16.0.2 still work.

## Hosting and limits

Continuous unattended jobs require an awake cloud service. Render's Free web instances sleep after 15 minutes without incoming traffic, so a sleeping service resumes its worker when a request wakes it. Use an always-on service for work that must keep progressing with all clients closed. This change does not alter your Render plan or billing. [Render's free-instance documentation](https://render.com/docs/free)

Provider containers are temporary; durable source ZIPs are stored privately in Supabase and restored when a container expires. Only saved checkpoints can be restored. Imported/downloadable source archives are limited to 32 MiB compressed, 256 MiB expanded and 5,000 entries; omit dependencies and build caches. Automatic memory uses the existing 200-item account limit.

Generated code runs in the hosted sandbox, never on the Render host or automatically on the user's Windows PC. Sandbox networking is not enabled. Some dependencies, hardware, Windows/Android builds and live integrations therefore need target-platform testing. No model can guarantee perfect software.

## Validation and rollback

The Python regression suites and the new PostgreSQL migration checks are included. SQL checks execute the actual migration and existing reservation/chat-save functions against PostgreSQL via PGlite with a minimal prerequisite fixture; this is not a live Supabase deployment test. The migration is also tested for rerun safety and owner isolation.

Cloud tests:

```sh
python -m pytest -q
npm install --no-save --ignore-scripts @electric-sql/pglite@0.5.4
node tests/test_v1603_migration.mjs
```

Windows' usual builder runs all four regression modules before packaging. No live OpenAI coding run, production deployment, native Windows GUI check or Windows installer build was performed in the development environment. Those are the live checks above.

To roll the cloud back, first stop active jobs, then redeploy the prior cloud commit. Keep the additive V16.0.3 tables; do not drop them or revert existing account data. Install Windows V16.0.2 if needed, and keep updater metadata pointed at the matching published installer.

API references: [background responses](https://developers.openai.com/api/docs/guides/background), [hosted shell](https://developers.openai.com/api/docs/guides/tools-shell), [GPT-6 Astra](https://developers.openai.com/api/docs/models/gpt-6-astra).
