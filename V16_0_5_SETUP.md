# LJ AI V16.0.5 — Windows and Android

This continues your published V16.0.4. Both new apps are **16.0.5**; Android's version code is **16005**. **No new Supabase SQL or new secret is required.** Keep the completed database and memory setup.

## What changed

**Coding:** the cloud now asks GPT-6 Astra to implement and checkpoint small runnable pieces. Build steps use high reasoning; final review uses maximum reasoning on the same model. There is no overall project deadline. Provider queue state, completed commands and the last cloud check are shown separately from completed steps. If the model has written source but has not packaged its ZIP, the worker can recover an initial source snapshot. Only a matching report and verified executed checks can finish a project. Source ZIP import/export, Stop/Resume, continuation, memory and Normal/Smart direct replies remain.

A job already submitted under V16.0.4 keeps its original provider request. After deploying this cloud update, if that old job is still stuck, press **Stop**, wait for **Stopped**, then **Resume** once to start a step with the new workflow. Do not repeatedly send the same request into the chat. Five minutes of reasoning alone is not proof of a crash, and this update cannot guarantee a model response time or bug-free code.

**SmartThings:** an accepted, recent TV offer can be followed with “yes”, “yeh do that” or “go ahead” in text or voice. The app retains the specific platform, TV and explicit search title. If LJ offers YouTube OR Netflix, reply with the platform name. One acceptance permits one attempt. Account/chat changes, unrelated requests, cancellation and a 90-second expiry clear the offer. Existing permission checks and real TV capability checks remain. Unsupported TV search or exact seeking is still reported honestly.

**Windows layout:** Chat has a wider reading area, calmer message styling, a compact composer and a VOICE shortcut. **CHATS** opens the existing conversation list, search, New Chat, Sync, Rename and Delete. **TOOLS & PHOTO OPTIONS** opens photo mode, Open Result, Mic and video attachment controls. Memory and Coding Projects stay available. Voice has a centred cyan LJ core and recent transcript. **VOICE CONTROLS** holds the existing microphone turn controls, output test, screen monitoring, mouse controls, messaging access, scan result, device handover and diagnostics. The main navigation and other pages remain.

**Links and video:** public HTTPS pages/images and retrievable videos can supply actual content to the model. A video preview includes up to six sampled visual frames from the first three minutes; it does not transcribe audio. LJ explicitly reports whether it read a page, thumbnail or video frames. Private/login-protected or blocked Instagram pages cannot be guaranteed. Public Instagram embeds are tried when the normal page exposes no media. For a blocked link, save the clip yourself and use **Video** in Android attachments or **+ VIDEO** in Windows's composer tools. Only the selected frames are uploaded; the whole local clip is not uploaded. Existing six-photo analysis/edit/create functions remain.

## Android wake and default assistant

1. Open **Voice → SET LJ AS PHONE ASSISTANT** and choose LJ AI in Android's system picker. On Samsung, the side-button assignment may be a separate setting and may still be restricted by the phone.
2. Tap **LISTEN FOR HEY LJ**. This now requests missing Microphone and Notification permissions. Enable it while the app is visible.
3. Say **“Hey el jay”** or **“LJ wake up”**, then wait for the ready chime/Listening before speaking. The chime happens after the live session is ready. **Heard:** shows the offline recognizer's last text to help diagnose microphone/pronunciation problems.
4. Wake listening continues through the visible foreground notification while other apps are open, and resumes after Voice stops. Closing the screen no longer intentionally disables the opted-in listener. The default-assistant service can restore it when Android reconnects that service. If no live screen/default assistant can handle the wake, a notification offers a tap to speak.
When LJ places a phone call, it releases its microphone and pauses wake listening. Wake resumes after Android reports that the phone call has ended and audio is idle. If Android never connects the call or does not report normal call audio, open Voice and enable Hey LJ again after the call. LJ does not join or speak on the call.

5. Use **DISABLE HEY LJ** or the notification's **Stop voice** to turn it off. Signing out disables it. Wake audio is processed locally and not recorded to disk or sent to the cloud.

Unlock the phone to start a voice session. A force-stop, revoked permission or some battery-management policies can stop background listening; reopen Voice in that case. **APP & BATTERY SETTINGS** opens the phone's settings. This uses Android's public assistant APIs, not Samsung/Siri's privileged always-on hardware access. Existing phone calls, message drafts, accessibility controls and SmartThings actions retain their original access settings.

## Build and release

1. Review the **V16.0.5 cloud draft PR**, mark it ready and merge when satisfied. Wait for Render **Live**. Keep `OPENAI_TEXT_DEVELOPER_MODEL=gpt-6-astra` and your existing secrets. The requirements file adds Pillow and the bundled FFmpeg provider for public-media previews; no extra Render service is required.
2. Extract each source ZIP into its own new folder.
3. **Windows:** run `BUILD_LJ_AI_V15_PUBLIC.bat` with Python 3.12 x64 and NSIS, as before. It runs the regression checks and creates `release/LJ_AI_Setup.exe`, its checksum, `client_update.json` and `RENDER_UPDATE_VALUES.txt`.
4. **Android:** open the Android source folder in Android Studio, sync Gradle and run `gradlew.bat :app:testDebugUnitTest`. Generate a signed **release APK using the same keystore and alias** as your existing app. Run `PREPARE_ANDROID_PUBLIC_RELEASE.bat` with the new APK and the previous public APK. It verifies the version/signing certificate and creates `release/LJ_AI_Mobile_V16.0.5.apk` and `ANDROID_RENDER_UPDATE_VALUES.txt`.
5. Install both builds over your existing apps and perform the checks below.
6. Create a new GitHub release: **tag `v16.0.5`**, title **`LJ AI V16.0.5 — Windows & Android`**. Upload the new `LJ_AI_Setup.exe` and `LJ_AI_Mobile_V16.0.5.apk`; wait for both uploads to finish before publishing. Keep old installers in their old releases.
7. Apply the exact values from each build's Render values file. Wait for Render **Live**, then replace the repository-root `client_update.json` with the Windows builder's generated file. That JSON is a repository file; Render values are environment values. Neither is an installer release asset.

The cloud draft does not change your current published updater pointers. Android and Windows update metadata remain independent, and V16.0.4 clients retain the existing API contract during rollout.

## Device checks before publishing

- Ask for a simple JS Bin game in Developer. Confirm real command/checkpoint progress, download the completed source ZIP and run it. Make one follow-up change. Test Stop/Resume on the previously stalled job. Check Normal and Smart replies too.
- Ask LJ to offer a specific TV action; accept with “yeh do that”. Verify it operates the right TV once. Try two alternatives, cancellation and a repeated yes. Confirm previous repeat/seek controls still work.
- Test Hey LJ with the app visible, another app foregrounded, and after closing the LJ screen. Test the system assistant gesture, ready chime, disabled state and sign-out. Check the actual phone's battery behaviour. Ask LJ to place a phone call and verify wake listening pauses for the call and resumes afterwards.
- Send a public image/video link, a blocked Reel and a locally attached clip. Confirm the access report matches what was actually available.
- Check every Windows navigation item and Voice Controls, chat history, Memory, image edit/create, full-code Copy, device handover and idle session reconnection.

## Validation

254 cloud tests plus 102 subtests, 152 Windows tests and 50 focused Kotlin tests passed during development. The Android wake/assistant/recognition services and video attachment code compiled against Android/Vosk APIs with UI collaborators stubbed. Both media-decoder paths produced six real frames from a generated test clip. The full Android Gradle build and Windows installer have not been built in this environment. Native desktop rendering, microphone recognition, live API project generation and real device actions still require the checks above.

Limits remain explicit: cloud source imports 32 MiB compressed / 256 MiB expanded, up to 5,000 ZIP entries. Public media previews are bounded to 24 MiB and 4K input. Local Windows clip sampling accepts supported clips up to 200 MiB. Dependencies and build caches should stay out of source imports.

The bundled Vosk model and its license are unchanged. FFmpeg is supplied through imageio-ffmpeg for media previews; its distribution notices and upstream source are available from https://github.com/imageio/imageio-ffmpeg and https://ffmpeg.org/legal.html.
