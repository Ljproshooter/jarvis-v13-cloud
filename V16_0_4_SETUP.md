# LJ AI V16.0.4 — Windows and Android

Both apps are **16.0.4**. Android uses version code **16004**. This continues your completed V16.0.3 cloud/database setup and the existing automatic memory work. **No new Supabase SQL is needed.** Do not repeat or reset the database setup.

## What is ready

These are source packages and a separate cloud pull request. They are not compiled installers, and creating the pull request does not deploy it. The published updater remains on the existing release until you build and upload the new binaries.

### Coding

- Windows now respects the mode selected when Send was pressed. Normal, Smart and Deep Think return direct coding replies; Developer uses saved coding projects for eligible VIP/Admin accounts.
- Large Windows replies render in small batches, and chat creation no longer holds the interface lock while waiting for the network. A watchdog records thread stacks if the interface stalls again.
- The cloud gives coding replies larger output budgets. Developer retains the existing `gpt-6-astra` maximum-reasoning configuration, hosted shell, saved files, continuation and review checks.
- Android now has **Chat → Coding Projects**, with progress, actual reported model, provider errors, Stop/Resume, source ZIP import/download and SHA-256 verification. Large replies are paged for display; Copy retains the complete reply.
- A running project is shown as existing work when another request conflicts. Temporary polling failures recover; permanent errors are displayed instead of retrying forever.
- Developer projects have no overall elapsed-time deadline. Individual provider responses still have limits; the worker continues from saved work. Jobs can pause for provider errors, missing input, an uncertain submission or repeated lack of progress. Resume is explicit in these cases.

An awake cloud service is required for unattended progress. Source ZIP checkpoints survive client disconnects. Code quality and external integrations still need testing; neither a model nor this update guarantees perfect code. Existing automatic memory is retained.

### Android actions and SmartThings

- TV commands accept **“go right twice”**, **“go right 3x”** and similar counts. Playback presses are spaced farther apart. A transport-key fallback is used only when the TV advertises it.
- Exact fast-forward/rewind durations need a TV capability that supports timed seeking. “3x” requests three button presses, not a guaranteed playback speed.
- **“Search Netflix for Stranger Things”** and **“find funny cats on YouTube”** open a search on the phone. App/browser behavior and sign-in can affect the destination.
- Add **“on the bedroom TV”** to request TV search. This works only if the TV advertises a compatible app-specific search capability. Otherwise LJ reports it as unsupported; opening the TV app and navigation remain available.
- **“Call Mum”** and **“ring Mum”** resolve the contact and place the call through Android after required permissions and Safe Mode approval, or under existing Full Access. LJ releases its microphone before calling and does not talk for you. Ambiguous contacts require a choice.
- **“Write Mum a message saying I will be home soon”** prepares an SMS draft for review. It does not silently send the message. Existing focused text and explicit Send controls remain.
- In Voice, enable **LISTEN FOR HEY LJ** after granting microphone and notification permissions. Wake detection runs offline using the bundled Vosk model. Say **“Hey LJ”** or **“LJ wake up”**, wait for Listening, then say the request. Wake audio is not uploaded or saved.
- Wake listening uses a visible microphone notification and must be enabled by you. It does not restart after force-close/reboot; re-enable it after stopping voice. Android power management can stop it. It is not a privileged system assistant. The offline model makes the APK larger.

Text and voice share the action routes. Android phone calls remain phone-specific; Windows uses its existing desktop and linked-device capabilities.

## Build and release, in order

1. Review and merge the V16.0.4 cloud pull request, then wait for Render **Live**. Keep your existing secrets and `OPENAI_TEXT_DEVELOPER_MODEL=gpt-6-astra`. No new server secret or database migration is required.
2. Extract each source ZIP into its own new folder. Keep every file together.
3. **Windows:** run `BUILD_LJ_AI_V15_PUBLIC.bat` with Python 3.12 x64 and NSIS installed. The familiar filename is intentional. It runs the regression checks and creates `release/LJ_AI_Setup.exe`, the new checksum, `client_update.json` and `RENDER_UPDATE_VALUES.txt`.
4. **Android:** open the Android source folder in Android Studio. Let Gradle sync, run `gradlew.bat :app:testDebugUnitTest`, then use **Build → Generate Signed App Bundle / APK → APK**. Use the **same keystore and alias as your published APK**. Build the release variant; do not rename an older APK as V16.0.4.
5. Run `PREPARE_ANDROID_PUBLIC_RELEASE.bat`. Supply the new signed APK and previous public APK when prompted. It verifies package/version/signing certificate, names the new file `release/LJ_AI_Mobile_V16.0.4.apk`, computes its SHA-256 and writes `release/ANDROID_RENDER_UPDATE_VALUES.txt`.
6. Install both new builds over the existing apps and run the short checks below.
7. Create GitHub release **tag `v16.0.4`**, title **`LJ AI V16.0.4 — Windows & Android`**. Upload **`LJ_AI_Setup.exe`** and **`LJ_AI_Mobile_V16.0.4.apk`**. Wait for both uploads to finish, then publish. Leave the old Android APK in its old release.
8. In Render Environment, apply the values from Windows `RENDER_UPDATE_VALUES.txt` and Android `ANDROID_RENDER_UPDATE_VALUES.txt`. Wait for **Live**. These are environment values, not release uploads. Use the hashes generated from these exact binaries.
9. Replace the repository-root **`client_update.json`** with the newly generated Windows file. It is a repository file, not a release asset. Doing this after Render is live keeps its version/hash aligned with the Windows download endpoint.

Windows and Android update values are independent. Updating one platform does not require pointing it at the other platform's installer.

## Short device checks

- In Normal, request a small HTML game. Confirm a complete reply and responsive scrolling/copying. Repeat in Smart.
- In Developer, request a JS Bin game. Open Coding Projects, check the reported model/status, wait for completion, save the ZIP and actually run the result. Check Stop/Resume and reopening the app during a job. Test on both clients.
- Ask a follow-up change in the same project chat. Import a small source ZIP and check that requested existing behavior is preserved.
- Try TV right twice/3x, fast-forward presses and a timed seek. Confirm real TV behavior and honest unsupported results.
- With a consenting test contact, check call placement, SMS drafts and wake activation from another app. Stop the notification and confirm wake listening ends.
- Check sign-in after idle, chat sync, automatic memory and ordinary voice. Existing authentication behavior is retained.

## Validation and practical limits

Development checks: **243 cloud tests plus 97 subtests; 147 Windows tests; 45 focused Kotlin/Android tests.** The wake listener was compiled against Android and the actual Vosk/JNA APIs. The full Android Gradle build was not completed because dependency access was unavailable in this environment. The Windows installer was not built here. Native GUI/audio, live OpenAI project generation, real calls and TV behavior require the device checks above.

The cloud worker still limits imported source archives to 32 MiB compressed, 256 MiB expanded and 5,000 entries. Leave dependencies and build caches out. These limits do not truncate source replies silently.

To roll back, stop active coding work, redeploy the preceding cloud commit and restore updater metadata for the matching published binaries. Keep the existing V16.0.3 database tables and user data.

Offline wake model: [Vosk small US English 0.15](https://alphacephei.com/vosk/models), Apache-2.0. Attribution and license are included in the Android source assets.
