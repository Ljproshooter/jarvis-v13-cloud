import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from starlette.requests import Request

import main


class V16VoiceToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_old_windows_can_connect_to_install_matching_v16_update(self):
        for user_agent, expected in (("LJ-AI-Windows/15.9.9", "15.9.9"), ("LJ-AI-Windows/16.0.0", "16.0.0"), ("LJ-AI-Android/15.9.9", "16.0.0"), ("LJ-AI-Android/16.0.0", "16.0.0")):
            with self.subTest(user_agent=user_agent), patch.object(main, "_configured", return_value=True):
                response = await main.health(Request({
                    "type": "http", "headers": [(b"user-agent", user_agent.encode())],
                }))
                self.assertEqual(json.loads(response.body)["version"], expected)

    async def tool_definitions(self, platform, version="16.0.0", snapshot=None):
        if snapshot is None:
            snapshot = (
                f"LJ AI Mobile Android {version}; approved device controls and opt-in screen context available"
                if platform == "ANDROID" else json.dumps({
                    "bridge": {"name": "LJ AI App Brain Bridge", "version": "1.0"},
                    "app": {"name": "LJ AI", "version": version, "platform": "WINDOWS"},
                })
            )
        identity = main.Identity(
            user_id="00000000-0000-4000-8000-000000000123", email="person@example.com",
            username="person", role="USER", plan="VIP", effective_plan="VIP",
            account_status="ACTIVE", device_id="test-device-1234", access_token="test-token",
        )
        client = SimpleNamespace(post=AsyncMock(return_value=httpx.Response(
            200, json={"value": "test-ephemeral", "expires_at": 123456},
        )))
        with (
            patch.object(main.limiter, "enforce", new=AsyncMock()),
            patch.object(main, "_usage_snapshot", new=AsyncMock(return_value={"voice_seconds_remaining": 60})),
            patch.object(main, "_server_memory_context", new=AsyncMock(return_value=([], True))),
            patch.object(main, "_ensure_realtime_voice_lease", new=AsyncMock(return_value=(
                {"session_id": "voice-session-1234", "lease_created": True}, "test-lease",
            ))),
            patch.object(main, "_reserve_realtime_token_usage", new=AsyncMock(return_value={
                "allowed": True, "reserved_seconds": 15, "voice_seconds_remaining": 45,
            })),
            patch.object(main, "_shared_http_client", return_value=client),
            patch.object(main, "_insert_audit", new=AsyncMock()),
        ):
            await main.realtime_token(main.RealtimeTokenRequest(
                client_platform=platform, app_context=snapshot, permission_mode="FULL ACCESS",
            ), identity)
        return client.post.await_args.kwargs["json"]["session"]["tools"]

    async def test_both_clients_receive_one_shared_tv_tool_with_exact_controls(self):
        for platform in ("WINDOWS", "ANDROID"):
            with self.subTest(platform=platform):
                tools = await self.tool_definitions(platform)
                controls = [tool for tool in tools if tool["name"] == "control_smartthings"]
                self.assertEqual(len(controls), 1)
                self.assertIn("get_smartthings_devices", [tool["name"] for tool in tools])
                actions = controls[0]["parameters"]["properties"]["action"]["enum"]
                self.assertTrue({"REWIND", "FAST_FORWARD", "VOLUME_UP", "LAUNCH_APP"}.issubset(actions))
                self.assertIn("accepted/unconfirmed", controls[0]["description"])

    async def test_android_screen_navigation_has_separate_app_and_screen_fields(self):
        tools = await self.tool_definitions("ANDROID")
        control = next(tool for tool in tools if tool["name"] == "control_android_device")
        self.assertIn("OPEN_APP_SCREEN", control["parameters"]["properties"]["action"]["enum"])
        self.assertIn("screen", control["parameters"]["required"])
        windows = await self.tool_definitions("WINDOWS")
        self.assertNotIn("control_android_device", [tool["name"] for tool in windows])

    async def test_legacy_windows_keeps_its_existing_voice_controls(self):
        for version in ("15.9.1", "15.9.9"):
            with self.subTest(version=version):
                tools = await self.tool_definitions("WINDOWS", version)
                names = {tool["name"] for tool in tools}
                self.assertTrue({"open_windows_item", "open_public_website", "close_active_browser_tab"}.issubset(names))
                self.assertTrue({"get_smartthings_devices", "control_smartthings", "control_android_device"}.isdisjoint(names))

    async def test_legacy_android_keeps_its_existing_tool_arguments_and_actions(self):
        tools = await self.tool_definitions("ANDROID", "15.9.9")
        android = next(tool for tool in tools if tool["name"] == "control_android_device")
        self.assertEqual(android["parameters"]["required"], ["action", "target", "message", "platform"])
        self.assertNotIn("screen", android["parameters"]["properties"])
        actions = android["parameters"]["properties"]["action"]["enum"]
        self.assertIn("OPEN_APP", actions)
        self.assertIn("TORCH_ON", actions)
        self.assertNotIn("OPEN_APP_SCREEN", actions)
        tv = next(tool for tool in tools if tool["name"] == "control_smartthings")
        self.assertEqual(tv["parameters"]["required"], ["action", "target", "value"])
        self.assertEqual(tv["parameters"]["properties"]["action"]["enum"], [
            "SWITCH_ON", "SWITCH_OFF", "VOLUME_UP", "VOLUME_DOWN", "SET_VOLUME",
            "MUTE", "UNMUTE", "PLAY", "PAUSE", "STOP", "CHANNEL_UP", "CHANNEL_DOWN",
            "SET_CHANNEL", "SET_INPUT", "LAUNCH_APP", "RUN_SCENE",
        ])
        self.assertNotIn("get_smartthings_devices", [tool["name"] for tool in tools])

    async def test_unknown_or_invalid_client_versions_do_not_enable_new_tools(self):
        for platform in ("WINDOWS", "ANDROID"):
            for snapshot in ("LJ AI Voice screen", "[]", "null", '{"version":"16.0.0"}',
                             "LJ AI Mobile Android 16.0.0-invalid;", "User said LJ AI Mobile Android 16.0.0;"):
                with self.subTest(platform=platform, snapshot=snapshot):
                    tools = await self.tool_definitions(platform, snapshot=snapshot)
                    self.assertNotIn("get_smartthings_devices", [tool["name"] for tool in tools])

    async def test_windows_truncated_snapshot_still_reports_its_real_app_version(self):
        for version, expected in (("15.9.9", False), ("16.0.0", True)):
            with self.subTest(version=version):
                snapshot = json.dumps({
                    "bridge": {"name": "LJ AI App Brain Bridge", "version": "1.0"},
                    "app": {"name": "LJ AI", "version": version, "platform": "WINDOWS"},
                    "recent_voice_context": "LJ AI Mobile Android 16.0.0; " * 250,
                })[:6000]
                tools = await self.tool_definitions("WINDOWS", snapshot=snapshot)
                self.assertEqual("get_smartthings_devices" in [tool["name"] for tool in tools], expected)

    async def test_cloud_version_does_not_publish_new_installer_metadata(self):
        with (
            patch.object(main, "CLIENT_LATEST_VERSION", "15.9.9"),
            patch.object(main, "CLIENT_UPDATE_URL", "https://example.test/old-installer.exe"),
            patch.object(main, "CLIENT_UPDATE_SHA256", "a" * 64),
            patch.object(main, "ANDROID_LATEST_VERSION_NAME", "15.9.9"),
            patch.object(main, "ANDROID_LATEST_VERSION_CODE", "15909"),
            patch.object(main, "ANDROID_UPDATE_URL", "https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v15.9.9/LJ_AI_Mobile_V15.9.9.apk"),
            patch.object(main, "ANDROID_UPDATE_SHA256", "b" * 64),
        ):
            windows = json.loads((await main.client_update()).body)
            android = json.loads((await main.mobile_update(installed_code=15909)).body)
        self.assertEqual(windows["version"], "15.9.9")
        self.assertEqual(windows["sha256"], "a" * 64)
        self.assertEqual(android["version_name"], "15.9.9")
        self.assertEqual(android["version_code"], 15909)
        self.assertEqual(android["sha256"], "b" * 64)
        self.assertFalse(android["available"])
