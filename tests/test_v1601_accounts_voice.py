import asyncio
import base64
import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException
from starlette.requests import Request

import main
import test_v16_voice_tools as v16


def identity(role="USER", device="android-device-1234"):
    return main.Identity(user_id="00000000-0000-4000-8000-000000000123", email="person@example.com",
        username="person", role=role, plan="VIP", effective_plan="ADMIN" if role == "ADMIN" else "VIP",
        account_status="ACTIVE", device_id=device, access_token="test-token")


class AccountOperationsTests(unittest.IsolatedAsyncioTestCase):
    async def test_registration_passes_limit_three_to_transactional_rpc(self):
        rpc = AsyncMock(return_value=[{"allowed": True}])
        with patch.object(main, "_rpc", new=rpc):
            await main._register_device(identity().user_id, "android-device-1234", "Phone", "Android", "attempt-12345678", datetime.now(timezone.utc))
        name, payload = rpc.await_args.args
        self.assertEqual(name, "register_lj_device_attempt")
        self.assertEqual(payload["p_max_devices"], 3)
        self.assertEqual(payload["p_user_id"], identity().user_id)
        self.assertNotIn("token", payload)

    async def test_fourth_device_denial_explains_three_limit(self):
        with patch.object(main, "_rpc", new=AsyncMock(return_value=[{"allowed": False, "denial_reason": "DEVICE_LIMIT"}])):
            with self.assertRaises(HTTPException) as error:
                await main._register_device(identity().user_id, "android-device-1234", "Phone", "Android", "attempt-12345678", datetime.now(timezone.utc))
        self.assertEqual(error.exception.status_code, 409)
        self.assertIn("3 signed-in devices", error.exception.detail)

    async def test_android_can_revoke_its_own_other_platform_device(self):
        rest = AsyncMock(side_effect=[[{"device_id": "windows-device-1234"}], None])
        with patch.object(main, "_rest_request", new=rest), patch.object(main, "_insert_audit", new=AsyncMock()):
            response = await main.revoke_device("windows-device-1234", identity())
        self.assertEqual(response, {"signed_out": True, "current_device": False})
        for request in rest.await_args_list:
            self.assertEqual(request.kwargs["params"]["user_id"], "eq." + identity().user_id)
            self.assertEqual(request.kwargs["params"]["device_id"], "eq.windows-device-1234")

    async def test_foreign_device_not_found_never_revokes(self):
        rest = AsyncMock(return_value=[])
        with patch.object(main, "_rest_request", new=rest):
            with self.assertRaises(HTTPException) as error:
                await main.revoke_device("foreign-device-1234", identity())
        self.assertEqual(error.exception.status_code, 404)
        self.assertEqual(rest.await_count, 1)

    async def test_device_listing_only_own_active_devices_and_three_limit(self):
        rest = AsyncMock(return_value=[{"device_id": identity().device_id}])
        with patch.object(main, "_rest_request", new=rest):
            rows = await main.devices(identity())
        self.assertEqual(rest.await_args.kwargs["params"]["is_active"], "eq.true")
        self.assertEqual(rest.await_args.kwargs["params"]["user_id"], "eq." + identity().user_id)
        self.assertEqual(rest.await_args.kwargs["params"]["limit"], "3")
        self.assertTrue(rows[0]["current"])
        self.assertEqual(rows[0]["max_devices"], 3)

    async def test_ticket_delete_requires_admin_before_database(self):
        rest = AsyncMock()
        with patch.object(main, "_rest_request", new=rest):
            with self.assertRaises(HTTPException) as error:
                await main.admin_delete_ticket("00000000-0000-4000-8000-000000000456", identity())
        self.assertEqual(error.exception.status_code, 403)
        rest.assert_not_awaited()

    async def test_ticket_delete_exact_id_and_audit(self):
        ticket_id = "00000000-0000-4000-8000-000000000456"
        rest, audit = AsyncMock(return_value=[{"id": ticket_id}]), AsyncMock()
        with patch.object(main, "_rest_request", new=rest), patch.object(main, "_insert_audit", new=audit), patch.object(main.limiter, "enforce", new=AsyncMock()):
            result = await main.admin_delete_ticket(ticket_id, identity("ADMIN"))
        self.assertEqual(result, {"deleted": True, "ticket_id": ticket_id})
        self.assertEqual(rest.await_args.args, ("DELETE", "tickets"))
        self.assertEqual(rest.await_args.kwargs["params"], {"id": "eq." + ticket_id, "select": "id"})
        self.assertEqual(audit.await_args.args[1], "TICKET_DELETED")

    async def test_ticket_delete_invalid_or_missing_never_deletes_other_rows(self):
        for value in ("all", "id=neq.0", "00000000-0000-4000-8000-000000000456"):
            rest = AsyncMock(return_value=[])
            with self.subTest(value=value), patch.object(main, "_rest_request", new=rest), patch.object(main.limiter, "enforce", new=AsyncMock()):
                with self.assertRaises(HTTPException) as error:
                    await main.admin_delete_ticket(value, identity("ADMIN"))
                self.assertEqual(error.exception.status_code, 404)
                if value != "00000000-0000-4000-8000-000000000456":
                    rest.assert_not_awaited()


class V1601VoiceContractTests(unittest.IsolatedAsyncioTestCase):
    async def definitions(self, platform, version="16.0.1"):
        return await v16.V16VoiceToolTests().tool_definitions(platform, version)

    async def test_only_new_android_gets_working_phone_contract(self):
        new_actions = {"SEARCH_WEB", "GO_BACK", "GO_HOME", "TYPE_TEXT", "SEND_CURRENT_MESSAGE", "CALL_CONTACT"}
        for version in ("15.9.9", "16.0.0", "16.0.1"):
            with self.subTest(version=version):
                tools = await self.definitions("ANDROID", version)
                tool = next(t for t in tools if t["name"] == "control_android_device")
                actual = set(tool["parameters"]["properties"]["action"]["enum"])
                self.assertEqual(new_actions.issubset(actual), version == "16.0.1")
                self.assertIn("TORCH_ON", actual)
                self.assertIn("BRIGHTNESS_UP", actual)
        self.assertIn("percentage points", tool["description"])
        self.assertIn("does not imply Send", tool["description"])

    async def test_new_remote_navigation_and_repeat_semantics_on_both_clients(self):
        for platform in ("ANDROID", "WINDOWS"):
            old = next(t for t in await self.definitions(platform, "16.0.0") if t["name"] == "control_smartthings")
            new = next(t for t in await self.definitions(platform) if t["name"] == "control_smartthings")
            self.assertNotIn("BACK", old["parameters"]["properties"]["action"]["enum"])
            self.assertTrue({"BACK", "HOME", "UP", "DOWN", "LEFT", "RIGHT", "SELECT"}.issubset(new["parameters"]["properties"]["action"]["enum"]))
            self.assertIn("not a guaranteed 3x playback speed", new["description"])
            self.assertIn("Never repeat an uncertain command", new["description"])

    async def test_saved_skill_tools_gated_and_variable_contract(self):
        for platform in ("ANDROID", "WINDOWS"):
            for version in ("16.0.0", "16.0.1"):
                tools = await self.definitions(platform, version)
                names = {t["name"] for t in tools}
                self.assertEqual("list_saved_skills" in names, version == "16.0.1")
                run = next(t for t in tools if t["name"] == "run_skill")
                self.assertEqual("variables" in run["parameters"]["properties"], version == "16.0.1")
        teach = next(t for t in await self.definitions("ANDROID") if t["name"] == "teach_lj")
        self.assertIn("To run a saved task use run_skill", teach["description"])

    async def test_prior_windows_installers_can_still_pass_exact_version_handshake(self):
        for version in ("15.9.9", "16.0.0", "16.0.1"):
            with patch.object(main, "_configured", return_value=True):
                response = await main.health(Request({"type": "http", "headers": [(b"user-agent", ("LJ-AI-Windows/" + version).encode())]}))
            self.assertEqual(json.loads(response.body)["version"], version)

    async def test_new_phone_prompt_allows_direct_calls_and_fresh_read_then_action(self):
        for version in ("16.0.0", "16.0.1"):
            session = await v16.V16VoiceToolTests().tool_definitions("ANDROID", version, include_session=True)
            instructions = session["instructions"]
            self.assertEqual("open only a visible dialler/composer" in instructions, version == "16.0.0")
            self.assertEqual("Full Access may start" in instructions, version == "16.0.1")
            self.assertIn("read-only capability lookup", instructions)
            self.assertIn("Never take your own spoken response", instructions)

    async def test_camera_advice_is_grounded_in_attached_image(self):
        encoded = base64.b64encode(b"test-image" * 20).decode()
        openai = AsyncMock(return_value={"output_text": "Try side lighting.", "usage": {}})
        with patch.object(main.limiter, "enforce", new=AsyncMock()), patch.object(main, "_openai_json", new=openai), patch.object(main, "_record_api_usage", new=AsyncMock()), patch.object(main, "_save_chat_log", new=AsyncMock()):
            await main.analyze_screen(main.ScreenRequest(image_base64=encoded, question="Best angle and camera settings?"), identity("ADMIN"))
        payload = openai.await_args.args[1]
        self.assertIn("distinguish visible settings from recommendations", payload["instructions"])
        self.assertIn("stale or missing", payload["instructions"])
        self.assertEqual(payload["input"][0]["content"][1]["image_url"], "data:image/png;base64," + encoded)


if __name__ == "__main__":
    unittest.main()
