import json
import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import ValidationError

import main
from text_actions import ActionOutput, TextActionRequest, register_text_actions


class RefreshRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_short_opaque_refresh_token_reaches_auth_only_after_device_verification(self):
        body = main.RefreshRequest(refresh_token="short-token", device_id="test-device-1602", device_token="d" * 64)
        events = []

        async def owner(*args):
            events.append("device")
            return "user-1602"

        async def upstream(*args, **kwargs):
            events.append("auth")
            self.assertEqual(kwargs["payload"]["refresh_token"], "short-token")
            return {"access_token": "renewed", "refresh_token": "rotated", "user": {"id": "user-1602"}}

        with patch.object(main, "_registered_device_owner", side_effect=owner), patch.object(main, "_auth_request", side_effect=upstream), patch.object(main, "_refresh_response_cache", {}):
            result = await main.refresh(body)
        self.assertEqual(events, ["device", "auth"])
        self.assertEqual(result["access_token"], "renewed")

    async def test_revoked_device_never_reaches_token_rotation(self):
        body = main.RefreshRequest(refresh_token="short", device_id="test-device-1602", device_token="d" * 64)
        auth = AsyncMock()
        with patch.object(main, "_registered_device_owner", new=AsyncMock(side_effect=HTTPException(401, "revoked"))), patch.object(main, "_auth_request", new=auth):
            with self.assertRaises(HTTPException):
                await main.refresh(body)
        auth.assert_not_awaited()

    def test_blank_tokens_still_rejected(self):
        for token in ("", "   "):
            with self.assertRaises(ValidationError):
                main.RefreshRequest(refresh_token=token, device_id="test-device-1602", device_token="d" * 64)


class TextActionRegressionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(main, "SUPABASE_SERVICE_ROLE_KEY", "test-service-secret"))
        self.stack.enter_context(patch.object(main.limiter, "enforce", new=AsyncMock()))
        self.reserve = self.stack.enter_context(patch.object(main, "_reserve_chat_usage", new=AsyncMock(return_value={"claim_token": "a" * 64})))
        self.refund = self.stack.enter_context(patch.object(main, "_refund_chat_usage", new=AsyncMock(return_value=True)))
        self.stack.enter_context(patch.object(main, "_complete_chat_usage", new=AsyncMock(return_value=True)))
        self.stack.enter_context(patch.object(main, "_owned_conversation", new=AsyncMock()))
        self.save = self.stack.enter_context(patch.object(main, "_save_canonical_chat_turn", new=AsyncMock(return_value={"user_message_id": "user-message", "assistant_message_id": "assistant-message"})))
        self.openai = self.stack.enter_context(patch.object(main, "_openai_json", new=AsyncMock()))
        self.endpoint = register_text_actions(FastAPI(), main)
        self.identity = main.Identity(user_id="user-1602", email="test@example.com", username="test", role="ADMIN", plan="ADMIN", effective_plan="ADMIN", account_status="ACTIVE", device_id="device-1602", access_token="access")

    def body(self, **updates):
        return TextActionRequest(**dict({"message": "Open Notepad", "client_platform": "WINDOWS", "app_context": json.dumps({"app": {"platform": "WINDOWS", "version": "16.0.2"}}), "request_id": "typed-request-1602", "conversation_id": "conversation-1602"}, **updates))

    def call(self, name="open_installed_app", arguments=None):
        return {"id": "resp_12345678", "status": "completed", "output": [{"type": "function_call", "call_id": "call-1", "name": name, "arguments": json.dumps(arguments or {"name": "Notepad"})}]}

    async def invoke(self, body):
        return await self.endpoint(body, BackgroundTasks(), self.identity)

    async def test_action_continuation_saves_one_canonical_turn_and_reuses_completed_step(self):
        self.openai.side_effect = [self.call(), {"output_text": "Notepad opened.", "status": "completed"}]
        first = await self.invoke(self.body())
        replay = await self.invoke(self.body())
        self.assertEqual(first, replay)
        self.assertEqual(self.openai.await_count, 1)
        last = await self.invoke(self.body(continuation=first["continuation"], outputs=[{"call_id": "call-1", "output": '{"ok":true,"opened":"Notepad"}'}]))
        self.assertTrue(last["history_saved"])
        self.assertEqual(last["reply"], "Notepad opened.")
        self.assertEqual(self.save.await_count, 1)
        self.refund.assert_awaited_once()  # The intermediate call is not another billed text message.
        self.assertEqual(self.openai.await_args.args[1]["previous_response_id"], "resp_12345678")

    async def test_confirmation_stops_further_actions(self):
        self.openai.side_effect = [self.call(), {"output_text": "Review the approval prompt.", "status": "completed"}]
        first = await self.invoke(self.body())
        await self.invoke(self.body(continuation=first["continuation"], outputs=[{"call_id": "call-1", "output": '{"ok":true,"confirmation_required":true}'}]))
        self.assertEqual(self.openai.await_args.args[1]["tool_choice"], "none")

    async def test_signed_continuation_cannot_cross_request_or_device(self):
        self.openai.return_value = self.call()
        first = await self.invoke(self.body())
        for changes in ({"message": "Open another app"}, {"continuation": first["continuation"] + "x"}):
            values = dict(continuation=first["continuation"], outputs=[{"call_id": "call-1", "output": '{"ok":true}'}])
            values.update(changes)
            with self.assertRaises(HTTPException) as error:
                await self.invoke(self.body(**values))
            self.assertEqual(error.exception.status_code, 409)
        self.identity.device_id = "another-device"
        with self.assertRaises(HTTPException):
            await self.invoke(self.body(continuation=first["continuation"], outputs=[{"call_id": "call-1", "output": '{"ok":true}'}]))
        self.assertEqual(self.openai.await_count, 1)

    async def test_normal_chat_falls_back_without_consuming_action_allowance(self):
        self.openai.return_value = {"output_text": "NO_ACTION", "status": "completed"}
        result = await self.invoke(self.body(message="What is the capital of France?"))
        self.assertFalse(result["handled"])
        self.refund.assert_awaited_once()
        self.save.assert_not_awaited()

    async def test_tools_match_voice_catalogue_on_each_platform(self):
        for platform, context in (("WINDOWS", self.body().app_context), ("ANDROID", "LJ AI Mobile Android 16.0.2; approved device controls")):
            self.openai.return_value = {"output_text": "NO_ACTION"}
            await self.invoke(self.body(client_platform=platform, app_context=context, request_id="parity-request-"+platform))
            actual = self.openai.await_args.args[1]["tools"]
            expected = main._app_action_tools(main.RealtimeTokenRequest(client_platform=platform, app_context=context), self.identity)
            self.assertEqual({tool["name"] for tool in actual}, {tool["name"] for tool in expected})
            self.assertIn("control_smartthings", {tool["name"] for tool in actual})

    async def test_unsupported_or_client_authority_arguments_never_issued(self):
        for name, args in (("delete_everything", {}), ("open_installed_app", {"name": "Notepad", "_spoken_command": "untrusted"})):
            self.openai.return_value = self.call(name, args)
            with self.assertRaises(HTTPException) as error:
                await self.invoke(self.body())
            self.assertEqual(error.exception.status_code, 502)

    async def test_incomplete_model_response_cannot_execute_a_tool(self):
        self.openai.return_value = dict(self.call(), status="incomplete")
        with self.assertRaises(HTTPException):
            await self.invoke(self.body())
        self.refund.assert_awaited_once()

    def test_malformed_tool_output_is_rejected_before_model_request(self):
        for output in ("broken JSON", "[]"):
            with self.assertRaises(ValidationError):
                ActionOutput(call_id="call-1", output=output)


if __name__ == "__main__":
    unittest.main()
