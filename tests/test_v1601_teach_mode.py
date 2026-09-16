import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException
from pydantic import ValidationError

import main
from teach_lj_routes import SkillRunStart, SkillRunAdvance, confirmation_reason, create_teach_lj_router


UID = "00000000-0000-4000-8000-000000000123"
SID = "00000000-0000-4000-8000-000000000456"
RID = "00000000-0000-4000-8000-000000000789"
DEVICE = "android-device-1234"
ORDINARY = {"step_id": "routine", "action": "click_element", "target": {"role": "button", "name": "Routines", "app": "SmartThings"}, "arguments": {}}


class TeachRunModePolicyTests(unittest.TestCase):
    def test_safe_default_and_explicit_full_access(self):
        self.assertEqual(SkillRunStart().control_mode, "SAFE_MODE")
        with self.assertRaises(ValidationError):
            SkillRunStart(control_mode="ADMIN")
        for action in ("click_element", "set_text", "select_option"):
            step = {**ORDINARY, "action": action}
            self.assertIsNotNone(confirmation_reason(step, {}, "SAFE_MODE"))
            self.assertIsNone(confirmation_reason(step, {}, "FULL_ACCESS"))

    def test_full_access_still_requires_sensitive_external_and_submit_confirmation(self):
        for label in ("Send", "Delete account", "Pay", "Authorize", "Password", "Terminal", "Complete", "Publish"):
            self.assertIsNotNone(confirmation_reason({**ORDINARY, "target": {"name": label}}, {}, "FULL_ACCESS"))
        for action in ("send_message", "delete_item", "make_purchase", "publish_content", "upload_file", "change_security_setting"):
            self.assertIsNotNone(confirmation_reason({**ORDINARY, "action": action}, {}, "FULL_ACCESS"))
        for key in ("ENTER", "SPACE", "DELETE", "BACKSPACE"):
            self.assertIsNotNone(confirmation_reason({"action": "press_key", "arguments": {"key": key}}, {}, "FULL_ACCESS"))


class TeachRunModeRoutesTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.run = {"id": RID, "skill_id": SID, "skill_version": 1, "user_id": UID,
            "device_id": DEVICE, "mode": "EXECUTE", "status": "RUNNING", "state_version": 0,
            "current_step_index": 0, "variables": {}, "control_mode": "FULL_ACCESS"}
        self.steps = [ORDINARY]
        self.summary_fails = False
        self.rpc = AsyncMock(side_effect=self.rpc_result)
        self.audit = AsyncMock()
        self.router = create_teach_lj_router(current_identity=AsyncMock(), rest_request=self.rest,
            rpc=self.rpc, insert_audit=self.audit, limiter=SimpleNamespace(enforce=AsyncMock()))
        self.identity = {"user_id": UID, "device_id": DEVICE}

    def endpoint(self, path, method):
        return next(route.endpoint for route in self.router.routes if route.path == path and method in route.methods)

    async def rest(self, method, path, **kwargs):
        if path == "lj_skills" and method == "GET":
            self.assertEqual(kwargs["params"]["user_id"], "eq." + UID)
            return [{"id": SID, "user_id": UID, "name": "Routines", "enabled": True, "current_version": 1}]
        if path == "lj_skill_versions":
            return [{"skill_id": SID, "user_id": UID, "version": 1, "steps": self.steps,
                "variables_schema": [], "required_apps": [], "required_sites": [], "safety_policy": {}}]
        if path == "lj_skill_runs":
            self.assertEqual(kwargs["params"]["user_id"], "eq." + UID)
            return [self.run.copy()]
        if path == "lj_skill_run_events":
            return None
        if path == "lj_skills" and method == "PATCH":
            if self.summary_fails:
                raise HTTPException(status_code=503, detail="Database service is unavailable.")
            return None
        raise AssertionError((method, path, kwargs))

    async def rpc_result(self, name, payload):
        if name.startswith("start_lj_skill_run"):
            return [{**self.run, "control_mode": payload.get("p_control_mode", "SAFE_MODE"),
                     "status": payload["p_status"], "pending_confirmation": payload["p_pending_confirmation"]}]
        if name == "transition_lj_skill_run":
            self.assertEqual(payload["p_user_id"], UID)
            self.assertEqual(payload["p_device_id"], DEVICE)
            self.assertEqual(payload["p_expected_state_version"], self.run["state_version"])
            return [{**self.run, "status": payload["p_new_status"], "current_step_index": payload["p_new_step"],
                     "pending_confirmation": payload["p_pending_confirmation"], "state_version": 1}]
        raise AssertionError(name)

    async def start(self, mode="FULL_ACCESS"):
        return await self.endpoint("/v1/skills/{skill_id}/runs", "POST")(
            SID, SkillRunStart(control_mode=mode), self.identity)

    async def test_full_access_run_permission_bound_atomically_by_new_rpc(self):
        result = await self.start()
        self.assertEqual(self.rpc.await_args.args[0], "start_lj_skill_run_v1601")
        payload = self.rpc.await_args.args[1]
        self.assertEqual(payload["p_user_id"], UID)
        self.assertEqual(payload["p_device_id"], DEVICE)
        self.assertEqual(payload["p_control_mode"], "FULL_ACCESS")
        self.assertEqual(payload["p_variables"], {})
        self.assertEqual(result["control_mode"], "FULL_ACCESS")
        self.assertTrue(result["should_execute"])
        self.assertIsNone(result["pending_confirmation"])

    async def test_missing_function_fallback_is_safe_and_visible(self):
        self.rpc.side_effect = [HTTPException(status_code=503, detail={"code": "teach_run_mode_unavailable"}),
            {**self.run, "control_mode": "SAFE_MODE", "status": "WAITING_CONFIRMATION"}]
        result = await self.start()
        self.assertEqual(self.rpc.await_count, 2)
        self.assertEqual(self.rpc.await_args.args[0], "start_lj_skill_run")
        self.assertEqual(self.rpc.await_args.args[1]["p_status"], "WAITING_CONFIRMATION")
        self.assertTrue(self.rpc.await_args.args[1]["p_confirmation_token_hash"])
        self.assertEqual(result["control_mode"], "SAFE_MODE")
        self.assertFalse(result["should_execute"])
        self.assertIn("database update", result["permission_notice"])

    async def test_unknown_rpc_failure_never_retries_mutation(self):
        for failure in (HTTPException(status_code=502, detail="Database request failed."),
                        HTTPException(status_code=503, detail="Database service is unavailable.")):
            with self.subTest(status=failure.status_code):
                self.rpc.reset_mock()
                self.rpc.side_effect = failure
                with self.assertRaises(HTTPException):
                    await self.start()
                self.assertEqual(self.rpc.await_count, 1)

    async def test_default_legacy_run_remains_safe(self):
        result = await self.start("SAFE_MODE")
        self.assertEqual(self.rpc.await_args.args[0], "start_lj_skill_run")
        self.assertEqual(result["status"], "WAITING_CONFIRMATION")
        self.assertFalse(result["should_execute"])

    async def test_continue_uses_stored_run_mode_not_input_variable(self):
        self.steps = [ORDINARY, {**ORDINARY, "step_id": "second"}]
        self.run["control_mode"] = "SAFE_MODE"
        self.run["variables"] = {"CONTROL_MODE": "FULL_ACCESS"}
        result = await self.endpoint("/v1/skill-runs/{run_id}/advance", "POST")(
            RID, SkillRunAdvance(completed_step=0, success=True), self.identity)
        self.assertEqual(result["status"], "WAITING_CONFIRMATION")
        self.assertFalse(result["should_execute"])

    async def test_foreign_device_cannot_advance_full_access_run(self):
        with self.assertRaises(HTTPException) as raised:
            await self.endpoint("/v1/skill-runs/{run_id}/advance", "POST")(
                RID, SkillRunAdvance(completed_step=0, success=True), {"user_id": UID, "device_id": "foreign-device-1234"})
        self.assertEqual(raised.exception.status_code, 403)
        self.rpc.assert_not_awaited()

    async def test_summary_database_failure_does_not_hide_committed_success(self):
        self.summary_fails = True
        result = await self.endpoint("/v1/skill-runs/{run_id}/advance", "POST")(
            RID, SkillRunAdvance(completed_step=0, success=True), self.identity)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertFalse(result["should_execute"])
        self.assertEqual(self.rpc.await_count, 1)
        self.assertIn("SKILL_RUN_SUMMARY_WRITE_FAILED", [call.args[1] for call in self.audit.await_args_list])


class MissingFunctionRecognitionTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_explicit_missing_new_rpc_maps_to_safe_fallback_code(self):
        for code, table, expected in (("PGRST202", "rpc/start_lj_skill_run_v1601", 503),
            ("PGRST202", "rpc/start_lj_skill_run", 502), ("PGRST301", "rpc/start_lj_skill_run_v1601", 502)):
            client = SimpleNamespace(request=AsyncMock(return_value=httpx.Response(404, json={"code": code})))
            with self.subTest(code=code, table=table), patch.object(main, "_require_configuration"), patch.object(main, "_shared_http_client", return_value=client):
                with self.assertRaises(HTTPException) as raised:
                    await main._rest_request("POST", table, payload={})
                self.assertEqual(raised.exception.status_code, expected)
                if expected == 503:
                    self.assertEqual(raised.exception.detail["code"], "teach_run_mode_unavailable")


if __name__ == "__main__":
    unittest.main()
