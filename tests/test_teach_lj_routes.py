from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

from pydantic import ValidationError

# The release installs FastAPI from requirements.txt.  Keep these policy tests
# runnable in minimal source-review environments too, where only Pydantic is
# available, by providing the tiny routing surface this module needs to import.
try:
    import fastapi  # noqa: F401
except ModuleNotFoundError:
    fastapi_stub = types.ModuleType("fastapi")

    class _Route:
        def __init__(self, path: str, method: str) -> None:
            self.path = path
            self.methods = {method}

    class _Router:
        def __init__(self, prefix: str = "", **_kwargs) -> None:
            self.prefix = prefix
            self.routes: list[_Route] = []

        def _decorator(self, method: str, path: str, **_kwargs):
            self.routes.append(_Route(f"{self.prefix}{path}", method))

            def wrap(function):
                return function

            return wrap

        def get(self, path: str, **kwargs):
            return self._decorator("GET", path, **kwargs)

        def post(self, path: str, **kwargs):
            return self._decorator("POST", path, **kwargs)

        def put(self, path: str, **kwargs):
            return self._decorator("PUT", path, **kwargs)

        def patch(self, path: str, **kwargs):
            return self._decorator("PATCH", path, **kwargs)

        def delete(self, path: str, **kwargs):
            return self._decorator("DELETE", path, **kwargs)

    class _HttpException(Exception):
        def __init__(self, status_code: int, detail: object) -> None:
            super().__init__(str(detail))
            self.status_code = status_code
            self.detail = detail

    fastapi_stub.APIRouter = _Router
    fastapi_stub.Depends = lambda dependency=None: dependency
    fastapi_stub.HTTPException = _HttpException
    fastapi_stub.Query = lambda default=None, **_kwargs: default
    fastapi_stub.status = types.SimpleNamespace(HTTP_201_CREATED=201, HTTP_204_NO_CONTENT=204)
    sys.modules["fastapi"] = fastapi_stub

from teach_lj_routes import (
    SemanticStep,
    SafetyPolicy,
    SkillCreate,
    SkillRunStart,
    SkillVariable,
    build_public_run,
    confirmation_material_facts,
    confirmation_reason,
    create_teach_lj_router,
    validate_run_variables,
)


class _Limiter:
    async def enforce(self, *_args, **_kwargs) -> None:
        return None


async def _async_stub(*_args, **_kwargs):
    return []


class TeachLjValidationTests(unittest.TestCase):
    def test_client_action_aliases_are_normalized(self) -> None:
        step = SemanticStep(
            step_id="open_chrome",
            action="open_app",
            arguments={"app": "Google Chrome"},
        )
        self.assertEqual(step.action, "launch_app")

    def test_semantic_workflow_accepts_variables(self) -> None:
        skill = SkillCreate(
            name="Upload YouTube Video",
            variables_schema=[
                {"name": "VIDEO_FILE", "type": "file_path"},
                {"name": "VIDEO_TITLE", "type": "text"},
            ],
            required_apps=["Google Chrome"],
            required_sites=["youtube.com"],
            steps=[
                {"step_id": "open", "action": "open_website", "arguments": {"url": "https://studio.youtube.com"}},
                {
                    "step_id": "file",
                    "action": "choose_file",
                    "target": {"role": "button", "name": "Select files"},
                    "arguments": {"variable": "VIDEO_FILE"},
                },
                {
                    "step_id": "title",
                    "action": "set_text",
                    "target": {"role": "textbox", "name": "Title"},
                    "arguments": {"variable": "VIDEO_TITLE", "clear_first": True},
                },
                {
                    "step_id": "publish",
                    "action": "publish_content",
                    "target": {"role": "button", "name": "Publish"},
                },
            ],
        )
        self.assertEqual(skill.steps[0].action, "open_url")
        self.assertEqual(skill.required_sites, ["https://youtube.com"])

    def test_raw_coordinates_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="bad",
                action="click_element",
                target={"role": "button", "name": "Upload"},
                arguments={"x": 450, "y": 200},
            )

    def test_scripts_and_shells_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="bad_script",
                action="click_element",
                target={"role": "button", "name": "Run"},
                arguments={"script": "do something"},
            )
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="bad_shell",
                action="launch_app",
                arguments={"app": "powershell.exe"},
            )
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="bad_shell_path",
                action="launch_app",
                arguments={"app": "C:/Windows/System32/cmd.exe"},
            )
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="bad_run_dialog",
                action="press_key",
                arguments={"key": "R", "modifiers": ["META"]},
            )

    def test_password_capture_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            SkillVariable(name="ACCOUNT_PASSWORD", type="text")
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="password",
                action="set_text",
                target={"role": "password", "name": "Password"},
                arguments={"value": "never store this"},
            )
        with self.assertRaises(ValidationError):
            SkillVariable(name="UPLOAD_FILE", type="file_path", default="C:/private/file.txt")

    def test_incomplete_and_literal_text_actions_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            SemanticStep(step_id="missing_url", action="open_url")
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="literal_text",
                action="set_text",
                target={"role": "textbox", "name": "Title"},
                arguments={"value": "recorded text"},
            )
        with self.assertRaises(ValidationError):
            SafetyPolicy(confirm_target_keywords=False)

    def test_risky_steps_require_confirmation(self) -> None:
        step = {
            "step_id": "send",
            "action": "send_message",
            "target": {"role": "button", "name": "Send"},
        }
        self.assertIsNotNone(confirmation_reason(step, {}))
        self.assertIsNotNone(
            confirmation_reason(
                step,
                {"auto_approve_actions": ["send_message"], "confirm_target_keywords": True},
            )
        )
        with self.assertRaises(ValidationError):
            SafetyPolicy(auto_approve_actions=["send_message"])
        purchase = {"step_id": "buy", "action": "make_purchase", "target": {"role": "button", "name": "Buy"}}
        self.assertIsNotNone(confirmation_reason(purchase, {"auto_approve_actions": ["make_purchase"]}))
        with self.assertRaises(ValidationError):
            SemanticStep(
                step_id="close",
                action="press_key",
                target={"role": "window", "name": "Browser"},
                arguments={"key": "W", "modifiers": ["CTRL"]},
            )
        disguised_delete = {
            "step_id": "generic_click",
            "action": "click_element",
            "target": {"role": "button", "accessibility_id": "delete-account"},
        }
        self.assertIsNotNone(confirmation_reason(disguised_delete, {}))

    def test_enter_needs_semantic_target_and_confirmation(self) -> None:
        with self.assertRaises(ValidationError):
            SemanticStep(step_id="enter", action="press_key", arguments={"key": "ENTER"})
        step = SemanticStep(
            step_id="enter",
            action="press_key",
            target={"role": "button", "name": "Continue"},
            arguments={"key": "ENTER"},
        )
        self.assertIsNotNone(confirmation_reason(step.model_dump(), {}))

    def test_generic_taps_and_option_changes_require_confirmation(self) -> None:
        for label in ("Continue", "Next", "Done", "OK"):
            with self.subTest(label=label):
                step = SemanticStep(
                    step_id=f"tap_{label.casefold()}",
                    action="click_element",
                    target={"role": "button", "name": label},
                )
                self.assertIsNotNone(confirmation_reason(step.model_dump(), {}))
        option = SemanticStep(
            step_id="visibility",
            action="select_option",
            target={"role": "combobox", "name": "Visibility"},
            arguments={"value": "Public"},
        )
        self.assertIsNotNone(confirmation_reason(option.model_dump(), {}))
        _context, facts = confirmation_material_facts(option.model_dump(), {})
        self.assertEqual(facts["value"], "Public")

    def test_set_text_requires_confirmation_with_bounded_resolved_value(self) -> None:
        step = SemanticStep(
            step_id="title",
            action="set_text",
            target={"role": "textbox", "name": "Video title"},
            arguments={"variable": "VIDEO_TITLE", "clear_first": True},
        )
        self.assertIsNotNone(confirmation_reason(step.model_dump(), {}))
        _context, facts = confirmation_material_facts(
            step.model_dump(), {"VIDEO_TITLE": "x" * 700}
        )
        self.assertEqual(facts["value"], "x" * 500)

    def test_signed_and_private_urls_are_rejected(self) -> None:
        for url in (
            "https://example.com/reset?code=secret",
            "https://example.com/path#token",
            "http://127.0.0.1:8080/admin",
            "http://localhost/settings",
        ):
            with self.subTest(url=url), self.assertRaises(ValidationError):
                SemanticStep(step_id="open", action="open_url", arguments={"url": url})

    def test_confirmation_resolves_material_facts(self) -> None:
        step = {
            "action": "make_purchase",
            "arguments": {
                "merchant": "Example Shop",
                "amount_variable": "TOTAL",
                "currency": "AUD",
            },
        }
        context, facts = confirmation_material_facts(step, {"TOTAL": 19.95})
        self.assertEqual(context["amount_variable"], "TOTAL")
        self.assertEqual(facts["amount"], 19.95)
        self.assertEqual(facts["merchant"], "Example Shop")
        self.assertEqual(facts["currency"], "AUD")

    def test_run_variables_are_typed_and_unknown_values_rejected(self) -> None:
        schema = [
            {"name": "VIDEO_FILE", "type": "file_path", "required": True},
            {"name": "VISIBILITY", "type": "choice", "choices": ["Public", "Private"], "required": True},
        ]
        values = validate_run_variables(schema, {"VIDEO_FILE": "C:/video.mp4", "VISIBILITY": "Private"})
        self.assertEqual(values["VISIBILITY"], "Private")
        with self.assertRaises(ValueError):
            validate_run_variables(schema, {"VIDEO_FILE": "C:/video.mp4", "VISIBILITY": "Friends"})

    def test_router_exposes_crud_and_run_state(self) -> None:
        router = create_teach_lj_router(
            current_identity=_async_stub,
            rest_request=_async_stub,
            rpc=_async_stub,
            insert_audit=_async_stub,
            limiter=_Limiter(),
        )
        paths = {(route.path, tuple(sorted(route.methods or []))) for route in router.routes}
        self.assertIn(("/v1/skills", ("GET",)), paths)
        self.assertIn(("/v1/skills", ("POST",)), paths)
        self.assertIn(("/v1/skills/{skill_id}/duplicate", ("POST",)), paths)
        self.assertIn(("/v1/skills/{skill_id}/runs", ("POST",)), paths)
        self.assertIn(("/v1/skill-runs/{run_id}/advance", ("POST",)), paths)
        self.assertIn(("/v1/skill-runs/{run_id}/confirm", ("POST",)), paths)

    def test_only_running_execute_state_authorizes_device_bound_execution(self) -> None:
        version = {
            "steps": [{"step_id": "open", "action": "launch_app", "arguments": {"app": "Chrome"}}]
        }
        base_run = {
            "id": "run-id",
            "skill_id": "skill-id",
            "skill_version": 2,
            "device_id": "device-1234",
            "current_step_index": 0,
            "state_version": 4,
            "variables": {},
        }
        running = build_public_run(
            {**base_run, "mode": "EXECUTE", "status": "RUNNING"}, version
        )
        self.assertTrue(running["should_execute"])
        self.assertEqual(running["device_id"], "device-1234")
        ready_execute = build_public_run(
            {**base_run, "mode": "EXECUTE", "status": "READY"}, version
        )
        self.assertFalse(ready_execute["should_execute"])
        test_ready = build_public_run(
            {**base_run, "mode": "TEST", "status": "READY"}, version
        )
        self.assertFalse(test_ready["should_execute"])
        self.assertNotIn("confirmation_token", running)

    def test_sql_enforces_run_cas_and_no_auto_approval(self) -> None:
        sql = (Path(__file__).resolve().parents[1] / "LJ_AI_TEACH_LJ_DATABASE_UPDATE.sql").read_text()
        self.assertIn("p_expected_state_version", sql)
        self.assertIn("state_version = r.state_version + 1", sql)
        self.assertIn("then 'RUNNING' else 'CANCELLED'", sql)
        self.assertIn("jsonb_array_length(policy->'auto_approve_actions') = 0", sql)
        self.assertIn("start_lj_skill_run", sql)
        self.assertIn("delete_lj_skill", sql)


class TeachLjRouterStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_execute_returns_running_and_test_returns_ready(self) -> None:
        skill_id = "00000000-0000-4000-8000-000000000111"
        user_id = "00000000-0000-4000-8000-000000000222"
        device_id = "device-12345678"

        async def rest_request(method: str, path: str, **kwargs):
            if method == "GET" and path == "lj_skills":
                return [{
                    "id": skill_id,
                    "user_id": user_id,
                    "name": "Open browser",
                    "enabled": True,
                    "current_version": 1,
                }]
            if method == "GET" and path == "lj_skill_versions":
                return [{
                    "id": "00000000-0000-4000-8000-000000000333",
                    "skill_id": skill_id,
                    "user_id": user_id,
                    "version": 1,
                    "variables_schema": [],
                    "required_apps": ["Chrome"],
                    "required_sites": [],
                    "safety_policy": {"auto_approve_actions": [], "confirm_target_keywords": True},
                    "steps": [{"step_id": "open", "action": "launch_app", "arguments": {"app": "Chrome"}}],
                    "change_note": "",
                }]
            if method == "POST" and path == "lj_skill_run_events":
                return None
            raise AssertionError((method, path, kwargs))

        async def rpc(name: str, payload: dict):
            self.assertEqual(name, "start_lj_skill_run")
            return [{
                "id": "00000000-0000-4000-8000-000000000444",
                "skill_id": skill_id,
                "skill_version": 1,
                "user_id": user_id,
                "device_id": device_id,
                "mode": payload["p_mode"],
                "status": payload["p_status"],
                "state_version": 0,
                "variables": {},
                "current_step_index": 0,
            }]

        router = create_teach_lj_router(
            current_identity=_async_stub,
            rest_request=rest_request,
            rpc=rpc,
            insert_audit=_async_stub,
            limiter=_Limiter(),
        )
        route = next(item for item in router.routes if item.path == "/v1/skills/{skill_id}/runs")
        if not hasattr(route, "endpoint"):
            self.skipTest("FastAPI route endpoints are unavailable in the minimal import stub.")
        identity = {"user_id": user_id, "device_id": device_id}
        execute = await route.endpoint(skill_id, SkillRunStart(mode="EXECUTE"), identity)
        self.assertEqual(execute["status"], "RUNNING")
        self.assertTrue(execute["should_execute"])
        self.assertEqual(execute["device_id"], device_id)
        preview = await route.endpoint(skill_id, SkillRunStart(mode="TEST"), identity)
        self.assertEqual(preview["status"], "READY")
        self.assertFalse(preview["should_execute"])


if __name__ == "__main__":
    unittest.main()
