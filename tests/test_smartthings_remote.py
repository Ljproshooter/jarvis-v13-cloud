"""Provider-facing TV regressions. No real account or devices are contacted."""
import asyncio
import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from cryptography.fernet import Fernet
from fastapi import HTTPException

from smartthings_routes import SmartThingsCommand, SmartThingsRemoteRequest, create_smartthings_router


DEVICE_ID = "test-tv-device"


def capability_definition(command, arguments=()):
    return {"commands": {command: {"arguments": list(arguments)}}}


class SmartThingsRemoteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        self.env = patch.dict(os.environ, {
            "SMARTTHINGS_CLIENT_ID": "test-client", "SMARTTHINGS_CLIENT_SECRET": "test-secret",
            "SMARTTHINGS_REDIRECT_URI": "https://example.test/callback",
            "SMARTTHINGS_TOKEN_ENCRYPTION_KEY": key.decode(),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.identity = SimpleNamespace(user_id="test-user", device_id="test-phone")
        self.rest = AsyncMock(return_value=[{
            "id": "connection-id", "access_token_ciphertext": cipher.encrypt(b"provider-test-token").decode(),
            "token_expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }])
        self.audit = AsyncMock()
        router = create_smartthings_router(current_identity=AsyncMock(), rest_request=self.rest,
            insert_audit=self.audit, limiter=SimpleNamespace(enforce=AsyncMock()))
        self.remote = next(route.endpoint for route in router.routes if route.path.endswith("/remote"))
        self.command = next(route.endpoint for route in router.routes if route.path.endswith("/commands"))
        self.device = {"label": "Lounge TV", "components": [{"id": "main", "capabilities": []}]}
        self.status = {}
        self.definitions = {}
        self.sent = []
        self.outcomes = []
        self.after_send_status = None
        self.stamp_after_send = False
        self.mock_client = AsyncMock()
        self.mock_client.__aenter__.return_value = self.mock_client
        self.mock_client.request.side_effect = self.request
        self.client_patch = patch("smartthings_routes.httpx.AsyncClient", return_value=self.mock_client)
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)
        self.sleep_patch = patch("smartthings_routes.asyncio.sleep", new=AsyncMock())
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)

    def expose(self, capability, command, arguments=(), component="main"):
        self.device["components"][0]["id"] = component
        self.device["components"][0]["capabilities"].append({"id": capability, "version": 1})
        self.definitions[capability] = capability_definition(command, arguments)

    async def request(self, method, url, **kwargs):
        path = url.split("/v1", 1)[1]
        if method == "POST":
            self.sent.append(kwargs["json"])
            if self.stamp_after_send and self.after_send_status is not None:
                for component in self.after_send_status.get("components", {}).values():
                    for capability in component.values():
                        for attribute in capability.values():
                            if isinstance(attribute, dict) and "value" in attribute:
                                attribute.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            outcome = self.outcomes.pop(0) if self.outcomes else {"results": [{"status": "ACCEPTED", "id": "cmd-id"}]}
            if isinstance(outcome, Exception):
                raise outcome
            return httpx.Response(200, json=outcome)
        if path.endswith("/status"):
            return httpx.Response(200, json=self.after_send_status if self.sent and self.after_send_status is not None else self.status)
        if path.startswith("/capabilities/"):
            return httpx.Response(200, json=self.definitions[path.split("/")[2]])
        return httpx.Response(200, json=self.device)

    async def run_action(self, action, value=""):
        return await self.remote(DEVICE_ID, SmartThingsRemoteRequest(action=action, value=value), self.identity)

    async def test_netflix_uses_current_tv_id_and_does_not_claim_opened_on_acceptance(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        result = await self.run_action("LAUNCH_APP", "Netflix")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], ["3201907018807"])
        self.assertTrue(result["accepted"])
        self.assertFalse(result["confirmed"])
        self.assertEqual(result["status"], "accepted")
        self.assertIn("has not confirmed", result["message"])

    async def test_twice_sends_exactly_two_separate_right_presses(self):
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string", "enum": ["RIGHT"]}}])
        result = await self.run_action("RIGHT", "twice")
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(result["requested_count"], 2)
        self.assertFalse(result["confirmed"])

    async def test_fast_forward_falls_back_only_to_an_advertised_transport_key(self):
        self.expose("samsungvd.remoteControl", "send", [{"name": "key", "schema": {"type": "string", "enum": ["FAST_FORWARD"]}}])
        result = await self.run_action("FAST_FORWARD", "3x")
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], ["FAST_FORWARD"])
        self.assertFalse(result["confirmed"])

    async def test_transport_key_is_never_guessed_from_a_free_form_remote(self):
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string"}}])
        with self.assertRaises(HTTPException) as raised:
            await self.run_action("FAST_FORWARD", "3x")
        self.assertEqual(raised.exception.status_code, 422)
        self.assertFalse(self.sent)

    async def test_tv_search_never_claims_support_or_launches_an_unrelated_app(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        with self.assertRaises(HTTPException) as raised:
            await self.run_action("SEARCH_NETFLIX", "Stranger Things")
        self.assertIn("does not advertise", raised.exception.detail)
        self.assertFalse(self.sent)

    async def test_search_uses_only_the_advertised_app_scoped_schema(self):
        self.expose("example.mediaSearch", "searchContent", [
            {"name": "app", "schema": {"type": "string", "enum": ["Netflix", "YouTube"]}},
            {"name": "query", "schema": {"type": "string"}},
        ])
        result = await self.run_action("SEARCH_NETFLIX", "Stranger Things")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], ["Netflix", "Stranger Things"])
        self.assertFalse(result["confirmed"])

    async def test_device_advertised_netflix_id_overrides_default_on_correct_component(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}], component="screen")
        self.status = {"components": {"screen": {"custom.launchapp": {
            "installedApps": {"value": [{"name": "Netflix", "appId": "tv-generation-id"}]}
        }}}}
        await self.run_action("LAUNCH_APP", "Netflix")
        command = self.sent[0]["commands"][0]
        self.assertEqual(command["arguments"], ["tv-generation-id"])
        self.assertEqual(command["component"], "screen")

    async def test_completed_app_command_still_needs_observed_application(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        self.outcomes = [{"results": [{"status": "COMPLETED"}]}]
        self.assertFalse((await self.run_action("LAUNCH_APP", "Netflix"))["confirmed"])

    async def test_observed_application_can_confirm_launch(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        self.after_send_status = {"components": {"main": {"tvChannel": {"tvChannelName": {"value": "Netflix"}}}}}
        self.stamp_after_send = True
        result = await self.run_action("LAUNCH_APP", "Netflix")
        self.assertTrue(result["confirmed"])
        self.assertIn("reports Netflix is open", result["message"])

    async def test_cached_or_undated_app_status_does_not_confirm_launch(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        for timestamp in [None, "not-a-date", datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                          (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                          (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()]:
            with self.subTest(timestamp=timestamp):
                attribute = {"value": "Netflix"}
                if timestamp is not None:
                    attribute["timestamp"] = timestamp
                self.after_send_status = {"components": {"main": {"custom.launchapp": {"currentApp": attribute}}}}
                result = await self.run_action("LAUNCH_APP", "Netflix")
                self.assertTrue(result["accepted"])
                self.assertFalse(result["confirmed"])

    async def test_cached_or_undated_switch_status_does_not_confirm_remote_command(self):
        self.expose("switch", "off")
        for attribute in [{"value": "off"}, {"value": "off", "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}]:
            self.after_send_status = {"components": {"main": {"switch": {"switch": attribute}}}}
            self.assertFalse((await self.run_action("SWITCH_OFF"))["confirmed"])

    async def test_fresh_switch_report_can_confirm_remote_command(self):
        self.expose("switch", "off")
        self.after_send_status = {"components": {"main": {"switch": {"switch": {"value": "off"}}}}}
        self.stamp_after_send = True
        self.assertTrue((await self.run_action("SWITCH_OFF"))["confirmed"])

    async def test_cached_or_undated_switch_status_does_not_confirm_legacy_command(self):
        self.expose("switch", "off")
        for attribute in [{"value": "off"}, {"value": "off", "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}]:
            self.after_send_status = {"components": {"main": {"switch": {"switch": attribute}}}}
            result = await self.command(DEVICE_ID, SmartThingsCommand(capability="switch", command="off"), self.identity)
            self.assertTrue(result["accepted"])
            self.assertFalse(result["confirmed"])

    async def test_fresh_switch_report_can_confirm_legacy_command(self):
        self.expose("switch", "off")
        self.after_send_status = {"components": {"main": {"switch": {"switch": {"value": "off"}}}}}
        self.stamp_after_send = True
        result = await self.command(DEVICE_ID, SmartThingsCommand(capability="switch", command="off"), self.identity)
        self.assertTrue(result["confirmed"])

    async def test_ten_volume_presses_are_ten_ordered_commands(self):
        self.expose("audioVolume", "volumeUp")
        result = await self.run_action("VOLUME_UP", "10x")
        self.assertEqual(len(self.sent), 10)
        self.assertEqual(result["sent_count"], 10)
        self.assertTrue(all(item["commands"][0]["command"] == "volumeUp" for item in self.sent))
        self.assertFalse(result["confirmed"])

    async def test_lower_volume_count_does_not_become_absolute_volume(self):
        self.expose("audioVolume", "volumeDown")
        await self.run_action("VOLUME_DOWN", "10 times")
        self.assertEqual(len(self.sent), 10)
        self.assertTrue(all(item["commands"][0]["arguments"] == [] for item in self.sent))
        self.assertTrue(all(item["commands"][0]["command"] == "volumeDown" for item in self.sent))

    async def test_partial_failure_stops_sequence_without_retry(self):
        self.expose("audioVolume", "volumeUp")
        self.outcomes = [{"results": [{"status": "ACCEPTED"}]}, {"results": [{"status": "FAILED"}]}]
        result = await self.run_action("VOLUME_UP", "10")
        self.assertEqual(len(self.sent), 2)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "partial")
        self.assertIn("1 of 10 acknowledged", result["message"])

    async def test_ambiguous_network_failure_is_not_retried(self):
        self.expose("audioVolume", "volumeUp")
        self.outcomes = [httpx.ReadTimeout("after write")]
        result = await self.run_action("VOLUME_UP", "10")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["ok"])
        self.assertIn("may have reached", result["message"])

    async def test_total_deadline_stops_repeat_sequence_after_inflight_timeout(self):
        self.expose("audioVolume", "volumeUp")
        normal_request = self.request

        async def slow_second_command(method, url, **kwargs):
            if method == "POST" and self.sent:
                self.sent.append(kwargs["json"])
                await asyncio.Event().wait()
            return await normal_request(method, url, **kwargs)

        self.mock_client.request.side_effect = slow_second_command
        with patch("smartthings_routes._REMOTE_DEADLINE_SECONDS", 0.01):
            result = await self.run_action("VOLUME_UP", "20")
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(result["sent_count"], 2)
        self.assertEqual(result["acknowledged_count"], 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "unknown")
        self.assertIn("did not retry", result["message"])

    async def test_total_deadline_during_discovery_sends_no_command(self):
        async def stuck_discovery(*args, **kwargs):
            await asyncio.Event().wait()

        self.mock_client.request.side_effect = stuck_discovery
        with patch("smartthings_routes._REMOTE_DEADLINE_SECONDS", 0.01):
            result = await self.run_action("LAUNCH_APP", "Netflix")
        self.assertEqual(self.sent, [])
        self.assertEqual(result["sent_count"], 0)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "timeout")
        self.assertIn("No TV command was sent", result["message"])

    async def test_excessive_count_is_rejected_before_provider_calls(self):
        for value in ["0", "-10", "21", "10.5", "ten more or whatever"]:
            with self.assertRaises(HTTPException):
                await self.run_action("VOLUME_UP", value)
        self.mock_client.request.assert_not_called()

    async def test_exact_rewind_cannot_fall_back_to_continuous_rewind(self):
        self.expose("mediaPlayback", "rewind")
        with self.assertRaises(HTTPException) as error:
            await self.run_action("REWIND", "15 minutes")
        self.assertEqual(error.exception.status_code, 422)
        self.assertIn("exact timed seeking", error.exception.detail)
        self.assertEqual(self.sent, [])

    async def test_declared_relative_seek_converts_seconds_and_minutes_to_milliseconds(self):
        self.expose("vendor.mediaPlayback", "skipBackward", [{"name": "deltaPositionMilliseconds", "schema": {"type": "integer", "minimum": 0}}])
        await self.run_action("REWIND", "5 seconds")
        await self.run_action("REWIND", "15 minutes")
        self.assertEqual([item["commands"][0]["arguments"] for item in self.sent], [[5000], [900000]])

    async def test_timed_seek_rejects_ambiguous_units(self):
        self.expose("vendor.mediaPlayback", "skipBackward", [{"name": "amount", "schema": {"type": "integer"}}])
        with self.assertRaises(HTTPException):
            await self.run_action("REWIND", "5 seconds")
        self.assertEqual(self.sent, [])

    async def test_timed_seek_respects_device_parameter_bounds(self):
        self.expose("vendor.mediaPlayback", "skipBackward", [{"name": "seconds", "schema": {"type": "integer", "maximum": 60}}])
        with self.assertRaises(HTTPException):
            await self.run_action("REWIND", "15 minutes")
        self.assertEqual(self.sent, [])

    async def test_absolute_seek_does_not_use_stale_cached_position(self):
        self.expose("vendor.mediaPlayback", "seek", [{"name": "positionMilliseconds", "schema": {"type": "integer", "minimum": 0}}])
        self.status = {"components": {"main": {"vendor.mediaPlayback": {"position": {
            "value": 120000, "unit": "ms", "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
        }}}}}
        with self.assertRaises(HTTPException):
            await self.run_action("REWIND", "5 seconds")
        self.assertEqual(self.sent, [])

    async def test_absolute_seek_converts_current_position_units(self):
        self.expose("vendor.mediaPlayback", "seek", [{"name": "positionMilliseconds", "schema": {"type": "integer", "minimum": 0}}])
        self.status = {"components": {"main": {"vendor.mediaPlayback": {"position": {
            "value": 120, "unit": "s", "timestamp": datetime.now(timezone.utc).isoformat(),
        }}}}}
        await self.run_action("REWIND", "5 seconds")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], [115000])

    async def test_absolute_seek_does_not_silently_shorten_requested_duration(self):
        self.expose("vendor.mediaPlayback", "seek", [{"name": "positionSeconds", "schema": {"type": "integer", "minimum": 0}}])
        self.status = {"components": {"main": {"vendor.mediaPlayback": {"position": {
            "value": 120, "unit": "s", "timestamp": datetime.now(timezone.utc).isoformat(),
        }}}}}
        with self.assertRaises(HTTPException) as error:
            await self.run_action("REWIND", "15 minutes")
        self.assertIn("before the start", error.exception.detail)
        self.assertEqual(self.sent, [])

    async def test_direction_status_cannot_confirm_exact_timed_rewind(self):
        self.expose("mediaPlayback", "rewind", [{"name": "seconds", "schema": {"type": "integer", "minimum": 0}}])
        self.after_send_status = {"components": {"main": {"mediaPlayback": {"playbackStatus": {"value": "rewinding"}}}}}
        result = await self.run_action("REWIND", "5 seconds")
        self.assertFalse(result["confirmed"])

    async def test_audit_database_outage_does_not_hide_accepted_device_result(self):
        self.expose("audioVolume", "volumeUp")
        self.audit.side_effect = RuntimeError("database unavailable")
        with self.assertLogs("smartthings_routes", "WARNING"):
            result = await self.run_action("VOLUME_UP", "10")
        self.assertTrue(result["accepted"])
        self.assertEqual(len(self.sent), 10)

    async def test_audit_database_outage_does_not_hide_legacy_command_result(self):
        self.expose("switch", "off")
        self.audit.side_effect = RuntimeError("database unavailable")
        with self.assertLogs("smartthings_routes", "WARNING"):
            result = await self.command(DEVICE_ID, SmartThingsCommand(capability="switch", command="off"), self.identity)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["confirmed"])

    async def test_standard_command_failed_result_is_not_accepted(self):
        self.expose("switch", "off")
        self.outcomes = [{"results": [{"status": "FAILED"}]}]
        with self.assertRaises(HTTPException) as error:
            await self.command(DEVICE_ID, SmartThingsCommand(capability="switch", command="off"), self.identity)
        self.assertEqual(error.exception.status_code, 502)

    async def test_unsupported_device_capability_is_not_sent(self):
        with self.assertRaises(HTTPException) as error:
            await self.run_action("LAUNCH_APP", "Netflix")
        self.assertEqual(error.exception.status_code, 422)
        self.assertEqual(self.sent, [])

    async def test_playback_command_must_be_supported_by_current_device(self):
        self.expose("mediaPlayback", "rewind")
        self.status = {"components": {"main": {"mediaPlayback": {"supportedPlaybackCommands": {"value": ["play", "pause"]}}}}}
        with self.assertRaises(HTTPException):
            await self.run_action("REWIND")
        self.assertEqual(self.sent, [])

    async def test_new_samsung_launch_omits_optional_app_objects(self):
        self.expose("samsungvd.appControl", "launch", [
            {"name": "appId", "schema": {"type": "string"}},
            {"name": "appData", "optional": True, "schema": {"type": "object"}},
            {"name": "launchingOption", "optional": True, "schema": {"type": "object"}},
        ], component="screen")
        result = await self.run_action("LAUNCH_APP", "Netflix")
        self.assertEqual(self.sent[0]["commands"][0], {"component": "screen", "capability": "samsungvd.appControl",
            "command": "launch", "arguments": ["3201907018807"]})
        self.assertTrue(result["accepted"])
        self.assertFalse(result["confirmed"])

    async def test_new_launch_resolves_advertised_app_name_and_application_id(self):
        self.expose("samsungvd.appControl", "launch", [{"name": "appId", "schema": {"type": "string"}}])
        self.status = {"components": {"main": {"samsungvd.appControl": {"appList": {
            "value": [{"appName": "My Player", "applicationId": "player-2026"}]
        }}}}}
        await self.run_action("LAUNCH_APP", "My Player")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], ["player-2026"])

    async def test_ambiguous_advertised_app_ids_do_not_fall_back_to_guessed_id(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        self.status = {"components": {"main": {"custom.launchapp": {"installedApps": {
            "value": [{"name": "Netflix", "id": "one"}, {"name": "Netflix", "id": "two"}]
        }}}}}
        with self.assertRaises(HTTPException):
            await self.run_action("LAUNCH_APP", "Netflix")
        self.assertEqual(self.sent, [])

    async def test_unknown_app_name_is_not_sent_as_an_invented_id(self):
        self.expose("custom.launchapp", "launchApp", [{"name": "appId", "schema": {"type": "string"}}])
        with self.assertRaises(HTTPException):
            await self.run_action("LAUNCH_APP", "Unknown Player")
        self.assertEqual(self.sent, [])

    async def test_required_trailing_launch_argument_is_not_fabricated(self):
        self.expose("samsungvd.appControl", "launch", [
            {"name": "appId", "schema": {"type": "string"}},
            {"name": "mandatoryOptions", "schema": {"type": "object"}},
        ])
        with self.assertRaises(HTTPException):
            await self.run_action("LAUNCH_APP", "Netflix")
        self.assertEqual(self.sent, [])

    async def test_optional_volume_argument_can_be_omitted(self):
        self.expose("audioVolume", "volumeUp", [{"name": "transition", "optional": True, "schema": {"type": "integer"}}])
        await self.run_action("VOLUME_UP", "3x")
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], [])

    async def test_scalar_constraints_are_checked_before_command(self):
        self.expose("mediaInputSource", "setInputSource", [{"name": "input", "schema": {"type": "string", "enum": ["HDMI1"]}}])
        with self.assertRaises(HTTPException):
            await self.run_action("SET_INPUT", "HDMI2")
        self.assertEqual(self.sent, [])

    async def test_samsung_back_uses_declared_bounded_press_release(self):
        self.expose("samsungvd.remoteControl", "send", [
            {"name": "key", "schema": {"type": "string", "enum": ["BACK", "OK"]}},
            {"name": "state", "schema": {"type": "string", "enum": ["PRESSED", "RELEASED", "PRESS_AND_RELEASED"]}},
        ])
        result = await self.run_action("BACK")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], ["BACK", "PRESS_AND_RELEASED"])
        self.assertTrue(result["accepted"])
        self.assertFalse(result["confirmed"])

    async def test_samsung_select_maps_to_ok_and_standard_select_remains_select(self):
        self.expose("samsungvd.remoteControl", "send", [{"name": "key", "schema": {"type": "string", "enum": ["OK"]}}])
        await self.run_action("SELECT")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], ["OK"])
        self.device["components"][0]["capabilities"] = []
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string", "enum": ["SELECT"]}}])
        await self.run_action("SELECT")
        self.assertEqual(self.sent[1]["commands"][0]["arguments"], ["SELECT"])

    async def test_unusable_native_schema_selects_standard_keypad_before_sending(self):
        self.expose("samsungvd.remoteControl", "send", [
            {"name": "key", "schema": {"type": "string"}},
            {"name": "state", "schema": {"type": "string", "enum": ["PRESSED", "RELEASED"]}},
        ])
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string", "enum": ["BACK"]}}])
        await self.run_action("BACK")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["commands"][0]["capability"], "keypadInput")

    async def test_native_failure_is_never_retried_as_keypad_fallback(self):
        self.expose("samsungvd.remoteControl", "send", [{"name": "key", "schema": {"type": "string"}}])
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string"}}])
        self.outcomes = [httpx.ReadTimeout("after write")]
        result = await self.run_action("BACK")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(result["status"], "unknown")

    async def test_current_supported_key_list_is_respected(self):
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string", "enum": ["BACK", "HOME"]}}])
        self.status = {"components": {"main": {"keypadInput": {"supportedKeyCodes": {"value": ["HOME"]}}}}}
        with self.assertRaises(HTTPException):
            await self.run_action("BACK")
        self.assertEqual(self.sent, [])

    async def test_navigation_repeat_count_and_completion_are_honest(self):
        self.expose("keypadInput", "sendKey", [{"name": "keyCode", "schema": {"type": "string", "enum": ["RIGHT"]}}])
        self.outcomes = [{"results": [{"status": "COMPLETED"}]}] * 3
        result = await self.run_action("RIGHT", "3x")
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(result["requested_count"], 3)
        self.assertFalse(result["confirmed"])

    async def test_rewind_and_fast_forward_repeat_without_time_arguments(self):
        self.expose("mediaPlayback", "rewind")
        self.definitions["mediaPlayback"]["commands"]["fastForward"] = {"arguments": []}
        for action, value in [("REWIND", "3x"), ("FAST_FORWARD", "3 times")]:
            result = await self.run_action(action, value)
            self.assertEqual(result["requested_count"], 3)
            self.assertFalse(result["confirmed"])
            self.assertIn("button presses", result["message"])
        self.assertEqual([item["commands"][0]["command"] for item in self.sent], ["rewind"] * 3 + ["fastForward"] * 3)
        self.assertTrue(all(item["commands"][0]["arguments"] == [] for item in self.sent))

    async def test_unsupported_exact_duration_does_not_become_three_presses(self):
        self.expose("mediaPlayback", "rewind")
        for value in ["3 seconds", "3"]:
            with self.assertRaises(HTTPException):
                await self.run_action("REWIND", value)
        self.assertEqual(self.sent, [])

    async def test_seek_repeats_still_obey_current_playback_command_list(self):
        self.expose("mediaPlayback", "fastForward")
        self.status = {"components": {"main": {"mediaPlayback": {"supportedPlaybackCommands": {"value": ["play"]}}}}}
        with self.assertRaises(HTTPException):
            await self.run_action("FAST_FORWARD", "3x")
        self.assertEqual(self.sent, [])

    async def test_invalid_repeat_counts_rejected_before_provider_calls(self):
        for action in ["REWIND", "FAST_FORWARD", "RIGHT", "CHANNEL_UP"]:
            for value in ["0x", "21x"]:
                with self.assertRaises(HTTPException):
                    await self.run_action(action, value)
        self.mock_client.request.assert_not_called()

    async def test_exact_seek_can_omit_optional_argument_and_use_argument_description_units(self):
        self.expose("vendor.mediaPlayback", "skipBackward", [
            {"name": "amount", "description": "Duration in seconds", "schema": {"type": "integer"}},
            {"name": "mode", "optional": True, "schema": {"type": "string"}},
        ])
        await self.run_action("REWIND", "5 seconds")
        self.assertEqual(self.sent[0]["commands"][0]["arguments"], [5])

    async def test_completed_exact_seek_does_not_claim_observed_distance(self):
        self.expose("vendor.mediaPlayback", "skipBackward", [{"name": "seconds", "schema": {"type": "integer"}}])
        self.outcomes = [{"results": [{"status": "COMPLETED"}]}]
        self.assertFalse((await self.run_action("REWIND", "5 seconds"))["confirmed"])


if __name__ == "__main__":
    unittest.main()
