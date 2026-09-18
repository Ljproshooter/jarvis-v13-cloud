"""Exercise real worker checkpoints across serialized database/API boundaries."""
import base64
import copy
import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from starlette.requests import Request
import main

from coding_jobs import WORKFLOW_REVISION, CodingService, shell_evidence, verified_checks
from test_v1603_coding_memory import CID, OWNER, RID, environment, job, ready_report, response, source_zip


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = job()
        self.db["state"].pop("archive_sha256")
        self.source = source_zip()
        self.report = ready_report()
        self.report["archive_sha256"] = hashlib.sha256(self.source).hexdigest()
        self.provider = response("in_progress")
        self.downloads = []
        self.saved_archive = None
        self.requests = []
        self.packaged = True
        self.env = environment()
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.provider_http))
        self.env._shared_http_client = lambda: self.client
        self.env._rest_request = self.database
        self.env._rpc = self.rpc
        self.service = CodingService(self.env)
        self.service.identity = AsyncMock(return_value=SimpleNamespace(user_id=OWNER))

    async def asyncTearDown(self):
        await self.client.aclose()

    async def database(self, method, table, *, params=None, payload=None, **kwargs):
        if table == "lj_coding_archives":
            return [copy.deepcopy(self.saved_archive)] if self.saved_archive else []
        self.assertEqual(table, "lj_coding_jobs")
        if method == "PATCH":
            for field in ("id", "user_id", "lease_token"):
                self.assertEqual(params[field], "eq." + self.db[field])
            expected = params.get("status")
            if expected == "in.(RUNNING,STOPPING)":
                self.assertIn(self.db["status"], {"RUNNING", "STOPPING"})
            elif expected:
                self.assertEqual(expected, "eq." + self.db["status"])
            self.db.update(json.loads(json.dumps(payload)))
        # PostgREST returns a new JSON object, never an alias of the input dict.
        return json.loads(json.dumps([self.db]))

    async def rpc(self, name, args):
        self.assertEqual(args["p_job_id"], self.db["id"])
        self.assertEqual(args["p_user_id"], OWNER)
        self.assertEqual(args["p_lease"], self.db["lease_token"])
        if name == "save_lj_coding_checkpoint":
            self.saved_archive = {"data_base64": args["p_data"], "sha256": args["p_sha256"]}
            self.db["state"] = json.loads(json.dumps(args["p_state"]))
        elif name == "finish_lj_coding_job":
            self.assertEqual(self.saved_archive["sha256"], args["p_state"]["archive_sha256"])
            self.db.update(status="COMPLETED", state=copy.deepcopy(args["p_state"]))
            self.db["state"]["reply"] = args["p_reply"]
        else:
            self.fail(name)
        return True

    async def provider_http(self, request):
        path = request.url.path.removeprefix("/v1/")
        if path == "responses" and request.method == "POST":
            self.requests.append(json.loads(request.content))
            return httpx.Response(200, json=response("queued"))
        if path == "responses/" + RID:
            return httpx.Response(200, json=self.provider)
        if path == "containers/" + CID:
            return httpx.Response(200, json={"id": CID, "status": "running"})
        if path == "containers/" + CID + "/files":
            if not self.packaged:
                return httpx.Response(200, json={"data": [
                    {"path": "/mnt/data/project/index.html", "id": "cfile_00000003", "bytes": 13}]})
            return httpx.Response(200, json={"data": [
                {"path": "/mnt/data/lj_project.zip", "id": "cfile_00000001"},
                {"path": "/mnt/data/lj_progress.json", "id": "cfile_00000002"}]})
        if path.endswith("/content"):
            self.downloads.append(path)
            if "00000003" in path:
                return httpx.Response(200, content=b"<h1>Game</h1>")
            raw = json.dumps(self.report).encode() if "00000002" in path else self.source
            return httpx.Response(200, content=raw)
        self.fail(str(request.url))

    async def test_periodic_checkpoint_survives_serialized_progress_write_and_restart(self):
        await self.service.step(copy.deepcopy(self.db))
        public = await self.service.public(copy.deepcopy(self.db))
        self.assertTrue(public["has_project"])
        self.assertEqual(public["sha256"], self.saved_archive["sha256"])
        self.assertEqual(public["files"][0]["path"], "index.html")
        self.assertEqual(public["tests"], "Game tests passed")
        self.assertGreater(self.db["state"]["last_checkpoint"], 0)
        before = len(self.downloads)
        # Another process loads the saved row, rather than reusing the first dict.
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(len(self.downloads), before)
        self.assertEqual(base64.b64decode(self.saved_archive["data_base64"]), self.source)

    async def test_initial_source_snapshot_is_not_redownloaded_every_checkpoint_interval(self):
        self.packaged = False
        await self.service.step(copy.deepcopy(self.db))
        self.assertTrue((await self.service.public(self.db))["has_project"])
        downloads = len(self.downloads)
        # Forty-six seconds later, a fresh process must still know a snapshot exists.
        with patch("coding_jobs.time.time", return_value=self.db["state"]["last_checkpoint"] + 46):
            await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(len(self.downloads), downloads)
        self.assertEqual(self.db["state"]["manifest"][0]["path"], "index.html")

    async def test_real_checkpoint_build_review_complete_across_database_round_trips(self):
        self.provider = response()
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(self.db["state"]["phase"], "REVIEW")
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(self.requests[-1]["reasoning"]["effort"], "max")
        self.report["checkpoint_id"] = self.db["state"]["checkpoint_id"]
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(self.db["status"], "COMPLETED")
        self.assertEqual(len(self.requests), 1)
        self.assertIn("SAVE PROJECT", self.db["state"]["reply"])

    async def test_completed_review_keeps_check_evidence_from_start_of_long_response(self):
        self.db["state"]["phase"] = "REVIEW"
        self.provider = long_response()
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(self.db["status"], "COMPLETED")
        self.assertEqual(self.db["state"]["last_step"]["commands_completed"], 32)
        self.assertEqual(len(self.db["state"]["evidence"]), 30)
        self.assertEqual(len(self.requests), 0)

    async def test_mismatched_check_names_report_the_actual_repair_needed(self):
        self.db["state"]["phase"] = "REVIEW"
        self.provider = response()
        self.report["checks"][0]["command"] = "node tests/different.js"
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(self.db["status"], "RUNNING")
        public = await self.service.public(copy.deepcopy(self.db))
        self.assertEqual(public["last_step"]["outcome"], "verification_missing")
        self.assertIn("test evidence", public["progress"])
        self.assertIn("No exactly matching", self.db["state"]["verification_repair"][0]["reason"])
        await self.service.step(copy.deepcopy(self.db))
        guidance = self.requests[-1]["input"][-1]["content"]
        self.assertIn("node tests/different.js", guidance)
        self.assertIn("Resolve ONLY the verification issues", guidance)

    async def test_stale_checkpoint_requests_repair_without_claiming_completion(self):
        self.db["state"]["phase"] = "REVIEW"
        self.provider = response()
        self.report["checkpoint_id"] = "old-checkpoint"
        await self.service.step(copy.deepcopy(self.db))
        self.assertEqual(self.db["status"], "RUNNING")
        self.assertEqual(self.db["state"]["last_step"]["outcome"], "checkpoint_missing")
        self.assertIn("repairing", self.db["progress"])
        self.assertIn("Do not start extra implementation", self.db["state"]["report"]["next_steps"])

    async def test_health_identifies_runtime_fix_without_changing_client_version(self):
        with patch.object(main, "_configured", return_value=True):
            result = await main.health(Request({"type": "http", "headers": []}))
        data = json.loads(result.body)
        self.assertEqual(data["coding_workflow"], WORKFLOW_REVISION)
        self.assertEqual(data["version"], "16.0.5")


def long_response():
    data = response()
    for i in range(31):
        data["output"] += [
            {"type": "shell_call", "call_id": f"call_{i}", "action": {"commands": [f"cat file_{i}.txt"]}},
            {"type": "shell_call_output", "call_id": f"call_{i}", "output": [
                {"stdout": "", "outcome": {"type": "exit", "exit_code": 0}}]}]
    return data


class EvidenceTests(unittest.TestCase):
    def test_early_successful_check_is_not_discarded_after_thirty_more_commands(self):
        self.assertEqual(len(verified_checks(ready_report(), shell_evidence(long_response()))), 1)

    def test_later_failed_rerun_invalidates_earlier_success_of_same_command(self):
        evidence = shell_evidence(response()) + shell_evidence(response(code=1))
        self.assertEqual(verified_checks(ready_report(), evidence), [])
