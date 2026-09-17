import base64
import copy
import hashlib
import io
import json
import stat
import unittest
import uuid
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
from fastapi import FastAPI, HTTPException
import main
from automatic_memory import (AutomaticMemory, fast_facts, memory_topic, new_voice_memory_turns,
                              rank_memories, validate_facts)
from coding_jobs import (CodingService, LostLease, archive_manifest, read_report,
                         register_coding_jobs, shell_evidence, verified_checks)


OWNER = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"
CID = "cntr_0123456789"
RID = "resp_0123456789"


def source_zip(name="index.html", content=b"<h1>Game</h1>"):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zipped:
        zipped.writestr(name, content)
    return stream.getvalue()


def job():
    return {"id": str(uuid.uuid4()), "user_id": OWNER, "conversation_id": "project-conversation",
        "request_id": "coding-request-one", "prompt": "Build a game", "status": "RUNNING",
        "progress": "Working", "created_at": "2026-09-17T00:00:00+00:00",
        "updated_at": "2026-09-17T00:00:00+00:00", "lease_token": str(uuid.uuid4()),
        "state": {"phase": "BUILD", "response_id": RID, "container_id": CID, "round": 0,
                  "checkpoint_id": "this-checkpoint", "archive_sha256": "a"*64}}


def response(status="completed", code=0):
    return {"id": RID, "status": status, "model": "gpt-6-astra", "usage": {"input_tokens": 100, "output_tokens": 500},
        "output": [{"type": "shell_call", "call_id": "call_123",
                    "action": {"commands": ["node --test tests/game.test.js"]}},
                   {"type": "shell_call_output", "call_id": "call_123",
                    "output": [{"stdout": "Game assertions executed", "stderr": "",
                        "outcome": {"type": "exit", "exit_code": code}}]}]}


def ready_report():
    return {"status": "ready", "checkpoint_id": "this-checkpoint", "summary": "Game built",
            "tests": "Game tests passed", "limitations": "",
            "checks": [{"command": "node --test tests/game.test.js", "description": "Game behavior"}]}


def environment():
    return SimpleNamespace(_configured=lambda: False, _rest_request=AsyncMock(), _rpc=AsyncMock(return_value=True),
        _rpc_boolean=lambda value: value is True, _record_api_usage=AsyncMock(),
        _canonical_chat_context=AsyncMock(return_value=([], [], True)), _memory_instruction_block=lambda x: "",
        OPENAI_TEXT_DEVELOPER_MODEL="gpt-6-astra", OPENAI_API_KEY="test-key")


class ArchiveTests(unittest.TestCase):
    def test_manifest_hashes_exact_source_without_executing(self):
        raw = source_zip("main.py", b"raise RuntimeError('must not run')")
        manifest, digest = archive_manifest(raw)
        self.assertEqual(manifest[0]["path"], "main.py")
        self.assertEqual(manifest[0]["sha256"], hashlib.sha256(b"raise RuntimeError('must not run')").hexdigest())
        self.assertEqual(len(digest), 64)

    def test_unsafe_paths_and_windows_aliases_rejected(self):
        for name in ("../outside", "/absolute", "C:/data", "a\\b", "./file", "aux.txt", "folder/file."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive_manifest(source_zip(name))

    def test_symlinks_and_duplicate_case_paths_rejected(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as zipped:
            entry = zipfile.ZipInfo("link")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(entry, "/outside")
        with self.assertRaises(ValueError):
            archive_manifest(stream.getvalue())
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as zipped:
            zipped.writestr("Readme.md", "one")
            zipped.writestr("README.md", "two")
        with self.assertRaises(ValueError):
            archive_manifest(stream.getvalue())

    def test_each_command_matches_its_own_exit_status(self):
        result = response()
        result["output"][0]["action"]["commands"].insert(0, "echo claimed-success")
        result["output"][1]["output"].insert(0, {"outcome":{"type":"exit", "exit_code":1}})
        evidence = shell_evidence(result)
        self.assertEqual(evidence[0]["command"], "echo claimed-success")
        self.assertEqual(len(verified_checks(ready_report(), evidence)), 1)
        self.assertEqual(verified_checks(ready_report(), shell_evidence(response(code=1))), [])

    def test_invalid_progress_cannot_mark_a_project_ready(self):
        with self.assertRaises(ValueError):
            read_report(b'{"status":"perfect"}')
        with self.assertRaises(ValueError):
            read_report(b'[]')


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    def service(self):
        service = CodingService(environment())
        service.identity = AsyncMock(return_value=SimpleNamespace(user_id=OWNER))
        async def save(row, **changes):
            row.update(copy.deepcopy(changes))
        service.save = AsyncMock(side_effect=save)
        service.api = AsyncMock(return_value=response())
        service.checkpoint = AsyncMock(return_value=True)
        return service

    async def test_in_progress_exposes_actual_model_before_completion(self):
        service, row = self.service(), job()
        service.api.return_value = response("in_progress")
        await service.step(row)
        public = await service.public(row)
        self.assertEqual(public["model"], "gpt-6-astra")
        self.assertEqual(public["provider_status"], "in_progress")

    async def test_stopping_before_first_checkpoint_does_not_claim_files_exist(self):
        service, row = self.service(), job()
        row["status"] = "STOPPING"
        row["state"].pop("archive_sha256")
        await service.step(row)
        self.assertEqual(row["status"], "STOPPED")
        self.assertIn("before the first", row["progress"])
        self.assertFalse((await service.public(row))["has_project"])

    async def test_provider_billing_error_is_actionable_and_does_not_reveal_raw_response(self):
        service, row = self.service(), job()
        service.api.return_value = {**response("failed"), "error": {"code": "insufficient_quota", "message": "secret request content"}}
        await service.step(row)
        public = await service.public(row)
        self.assertEqual(public["provider_error_code"], "insufficient_quota")
        self.assertIn("billing", public["progress"])
        self.assertNotIn("secret", json.dumps(public))

    async def test_token_limit_automatically_continues_saved_work(self):
        service, row = self.service(), job()
        row["state"].update(report=ready_report())
        service.api.return_value = response("incomplete")
        await service.step(row)
        self.assertEqual(row["status"], "RUNNING")
        self.assertEqual(row["state"]["phase"], "BUILD")
        self.assertIsNone(row["state"]["response_id"])
        self.assertEqual(row["state"]["previous_response_id"], RID)
        self.assertFalse(service.env._rpc.called)

    async def test_ready_build_gets_a_separate_review_step(self):
        service, row = self.service(), job()
        row["state"]["report"] = ready_report()
        await service.step(row)
        self.assertEqual(row["state"]["phase"], "REVIEW")
        self.assertEqual(row["status"], "RUNNING")

    async def test_stale_ready_report_never_finishes_a_later_response(self):
        service, row = self.service(), job()
        row["state"].update(phase="REVIEW", report=ready_report())
        service.checkpoint.return_value = False
        await service.step(row)
        service.env._rpc.assert_not_called()

    async def test_failed_test_prevents_completion(self):
        service, row = self.service(), job()
        row["state"].update(phase="REVIEW", report=ready_report())
        service.api.return_value = response(code=1)
        await service.step(row)
        self.assertEqual(row["status"], "RUNNING")
        self.assertIn("Fix failures", row["state"]["report"]["next_steps"])
        service.env._rpc.assert_not_called()

    async def test_prose_only_review_cannot_claim_tested_completion(self):
        service, row = self.service(), job()
        row["state"].update(phase="REVIEW", report=ready_report())
        service.api.return_value = {**response(), "output": []}
        await service.step(row)
        service.env._rpc.assert_not_called()

    async def test_checked_review_atomically_completes_chat_and_job(self):
        service, row = self.service(), job()
        row["state"].update(phase="REVIEW", report=ready_report())
        await service.step(row)
        self.assertEqual(row["status"], "COMPLETED")
        name, args = service.env._rpc.call_args.args
        self.assertEqual(name, "finish_lj_coding_job")
        self.assertEqual(args["p_user_id"], OWNER)
        self.assertEqual(args["p_model"], "gpt-6-astra")
        self.assertIn("SAVE PROJECT", args["p_reply"])

    async def test_missing_zip_at_token_limit_does_not_fail_the_job(self):
        service, row = self.service(), job()
        service.api.return_value = response("incomplete")
        service.checkpoint.side_effect = ValueError("incomplete archive")
        await service.step(row)
        self.assertEqual(row["status"], "RUNNING")
        self.assertIn("valid matching progress", row["state"]["report"]["next_steps"])

    async def test_provider_session_expiry_restores_from_durable_files(self):
        service, row = self.service(), job()
        service.api.side_effect = HTTPException(404, "Expired")
        await service.step(row)
        self.assertEqual(row["status"], "RUNNING")
        self.assertIsNone(row["state"]["response_id"])
        self.assertIsNone(row["state"]["container_id"])

    async def test_uncertain_creation_pauses_instead_of_silently_spending_twice(self):
        service, row = self.service(), job()
        row["state"].update(response_id=None, submitting=True)
        await service.step(row)
        self.assertEqual(row["status"], "PAUSED")
        service.api.assert_not_called()

    async def test_stop_preserves_checkpoint_and_waits_for_cancel_confirmation(self):
        service, row = self.service(), job()
        row["status"] = "STOPPING"
        service.api.return_value = {"status":"in_progress"}
        await service.step(row)
        self.assertEqual(row["status"], "STOPPING")
        service.api.return_value = {"status":"cancelled"}
        await service.step(row)
        self.assertEqual(row["status"], "STOPPED")
        self.assertIsNone(row["state"]["container_id"])
        service.checkpoint.assert_awaited_once()

    async def test_periodic_snapshots_do_not_count_as_stalled_work(self):
        service, row = self.service(), job()
        raw = source_zip()
        row["state"]["unchanged"] = 0
        for _ in range(6):
            await service.persist_archive(row, raw)
        self.assertEqual(row["state"]["unchanged"],0)
        service.env._rpc.return_value = False
        with self.assertRaises(LostLease):
            await service.persist_archive(row,raw)

    async def test_checkpoint_requires_matching_round_and_zip_digest(self):
        service, row = self.service(), job()
        raw, report = source_zip(), ready_report()
        report["archive_sha256"] = hashlib.sha256(raw).hexdigest()
        service.container_files = AsyncMock(return_value=[
            {"path":"/mnt/data/lj_project.zip","id":"cfile_00000001"},
            {"path":"/mnt/data/lj_progress.json","id":"cfile_00000002"}])
        async def api(method,path,*args,**kwargs):
            return json.dumps(report).encode() if "00000002" in path else raw
        service.api.side_effect = api
        self.assertTrue(await CodingService.checkpoint(service,row))
        report["checkpoint_id"] = "previous-round"
        self.assertFalse(await CodingService.checkpoint(service,row))
        report["checkpoint_id"] = "this-checkpoint"
        report["archive_sha256"] = "b"*64
        self.assertFalse(await CodingService.checkpoint(service,row))

    async def test_restart_between_container_creation_and_upload_restores_source(self):
        service, row = self.service(), job()
        row["state"].update(response_id=None,restore_pending=True)
        raw=source_zip()
        service.archive = AsyncMock(return_value={"data_base64":base64.b64encode(raw).decode(),
                                                  "sha256":hashlib.sha256(raw).hexdigest()})
        service.api.side_effect = [{"id":CID,"status":"running"}, {"path":"/mnt/data/lj_restore.zip"}]
        await service.ensure_container(row)
        self.assertEqual(service.api.call_count,2)
        self.assertEqual(service.api.call_args.args[:2],("POST","containers/"+CID+"/files"))
        self.assertFalse(row["state"]["restore_pending"])

    async def test_new_response_has_background_max_reasoning_and_isolated_shell(self):
        service, row = self.service(), job()
        row["state"].update(response_id=None)
        service.ensure_container = AsyncMock()
        service.env._rest_request.return_value = [row]
        await service.begin_response(row,SimpleNamespace(user_id=OWNER))
        payload = service.api.call_args.args[2]
        self.assertTrue(payload["background"])
        self.assertEqual(payload["reasoning"]["effort"],"max")
        self.assertEqual(payload["model"],"gpt-6-astra")
        self.assertEqual(payload["tools"][0]["environment"]["type"],"container_reference")
        self.assertNotIn("network_policy",json.dumps(payload))
        self.assertNotIn("test-key",json.dumps(payload))

    async def test_poll_progress_does_not_expose_provider_identifiers(self):
        row = job()
        row["state"]["submitting"] = True
        public = await CodingService(environment()).public(row)
        for secret in (OWNER,row["lease_token"],RID,CID,"claim_token","submitting"):
            self.assertNotIn(secret,json.dumps(public))


class RouteOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_accounts_cannot_read_download_control_or_delete_job(self):
        env=environment()
        async def identity():
            return SimpleNamespace(user_id=OTHER)
        env.current_identity=identity
        env._authorise_ai_mode=lambda *_:None
        env._rest_request.return_value=[]
        app=FastAPI()
        register_coding_jobs(app,env)
        target=str(uuid.uuid4())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
            for method,suffix in (("GET",""),("GET","/archive"),("POST","/stop"),("POST","/resume"),("DELETE","")):
                result=await client.request(method,"/v1/coding/jobs/"+target+suffix)
                self.assertEqual(result.status_code,404)
        for call in env._rest_request.call_args_list:
            self.assertEqual(call.kwargs["params"]["user_id"],"eq."+OTHER)
        env._rpc.assert_not_called()

    async def test_create_conflict_is_clear_and_does_not_create_second_job(self):
        env=environment()
        async def identity():
            return SimpleNamespace(user_id=OWNER)
        env.current_identity=identity
        env._authorise_ai_mode=lambda *_:None
        env._owned_conversation=AsyncMock()
        env.limiter=SimpleNamespace(enforce=AsyncMock())
        env._rpc.return_value={"conflict":"A project is already running"}
        app=FastAPI()
        register_coding_jobs(app,env)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
            result=await client.post("/v1/coding/jobs",json={"message":"Build a game",
                "conversation_id":"project-chat","request_id":"request-unique"})
        self.assertEqual(result.status_code,409)
        self.assertIn("already running",result.json()["detail"])


class MemoryTests(unittest.IsolatedAsyncioTestCase):
    def test_favourite_colour_and_correction_share_one_key(self):
        for message in ("My favourite colour is purple","Actually, my favorite color has changed to green"):
            facts=fast_facts(message,main._memory_fact_is_safe)
            self.assertEqual(facts[0]["key"],"preference.favorite_color")
            self.assertIn(facts[0]["evidence"],message)

    def test_quotes_hypotheticals_and_code_do_not_become_personal_facts(self):
        for message in ('The NPC says "My favourite colour is purple"',
                        "John said 'My favourite colour is purple'",
                        "Imagine my favourite colour is purple", "My favourite colour is not purple",
                        "function example() { return 'My name is Lauchlan'; }"):
            self.assertEqual(fast_facts(message,main._memory_fact_is_safe),[])

    def test_model_cannot_invent_a_fact_without_user_evidence(self):
        data={"facts":[{"key":"preference.favorite_color","category":"PREFERENCE",
                        "evidence":"My favourite colour is purple"}]}
        self.assertEqual(validate_facts(data,"What is my favourite colour?",main._memory_fact_is_safe),[])

    def test_known_relevant_fact_survives_a_large_newer_memory_list(self):
        rows=[{"fact":"My favorite color is purple","category":"PREFERENCE","updated_at":"2020"}]
        rows += [{"fact":"My project number "+str(n),"category":"PROJECT","updated_at":"2026"} for n in range(100)]
        self.assertIn("My favorite color is purple",rank_memories(rows,"whats my fav colour",3))
        self.assertEqual(rank_memories([{"fact":"disabled","enabled":False},{"fact":"enabled"}],"",1),["enabled"])

    def test_forget_topics_are_precise(self):
        self.assertEqual(memory_topic("my favourite colour"),"preference.favorite_color")
        self.assertIsNone(memory_topic("something about games"))

    def test_voice_heartbeat_replays_and_older_tails_do_not_relearn_facts(self):
        a={"role":"user","content":"My favourite colour is blue"}
        b={"role":"assistant","content":"Understood"}
        c={"role":"user","content":"My favourite colour is green"}
        self.assertEqual(new_voice_memory_turns([a,b],[a,b]),[])
        self.assertEqual(new_voice_memory_turns([a,b,c],[a,b]),[])
        self.assertEqual(new_voice_memory_turns([a,b],[a,b,c]),[(2,c)])

    def test_repeating_a_previous_colour_later_is_a_new_voice_turn(self):
        blue={"role":"user","content":"My favourite colour is blue"}
        green={"role":"user","content":"My favourite colour is green"}
        self.assertEqual(new_voice_memory_turns([blue,green],[blue,green,blue]),[(2,blue)])

    async def test_sensitive_and_quoted_messages_never_enter_memory_queue(self):
        env=environment()
        env._explicit_memory_command=main._explicit_memory_command
        env._memory_fact_is_safe=main._memory_fact_is_safe
        service=AutomaticMemory(env)
        for message in ("My password is banana12345",'He said "my name is Peter"'):
            await service.capture(SimpleNamespace(user_id=OWNER),message,"conversation","memory-request")
        env._rpc.assert_not_called()

    async def test_clear_personal_fact_is_saved_before_capture_returns(self):
        env=environment()
        env._explicit_memory_command=main._explicit_memory_command
        env._memory_fact_is_safe=main._memory_fact_is_safe
        env._rpc.side_effect=[{"id":"event-id","status":"QUEUED"},1]
        result=await AutomaticMemory(env).capture(SimpleNamespace(user_id=OWNER),
            "My favourite colour is purple","conversation","memory-request")
        self.assertEqual(result,{"action":"AUTOMATIC","saved":1})
        self.assertEqual(env._rpc.call_args.args[0],"apply_lj_memory_event")
        self.assertEqual(env._rpc.call_args.args[1]["p_user_id"],OWNER)
