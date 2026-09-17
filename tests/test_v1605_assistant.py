import asyncio
import base64
import io
import json
import socket
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from PIL import Image
from coding_jobs import CodingService
from link_media import LinkEvidence, checked_url, fetch_public, inspect_link, public_addresses
from tests import test_v1603_coding_memory as fixtures
from tests.test_v1603_coding_memory import job, response, OWNER
from types import SimpleNamespace


class CodingProgressTests(unittest.IsolatedAsyncioTestCase):
    def service(self):
        return fixtures.WorkerTests().service()

    async def test_review_retains_maximum_model_effort(self):
        service, row = self.service(), job()
        row["state"].update(response_id=None, phase="REVIEW")
        service.ensure_container = AsyncMock()
        service.env._rest_request.return_value = [row]
        await service.begin_response(row, SimpleNamespace(user_id=OWNER))
        payload = service.api.call_args.args[2]
        self.assertEqual(payload["reasoning"]["effort"], "max")
        self.assertEqual(payload["model"], "gpt-6-astra")

    async def test_live_commands_are_separate_from_completed_steps(self):
        service, row = self.service(), job()
        service.api.return_value = response("in_progress")
        await service.step(row)
        public = await service.public(row)
        self.assertEqual(public["round"], 0)
        self.assertEqual(public["commands_completed"], 1)
        self.assertIn("1 commands finished", public["progress"])
        self.assertTrue(public["last_checked_at"])

    async def test_long_reasoning_is_reported_truthfully_without_a_project_deadline(self):
        service, row = self.service(), job()
        row["state"]["round"] = 3
        row["state"]["response_started_at"] = "2020-01-01T00:00:00+00:00"
        service.api.return_value = {"id": "resp_0123456789", "status":"in_progress", "output":[]}
        await service.step(row)
        self.assertEqual(row["status"], "RUNNING")
        self.assertIn("Build step 4:", row["progress"])
        self.assertIn("no completed commands reported in this step", row["progress"])
        self.assertNotIn("no shell commands have run", row["progress"])
        self.assertEqual(row["state"]["round"], 3)
        self.assertTrue(row["state"]["archive_sha256"])

    async def test_first_ready_build_then_checked_review_delivers_without_extra_build_rounds(self):
        service, row = self.service(), job()
        row["state"]["report"] = fixtures.ready_report()
        await service.step(row)
        self.assertEqual(row["state"]["phase"], "REVIEW")
        self.assertEqual(row["state"]["round"], 1)
        service.env._rpc.assert_not_called()
        row["state"]["response_id"] = fixtures.RID
        await service.step(row)
        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(row["state"]["round"], 2)
        self.assertEqual(service.env._rpc.call_args.args[0], "finish_lj_coding_job")

    async def test_partial_source_survives_missing_model_zip(self):
        service, row = self.service(), job()
        row["state"].pop("archive_sha256")
        service.container_files = AsyncMock(return_value=[
            {"path":"/mnt/data/project/index.html", "id":"cfile_00000001"},
            {"path":"/mnt/data/project/.env", "id":"cfile_00000002"}])
        service.api.return_value = b"<html>Real saved source</html>"
        service.persist_archive = AsyncMock()
        self.assertFalse(await CodingService.checkpoint(service, row))
        self.assertEqual(service.api.await_count, 1)
        import zipfile
        with zipfile.ZipFile(io.BytesIO(service.persist_archive.call_args.args[1])) as archive:
            self.assertEqual(archive.namelist(), ["index.html"])
            self.assertIn(b"Real saved source", archive.read("index.html"))


class LinkTests(unittest.IsolatedAsyncioTestCase):
    def image_bytes(self):
        value = io.BytesIO()
        Image.new("RGB", (16,16), "cyan").save(value, format="PNG")
        return value.getvalue()

    async def test_preview_thumbnail_never_claims_to_be_video(self):
        async def fetch(url, **kwargs):
            if url.endswith("image.png"):
                return self.image_bytes(), "image/png", url
            return b'<meta property="og:image" content="https://media.example/image.png"><meta property="og:description" content="A caption">', "text/html", url
        result = await inspect_link("https://social.example/reel/one", fetch)
        self.assertEqual(result.kind, "thumbnail")
        self.assertEqual(len(result.images), 1)
        self.assertIn("not the video", result.note)
        self.assertIn("A caption", result.extract)

    async def test_blocked_site_returns_no_invented_images(self):
        result = await inspect_link("https://social.example/reel/one", AsyncMock(side_effect=ValueError("HTTP 403")))
        self.assertEqual(result.kind, "unavailable")
        self.assertEqual(result.images, [])

    async def test_direct_image_bytes_are_supplied_for_vision(self):
        result = await inspect_link("https://media.example/photo.png", AsyncMock(return_value=(self.image_bytes(), "image/png", "https://media.example/photo.png")))
        self.assertEqual(result.kind, "image")
        self.assertEqual(result.content()[1]["type"], "input_image")

    async def test_private_dns_answer_prevents_any_connection(self):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(socket.AF_INET,1,6,"",("127.0.0.1",443))])):
            with self.assertRaises(ValueError):
                await public_addresses("example.com")

    async def test_https_redirect_is_rechecked_and_connection_is_pinned(self):
        requests = []
        def handle(request):
            requests.append(request)
            return httpx.Response(302, headers={"location":"https://private.example/secret"})
        real_client = httpx.AsyncClient
        with patch("link_media.public_addresses", AsyncMock(side_effect=[["93.184.216.34"],ValueError("private")])):
            with patch("link_media.httpx.AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs)):
                with self.assertRaises(ValueError):
                    await fetch_public("https://public.example/page")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.host, "93.184.216.34")
        self.assertEqual(requests[0].headers["host"], "public.example")
        self.assertEqual(requests[0].extensions["sni_hostname"], "public.example")
        self.assertNotIn("authorization", requests[0].headers)

    def test_credentials_local_urls_and_alternate_ports_are_rejected(self):
        for url in ("http://example.com", "https://user:pass@example.com", "https://localhost", "https://router.local", "https://example.com:444/a"):
            with self.subTest(url=url), self.assertRaises(ValueError): checked_url(url)

    async def test_no_private_context_is_used_as_a_lookup_url(self):
        from link_media import link_context
        self.assertEqual(await link_context("hello"), [])


if __name__ == "__main__":
    unittest.main()
