import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
from fastapi import HTTPException

import main


class WindowsInstallerVersionTests(unittest.IsolatedAsyncioTestCase):
    async def test_android_latest_does_not_change_windows_download_or_checksum(self):
        upstream = httpx.Response(200, content=b"windows-installer", headers={"Content-Length": "17"})
        client = SimpleNamespace(
            build_request=Mock(return_value=httpx.Request("GET", "https://example.test")),
            send=AsyncMock(return_value=upstream), aclose=AsyncMock(),
        )
        with (
            patch.object(main, "CLIENT_LATEST_VERSION", "16.0.0"),
            patch.object(main, "CLIENT_UPDATE_URL", "https://jarvis-v13-cloud.onrender.com/v1/client/download"),
            patch.object(main, "CLIENT_UPDATE_SHA256", "a" * 64),
            patch.object(main, "ANDROID_LATEST_VERSION_NAME", "16.0.1"),
            patch.object(main, "ANDROID_UPDATE_URL", "https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v16.0.1/LJ_AI_Mobile_V16.0.1.apk"),
            patch.object(main.httpx, "AsyncClient", return_value=client),
        ):
            response = await main.client_download()
            data = b"".join([chunk async for chunk in response.body_iterator])
            metadata = json.loads((await main.client_update()).body)
        self.assertEqual(client.build_request.call_args.args, ("GET", "https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v16.0.0/LJ_AI_Setup.exe"))
        self.assertEqual(data, b"windows-installer")
        self.assertEqual(metadata["version"], "16.0.0")
        self.assertEqual(metadata["sha256"], "a" * 64)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
        client.aclose.assert_awaited_once()

    async def test_invalid_version_fails_before_network(self):
        for version in ("", "latest", "v16.0.0", "16.0", "16.0.1-rc1", "16.0.0/../../main", "01.0.0", "16.0.0?x=1", "16.0.0\n", None):
            with self.subTest(version=version), patch.object(main, "CLIENT_LATEST_VERSION", version), patch.object(main.httpx, "AsyncClient") as client:
                with self.assertRaises(HTTPException) as raised:
                    await main.client_download()
                self.assertEqual(raised.exception.status_code, 503)
                client.assert_not_called()

    def test_each_configured_windows_version_gets_exact_fixed_repo_asset(self):
        for version in ("15.9.9", "16.0.0", "16.0.1", "17.2.12"):
            with patch.object(main, "CLIENT_LATEST_VERSION", version):
                self.assertEqual(main._client_installer_source_url(), f"https://github.com/Ljproshooter/jarvis-v13-cloud/releases/download/v{version}/LJ_AI_Setup.exe")


if __name__ == "__main__":
    unittest.main()
