"""Dependency-free checks for V15.9.6 paired-device command boundaries."""

from __future__ import annotations

import unittest

from mobile_security import sanitize_remote_command_payload


class MobileSecurityPolicyTests(unittest.TestCase):
    def test_open_app_accepts_only_one_friendly_installed_app_name(self) -> None:
        self.assertEqual(
            sanitize_remote_command_payload("open_app", {"app_name": "  Visual   Studio Code  "}),
            {"app_name": "Visual Studio Code"},
        )
        for unsafe in (
            r"C:\\Windows\\System32\\cmd.exe",
            "https://example.com",
            "Spotify && shutdown /s",
            "powershell -Command whoami",
            "cmd.exe",
            "Windows Terminal",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                sanitize_remote_command_payload("open_app", {"app_name": unsafe})

    def test_parameterless_actions_reject_hidden_details(self) -> None:
        self.assertEqual(sanitize_remote_command_payload("volume_mute", {}), {})
        with self.assertRaises(ValueError):
            sanitize_remote_command_payload("volume_mute", {"command": "anything"})

    def test_unknown_action_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            sanitize_remote_command_payload("run_shell", {})


if __name__ == "__main__":
    unittest.main()
