"""Safe Learning-by-Demonstration API for LJ AI clients.

The cloud stores versioned, semantic workflows.  It deliberately does not run
desktop commands, JavaScript, shell text, or coordinate macros.  Windows and
Android clients must execute only the allow-listed instruction returned by a
run state endpoint and report the outcome before receiving the next step.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


ActionName = Literal[
    "launch_app",
    "activate_window",
    "open_url",
    "open_folder",
    "click_element",
    "set_text",
    "press_key",
    "choose_file",
    "select_option",
    "wait_for_element",
    "read_element",
    "scroll",
    "submit_form",
    "upload_file",
    "send_message",
    "publish_content",
    "delete_item",
    "make_purchase",
    "change_security_setting",
    "download_file",
    "take_screenshot",
]

RISKY_ACTIONS = {
    "download_file",
    "submit_form",
    "take_screenshot",
    "upload_file",
    "send_message",
    "publish_content",
    "delete_item",
    "make_purchase",
    "change_security_setting",
}

# Every risky or externally visible action requires a fresh, run-scoped
# confirmation. A saved demonstration can never turn that protection off.
NEVER_AUTO_APPROVE = set(RISKY_ACTIONS)

DANGEROUS_TARGET_WORDS = {
    "buy",
    "authorize",
    "allow",
    "checkout",
    "complete",
    "confirm purchase",
    "delete",
    "erase",
    "install",
    "order",
    "pay",
    "place order",
    "post",
    "publish",
    "remove",
    "send",
    "submit",
    "upload",
    "uninstall",
}

# UI surfaces that can turn otherwise harmless text/key steps into arbitrary
# command execution.  Legitimate navigation is represented by launch_app,
# open_url, and open_folder instead of typing into an OS/browser launcher.
BLOCKED_COMMAND_SURFACE_WORDS = {
    "address bar",
    "command launcher",
    "command palette",
    "command prompt",
    "developer console",
    "developer tools",
    "omnibox",
    "powershell",
    "run dialog",
    "terminal",
}

SENSITIVE_WORDS = {
    "api key",
    "auth token",
    "card number",
    "credential",
    "cvv",
    "one time password",
    "otp",
    "passcode",
    "password",
    "pin",
    "pin code",
    "private key",
    "recovery code",
    "secret",
    "security code",
}

BLOCKED_APP_NAMES = {
    "bash",
    "cmd",
    "cmd.exe",
    "command prompt",
    "cscript",
    "mshta",
    "node",
    "powershell",
    "powershell.exe",
    "pwsh",
    "python",
    "python.exe",
    "regedit",
    "rundll32",
    "sh",
    "terminal",
    "termux",
    "windows terminal",
    "wscript",
}

BLOCKED_ARGUMENT_KEYS = {
    "code",
    "command",
    "coordinates",
    "css_selector",
    "javascript",
    "password",
    "raw_keys",
    "screen_x",
    "screen_y",
    "script",
    "secret",
    "shell",
    "token",
    "xpath",
    "x",
    "y",
}

ALLOWED_ARGUMENT_KEYS: dict[str, set[str]] = {
    "launch_app": {"app", "package"},
    "activate_window": {"app", "window"},
    "open_url": {"url", "url_variable"},
    "open_folder": {"folder_variable"},
    "click_element": set(),
    "set_text": {"variable", "clear_first"},
    "press_key": {"key", "modifiers"},
    "choose_file": {"variable"},
    "select_option": {"value", "variable"},
    "wait_for_element": {"state"},
    "read_element": {"save_as"},
    "scroll": {"direction", "amount"},
    "submit_form": set(),
    "upload_file": {"variable"},
    "send_message": {"recipient", "recipient_variable", "message_variable"},
    "publish_content": set(),
    "delete_item": set(),
    "make_purchase": {"amount", "amount_variable", "currency", "merchant"},
    "change_security_setting": {"setting", "variable"},
    "download_file": {"destination_variable", "url", "url_variable"},
    "take_screenshot": {"save_as"},
}

TARGET_REQUIRED = {
    "activate_window",
    "click_element",
    "set_text",
    "select_option",
    "wait_for_element",
    "read_element",
    "scroll",
    "submit_form",
    "upload_file",
    "send_message",
    "publish_content",
    "delete_item",
    "make_purchase",
    "press_key",
    "change_security_setting",
}

VARIABLE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
STEP_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
SAFE_KEY_PATTERN = re.compile(r"^[A-Z0-9]$")
SPECIAL_KEYS = {
    "ARROWDOWN",
    "ARROWLEFT",
    "ARROWRIGHT",
    "ARROWUP",
    "BACKSPACE",
    "DELETE",
    "END",
    "ENTER",
    "ESCAPE",
    "HOME",
    "PAGEDOWN",
    "PAGEUP",
    "SPACE",
    "TAB",
}

SAFE_MODIFIED_KEYS = {
    ("ALT", "TAB"),
    ("CTRL", "A"),
    ("CTRL", "F"),
    ("SHIFT", "TAB"),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _identity_value(identity: Any, key: str, default: Any = "") -> Any:
    return identity.get(key, default) if isinstance(identity, dict) else getattr(identity, key, default)


def _uuid(value: str, unavailable: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=404, detail=unavailable) from None


def _contains_word(value: str, words: set[str]) -> bool:
    normalized = " ".join(re.sub(r"[^a-z0-9]+", " ", str(value).casefold()).split())
    padded = f" {normalized} "
    return any(f" {word} " in padded for word in words)


def _reject_sensitive_label(value: str, label: str) -> str:
    cleaned = " ".join(str(value).split())
    if _contains_word(cleaned, SENSITIVE_WORDS):
        raise ValueError(f"{label} cannot describe passwords, tokens, payment-card data, or other secrets.")
    return cleaned


def _blocked_app(value: str) -> bool:
    clean = " ".join(str(value).split()).casefold()
    if not clean:
        return False
    # A Skill identifies an app by friendly name or Android package. Absolute
    # executable paths and command-line fragments are never valid app IDs.
    if (
        "/" in clean
        or "\\" in clean
        or re.search(r"\s[-/][a-z0-9]", clean)
        or any(character in clean for character in ("&", "|", ";", "<", ">", "`", "\"", "'"))
        or "$" in clean
    ):
        return True
    words = set(re.sub(r"[^a-z0-9]+", " ", clean).split())
    blocked_words = {
        "bash",
        "cmd",
        "cscript",
        "mshta",
        "node",
        "powershell",
        "pwsh",
        "python",
        "regedit",
        "rundll32",
        "shell",
        "terminal",
        "termux",
        "wscript",
    }
    return clean in BLOCKED_APP_NAMES or bool(words & blocked_words) or clean == "run"


def _blocked_command_surface(target: "SemanticTarget") -> bool:
    text = " ".join(
        (target.role, target.name, target.label, target.app, target.accessibility_id, target.dom_id)
    )
    return _contains_word(text, BLOCKED_COMMAND_SURFACE_WORDS)


def _clean_argument_text(value: Any, key: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text.")
    if "\x00" in value or any(ord(character) < 32 and character not in "\t\r\n" for character in value):
        raise ValueError(f"{key} contains unsupported control characters.")
    clean = value.strip()
    if not clean or len(clean) > max_length:
        raise ValueError(f"{key} must contain 1 to {max_length} characters.")
    return clean


def _safe_site(value: str) -> str:
    clean = str(value).strip()
    candidate = clean if "://" in clean else f"https://{clean}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Websites must be normal http(s) domains or URLs without embedded credentials.")
    _reject_private_web_host(parsed.hostname)
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        raise ValueError("Website port is invalid.") from None
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{port}"


def _reject_private_web_host(hostname: str) -> None:
    host = hostname.rstrip(".").casefold()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Local and private network websites cannot be saved in a Skill.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("Local and private network addresses cannot be saved in a Skill.")


def _safe_web_url(value: str) -> str:
    clean = str(value).strip()
    parsed = urlparse(clean)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Only normal http(s) links without embedded credentials can be saved.")
    _reject_private_web_host(parsed.hostname)
    if parsed.query or parsed.fragment:
        raise ValueError(
            "Recorded URLs cannot contain a query or fragment; use a typed URL variable at run time."
        )
    return clean


class SemanticTarget(BaseModel):
    """Accessibility/DOM description of a target, never a screen position."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=60)
    name: str = Field(default="", max_length=180)
    label: str = Field(default="", max_length=180)
    app: str = Field(default="", max_length=100)
    site: str = Field(default="", max_length=300)
    accessibility_id: str = Field(default="", max_length=180)
    dom_id: str = Field(default="", max_length=180)

    @field_validator("role", "name", "label", "accessibility_id", "dom_id")
    @classmethod
    def no_sensitive_controls(cls, value: str, info: Any) -> str:
        return _reject_sensitive_label(value, f"Target {info.field_name}")

    @field_validator("app")
    @classmethod
    def safe_app(cls, value: str) -> str:
        clean = " ".join(value.split())
        if _blocked_app(clean):
            raise ValueError("Shells, script hosts, and system command tools cannot be workflow targets.")
        return clean

    @field_validator("site")
    @classmethod
    def safe_site(cls, value: str) -> str:
        return _safe_site(value) if value.strip() else ""

    @model_validator(mode="after")
    def identifiable(self) -> "SemanticTarget":
        if not any((self.name, self.label, self.accessibility_id, self.dom_id, self.app, self.site)):
            raise ValueError("A target needs an accessible name, label, identifier, app, or website.")
        if self.role.casefold() in {"password", "passwordbox", "securetext", "secure_text"}:
            raise ValueError("Password and secure-input controls are never recorded by Teach LJ.")
        return self


class SkillVariable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=64)
    type: Literal["text", "url", "file_path", "number", "boolean", "choice"] = "text"
    description: str = Field(default="", max_length=240)
    required: bool = True
    default: str | float | bool | None = None
    choices: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        clean = value.strip().upper()
        if not VARIABLE_PATTERN.fullmatch(clean):
            raise ValueError("Variable names use uppercase letters, numbers, and underscores.")
        _reject_sensitive_label(clean.replace("_", " "), "Variable name")
        return clean

    @field_validator("description")
    @classmethod
    def safe_description(cls, value: str) -> str:
        return _reject_sensitive_label(value, "Variable description")

    @field_validator("choices")
    @classmethod
    def clean_choices(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            clean = _reject_sensitive_label(value, "Choice")[:120]
            if clean and clean not in result:
                result.append(clean)
        return result

    @model_validator(mode="after")
    def valid_shape(self) -> "SkillVariable":
        if self.type == "choice" and not self.choices:
            raise ValueError("Choice variables need at least one allowed choice.")
        if self.type != "choice" and self.choices:
            raise ValueError("Only choice variables can define choices.")
        if self.default is not None and self.type in {"text", "url", "file_path"}:
            raise ValueError(
                "Text, URL, and file variables are supplied when a Skill runs and cannot store recorded defaults."
            )
        if self.default is not None:
            _validate_variable_value(self, self.default)
        return self


class SemanticStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1, max_length=64)
    action: ActionName
    target: SemanticTarget | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    on_failure: Literal["STOP", "ASK_USER", "RETRY"] = "ASK_USER"
    timeout_seconds: int = Field(default=30, ge=1, le=180)

    @field_validator("action", mode="before")
    @classmethod
    def normalize_client_action_names(cls, value: Any) -> Any:
        return {
            "open_app": "launch_app",
            "open_website": "open_url",
        }.get(str(value), value)

    @field_validator("step_id")
    @classmethod
    def safe_step_id(cls, value: str) -> str:
        clean = value.strip()
        if not STEP_ID_PATTERN.fullmatch(clean):
            raise ValueError("Step IDs may contain letters, numbers, underscores, and hyphens.")
        return clean

    @field_validator("arguments")
    @classmethod
    def bounded_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 8192:
            raise ValueError("Step arguments are too large.")
        return value

    @model_validator(mode="after")
    def safe_action(self) -> "SemanticStep":
        keys = set(self.arguments)
        blocked = keys & BLOCKED_ARGUMENT_KEYS
        if blocked:
            raise ValueError(f"Unsafe step argument(s): {', '.join(sorted(blocked))}.")
        unexpected = keys - ALLOWED_ARGUMENT_KEYS[self.action]
        if unexpected:
            raise ValueError(f"Unsupported argument(s) for {self.action}: {', '.join(sorted(unexpected))}.")
        for key, value in self.arguments.items():
            if isinstance(value, (dict, tuple, set)) or (isinstance(value, list) and key != "modifiers"):
                raise ValueError(f"{key} must be a scalar value, not a nested object or list.")
            if value is None:
                raise ValueError(f"{key} cannot be null.")
        if self.action in TARGET_REQUIRED and self.target is None:
            raise ValueError(f"{self.action} needs a semantic accessibility or browser target.")
        if self.target is not None and self.action in {"click_element", "set_text", "press_key"}:
            if _blocked_command_surface(self.target):
                raise ValueError(
                    "Teach LJ cannot type or click inside command launchers, terminals, developer consoles, or address bars."
                )
        if self.action == "launch_app":
            sources = [key for key in ("app", "package") if key in self.arguments]
            if len(sources) != 1:
                raise ValueError("launch_app needs exactly one app name or Android package.")
            app = _clean_argument_text(self.arguments[sources[0]], sources[0], 120)
            if _blocked_app(app):
                raise ValueError("Shells, script hosts, and system command tools cannot be launched by a Skill.")
            self.arguments[sources[0]] = app
        if self.action == "activate_window":
            for key in ("app", "window"):
                if key in self.arguments:
                    clean = _clean_argument_text(self.arguments[key], key, 180)
                    if key == "app" and _blocked_app(clean):
                        raise ValueError("Shells and system command tools cannot be activated by a Skill.")
                    self.arguments[key] = clean
        if self.action == "open_folder" and not self.arguments.get("folder_variable"):
            raise ValueError("open_folder must use a file_path variable, not a recorded local path.")
        if self.action == "open_url":
            sources = [bool(self.arguments.get("url")), bool(self.arguments.get("url_variable"))]
            if sum(sources) != 1:
                raise ValueError("open_url needs exactly one url or url_variable.")
        if self.action == "open_url" and "url" in self.arguments:
            self.arguments["url"] = _safe_web_url(str(self.arguments["url"]))
        if self.action == "download_file":
            sources = [bool(self.arguments.get("url")), bool(self.arguments.get("url_variable"))]
            if sum(sources) != 1 or not self.arguments.get("destination_variable"):
                raise ValueError("download_file needs one URL source and a destination_variable.")
            if "url" in self.arguments:
                self.arguments["url"] = _safe_web_url(str(self.arguments["url"]))
        if self.action == "set_text" and not self.arguments.get("variable"):
            raise ValueError("set_text must use a declared variable; recorded typed text is not stored in a Skill.")
        if self.action == "set_text" and "clear_first" in self.arguments:
            if not isinstance(self.arguments["clear_first"], bool):
                raise ValueError("clear_first must be true or false.")
        if self.action == "select_option" and not any(
            self.arguments.get(key) is not None for key in ("value", "variable")
        ):
            raise ValueError("select_option needs a value or declared variable.")
        if self.action == "select_option":
            if "value" in self.arguments and "variable" in self.arguments:
                raise ValueError("select_option accepts either value or variable, not both.")
            if "value" in self.arguments:
                value = self.arguments["value"]
                if not isinstance(value, (str, int, float, bool)) or isinstance(value, str) and len(value) > 240:
                    raise ValueError("select_option value must be a short text, number, or boolean value.")
                if isinstance(value, str):
                    self.arguments["value"] = _reject_sensitive_label(
                        _clean_argument_text(value, "Option value", 240),
                        "Option value",
                    )
        if self.action == "press_key":
            key = str(self.arguments.get("key") or "").strip().upper()
            raw_modifiers = self.arguments.get("modifiers", [])
            if not isinstance(raw_modifiers, list):
                raise ValueError("Keyboard modifiers must be a list.")
            modifiers = [str(item).strip().upper() for item in raw_modifiers]
            if any(item not in {"ALT", "CTRL", "META", "SHIFT"} for item in modifiers) or len(modifiers) > 3:
                raise ValueError("Unsupported keyboard modifier.")
            if modifiers:
                normalized_combo = tuple(sorted(set(modifiers)) + [key])
                allowed_combos = {
                    tuple(sorted(combo[:-1]) + [combo[-1]]) for combo in SAFE_MODIFIED_KEYS
                }
                if normalized_combo not in allowed_combos:
                    raise ValueError(
                        "Only Select All, Find, previous-field, and window-switch shortcuts are allowed."
                    )
            elif key not in SPECIAL_KEYS:
                raise ValueError("Keyboard steps may use navigation keys only; text must use a variable.")
            self.arguments["key"] = key
            self.arguments["modifiers"] = sorted(set(modifiers))
        if self.action == "scroll":
            direction = str(self.arguments.get("direction") or "down").casefold()
            if direction not in {"up", "down", "left", "right"}:
                raise ValueError("Scroll direction must be up, down, left, or right.")
            try:
                amount = int(self.arguments.get("amount") or 1)
            except (TypeError, ValueError):
                raise ValueError("Scroll amount must be a whole number.") from None
            if amount < 1 or amount > 10:
                raise ValueError("Scroll amount must be between 1 and 10 semantic increments.")
            self.arguments.update({"direction": direction, "amount": amount})
        if self.action in {"choose_file", "upload_file"} and not self.arguments.get("variable"):
            raise ValueError(f"{self.action} must use a file_path variable, not a recorded local path.")
        if self.action == "send_message":
            recipient_sources = [key for key in ("recipient", "recipient_variable") if self.arguments.get(key)]
            if len(recipient_sources) != 1:
                raise ValueError("send_message needs exactly one recipient or recipient_variable.")
            if not self.arguments.get("message_variable"):
                raise ValueError("send_message must use a declared message_variable.")
            if "recipient" in self.arguments:
                self.arguments["recipient"] = _clean_argument_text(self.arguments["recipient"], "recipient", 320)
        if self.action == "make_purchase":
            amount_sources = [key for key in ("amount", "amount_variable") if key in self.arguments]
            if not self.arguments.get("merchant") or len(amount_sources) != 1:
                raise ValueError("make_purchase needs a merchant and exactly one amount or amount_variable.")
            self.arguments["merchant"] = _clean_argument_text(self.arguments["merchant"], "merchant", 180)
            if self.arguments.get("amount") is not None:
                amount = self.arguments["amount"]
                if (
                    isinstance(amount, bool)
                    or not isinstance(amount, (int, float))
                    or not math.isfinite(float(amount))
                    or not 0 < float(amount) <= 1_000_000
                ):
                    raise ValueError("Purchase amount must be a positive number no greater than 1,000,000.")
            if self.arguments.get("currency") is None:
                raise ValueError("make_purchase needs an explicit three-letter currency code.")
            currency = _clean_argument_text(self.arguments["currency"], "currency", 3).upper()
            if not re.fullmatch(r"[A-Z]{3}", currency):
                raise ValueError("Purchase currency must be a three-letter currency code.")
            self.arguments["currency"] = currency
        if self.action == "change_security_setting":
            if not self.arguments.get("setting") or not self.arguments.get("variable"):
                raise ValueError("change_security_setting needs a setting name and declared variable.")
            self.arguments["setting"] = _reject_sensitive_label(
                _clean_argument_text(self.arguments["setting"], "setting", 180),
                "Security setting",
            )
        if self.action in {"read_element", "take_screenshot"} and not self.arguments.get("save_as"):
            raise ValueError(f"{self.action} needs a save_as variable.")
        if self.action == "wait_for_element" and "state" in self.arguments:
            state = _clean_argument_text(self.arguments["state"], "state", 20).casefold()
            if state not in {"exists", "visible", "enabled", "hidden"}:
                raise ValueError("wait_for_element state must be exists, visible, enabled, or hidden.")
            self.arguments["state"] = state

        string_argument_limits = {
            "amount_variable": 64,
            "destination_variable": 64,
            "folder_variable": 64,
            "message_variable": 64,
            "recipient_variable": 64,
            "save_as": 64,
            "url_variable": 64,
            "variable": 64,
        }
        for key, limit in string_argument_limits.items():
            if key in self.arguments:
                self.arguments[key] = _clean_argument_text(self.arguments[key], key, limit)
        return self


class SafetyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto_approve_actions: list[ActionName] = Field(default_factory=list, max_length=10)
    confirm_target_keywords: bool = True

    @field_validator("auto_approve_actions")
    @classmethod
    def safe_auto_approvals(cls, values: list[str]) -> list[str]:
        if values:
            raise ValueError("Risky and externally visible actions cannot be auto-approved.")
        return []

    @field_validator("confirm_target_keywords")
    @classmethod
    def target_confirmation_stays_enabled(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Semantic risk detection cannot be disabled.")
        return True


class WorkflowBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    variables_schema: list[SkillVariable] = Field(default_factory=list, max_length=50)
    required_apps: list[str] = Field(default_factory=list, max_length=30)
    required_sites: list[str] = Field(default_factory=list, max_length=30)
    steps: list[SemanticStep] = Field(min_length=1, max_length=100)
    safety_policy: SafetyPolicy = Field(default_factory=SafetyPolicy)
    change_note: str = Field(default="", max_length=240)

    @field_validator("required_apps")
    @classmethod
    def clean_apps(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            clean = " ".join(str(value).split())[:100]
            if not clean:
                continue
            if _blocked_app(clean):
                raise ValueError("Shells, script hosts, and system command tools cannot be Skill requirements.")
            if clean.casefold() not in {item.casefold() for item in result}:
                result.append(clean)
        return result

    @field_validator("required_sites")
    @classmethod
    def clean_sites(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            clean = _safe_site(value)
            if clean not in result:
                result.append(clean)
        return result

    @field_validator("change_note")
    @classmethod
    def clean_note(cls, value: str) -> str:
        return " ".join(value.split())

    @model_validator(mode="after")
    def coherent_workflow(self) -> "WorkflowBody":
        variable_names = {item.name for item in self.variables_schema}
        if len(variable_names) != len(self.variables_schema):
            raise ValueError("Variable names must be unique.")
        step_ids = {item.step_id for item in self.steps}
        if len(step_ids) != len(self.steps):
            raise ValueError("Step IDs must be unique.")
        variable_types = {item.name: item.type for item in self.variables_schema}
        for step in self.steps:
            for key, raw_value in step.arguments.items():
                if key == "variable" or key.endswith("_variable"):
                    name = str(raw_value).strip().upper()
                    if name not in variable_names:
                        raise ValueError(f"Step {step.step_id} references unknown variable {name}.")
                    step.arguments[key] = name
            if step.action in {"choose_file", "upload_file"}:
                name = str(step.arguments.get("variable") or "")
                if variable_types.get(name) != "file_path":
                    raise ValueError(f"Step {step.step_id} requires a file_path variable.")
            if step.action == "set_text":
                name = str(step.arguments.get("variable") or "")
                if variable_types.get(name) != "text":
                    raise ValueError(f"Step {step.step_id} requires a text variable.")
            if step.action == "select_option" and step.arguments.get("variable"):
                name = str(step.arguments.get("variable") or "")
                if variable_types.get(name) not in {"text", "choice", "boolean"}:
                    raise ValueError(
                        f"Step {step.step_id} requires a text, choice, or boolean variable."
                    )
            if step.action == "open_folder":
                name = str(step.arguments.get("folder_variable") or "")
                if variable_types.get(name) != "file_path":
                    raise ValueError(f"Step {step.step_id} requires a file_path variable.")
            if step.action in {"open_url", "download_file"} and step.arguments.get("url_variable"):
                if variable_types.get(str(step.arguments["url_variable"])) != "url":
                    raise ValueError(f"Step {step.step_id} requires a url variable.")
            if step.action in {"read_element", "take_screenshot"}:
                name = str(step.arguments.get("save_as") or "").strip().upper()
                expected_type = "file_path" if step.action == "take_screenshot" else "text"
                if variable_types.get(name) != expected_type:
                    raise ValueError(f"Step {step.step_id} save_as requires a {expected_type} variable.")
                step.arguments["save_as"] = name
            if step.action == "send_message":
                message_name = str(step.arguments.get("message_variable") or "")
                if variable_types.get(message_name) != "text":
                    raise ValueError(f"Step {step.step_id} requires a text message_variable.")
                recipient_name = str(step.arguments.get("recipient_variable") or "")
                if recipient_name and variable_types.get(recipient_name) != "text":
                    raise ValueError(f"Step {step.step_id} requires a text recipient_variable.")
            if step.action == "make_purchase" and step.arguments.get("amount_variable"):
                if variable_types.get(str(step.arguments["amount_variable"])) != "number":
                    raise ValueError(f"Step {step.step_id} requires a number amount_variable.")
            if step.action == "download_file":
                if variable_types.get(str(step.arguments.get("destination_variable") or "")) != "file_path":
                    raise ValueError(f"Step {step.step_id} requires a file_path destination_variable.")
            if step.action == "change_security_setting":
                name = str(step.arguments.get("variable") or "")
                if variable_types.get(name) not in {"boolean", "choice"}:
                    raise ValueError(
                        f"Step {step.step_id} requires a boolean or choice setting variable."
                    )
        return self


class SkillCreate(WorkflowBody):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)
    enabled: bool = True

    @field_validator("name", "description")
    @classmethod
    def clean_text(cls, value: str, info: Any) -> str:
        clean = " ".join(value.split())
        if info.field_name == "name" and not clean:
            raise ValueError("Give the Skill a name.")
        return clean


class SkillMetadataUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)

    @field_validator("name", "description")
    @classmethod
    def clean_text(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        clean = " ".join(value.split())
        if info.field_name == "name" and not clean:
            raise ValueError("Give the Skill a name.")
        return clean

    @model_validator(mode="after")
    def changed(self) -> "SkillMetadataUpdate":
        if self.name is None and self.description is None:
            raise ValueError("Supply a name or description to update.")
        return self


class SkillEnabledUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class SkillDuplicate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=80)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str | None) -> str | None:
        return " ".join(value.split()) if value is not None else None


class SkillRunStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["TEST", "EXECUTE"] = "EXECUTE"
    variables: dict[str, Any] = Field(default_factory=dict)

    @field_validator("variables")
    @classmethod
    def bounded_variables(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 32768:
            raise ValueError("Skill variables are too large.")
        for key in value:
            clean = str(key).strip().upper()
            if not VARIABLE_PATTERN.fullmatch(clean):
                raise ValueError("Invalid Skill variable name.")
            _reject_sensitive_label(clean.replace("_", " "), "Variable name")
        return {str(key).strip().upper(): item for key, item in value.items()}


class SkillRunAdvance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    completed_step: int = Field(ge=0, le=99)
    success: bool
    message: str = Field(default="", max_length=500)

    @field_validator("message")
    @classmethod
    def safe_message(cls, value: str) -> str:
        clean = " ".join(value.split())
        if _contains_word(clean, SENSITIVE_WORDS):
            return "Client omitted a potentially sensitive diagnostic message."
        return clean


class SkillRunConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation_token: str = Field(min_length=32, max_length=200)
    approved: bool


def _validate_variable_value(definition: SkillVariable, value: Any) -> Any:
    if value is None:
        if definition.required:
            raise ValueError(f"{definition.name} is required.")
        return None
    if definition.type in {"text", "file_path", "choice", "url"}:
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError(f"{definition.name} must be text under 4096 characters.")
        if definition.required and not value.strip():
            raise ValueError(f"{definition.name} cannot be blank.")
        if definition.type == "choice" and value not in definition.choices:
            raise ValueError(f"{definition.name} must be one of its allowed choices.")
        if definition.type == "url":
            return _safe_web_url(value)
        return value
    if definition.type == "number":
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or abs(float(value)) > 1_000_000_000_000
        ):
            raise ValueError(f"{definition.name} must be a number.")
        return value
    if definition.type == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{definition.name} must be true or false.")
        return value
    raise ValueError(f"Unsupported variable type for {definition.name}.")


def validate_run_variables(schema: list[dict[str, Any]], supplied: dict[str, Any]) -> dict[str, Any]:
    definitions = [SkillVariable.model_validate(item) for item in schema]
    known = {item.name for item in definitions}
    unknown = set(supplied) - known
    if unknown:
        raise ValueError(f"Unknown Skill variable(s): {', '.join(sorted(unknown))}.")
    result: dict[str, Any] = {}
    for definition in definitions:
        value = supplied.get(definition.name, definition.default)
        if value is None and not definition.required:
            continue
        result[definition.name] = _validate_variable_value(definition, value)
    return result


def confirmation_reason(step: dict[str, Any], safety_policy: dict[str, Any]) -> str | None:
    action = str(step.get("action") or "")
    arguments = step.get("arguments") if isinstance(step.get("arguments"), dict) else {}
    # Android demonstrations currently describe every tap as click_element.
    # A label such as Continue, Next, Done, or OK does not prove that the tap is
    # non-mutating: it can submit a payment, send content, or commit a setting.
    # Likewise, choosing an option or typing into an auto-save/settings field
    # may immediately alter externally visible state. Until a trusted recorder
    # supplies a verifiable non-mutating class, all three actions therefore
    # require a fresh run-scoped confirmation.
    if action in {"click_element", "select_option", "set_text"}:
        return "This recorded interaction may commit a change and always needs confirmation."
    if action == "press_key":
        key = str(arguments.get("key") or "").upper()
        modifiers = {str(item).upper() for item in arguments.get("modifiers", []) if isinstance(item, str)}
        if key in {"DELETE", "ENTER", "SPACE"}:
            return "This keyboard action can change or submit the focused control and needs confirmation."
    if action in RISKY_ACTIONS:
        return f"{action} is important, external, or irreversible and always needs confirmation."
    target = step.get("target") if isinstance(step.get("target"), dict) else {}
    target_text = " ".join(
        str(target.get(key) or "")
        for key in ("name", "label", "role", "accessibility_id", "dom_id")
    )
    if _contains_word(target_text, DANGEROUS_TARGET_WORDS):
        return "The target looks like it may cause an external or irreversible action."
    return None


def _workflow_payload(body: WorkflowBody) -> dict[str, Any]:
    required_apps = list(body.required_apps)
    required_sites = list(body.required_sites)
    known_apps = {item.casefold() for item in required_apps}
    known_sites = set(required_sites)
    for step in body.steps:
        candidates: list[str] = []
        if step.action == "launch_app":
            candidates.append(str(step.arguments.get("app") or step.arguments.get("package") or ""))
        if step.target and step.target.app:
            candidates.append(step.target.app)
        for candidate in candidates:
            clean = " ".join(candidate.split())[:100]
            if clean and clean.casefold() not in known_apps:
                required_apps.append(clean)
                known_apps.add(clean.casefold())
        site_candidates: list[str] = []
        if step.target and step.target.site:
            site_candidates.append(step.target.site)
        if step.action in {"open_url", "download_file"} and step.arguments.get("url"):
            site_candidates.append(str(step.arguments["url"]))
        for candidate in site_candidates:
            clean_site = _safe_site(candidate)
            if clean_site not in known_sites:
                required_sites.append(clean_site)
                known_sites.add(clean_site)
    if len(required_apps) > 50 or len(required_sites) > 50:
        raise HTTPException(status_code=422, detail="A Skill may require at most 50 apps and 50 websites.")
    return {
        "variables_schema": [item.model_dump(mode="json") for item in body.variables_schema],
        "required_apps": required_apps,
        "required_sites": required_sites,
        "safety_policy": body.safety_policy.model_dump(mode="json"),
        "steps": [item.model_dump(mode="json", exclude_none=True) for item in body.steps],
    }


def _validated_stored_version(version: dict[str, Any]) -> dict[str, Any]:
    """Revalidate database content before it can ever reach a runner.

    This is a fail-closed boundary for workflows saved by an older release or
    altered outside this API. Stored JSON is not treated as executable merely
    because it already exists in the database.
    """
    try:
        body = WorkflowBody.model_validate(
            {
                "variables_schema": version.get("variables_schema") or [],
                "required_apps": version.get("required_apps") or [],
                "required_sites": version.get("required_sites") or [],
                "steps": version.get("steps") or [],
                "safety_policy": version.get("safety_policy") or {},
                "change_note": version.get("change_note") or "",
            }
        )
        safe = _workflow_payload(body)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="This Skill was saved by an older or unsafe format and must be edited before it can run.",
        ) from exc
    return {**version, **safe, "change_note": body.change_note}


def build_public_run(
    run: dict[str, Any],
    version: dict[str, Any],
    *,
    confirmation_token: str | None = None,
) -> dict[str, Any]:
    steps = version.get("steps") if isinstance(version.get("steps"), list) else []
    index = int(run.get("current_step_index") or 0)
    state = {
        "id": run.get("id"),
        "skill_id": run.get("skill_id"),
        "skill_version": int(run.get("skill_version") or 1),
        "device_id": run.get("device_id"),
        "mode": run.get("mode"),
        "status": run.get("status"),
        "state_version": int(run.get("state_version") or 0),
        "current_step_index": index,
        "total_steps": len(steps),
        "variables": run.get("variables") or {},
        "pending_confirmation": run.get("pending_confirmation"),
        "error_message": run.get("error_message"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "completed_at": run.get("completed_at"),
        "should_execute": run.get("mode") == "EXECUTE" and run.get("status") == "RUNNING",
    }
    if run.get("status") in {"READY", "RUNNING"} and 0 <= index < len(steps):
        state["next_step"] = steps[index]
    else:
        state["next_step"] = None
    if confirmation_token:
        state["confirmation_token"] = confirmation_token
    return state


def confirmation_material_facts(
    step: dict[str, Any],
    variables: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    arguments = step.get("arguments") if isinstance(step.get("arguments"), dict) else {}
    context_keys = {
        "amount",
        "amount_variable",
        "currency",
        "destination_variable",
        "folder_variable",
        "merchant",
        "message_variable",
        "recipient",
        "recipient_variable",
        "save_as",
        "setting",
        "url",
        "url_variable",
        "variable",
        "value",
    }
    context: dict[str, Any] = {}
    for key in context_keys:
        value = arguments.get(key)
        if isinstance(value, (str, int, float, bool)):
            context[key] = value[:300] if isinstance(value, str) else value
    resolved_names = {
        "amount_variable": "amount",
        "destination_variable": "destination",
        "folder_variable": "folder",
        "message_variable": "message",
        "recipient_variable": "recipient",
        "url_variable": "url",
        "variable": "value",
    }
    material_facts: dict[str, Any] = {
        key: value for key, value in context.items() if not key.endswith("_variable")
    }
    for argument_key, display_key in resolved_names.items():
        variable_name = str(arguments.get(argument_key) or "").strip().upper()
        value = variables.get(variable_name)
        if isinstance(value, str):
            material_facts[display_key] = value[:500]
        elif isinstance(value, (int, float, bool)):
            material_facts[display_key] = value
    return context, material_facts


def create_teach_lj_router(
    *,
    current_identity: Callable[..., Awaitable[Any]],
    rest_request: Callable[..., Awaitable[Any]],
    rpc: Callable[..., Awaitable[Any]],
    insert_audit: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    limiter: Any,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["teach-lj"])

    async def get_skill(skill_id: str, user_id: str, *, include_deleted: bool = False) -> dict[str, Any]:
        clean_id = _uuid(skill_id, "That Skill is unavailable.")
        params = {
            "id": f"eq.{clean_id}",
            "user_id": f"eq.{user_id}",
            "select": "*",
            "limit": "1",
        }
        if not include_deleted:
            params["deleted_at"] = "is.null"
        rows = await rest_request(
            "GET",
            "lj_skills",
            params=params,
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="That Skill is unavailable.")
        return rows[0]

    async def get_version(skill: dict[str, Any], version: int | None = None) -> dict[str, Any]:
        selected_version = int(version or skill.get("current_version") or 1)
        rows = await rest_request(
            "GET",
            "lj_skill_versions",
            params={
                "skill_id": f"eq.{skill['id']}",
                "user_id": f"eq.{skill['user_id']}",
                "version": f"eq.{selected_version}",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=409, detail="That Skill version is unavailable.")
        return _validated_stored_version(rows[0])

    async def get_run(run_id: str, user_id: str) -> dict[str, Any]:
        clean_id = _uuid(run_id, "That Skill run is unavailable.")
        rows = await rest_request(
            "GET",
            "lj_skill_runs",
            params={
                "id": f"eq.{clean_id}",
                "user_id": f"eq.{user_id}",
                "select": "*",
                "limit": "1",
            },
        ) or []
        if not rows:
            raise HTTPException(status_code=404, detail="That Skill run is unavailable.")
        return rows[0]

    async def add_run_event(
        run: dict[str, Any],
        event_type: str,
        *,
        step_index: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        # Details are intentionally structural; variable values and captured UI
        # text are never copied into the audit stream.
        try:
            await rest_request(
                "POST",
                "lj_skill_run_events",
                payload={
                    "user_id": run["user_id"],
                    "skill_id": run["skill_id"],
                    "run_id": run["id"],
                    "event_type": event_type[:80],
                    "step_index": step_index,
                    "details": details or {},
                },
                prefer="return=minimal",
            )
        except HTTPException:
            # A transient secondary audit write must not make a successfully
            # committed state transition look failed and tempt the client to
            # execute it twice. The main audit sink is deliberately best-effort.
            await insert_audit(
                str(run["user_id"]),
                "SKILL_RUN_AUDIT_WRITE_FAILED",
                {"skill_id": run["skill_id"], "run_id": run["id"], "event": event_type[:80]},
            )

    async def transition_run(
        run: dict[str, Any],
        *,
        expected_step: int,
        new_status: str,
        new_step: int,
        pending_confirmation: dict[str, Any] | None = None,
        confirmation_token_hash: str | None = None,
        confirmation_expires_at: str | None = None,
        error_message: str | None = None,
        completed: bool = False,
    ) -> dict[str, Any]:
        result = await rpc(
            "transition_lj_skill_run",
            {
                "p_user_id": run["user_id"],
                "p_run_id": run["id"],
                "p_device_id": run["device_id"],
                "p_expected_step": expected_step,
                "p_expected_state_version": int(run.get("state_version") or 0),
                "p_new_status": new_status,
                "p_new_step": new_step,
                "p_pending_confirmation": pending_confirmation,
                "p_confirmation_token_hash": confirmation_token_hash,
                "p_confirmation_expires_at": confirmation_expires_at,
                "p_error_message": error_message,
                "p_completed": completed,
            },
        )
        rows = result if isinstance(result, list) else ([result] if isinstance(result, dict) and result else [])
        if not rows:
            raise HTTPException(status_code=409, detail="This Skill run changed on another request.")
        return rows[0]

    def public_skill(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "name": row.get("name"),
            "description": row.get("description") or "",
            "enabled": bool(row.get("enabled")),
            "current_version": int(row.get("current_version") or 1),
            "required_apps": row.get("required_apps") or [],
            "required_sites": row.get("required_sites") or [],
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "last_used_at": row.get("last_used_at"),
            "last_run_at": row.get("last_run_at"),
            "last_run_status": row.get("last_run_status"),
        }

    def public_run(
        run: dict[str, Any],
        version: dict[str, Any],
        *,
        confirmation_token: str | None = None,
    ) -> dict[str, Any]:
        return build_public_run(run, version, confirmation_token=confirmation_token)

    async def ensure_unique_name(user_id: str, name: str, excluding: str | None = None) -> None:
        rows = await rest_request(
            "GET",
            "lj_skills",
            params={
                "user_id": f"eq.{user_id}",
                "deleted_at": "is.null",
                "select": "id,name",
                "limit": "500",
            },
        ) or []
        if any(
            str(row.get("id")) != str(excluding or "")
            and str(row.get("name") or "").casefold() == name.casefold()
            for row in rows
        ):
            raise HTTPException(status_code=409, detail="You already have a Skill with that name.")

    def make_confirmation(
        step: dict[str, Any],
        index: int,
        reason: str,
        variables: dict[str, Any],
    ) -> tuple[dict[str, Any], str, str]:
        token = secrets.token_urlsafe(40)
        target = step.get("target") if isinstance(step.get("target"), dict) else {}
        context, material_facts = confirmation_material_facts(step, variables)
        pending = {
            "step_index": index,
            "action": step.get("action"),
            "target_name": str(target.get("name") or target.get("label") or "")[:180],
            "target_app": str(target.get("app") or "")[:100],
            "target_site": str(target.get("site") or "")[:300],
            "context": context,
            "material_facts": material_facts,
            "reason": reason,
            "expires_at": (_utcnow() + timedelta(minutes=10)).isoformat(),
        }
        return pending, token, hashlib.sha256(token.encode("utf-8")).hexdigest()

    @router.get("/skills")
    async def list_skills(
        include_disabled: bool = Query(default=True),
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        await limiter.enforce(f"skills-list:{user_id}", 60, 60)
        params = {
            "user_id": f"eq.{user_id}",
            "deleted_at": "is.null",
            "select": "*",
            "order": "updated_at.desc",
            "limit": "200",
        }
        if not include_disabled:
            params["enabled"] = "eq.true"
        rows = await rest_request("GET", "lj_skills", params=params) or []
        return {"skills": [public_skill(row) for row in rows]}

    @router.post("/skills", status_code=status.HTTP_201_CREATED)
    async def create_skill(body: SkillCreate, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        await limiter.enforce(f"skills-create:{user_id}", 20, 3600)
        await ensure_unique_name(user_id, body.name)
        workflow = _workflow_payload(body)
        result = await rpc(
            "create_lj_skill",
            {
                "p_user_id": user_id,
                "p_name": body.name,
                "p_description": body.description,
                "p_enabled": body.enabled,
                "p_variables_schema": workflow["variables_schema"],
                "p_required_apps": workflow["required_apps"],
                "p_required_sites": workflow["required_sites"],
                "p_safety_policy": workflow["safety_policy"],
                "p_steps": workflow["steps"],
                "p_change_note": body.change_note or "Initial demonstration",
                "p_device_id": device_id,
            },
        )
        created = result[0] if isinstance(result, list) and result else result or {}
        skill_id = str(created.get("skill_id") or "")
        if not skill_id:
            raise HTTPException(status_code=502, detail="The Skill could not be saved.")
        await insert_audit(user_id, "SKILL_CREATED", {"skill_id": skill_id, "version": 1})
        skill = await get_skill(skill_id, user_id)
        version = await get_version(skill)
        return {**public_skill(skill), "workflow": version}

    @router.get("/skills/{skill_id}")
    async def view_skill(skill_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        version = await get_version(skill)
        return {**public_skill(skill), "workflow": version}

    @router.patch("/skills/{skill_id}")
    async def edit_skill_metadata(
        skill_id: str,
        body: SkillMetadataUpdate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        changes: dict[str, Any] = {"updated_at": _utcnow().isoformat()}
        if body.name is not None:
            await ensure_unique_name(user_id, body.name, excluding=skill["id"])
            changes["name"] = body.name
        if body.description is not None:
            changes["description"] = body.description
        rows = await rest_request(
            "PATCH",
            "lj_skills",
            params={
                "id": f"eq.{skill['id']}",
                "user_id": f"eq.{user_id}",
                "deleted_at": "is.null",
            },
            payload=changes,
            prefer="return=representation",
        ) or []
        if not rows:
            raise HTTPException(status_code=409, detail="That Skill was changed or deleted.")
        await insert_audit(user_id, "SKILL_METADATA_UPDATED", {"skill_id": skill["id"]})
        return public_skill(rows[0])

    @router.put("/skills/{skill_id}/workflow")
    async def edit_skill_workflow(
        skill_id: str,
        body: WorkflowBody,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        await limiter.enforce(f"skills-version:{user_id}", 30, 3600)
        skill = await get_skill(skill_id, user_id)
        workflow = _workflow_payload(body)
        result = await rpc(
            "create_lj_skill_version",
            {
                "p_user_id": user_id,
                "p_skill_id": skill["id"],
                "p_variables_schema": workflow["variables_schema"],
                "p_required_apps": workflow["required_apps"],
                "p_required_sites": workflow["required_sites"],
                "p_safety_policy": workflow["safety_policy"],
                "p_steps": workflow["steps"],
                "p_change_note": body.change_note or "Workflow edited",
                "p_device_id": device_id,
            },
        )
        created = result[0] if isinstance(result, list) and result else result or {}
        version_number = int(created.get("new_version") or 0)
        if version_number < 1:
            raise HTTPException(status_code=502, detail="The new Skill version could not be saved.")
        await insert_audit(
            user_id,
            "SKILL_VERSION_CREATED",
            {"skill_id": skill["id"], "version": version_number},
        )
        updated_skill = await get_skill(skill["id"], user_id)
        return {**public_skill(updated_skill), "workflow": await get_version(updated_skill)}

    @router.patch("/skills/{skill_id}/enabled")
    async def set_skill_enabled(
        skill_id: str,
        body: SkillEnabledUpdate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        rows = await rest_request(
            "PATCH",
            "lj_skills",
            params={
                "id": f"eq.{skill['id']}",
                "user_id": f"eq.{user_id}",
                "deleted_at": "is.null",
            },
            payload={"enabled": body.enabled, "updated_at": _utcnow().isoformat()},
            prefer="return=representation",
        ) or []
        if not rows:
            raise HTTPException(status_code=409, detail="That Skill was changed or deleted.")
        await insert_audit(
            user_id,
            "SKILL_ENABLED" if body.enabled else "SKILL_DISABLED",
            {"skill_id": skill["id"]},
        )
        return public_skill(rows[0])

    @router.delete("/skills/{skill_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_skill(skill_id: str, identity: Any = Depends(current_identity)) -> None:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        deleted = await rpc(
            "delete_lj_skill",
            {"p_user_id": user_id, "p_skill_id": skill["id"]},
        )
        value = deleted[0] if isinstance(deleted, list) and deleted else deleted
        if isinstance(value, dict):
            value = next(iter(value.values()), False)
        if value is not True:
            raise HTTPException(status_code=409, detail="That Skill was already changed or deleted.")
        await insert_audit(user_id, "SKILL_DELETED", {"skill_id": skill["id"]})
        return None

    @router.post("/skills/{skill_id}/duplicate", status_code=status.HTTP_201_CREATED)
    async def duplicate_skill(
        skill_id: str,
        body: SkillDuplicate,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        skill = await get_skill(skill_id, user_id)
        version = await get_version(skill)
        name = body.name or f"{str(skill['name'])[:75]} Copy"
        await ensure_unique_name(user_id, name)
        result = await rpc(
            "create_lj_skill",
            {
                "p_user_id": user_id,
                "p_name": name,
                "p_description": skill.get("description") or "",
                "p_enabled": bool(skill.get("enabled")),
                "p_variables_schema": version.get("variables_schema") or [],
                "p_required_apps": version.get("required_apps") or [],
                "p_required_sites": version.get("required_sites") or [],
                "p_safety_policy": version.get("safety_policy") or {},
                "p_steps": version.get("steps") or [],
                "p_change_note": f"Duplicated from {skill['name']}",
                "p_device_id": device_id,
            },
        )
        created = result[0] if isinstance(result, list) and result else result or {}
        duplicate_id = str(created.get("skill_id") or "")
        if not duplicate_id:
            raise HTTPException(status_code=502, detail="The Skill could not be duplicated.")
        await insert_audit(
            user_id,
            "SKILL_DUPLICATED",
            {"skill_id": duplicate_id, "source_skill_id": skill["id"]},
        )
        duplicate = await get_skill(duplicate_id, user_id)
        return {**public_skill(duplicate), "workflow": await get_version(duplicate)}

    @router.get("/skills/{skill_id}/versions")
    async def list_skill_versions(skill_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        rows = await rest_request(
            "GET",
            "lj_skill_versions",
            params={
                "skill_id": f"eq.{skill['id']}",
                "user_id": f"eq.{user_id}",
                "select": "version,change_note,created_at,created_by_device_id",
                "order": "version.desc",
                "limit": "100",
            },
        ) or []
        return {"skill_id": skill["id"], "current_version": skill["current_version"], "versions": rows}

    @router.get("/skills/{skill_id}/versions/{version_number}")
    async def view_skill_version(
        skill_id: str,
        version_number: int,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        if version_number < 1:
            raise HTTPException(status_code=404, detail="That Skill version is unavailable.")
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        return await get_version(skill, version_number)

    @router.post("/skills/{skill_id}/runs", status_code=status.HTTP_201_CREATED)
    async def start_skill_run(
        skill_id: str,
        body: SkillRunStart,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        await limiter.enforce(f"skill-run-start:{user_id}", 30, 60)
        skill = await get_skill(skill_id, user_id)
        if body.mode == "EXECUTE" and not skill.get("enabled"):
            raise HTTPException(status_code=409, detail="Enable this Skill before running it.")
        version = await get_version(skill)
        try:
            variables = validate_run_variables(version.get("variables_schema") or [], body.variables)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        steps = version.get("steps") if isinstance(version.get("steps"), list) else []
        if not steps:
            raise HTTPException(status_code=409, detail="This Skill has no runnable steps.")
        run_status = "READY" if body.mode == "TEST" else "RUNNING"
        pending: dict[str, Any] | None = None
        token: str | None = None
        token_hash: str | None = None
        expires: str | None = None
        if body.mode == "EXECUTE":
            reason = confirmation_reason(steps[0], version.get("safety_policy") or {})
            if reason:
                run_status = "WAITING_CONFIRMATION"
                pending, token, token_hash = make_confirmation(steps[0], 0, reason, variables)
                expires = pending["expires_at"]
        result = await rpc(
            "start_lj_skill_run",
            {
                "p_user_id": user_id,
                "p_skill_id": skill["id"],
                "p_skill_version": int(version["version"]),
                "p_device_id": device_id,
                "p_mode": body.mode,
                "p_status": run_status,
                "p_variables": variables,
                "p_pending_confirmation": pending,
                "p_confirmation_token_hash": token_hash,
                "p_confirmation_expires_at": expires,
            },
        )
        rows = result if isinstance(result, list) else ([result] if isinstance(result, dict) and result else [])
        if not rows:
            raise HTTPException(status_code=502, detail="The Skill run could not be started.")
        run = rows[0]
        await add_run_event(run, "RUN_CREATED", step_index=0, details={"mode": body.mode})
        if pending:
            await add_run_event(
                run,
                "CONFIRMATION_REQUIRED",
                step_index=0,
                details={"action": steps[0].get("action")},
            )
        await insert_audit(
            user_id,
            "SKILL_RUN_STARTED",
            {"skill_id": skill["id"], "run_id": run["id"], "mode": body.mode},
        )
        return public_run(run, version, confirmation_token=token)

    @router.get("/skills/{skill_id}/runs")
    async def list_skill_runs(skill_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        rows = await rest_request(
            "GET",
            "lj_skill_runs",
            params={
                "skill_id": f"eq.{skill['id']}",
                "user_id": f"eq.{user_id}",
                "select": "id,skill_version,device_id,mode,status,state_version,current_step_index,error_message,created_at,updated_at,completed_at",
                "order": "created_at.desc",
                "limit": "100",
            },
        ) or []
        return {"skill_id": skill["id"], "runs": rows}

    @router.get("/skills/{skill_id}/audit")
    async def skill_audit(skill_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        skill = await get_skill(skill_id, user_id)
        rows = await rest_request(
            "GET",
            "lj_skill_run_events",
            params={
                "skill_id": f"eq.{skill['id']}",
                "user_id": f"eq.{user_id}",
                "select": "id,run_id,event_type,step_index,details,created_at",
                "order": "created_at.desc",
                "limit": "200",
            },
        ) or []
        return {"skill_id": skill["id"], "events": rows}

    @router.get("/skill-runs/{run_id}")
    async def skill_run_state(run_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        run = await get_run(run_id, user_id)
        if str(run.get("device_id")) != device_id:
            raise HTTPException(status_code=403, detail="View this run on the device that started it.")
        skill = await get_skill(run["skill_id"], user_id, include_deleted=True)
        version = await get_version(skill, int(run["skill_version"]))
        return public_run(run, version)

    @router.post("/skill-runs/{run_id}/advance")
    async def advance_skill_run(
        run_id: str,
        body: SkillRunAdvance,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        await limiter.enforce(f"skill-run-advance:{user_id}:{device_id}", 120, 60)
        run = await get_run(run_id, user_id)
        if str(run.get("device_id")) != device_id:
            raise HTTPException(status_code=403, detail="Continue this run on the device that started it.")
        expected_status = "RUNNING" if run.get("mode") == "EXECUTE" else "READY"
        if run.get("status") != expected_status:
            raise HTTPException(status_code=409, detail="This run is not ready to advance.")
        index = int(run.get("current_step_index") or 0)
        if body.completed_step != index:
            raise HTTPException(status_code=409, detail=f"The run is waiting for step {index}.")
        skill = await get_skill(run["skill_id"], user_id)
        version = await get_version(skill, int(run["skill_version"]))
        steps = version.get("steps") if isinstance(version.get("steps"), list) else []
        if index >= len(steps):
            raise HTTPException(status_code=409, detail="This run has no remaining step.")
        now = _utcnow().isoformat()
        if not body.success:
            failure_policy = str(steps[index].get("on_failure") or "ASK_USER")
            retry_reason: str | None = None
            if run.get("mode") == "EXECUTE" and failure_policy == "ASK_USER":
                retry_reason = "This step failed. Confirm before LJ tries the same step again."
            elif run.get("mode") == "EXECUTE" and failure_policy == "RETRY":
                retry_reason = confirmation_reason(steps[index], version.get("safety_policy") or {})
            if failure_policy != "STOP":
                retry_status = "RUNNING" if run.get("mode") == "EXECUTE" else "READY"
                pending = None
                token = None
                token_hash = None
                expires = None
                if retry_reason:
                    retry_status = "WAITING_CONFIRMATION"
                    pending, token, token_hash = make_confirmation(
                        steps[index], index, retry_reason, run.get("variables") or {}
                    )
                    expires = pending["expires_at"]
                retry_run = await transition_run(
                    run,
                    expected_step=index,
                    new_status=retry_status,
                    new_step=index,
                    pending_confirmation=pending,
                    confirmation_token_hash=token_hash,
                    confirmation_expires_at=expires,
                    error_message=f"Step {index} failed and is ready to retry.",
                    completed=False,
                )
                await add_run_event(
                    run,
                    "STEP_RETRY_CONFIRMATION_REQUIRED" if pending else "STEP_RETRY_READY",
                    step_index=index,
                    details={"action": steps[index].get("action"), "policy": failure_policy},
                )
                return public_run(retry_run, version, confirmation_token=token)
            failed = await transition_run(
                run,
                expected_step=index,
                new_status="FAILED",
                new_step=index,
                # Never persist UI text supplied by a recorder/runner. It may
                # accidentally contain private on-screen information.
                error_message=f"Step {index} failed on the client.",
                completed=True,
            )
            await add_run_event(run, "STEP_FAILED", step_index=index, details={"action": steps[index].get("action")})
            await rest_request(
                "PATCH",
                "lj_skills",
                params={"id": f"eq.{skill['id']}", "user_id": f"eq.{user_id}"},
                payload={"last_run_at": now, "last_run_status": "FAILED"},
                prefer="return=minimal",
            )
            await insert_audit(user_id, "SKILL_RUN_FAILED", {"skill_id": skill["id"], "run_id": run["id"]})
            return public_run(failed, version)

        next_index = index + 1
        if next_index >= len(steps):
            completed = await transition_run(
                run,
                expected_step=index,
                new_status="SUCCEEDED",
                new_step=next_index,
                error_message=None,
                completed=True,
            )
            await add_run_event(run, "STEP_SUCCEEDED", step_index=index, details={"action": steps[index].get("action")})
            skill_patch: dict[str, Any] = {"last_run_at": now, "last_run_status": "SUCCEEDED"}
            if run.get("mode") == "EXECUTE":
                skill_patch["last_used_at"] = now
            await rest_request(
                "PATCH",
                "lj_skills",
                params={"id": f"eq.{skill['id']}", "user_id": f"eq.{user_id}"},
                payload=skill_patch,
                prefer="return=minimal",
            )
            await add_run_event(run, "RUN_SUCCEEDED", step_index=index)
            await insert_audit(user_id, "SKILL_RUN_SUCCEEDED", {"skill_id": skill["id"], "run_id": run["id"]})
            return public_run(completed, version)

        next_step = steps[next_index]
        next_status = "RUNNING" if run.get("mode") == "EXECUTE" else "READY"
        pending = None
        token = None
        token_hash = None
        expires = None
        if run.get("mode") == "EXECUTE":
            reason = confirmation_reason(next_step, version.get("safety_policy") or {})
            if reason:
                next_status = "WAITING_CONFIRMATION"
                pending, token, token_hash = make_confirmation(
                    next_step, next_index, reason, run.get("variables") or {}
                )
                expires = pending["expires_at"]
        advanced = await transition_run(
            run,
            expected_step=index,
            new_status=next_status,
            new_step=next_index,
            pending_confirmation=pending,
            confirmation_token_hash=token_hash,
            confirmation_expires_at=expires,
            error_message=None,
            completed=False,
        )
        await add_run_event(run, "STEP_SUCCEEDED", step_index=index, details={"action": steps[index].get("action")})
        if pending:
            await add_run_event(
                run,
                "CONFIRMATION_REQUIRED",
                step_index=next_index,
                details={"action": next_step.get("action")},
            )
        return public_run(advanced, version, confirmation_token=token)

    @router.post("/skill-runs/{run_id}/confirm")
    async def confirm_skill_run(
        run_id: str,
        body: SkillRunConfirmation,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        await limiter.enforce(f"skill-run-confirm:{user_id}", 30, 60)
        run = await get_run(run_id, user_id)
        if str(run.get("device_id")) != device_id:
            raise HTTPException(status_code=403, detail="Confirm this run on the device that started it.")
        if run.get("status") != "WAITING_CONFIRMATION":
            raise HTTPException(status_code=409, detail="This run is not waiting for confirmation.")
        expected = str(run.get("confirmation_token_hash") or "")
        supplied = hashlib.sha256(body.confirmation_token.encode("utf-8")).hexdigest()
        expiry = str(run.get("confirmation_expires_at") or "")
        try:
            expiry_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError:
            expiry_at = datetime.min.replace(tzinfo=timezone.utc)
        if not expected or not secrets.compare_digest(expected, supplied) or expiry_at <= _utcnow():
            raise HTTPException(status_code=409, detail="That confirmation expired. Cancel and start the Skill again.")
        now = _utcnow().isoformat()
        result = await rpc(
            "confirm_lj_skill_run",
            {
                "p_user_id": user_id,
                "p_run_id": run["id"],
                "p_device_id": device_id,
                "p_confirmation_token_hash": supplied,
                "p_expected_state_version": int(run.get("state_version") or 0),
                "p_approved": body.approved,
            },
        )
        rows = result if isinstance(result, list) else ([result] if isinstance(result, dict) and result else [])
        if not rows:
            raise HTTPException(status_code=409, detail="This Skill confirmation expired or was already handled.")
        updated = rows[0]
        await add_run_event(
            run,
            "CONFIRMATION_APPROVED" if body.approved else "CONFIRMATION_DENIED",
            step_index=int(run.get("current_step_index") or 0),
        )
        skill = await get_skill(run["skill_id"], user_id, include_deleted=True)
        version = await get_version(skill, int(run["skill_version"]))
        if not body.approved:
            await rest_request(
                "PATCH",
                "lj_skills",
                params={"id": f"eq.{skill['id']}", "user_id": f"eq.{user_id}"},
                payload={"last_run_at": now, "last_run_status": "CANCELLED"},
                prefer="return=minimal",
            )
        await insert_audit(
            user_id,
            "SKILL_CONFIRMATION_APPROVED" if body.approved else "SKILL_CONFIRMATION_DENIED",
            {"skill_id": skill["id"], "run_id": run["id"], "step": run.get("current_step_index")},
        )
        return public_run(updated, version)

    @router.post("/skill-runs/{run_id}/cancel")
    async def cancel_skill_run(run_id: str, identity: Any = Depends(current_identity)) -> dict[str, Any]:
        user_id = str(_identity_value(identity, "user_id"))
        device_id = str(_identity_value(identity, "device_id"))
        run = await get_run(run_id, user_id)
        if str(run.get("device_id")) != device_id:
            raise HTTPException(status_code=403, detail="Cancel this run on the device that started it.")
        if run.get("status") in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            raise HTTPException(status_code=409, detail="This Skill run has already finished.")
        now = _utcnow().isoformat()
        result = await rpc(
            "cancel_lj_skill_run",
            {
                "p_user_id": user_id,
                "p_run_id": run["id"],
                "p_device_id": device_id,
                "p_expected_state_version": int(run.get("state_version") or 0),
            },
        )
        rows = result if isinstance(result, list) else ([result] if isinstance(result, dict) and result else [])
        if not rows:
            raise HTTPException(status_code=409, detail="This Skill run was already changed.")
        cancelled = rows[0]
        await add_run_event(run, "RUN_CANCELLED", step_index=int(run.get("current_step_index") or 0))
        skill = await get_skill(run["skill_id"], user_id, include_deleted=True)
        version = await get_version(skill, int(run["skill_version"]))
        await rest_request(
            "PATCH",
            "lj_skills",
            params={"id": f"eq.{skill['id']}", "user_id": f"eq.{user_id}"},
            payload={"last_run_at": now, "last_run_status": "CANCELLED"},
            prefer="return=minimal",
        )
        await insert_audit(user_id, "SKILL_RUN_CANCELLED", {"skill_id": skill["id"], "run_id": run["id"]})
        return public_run(cancelled, version)

    return router
