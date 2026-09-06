# Teach LJ API

Teach LJ stores reusable, per-user workflows learned by demonstration. Windows
and Android use the same authenticated cloud API.

## Deploy

1. Run `LJ_AI_TEACH_LJ_DATABASE_UPDATE.sql` in the production Supabase SQL Editor.
2. Deploy `teach_lj_routes.py` with the registered `main.py`.
3. Keep the existing bearer token, `X-LJ-Device-ID`, and
   `X-LJ-Device-Token` headers on every request.

The database migration must be applied before the new cloud code is deployed.

## Safety contract

- A step describes an accessible UI or browser element. It never contains
  screen coordinates, XPath, CSS selectors, raw key streams, scripts, shell
  commands, or executable code.
- Password, passcode, private-key, API-key, token, recovery-code, and
  payment-card variables/controls are rejected.
- Shells, script hosts, and system command tools cannot be launched.
- Important actions pause in `WAITING_CONFIRMATION`. The client must show the
  supplied reason and send the one-time confirmation token back.
- Downloads, screenshots, form submission, uploads, messages, public posts,
  purchases, deletion, and security-setting changes always require a fresh
  confirmation. Generic `click_element` taps, `select_option` changes, and
  `set_text` entries also always require confirmation because their labels
  cannot prove that they are non-mutating. Text confirmations include the
  resolved value, safely bounded to 500 characters. No saved policy can bypass
  this.
- Semantic risk detection is mandatory; `confirm_target_keywords` must remain
  `true`. Risk words are checked across accessible names, labels, roles, and IDs.
- In `TEST` mode, status is `READY` and `should_execute` is `false`; clients
  preview each step without causing the action. Only an `EXECUTE` run with
  status `RUNNING`, `should_execute: true`, and the exact initiating
  `device_id` may execute.
- The server is a state coordinator. It never remotely executes a workflow.

## Semantic actions

Canonical action names are:

`launch_app`, `activate_window`, `open_url`, `open_folder`, `click_element`,
`set_text`, `press_key`, `choose_file`, `select_option`, `wait_for_element`,
`read_element`, `scroll`, `submit_form`, `upload_file`, `send_message`,
`publish_content`, `delete_item`, `make_purchase`,
`change_security_setting`, `download_file`, and `take_screenshot`.

For input compatibility, `open_app` normalizes to `launch_app`, and
`open_website` normalizes to `open_url`. Responses always contain canonical
names.

An element target uses only semantic data:

```json
{
  "role": "button",
  "name": "Upload",
  "label": "",
  "app": "Google Chrome",
  "site": "https://studio.youtube.com",
  "accessibility_id": "",
  "dom_id": ""
}
```

## Create a Skill

`POST /v1/skills`

```json
{
  "name": "Upload YouTube Video",
  "description": "Upload a video using the demonstrated Studio workflow.",
  "enabled": true,
  "variables_schema": [
    {
      "name": "VIDEO_FILE",
      "type": "file_path",
      "description": "Video to upload",
      "required": true
    },
    {
      "name": "VIDEO_TITLE",
      "type": "text",
      "description": "Public video title",
      "required": true
    },
    {
      "name": "VISIBILITY",
      "type": "choice",
      "description": "YouTube visibility",
      "required": true,
      "choices": ["Public", "Unlisted", "Private"]
    }
  ],
  "required_apps": ["Google Chrome"],
  "required_sites": ["https://studio.youtube.com"],
  "safety_policy": {
    "auto_approve_actions": [],
    "confirm_target_keywords": true
  },
  "steps": [
    {
      "step_id": "open_studio",
      "action": "open_url",
      "arguments": {"url": "https://studio.youtube.com"}
    },
    {
      "step_id": "choose_video",
      "action": "choose_file",
      "target": {"role": "button", "name": "Select files"},
      "arguments": {"variable": "VIDEO_FILE"}
    },
    {
      "step_id": "enter_title",
      "action": "set_text",
      "target": {"role": "textbox", "name": "Title"},
      "arguments": {"variable": "VIDEO_TITLE", "clear_first": true}
    },
    {
      "step_id": "publish",
      "action": "publish_content",
      "target": {"role": "button", "name": "Publish"}
    }
  ],
  "change_note": "Initial demonstration"
}
```

Variable types are `text`, `url`, `file_path`, `number`, `boolean`, and
`choice`. Names use uppercase letters, numbers, and underscores. Recorded text,
URLs, and local paths cannot be stored as schema defaults; clients request
those values when the Skill runs.

## Skill management

- `GET /v1/skills` — list the current user's Skills.
- `GET /v1/skills/{skill_id}` — view current workflow.
- `PATCH /v1/skills/{skill_id}` — rename or update the description.
- `PUT /v1/skills/{skill_id}/workflow` — save an edit as a new immutable version.
- `PATCH /v1/skills/{skill_id}/enabled` with `{"enabled": false}` — disable or enable.
- `POST /v1/skills/{skill_id}/duplicate` with `{"name": "New name"}` — duplicate.
- `DELETE /v1/skills/{skill_id}` — soft-delete and cancel active runs.
- `GET /v1/skills/{skill_id}/versions` — list version history.
- `GET /v1/skills/{skill_id}/versions/{version}` — view one version.
- `GET /v1/skills/{skill_id}/runs` — view recent tests/executions.
- `GET /v1/skills/{skill_id}/audit` — view structural run events.

## Test or execute

Start:

`POST /v1/skills/{skill_id}/runs`

```json
{
  "mode": "EXECUTE",
  "variables": {
    "VIDEO_FILE": "C:/Videos/gta.mp4",
    "VIDEO_TITLE": "GTA 6 Funny Moments",
    "VISIBILITY": "Unlisted"
  }
}
```

A safe step returns:

```json
{
  "id": "run-uuid",
  "device_id": "the-initiating-device-id",
  "status": "RUNNING",
  "state_version": 0,
  "current_step_index": 0,
  "total_steps": 4,
  "mode": "EXECUTE",
  "should_execute": true,
  "next_step": {
    "step_id": "open_studio",
    "action": "open_url",
    "arguments": {"url": "https://studio.youtube.com"}
  }
}
```

After the client safely performs or previews that one step:

`POST /v1/skill-runs/{run_id}/advance`

```json
{"completed_step": 0, "success": true, "message": ""}
```

The response supplies the next step, `SUCCEEDED`, or
`WAITING_CONFIRMATION`. When confirmation is required, show
`pending_confirmation.reason`, target app/site/name, and every supplied
`material_facts` value (for example amount/currency/merchant, recipient/message,
URL/path, or setting/value) to the user. Retain the response-only
`confirmation_token` in memory.

Approve or deny:

`POST /v1/skill-runs/{run_id}/confirm`

```json
{"confirmation_token": "response-only-token", "approved": true}
```

Other run endpoints:

- `GET /v1/skill-runs/{run_id}` — refresh state on the initiating device (never
  returns the token again).
- `POST /v1/skill-runs/{run_id}/cancel` — cancel an unfinished run.

If the client loses a one-time confirmation token, it should cancel and start a
new run. It must never cache confirmation tokens on disk.
