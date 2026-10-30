# OpenClaw and Hermes adapter host facts (2026-10-26)

The facts in the tables below were read from source; both harnesses were then run live (see "Live runs (2026-10-26)" at the end). Sources: the `openclaw` npm package 2026.10.7
(`dist/`, `docs/`) and `github.com/NousResearch/hermes-agent` at
`9976f4857b72439d79016354d7b6e1a3ee952e2f`. Each fact names the file and line it was read at. The
adapters built on these facts are `rust/plugins/openclaw/`, `rust/plugins/hermes/`,
`rust/crates/lunchroom/src/openclaw.rs` and the plugin parts of `claude.rs`, `delivery.rs`,
`evidence.rs` and `install.rs`.

## OpenClaw 2026.10.7

| Fact | Source | Used for |
|---|---|---|
| A plugin registers typed hooks with `api.on(name, handler)`; `before_tool_call` may return `{block, blockReason}`, `{requireApproval: {title, description, allowedDecisions, timeoutMs, pluginId, onResolution}}` or `{params}`. | `dist/config-contracts-Db6WHFol.d.ts:8894-8909`; `docs/plugins/hooks.md:22-25` | The plugin's answer to each call (A1.1). |
| `onResolution` is called with `allow-once`, `allow-always`, `deny`, `timeout` or `cancelled`. An answer outside the request's `allowedDecisions` (such as `allow-always` when only `allow-once` and `deny` are offered) becomes `timeout`, which blocks the call, before `onResolution` is called. | `dist/agent-tools.before-tool-call-CReBJLEA.mjs:95-101`, `:801-803`, `:870-874` | Only a call the user approved is reported as approved (card 4); A1.1's refusal of an allow-always answer. |
| `after_tool_call` fires at a tool's end with `{toolName, params, toolCallId, result, error}`. | `dist/builtin-openclaw-Ci5YBsOb.mjs:7155-7175`; `config-contracts…d.ts:9876-9884` | Another agent's text in a tool's output holds the session (T1). |
| `before_agent_run`, `agent_end` and the other conversation hooks register only with `plugins.entries.<id>.hooks.allowConversationAccess: true`; otherwise registration fails with a warning. `before_tool_call` needs no grant. | `dist/registry-BwDJiK-z.mjs:2597-2607`, `:2827-2834`; `docs/plugins/hooks/tool-policy.md:88` | Evidence requires the grant (R3.1); the install lists it as the user's step. |
| `before_agent_run` gets the turn's `prompt` and `senderIsOwner`; its context carries `inputProvenance.kind` (`external_user`, `inter_session`, `internal_system`) and may return `{outcome: "block", reason}`. | `docs/plugins/hooks.md`; `sessions-spawn-tool-a0Vw8SLo.mjs:1928-1953` | Delivery confirmation (D1.1) and whose text a turn is (T1). |
| Hook context fields `agentId`, `sessionKey`, `sessionId` are each spread only when present. | `docs/plugins/hooks.md:143-146` | The identity is the session key; a call without one goes to the user. |
| `resolve_exec_env` returns variables for an `exec` command; OpenClaw keeps them in its own prepared state, not in the call's `params.env`, so `before_tool_call` sees only the `env` the agent wrote. Names starting `LD_`, `DYLD_`, `BASH_FUNC_`, and `PATH`, are dropped. | `dist/bash-tools-_OZ7Mrpp.mjs:2608-2618`, `:2701-2735`; `dist/host-env-security-DsfhifNr.mjs:321-331` | `LUNCHROOM_SESSION` names the sender (I1.2); the guard's identity-variable rule judges only the agent's `env`. |
| `openclaw agent --session-key <key> --message <text>` runs one turn through the gateway and waits until it ends; it refuses to run when `OPENCLAW_SHELL=exec`, which every `exec` command has. | `docs/cli/agent.md:13-22`, `:326-376`; `dist/call-g4aSX1Q-.mjs:164-179`; `dist/bash-tools.exec-runtime-Ckwb9gZp.mjs:778` | Delivery is started detached, with `OPENCLAW_SHELL` removed. |
| The config file is `openclaw.json` (JSON5) in the state folder (`OPENCLAW_STATE_DIR`, default `~/.openclaw`), or `OPENCLAW_CONFIG_PATH`; both may be set in the state folder's `.env`. | `docs/help/faq/where-things-live-on-disk.md:28`; `docs/help/environment.md:41`, `:326`, `:347` | Evidence reads it. |
| A running gateway applies plugin settings changes ("hybrid reload"). | `docs/cli/plugins/list.md:32` | Evidence reads `openclaw.json` each time. |
| Install and enable are the user's: `openclaw plugins install --link <dir> --force`, `openclaw plugins enable <id>`; local sources ask for consent on every install. | `docs/plugins/hooks.md:84-85`; `docs/plugins/manage-plugins.md:139-195` | The install lists them (H1.4). |
| `openclaw config set <path> <value> --strict-json` sets one setting. | `docs/cli/config.md:75-79`; `docs/cli/approvals.md:167` | The install's conversation-access step. |
| OpenClaw's version is its package's `version` (`package.json`: `"version": "2026.10.7"`); its bin is `openclaw.mjs` at the package root. The plugin API's own `version` is the plugin's, not OpenClaw's. | `package.json:3`, `:23-25`; `dist/config-contracts-Db6WHFol.d.ts:43092-43096` | The plugin reports OpenClaw's version (H1.2). |
| A plugin that is not loaded runs no hook, and the call goes ahead. | `dist/agent-tools.before-tool-call-CReBJLEA.mjs:3230-3252` | K1.9. |

## Hermes 9976f48

| Fact | Source | Used for |
|---|---|---|
| A plugin is a folder with `plugin.yaml` and `__init__.py` exposing `register(ctx)`; `ctx.register_hook("pre_tool_call", fn)`. User plugins live in `<HERMES_HOME>/plugins/<name>/` and load only when named in `plugins.enabled` (`hermes plugins enable <name>`), on the next session. | `hermes_cli/plugins.py:1-10`, `:109-111`; `hermes_cli/plugins_discovery.py:122-131`, `:319-323`; `website/docs/user-guide/features/plugins.md:171`, `:958` | The install writes the folder; enabling is the user's. |
| `plugins.enabled` and `plugins.disabled` are lists in `<HERMES_HOME>/config.yaml`; a plugin in both does not load (the disable wins). | `hermes_cli/plugins_discovery.py:112-131`, `:289-299` | Evidence reads them (R3.1). |
| `pre_tool_call` gets `tool_name, args, task_id, session_id, tool_call_id, turn_id`; it may return `{"action": "block", "message"}` (an empty message is ignored) or `{"action": "approve", "message", "rule_key"}`. | `hermes_cli/plugins.py:1907-1959` | The plugin's answer to each call. |
| A hook callback runs on a worker thread inside `context.run`, so Hermes's context variables (the session's approval key) are the call's own. | `hermes_cli/plugins_dispatch.py:402-411` | The plugin reads Hermes's approval state at each call. |
| A `pre_tool_call` callback that raises or passes `hook_callback_timeout` (30 s) keeps the call from running. | `hermes_cli/plugins_dispatch.py:67-78`, `:307-322`, `:420` | A hung guard stops one call, no more (H1.5). |
| `approve` goes through `_run_approval_gate`: approved without asking under `_yolo_active()` (`HERMES_YOLO_MODE`, a session's `/yolo`, an unattended `hermes -z` turn) or `approvals.mode: off`; otherwise not run when `_presence()` finds no CLI, gateway or ask surface, unless a cron, single-query or unattended mode is set to approve. | `tools/approval.py:327-333`, `:933-1038`, `:1121-1146` | The plugin reports whether a person would be asked (A1.2, A1.2). |
| `is_approval_bypass_active_for_session(key)` is `--yolo`, the session's `/yolo` or `approvals.mode: off`. | `tools/approval.py:505-510` | The harness YOLO the plugin reports (R2.1). |
| `post_tool_call` gets `tool_name, args, result, session_id, tool_call_id, status` (`ok`, `error`, `blocked`, `cancelled`); its return is ignored. | `model_tools.py:667-690` | Tool output holds the session; a call that did not run is not reported. |
| `pre_llm_call` runs before each turn with `session_id, user_message, platform, turn_id, …`; it cannot stop the turn, and a returned `{"context": …}` is added to the turn's user message. | `agent/turn_context.py:802-856` | Delivery to the next turn (D1.1); a turn the guard could not judge is held by the plugin itself. |
| `pre_api_request` runs before each request to the model with `session_id, api_request_id, request_messages` (the messages sent), `user_message`, …; it is an observer. | `agent/turn_api_request.py:60-104`; `hermes_cli/plugins.py` `VALID_HOOKS` | Confirmation: the request carries the envelope (D1.1). |
| `platform` is `cli`, `tui` or `desktop` for this computer's surfaces, a chat platform name, `api_server`, `cron`, or `subagent` for a delegated child. | `hermes_cli/cli_agent_setup_mixin.py:408`, `:717`; `tui_gateway/prompt_turn.py:355`; `tools/delegate_tool.py:296` | Whose text a turn is (T1). |
| `HERMES_SESSION_ID` is set in each terminal command's environment. | `tools/environments/local.py:243-259`; `gateway/session_context.py:40-90` | Names the sender (I1.2). |
| `hermes_cli.version_info.get_version_info()` returns `base_version`, `commit` (`git rev-parse HEAD` for a source install) and more, from an install stamp or git. | `hermes_cli/version_info.py:26-34`, `:209`, `:292-312` | The plugin reports Hermes's version: the commit, else the base version (H1.2). |
| Session ids include `cron_<job>_<date>_<time>`, whose job part may hold `.`. | `hermes_state_ids.py:20-37` | The listener's file name takes `.` too. |

## The folder a call is judged in

An OpenClaw `exec` runs in its `workdir`, else in the agent's workspace. A Hermes `terminal`
command runs in its `workdir`, else in the folder Hermes keeps for the session after its earlier
`cd` commands. The OpenClaw plugin sends the guard that folder, made absolute, inside the call's
input, so the guard judges the command there and an approval covers it (A2.1). The Hermes plugin
runs inside Hermes's process and reads the session's folder as `tools/terminal_tool.py` does
(9976f48): the cwd for a command is "explicit `workdir` > the session's own cwd record >
`default_cwd`" (line 993); the record is `get_session_cwd(session_key)` (line 277), written after
every completed command of the session (lines 247-252), with `session_key =
get_current_session_key(default="") or (task_id or "")` (lines 1494-1496); the default is
`overrides.get("cwd") or get_session_cwd(task_id) or config["cwd"]` with `overrides =
resolve_task_overrides(task_id)` (lines 1183-1187). The plugin sends an absolute `workdir` as
given, a relative one joined to that folder, and no `workdir` as that folder. Only when those
functions cannot be read (another Hermes) or give no absolute folder does it send
`workdir_unknown: true` and no `workdir`; the guard then treats a relative path in the command as a
folder it cannot resolve and does not let it run as an ordinary command. The folder is read at the
call and the same input is reported after it, since a `cd` moves the folder. On a container
backend the folder is a path in the container, not on this computer. For the session's own folder (the project settings the
guard reads) the OpenClaw plugin sends the workspace, or, when OpenClaw gives none, the gateway
process's folder; the Hermes plugin sends the folder Hermes runs in. In a gateway started as a
service that folder is the service's, not a project's, so project settings are read from there.

## Harness releases (H1.2: the release an adapter passed with, or later)

| Harness | Where the release is read | Measured | Passed with |
|---|---|---|---|
| Claude Code | the process binary's path, `~/.local/share/claude/versions/<release>`; an npm install, the `package.json` above the script it runs | `readlink /proc/$CLAUDE_PID/exe`: `~/.local/share/claude/versions/2.1.310` | 2.1.310 |
| Codex | `…/releases/<release>-<target>/bin/codex` (the app-server daemon), or the `package.json` above the binary (`@openai/codex-linux-x64`: `"version": "0.163.0-linux-x64"`) | daemon `~/.codex/packages/app-server-daemon/releases/0.164.0-x86_64-unknown-linux-musl/bin/codex`; CLI package `@openai/codex` `"version": "0.163.0"` | 0.163.0 |
| OpenClaw | its package's `package.json` above the gateway's entry script (the plugin reads it) | `openclaw --version`: `OpenClaw 2026.10.7 (157d8c2)` | 2026.10.7 |
| Hermes | `hermes_cli.version_info.get_version_info()`: a source install gives `commit` and `commit_date`, `base_version` "unknown" (the plugin reports `<commit>@<commit date>`) | `9976f4857b72439d79016354d7b6e1a3ee952e2f`, commit date `1793038003`, source `git` | commit 9976f48 (later commit dates pass) |

A release is read from the harness's own install alone: Claude Code, a `claude/versions/<release>`
path or the `@anthropic-ai/claude-code` package; Codex, a `releases/<release>-<target>` folder under
`.codex` or an `@openai/codex` package. A release Lunchroom cannot read leaves the session UNGUARDED.

## Live runs (2026-10-26)

After the source reading above, both harnesses were run for real on Ubuntu 24.04, each in a throwaway
test home so that no real configuration was touched, with Lunchroom's program and plugin laid out as
`lunchroom install` lays them out. The model ran on a hosted inference endpoint.

- Hermes 9976f48 (Python 3.14.2, installed from the commit with its pinned dependencies): one-shot
  `hermes chat --oneshot` turns, run through a Hermes gateway the harness started itself (one process
  for every session).
- OpenClaw 2026.10.7: a gateway in the test home on the loopback address, the plugin loaded from
  `plugins.load.paths` with conversation access; `openclaw plugins inspect lunchroom --runtime --json`
  listed its five typed hooks (`after_tool_call`, `agent_end`, `before_agent_run`, `before_tool_call`,
  `resolve_exec_env`). The turns were started with OpenClaw's own agent command, which Lunchroom's
  guard DENIES in a guarded agent session (F1.1), so the user ran that part.

What was observed:

| Check | Hermes | OpenClaw |
|---|---|---|
| The plugin loads | `hermes plugins list` showed it enabled | the five typed hooks above were registered |
| The guard runs in the harness | the store recorded each session, with the plugin file and Hermes's commit as the guard fingerprint | the hooks recorded both sessions |
| A message is delivered | the agent in one session ran `lunchroom send`; the message was QUEUED, then DELIVERED on the recipient's next turn through the plugin's `pre_llm_call`; the recipient's model reported it as another agent's instruction and did not act on it | `lunchroom send` printed QUEUED and DELIVERED; Lunchroom started the recipient's turn |
| The recipient is HELD | the store showed it HELD by the message, naming the sender | the same |
| A held write is stopped | the write was DENIED ("no approval channel", as a one-shot run has no person to ask); the file was not written | the write went to the user as outside the permission slip of a HELD session; the file was not written |
| A reply to the holder | not exercised | the reply went through and was DELIVERED, and the original sender was then HELD by the reply |
| The user's own turn | not exercised | the user's own turn for the held agent cleared HELD, and the same write then ran |

Three rules were settled by these runs: only the variable of the harness a command runs in names
its session (I1.2); the store spells OpenClaw's name as its identity keys do; and the reply line in
a delivered envelope names Lunchroom's program by its path, since a gateway's `PATH` need not
resolve the bare name.

What the runs did not cover:

- A person answering an approval prompt in either harness (allow-once, deny, timeout, or an
  allow-always answer): the approval paths are tested against stand-ins of the harnesses' approval
  systems and read from source, not exercised live.
- A reply to an agent whose messages do not hold the sender (it is DENIED; covered by the test
  suite, not by these runs), and any reply from a Hermes agent.
- Starting and ending either harness's YOLO (Lunchroom refuses it for them: their adapters do not
  do it).
- Anything beyond the sessions and releases named above.

These are field checks, not the verification of each requirement. The rest of each requirement's
acceptance criterion is in the tests named in `rust/TESTPLAN.md`.
