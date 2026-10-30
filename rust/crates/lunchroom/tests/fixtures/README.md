# Real-input fixtures

Hook inputs and configuration files shaped as the harnesses write them. `tests/real_inputs.rs`
rewrites `__HOME__` to the sandbox home and `__LUNCHROOM__` to the program's path before use.
Sources are the host-facts documents in `docs/host-facts/`: `claude-code.md` (Claude Code),
`codex.md` (Codex) and `claude-code-and-codex-2026-10-24.md` (the earlier Claude Code and Codex
probes).

## claude/

Common keys of every Claude Code input: `session_id`, `transcript_path`, `cwd`, `permission_mode`,
`hook_event_name`. Values: UUID session id; `permission_mode` `default` (`claude-code.md` section 2:
"`default` (manual)").

| File | Source |
|---|---|
| `pretool-bash.json`, `pretool-read.json`, `pretool-edit.json` | `claude-code.md` section 2, hook input keys under `claude -p`: `cwd, effort, hook_event_name, permission_mode, prompt_id, session_id, tool_input, tool_name, tool_use_id, transcript_path`. `effort` is omitted: no document shows its value. `Bash` `tool_input.command`: `claude-code-and-codex-2026-10-24.md` section 1 and `tests/guard.rs`. The `Read` and `Edit` argument names (`file_path`, `old_string`, `new_string`) are the tools' own, not in the host-facts documents. |
| `posttool-bash.json` | PreToolUse's keys plus `tool_response` `{stdout, stderr, interrupted, isImage}`: the shape `src/claude.rs` reads; not in the host-facts documents. |
| `posttool-failure-bash.json` | PreToolUse's keys plus `error` (string), event `PostToolUseFailure`: `src/claude.rs` (`tool_response` doc comment); not in the host-facts documents. |
| `prompt.json` | `claude-code.md` section 3, UserPromptSubmit input keys: `cwd, hook_event_name, permission_mode, prompt, prompt_id, scratchpad_dir, session_id, transcript_path`. |
| `session-start.json` | `claude-code.md` section 3 ("SessionStart:startup"): the common keys plus `source` `startup`. |
| `stop.json` | `claude-code.md` section 3 ("A Stop hook then fired"): the common keys only; no document lists Stop's other keys. |

## codex/

`session_id` is the thread id; `transcript_path` is `<CODEX_HOME>/sessions/YYYY/MM/DD/rollout-<time>-<thread id>.jsonl`;
`permission_mode` `bypassPermissions` (`codex.md` section 2). `model` is a placeholder value
(`codex.md` lists the key only).

| File | Source |
|---|---|
| `session-start.json` | `codex.md` section 2 table, SessionStart: `session_id, cwd, transcript_path, permission_mode, model, source` (`startup`). |
| `prompt.json` | `codex.md` section 2 table, UserPromptSubmit: the SessionStart keys without `source`, plus `turn_id`, `prompt`. |
| `pretool-bash.json` | `codex.md` section 2 table, PreToolUse: `session_id, turn_id, cwd, tool_name` (`Bash`), `tool_input` (`{"command": …}`), `tool_use_id, transcript_path, permission_mode, model`. |
| `posttool-bash.json` | PreToolUse's fields plus `tool_response`. `codex.md` gives no shape for it; a string is used here and is not verified. |
| `stop.json` | `codex.md` section 2 table, Stop: `session_id, turn_id, cwd, transcript_path, permission_mode, model, last_assistant_message, stop_hook_active`. |

## Configuration

- `settings-claude.json`: the structure of a Claude Code `~/.claude/settings.json` (top-level keys
  and hook groups); every value is a placeholder, `env` holds only `EXAMPLE`. `UserPromptSubmit` is
  one shared group with Lunchroom's hook last.
- `codex-hooks-old-name.json`: `<CODEX_HOME>/hooks.json` shape (`codex.md` section 1) holding the
  hooks of a command under another name (`~/.oldname/bin/oldname guard pretool|posttool|prompt`). An
  install removes them when that name is a link to Lunchroom's program, and leaves them where they
  are when it is another application's program.
