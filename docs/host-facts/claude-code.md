# Claude Code adapter: host facts (measured 2026-10-26)

For the Claude Code adapter (spec §13 H1). Measured on Ubuntu 24.04 with Claude Code 2.1.310
(`claude --version`). Every probe ran in a scratch folder with only a project settings file (`--setting-sources project
--strict-mcp-config`), on the Haiku model. Documentation quotes are from
https://code.claude.com/docs/en/hooks.md (H) and https://code.claude.com/docs/en/env-vars.md (E).

## 1. Hook output (documentation)

- PreToolUse decides with `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":
  "allow"|"deny"|"ask","permissionDecisionReason":"…"}}` (H, "PreToolUse decision control"). For
  "ask" the reason is "shown to the user in the permission prompt"; for "deny", "shown to Claude".
- Exit code 2 stops the tool call; any other failure is an error Claude Code passes over and "the action goes
  ahead", unless the hook sets `"onFailure": "block"` (v2.1.295 or later), when "A `PreToolUse`
  failure blocks the tool call and a `UserPromptSubmit` failure blocks the prompt" (H, "Block the
  action when a hook fails"). Timeouts, failing to start and exit codes other than 0 or 2 count as
  failures.
- UserPromptSubmit stops a prompt with exit 2 or `{"decision":"block"}`; the prompt then "never
  reaches Claude" (H).
- `asyncRewake`: "runs in the background and wakes Claude on exit code 2. The hook's stderr … is
  shown to Claude" (H, common fields).
- To show text to the user: "To surface a message to the user on any platform, return
  systemMessage in JSON output" (H, common fields); for an async hook, "Unlike a synchronous hook's
  systemMessage, neither field is shown to you" (H, "How async hooks execute"). Measured in the
  card 4 replay: a PostToolUse `additionalContext` reaches Claude's context (the transcript holds a
  `hook_additional_context` attachment) and is not drawn in the terminal; card 4's line is
  therefore returned as both `additionalContext` and `systemMessage`.

## 2. What a hook can see of the session that started it (measured)

A PreToolUse hook that recorded its ancestors and environment, under `claude -p` started from an
empty environment (`env -i HOME PATH TERM`):

| Seen by the hook | `claude -p` | interactive (for comparison) |
|---|---|---|
| `CLAUDE_PID` | the Claude Code process (its `/proc/<pid>/cmdline` is `claude -p …`) | the Claude Code process (`claude --dangerously-skip-permissions`) |
| `CLAUDE_CODE_SESSION_ATTENDED` | `0` | `1` |
| `CLAUDE_CODE_ENTRYPOINT` | `sdk-cli` | `cli` |
| hook input keys | `cwd, effort, hook_event_name, permission_mode, prompt_id, session_id, tool_input, tool_name, tool_use_id, transcript_path` | — |
| `permission_mode` | `default` (manual) | — |

The hook process's parent is `/bin/sh -c <command>`, whose parent is the Claude Code process.
Hook stdin is not a terminal (`/dev/null` for the Claude process under `-p`).

What this gives the guard (A1.1, A1.2): the approval channel exists only when the process named by
`CLAUDE_PID` has none of `-p`, `--print`, `--permission-prompt-tool` on its command line, and
`CLAUDE_CODE_SESSION_ATTENDED` is `1` and `CLAUDE_CODE_ENTRYPOINT` is `cli`; anything else, or
anything unreadable, means no channel, so the guard denies instead of asking.

## 3. Delivery by `asyncRewake` reaches UserPromptSubmit (measured, interactive)

An interactive session (driven in `tmux`) with a SessionStart hook marked `asyncRewake` that waited
8 seconds, wrote `LRPROBE-DELIVERY-7f3a: a probe text delivered by an asyncRewake hook` to stderr
and exited 2. The session woke, and the UserPromptSubmit hook received, before the model answered:

```
Stop hook blocking error from command "SessionStart:startup": LRPROBE-DELIVERY-7f3a: a probe text delivered by an asyncRewake hook
```

with input keys `cwd, hook_event_name, permission_mode, prompt, prompt_id, session_id,
transcript_path`. A Stop hook then fired after the model's answer.

What this gives the guard (D1.1, D1.2): the delivery prompt passes through the guard's
UserPromptSubmit hook before the model sees it. The guard confirms the message there (DELIVERED)
and stops a copy whose message is already DELIVERED. Lunchroom's hooks do not set `onFailure`
(H1.5, so that a broken guard never locks the user out): a guard that fails or is missing lets the
call or the prompt through unchecked, which the README states as a limit (K1.9).
