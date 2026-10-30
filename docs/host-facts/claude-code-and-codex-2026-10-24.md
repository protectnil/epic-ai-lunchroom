# Host facts measured on 2026-10-24: a hook's "ask" in Claude Code and Codex

Measured on Ubuntu 24.04 with Claude Code 2.1.310 and codex-cli 0.163.0. Every probe ran in a scratch folder; Claude Code
probes loaded only a test settings file (`--setting-sources project --settings <file>
--strict-mcp-config`), Codex probes used a scratch `CODEX_HOME`. The probe was
`touch <scratch>/out/lr-marker-<case>`, and a test PreToolUse hook answered "ask" for it. The
marker file existing afterwards means the command ran.

## 1. Claude Code: a hook's "ask"

2.1.310 offers the modes `manual` (reported to hooks as `default`), `acceptEdits`, `auto`,
`bypassPermissions`, `dontAsk` and `plan`.

| Path | Result | Marker |
|---|---|---|
| Interactive, `manual` | Prompt shown: "Hook PreToolUse:Bash requires confirmation for this command" | not created (answered No) |
| Interactive, `auto` | Same prompt | not created |
| Interactive, `bypassPermissions` | Same prompt | not created |
| Interactive, `acceptEdits` | Same prompt | not created |
| Interactive, `dontAsk` | Same prompt | not created |
| `-p`, each of the five modes | Denied; `permission_denials` has 1 entry | not created |
| `-p --permission-prompts none` | Denied | not created |
| `-p --permission-prompt-tool` (tool answers deny) | The tool was called; denied | not created |
| `-p --permission-prompt-tool` (tool approves), `manual` | The tool was called; **command ran** | **created** |
| same, `bypassPermissions` | **command ran** | **created** |

What follows for approvals:

- In every interactive mode the "ask" reaches the user's prompt, which offers "Tab to amend".
- With `--permission-prompt-tool`, whatever program answers that tool approves the "ask"; the user
  is not involved. The tool receives `tool_name`, `input` and `tool_use_id`, but not the hook's
  reason text.
- `plan` mode was not measured.

## 2. Codex 0.163.0

| Probe | Result |
|---|---|
| PreToolUse returns `permissionDecision: "ask"` (`exec`, and the interactive TUI) | **Fails open.** The TUI shows "Hook failed └ PreToolUse hook returned unsupported permissionDecision:ask", and **the command ran** (marker created). |
| PermissionRequest, `-a on-request -s workspace-write`, TUI | Fires only when the model asks to run outside the sandbox. Its `tool_input` carries a `description` field holding the reason the model wrote. With no hook answer, the user saw "Would you like to run the following command?" |
| PermissionRequest hook answers with approval | **The escalated command ran with no prompt to the user** (marker created). |
| `codex exec` approval policy | The run header always showed `approval: never`, even with `-c approval_policy="on-request"`. |
| Measured configuration | `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`. PermissionRequest never fires under this configuration. |
| Shell tool payload | `tool_name: "Bash"`, `tool_input: {"command": "<string>"}` in both `exec` and the TUI. |
| `-a` values accepted | `on-request` and `never` only (`untrusted` is rejected). |

What follows: on Codex, a hook cannot ask the user. "Ask" fails open, so the guard DENIES (exit 2)
what would go to the user. The only approval surface is PermissionRequest, which fires only on
sandbox escalation, cannot happen under the measured configuration, and a hook can answer it in
the user's place.
