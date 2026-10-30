# Codex adapter: host facts (measured 2026-10-26)

For the Codex adapter (spec §13 H1). Measured on Ubuntu 24.04 with codex-cli 0.163.0
(`codex --version`). Probes ran in a scratch
`CODEX_HOME` (`config.toml`: `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`, the
project folder trusted; `auth.json` a link to an existing login), with a recorder hook on every event that
wrote the input's field names and values, the environment's variable names, and the parent process
chain. Earlier facts: `docs/host-facts/claude-code-and-codex-2026-10-24.md` section 2.

## 1. Hooks and their trust (measured)

- Codex reads hooks from `<CODEX_HOME>/hooks.json` (the same `{"hooks": {"<Event>": [{"hooks":
  [{"type": "command", "command": …}]}]}}` shape as Claude Code's settings).
- A `codex exec` run with new hooks ran none of them. The interactive terminal showed "Hooks need
  review · 5 hooks are new or changed · Hooks can run outside the sandbox after you trust them",
  with "Review hooks", "Trust all and continue" and "Continue without trusting (hooks won't run)".
- After "Trust all and continue", `config.toml` held one section per hook,
  `[hooks.state."<path to hooks.json>:<event>:<group>:<hook>"]` with a `trusted_hash` (the
  `PreToolUse` entry also with `enabled = true`), and every hook then ran. The installer writes no
  such record; the user approves the hooks in `/hooks` (H1.4).
- The hash is Codex's own (`sha256:` over a normalised form of the hook; codex-rs
  `command_hook_hash`). No plain serialisation of the hook entry reproduced it here, and openai/codex
  issue 21615 warns that copying the normalisation breaks silently; the supported reader is the
  app-server's `hooks/list` (`currentHash`). So Lunchroom does not compute it. Instead it relies on
  what Codex guarantees: Codex runs only a hook whose current definition the user trusted. When
  Lunchroom's guard runs in a Codex session, Lunchroom records a fingerprint of that trusted guard
  (the `hooks.json` path, the hook's position and definition, and its `trusted_hash`), and the session
  counts as guarded only while the same fingerprint is still there.

## 2. Hook input (measured, interactive)

| Event | Fields |
|---|---|
| SessionStart | `session_id`, `cwd`, `transcript_path`, `permission_mode`, `model`, `source` (`startup`) |
| UserPromptSubmit | the above but `source`, plus `turn_id`, `prompt` |
| PreToolUse | `session_id`, `turn_id`, `cwd`, `tool_name` (`Bash`), `tool_input` (`{"command": …}`), `tool_use_id`, `transcript_path`, `permission_mode`, `model` |
| PostToolUse | PreToolUse's fields plus `tool_response` |
| Stop | `session_id`, `turn_id`, `cwd`, `transcript_path`, `permission_mode`, `model`, `last_assistant_message`, `stop_hook_active` |

- `session_id` is the thread id. `transcript_path` is
  `<CODEX_HOME>/sessions/YYYY/MM/DD/rollout-<time>-<thread id>.jsonl`. `permission_mode` was
  `bypassPermissions` under this configuration.
- Lunchroom tells a Codex hook from a Claude Code one by `turn_id` or a `rollout-` transcript name.

## 3. Processes and environment (measured)

- Each hook's parent process is the native `codex` process (`/proc/<pid>/cmdline` first word
  ending `codex`), under a second `codex` process and the `node` launcher.
- An agent's shell command runs under that same `codex` process, so `lunchroom send` finds the
  session a hook recorded by walking its own parent processes, as under Claude Code (I1.2).
- A hook's environment has no `CODEX_THREAD_ID`; it has `CODEX_HOME` only when the user set it.
- An agent's command's environment has `CODEX_THREAD_ID`, `CODEX_SESSION_ID`, `CODEX_VERSION`,
  `CODEX_HOME` and others. `lunchroom send` DENIES a command whose `CODEX_THREAD_ID` names another
  thread than the one its process shows.

## 4. Approval and YOLO (from the 2026-10-24 facts)

- A `PreToolUse` answer of `"ask"` fails open: the call runs. So Codex has no approval channel a
  hook can use; a call that needs the user is DENIED (exit 2) and kept for `lunchroom approve`
  (A1.2), and runs on its retry once the user approved that exact call.
- Lunchroom answers a call that goes ahead with nothing on Codex, never with a
  `permissionDecision` value. `lunchroom yolo` refuses a Codex agent: the adapter has not passed its
  test of starting and ending Codex's YOLO (R2.2), so nothing can set a Lunchroom YOLO for Codex in
  1.0. The guard's rule for a HELD Codex agent under one is built and tested (its ordinary calls run
  until the end time and its PROTECTED calls are still DENIED), and is not reachable until then.

## 5. Delivery (not measured)

`codex queue --thread <id> --message <text>` (stable since 0.149) puts a message into an existing
session. Delivery was read from source and documentation, not measured: no probe ran it, because
Lunchroom's own guard DENIES it to an agent as a fence. What is known:

- Lunchroom's earlier implementation delivered to Codex this way and confirmed delivery by finding
  the message id in the thread's rollout file.
- openai/codex issue 54991 (2026-10) reports that a queued message is user input: the terminal
  draws it as a prompt (`› text`, `role: "user"`).

So the adapter fails safe whichever way `UserPromptSubmit` behaves for a queued message: Lunchroom
HOLDS the Codex session by the message before it queues it, and counts the message DELIVERED when
either the guard's prompt hook sees its envelope or its id appears in the thread's rollout file.
The binary tests run this with a stand-in `codex` that records the queued text and writes the
rollout file. Not measured: whether the prompt hook sees a queued message.
