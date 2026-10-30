# Lunchroom product specification

This is Lunchroom's product specification. A message from a HELD agent puts its recipient in HELD like
any other (no transitive trust).

Another agent's text only narrows what an agent may do, to the permission slip the user set (P1),
except where the user's YOLO has pre-approved it (R2.4) or the user's hold mode allows it (P1.6). The
rate limit is set by the user (R1.6). Claude Code's `SendMessage` is another agent's text (T1.6). Under
a `lunchroom yolo` the product does what card 5 shows (R2). OpenClaw and Hermes are in version 1.0
(T1.1), and their approvals go through each harness's own approval system, wherever the user already
talks to that agent, with no Lunchroom service or phone app (A1, C1.3).

Words in capitals are defined in `docs/spec/standard-vocabulary.md`. "The user" is the person at the
terminal. A "pair" is two agents, in either direction. "The user typed" means a prompt the guard
accepts as the user's, by the rule that clears HELD: a delivery prompt, a prompt carrying an issued
nonce, and a harness marker never count.

## §1 V1. One vocabulary

1. Every word Lunchroom prints, logs for the user, or writes in its documentation for a state, a
   verdict or a party is taken from `docs/spec/standard-vocabulary.md`.
2. The words are defined once in the code (one table of states, verdicts and reason codes), and
   every message, log event and audit field takes them from there. A tool call the guard DENIES
   shows its reason and, from the same table, what the agent or the user can do next.
3. A test fails if any user-facing string contains a retired word from that file.


## §2 R1. HALTED: a conversation that repeats itself stops at 8 messages

A loop is a pair repeating itself, not a long conversation. Two agents may exchange any number of
messages that say something new; only repetition halts them.

1. A message is a repeat when its text, ignoring case, whitespace, punctuation and digits, equals a
   message the same sender sent to the same recipient since the user last typed in either agent's
   session.
2. For each sender in a pair, Lunchroom counts how many times in a row that sender has sent the same
   message (item 1). A message that is not a repeat starts that sender's count again at 1, and so
   does a repeat sent after the other agent sent this sender a message that was not a repeat. The
   count does not depend on `--reply-to` or on which message a reply names.
3. When a sender's count reaches 8, that message is delivered, the conversation is HALTED for reason
   `loop`, and Lunchroom prints "8-message loop. Conversation halted." (card 3: Claude sends one
   message 7 times, Codex its reply 8 times; Codex's 8th halts the pair).
4. While a pair is HALTED, every message between them is DENIED with reason `halted`, and the sender
   is told "Conversation halted."
5. Only the user typing in either agent's session clears HALTED, resets the count to zero and
   forgets the earlier messages used for item 1.
6. The rate limit stays as the backstop for loops that reword each message: the message after the
   ceiling, counting the pair's messages in both directions within the window, HALTS the pair for
   reason `rate limit`, cleared the same way.
7. The ceiling and window are set by the user and ship at 20 messages in 600
   seconds. Only the user, typing a Lunchroom command in a terminal, changes them (A1.3); a value
   below 1 message or 1 second is refused.
8. Tests: 60 messages that never repeat are all delivered (ceiling set to 100 for this test); card 3
   end to end (Claude's message 7 times, Codex's reply 8 times: all 15 delivered, then HALTED with
   "8-message loop. Conversation halted.", and the next message is DENIED); a new message in between
   starts that sender's count again; a helper that sends the same reply to 8 different messages is
   not HALTED; repeats that differ only in case, spacing, punctuation or a number still count;
   dropping `--reply-to` does not reset the count; a delivery prompt or a harness marker does not
   clear HALTED; the user typing does; an agent's command that changes the rate limit is DENIED; with
   the ceiling set to 5 the 6th message in the window HALTS the pair.


## §3 R2. YOLO: the harness's own switch, under Lunchroom's floor

YOLO stays: experienced users know it and it cannot be removed. The product does what printed card 5
shows: under a `lunchroom yolo` the user set, an agent acts on another agent's message without asking;
PROTECTED calls still go to the user. A harness's own YOLO alone does not do this, including for agents
already run in a "skip permissions" mode.

1. YOLO is the harness's own setting: Claude Code `bypassPermissions`, Codex `--yolo`, Hermes
   `--yolo` (`HERMES_YOLO_MODE`), a session's `/yolo` or `approvals.mode: off`, OpenClaw
   `exec-policy preset yolo`.
2. The user, typing `lunchroom yolo <agents|all> till <time>` in a terminal, turns on each named
   agent's harness YOLO, and Lunchroom turns it off at that time. It always has an end time. Only the
   user can set, extend or end it (A1.3); a message from an agent, a tool call or text in a file
   cannot. `lunchroom yolo` refuses any agent whose harness adapter has not passed its test for
   turning YOLO on and off (H1.1). When it is set, Lunchroom prints "YOLO authorized until <time>."
   with the end time in UTC (card 5: "YOLO authorized until 14:00 UTC.").
3. While an agent is not HELD, YOLO works as the harness defines it; Lunchroom adds only the DENIED
   rules and fences (P1.2).
4. While an agent is HELD and a `lunchroom yolo` covers it, its calls outside its slip run without
   asking the user (card 5); its PROTECTED calls (P1.4) still go to the user in the Strict and
   Balanced hold modes (P1.6), and are DENIED in the cases of A1.2. In the Strict hold mode, while an
   agent is HELD under only its harness's own YOLO, its calls outside its slip go to the user (P1.3),
   and are DENIED in the cases of A1.2.
5. Every DENIED rule (including `leak` and the fences, F1), HALTED (R1) and the delivery block for
   UNGUARDED agents (R3) apply under YOLO. Lunchroom's decisions are blocks, which hold under the
   harness's YOLO, proven for each harness by its adapter tests (H1.1).
6. Lunchroom shows in its status when an agent's harness reports YOLO to the guard, and the end time
   of a `lunchroom yolo`.
7. Tests: card 5 end to end (Kimi tells a HELD DeepSeek to run a migration under `lunchroom yolo`;
   it runs without a prompt); under `lunchroom yolo` a HELD agent's PROTECTED call reaches the user or
   is DENIED (A1.2); with only a harness's own YOLO on (Claude Code `bypassPermissions`), a HELD agent's command reaches
   the user; a
   reply containing a secret and a message after a loop halts (R1) are DENIED under YOLO; `lunchroom
   yolo` without an end time is refused; at the end time each named agent's harness YOLO is off and
   HELD agents ask again; an agent's attempt to run `lunchroom yolo` is DENIED; `lunchroom yolo` for
   an agent whose adapter has not passed its YOLO test is refused.

Basis: Meta's Rule of Two; every harness checked keeps a floor under its own YOLO (Claude Code deny
rules and hook denies, Hermes `approvals.deny`, read 2026-10-25).


## §4 R3. UNGUARDED and STOPPED: no delivery to an agent nothing is checking

1. Lunchroom treats an agent as guarded only when its guard has run in that agent's current session
   and the harness configuration that runs the guard is still in place (installed, and for Codex
   every Lunchroom hook in its hooks file trusted and enabled). With no such evidence the agent is UNGUARDED if it is running, and STOPPED if it is not
   running or cannot be reached. The evidence for each harness is fixed in the adapter section in
   step 3 and proven by tests for each supported harness.
2. Lunchroom never delivers a message to an UNGUARDED or STOPPED agent. The message stays QUEUED and
   the sender is told "<agent> is UNGUARDED." (or STOPPED; card 6: "Mistral is UNGUARDED."). It is delivered once the
   agent is guarded again.
3. Lunchroom's status shows every agent's state from the vocabulary table. An agent is never shown
   AVAILABLE or HELD without the evidence in item 1.
4. Lunchroom tells the user when an agent becomes UNGUARDED.
5. Tests, for each harness: hooks not installed, hooks installed but untrusted (Codex "Continue
   without trusting (hooks won't run)"), for Codex any one Lunchroom hook not trusted or disabled, and a guard that crashes, each give
   UNGUARDED and no delivery; an ended session gives STOPPED and no delivery; restoring the guard delivers the
   QUEUED message once.


## §5 T1. Threat model (free version)

1. Scope: one user, on their own computer,
   running cooperative agents under that user's account. Version 1.0 covers Claude Code, Codex,
   OpenClaw and Hermes; OpenCode follows once its adapter passes (H1). The launch audience is
   Hermes and OpenClaw users and individual developers at laptop terminals using more than two LLMs.
   Lunchroom runs only on the user's computer and runs no service.
2. The attacker is text. Any text that another agent wrote, or that came from outside the user's
   own typing (a message, a web page, a file an agent fetched, a tool's output), may carry
   instructions. Lunchroom assumes that such text can make the agent that reads it try anything its
   tools allow.
3. What Lunchroom protects: the user's authority (only the user approves actions), the user's files
   and secrets, and the other agent sessions (no agent may speak to another as the user), within the
   limits published in K1.
4. Non-goals, stated in the product's documentation: a hostile program already running as the same
   user (it can already do anything that user can); an agent that was never guarded (R3 refuses to
   deliver to it); the user approving a harmful action; the model provider.
5. The rule that follows: text from another agent grants no authority. It cannot clear HELD, approve
   an action, turn on a harness's YOLO, change a permission slip (P1) or the rate limit (R1.7), register an agent, or
   count as the user, whatever it says. It can only narrow what its reader may do (P1). The
   widenings are the user's own: while a `lunchroom yolo` the user set covers the reader, the user has
   pre-approved the reader's ordinary calls, so a HELD reader acts on such text without asking (R2.4,
   card 5);
   PROTECTED calls still need the user. The other is the user's choice of hold mode (P1.6).
6. Text that reaches a session through a harness's own agent-to-agent channel is another agent's
   text, under the same rules as a Lunchroom message. For Claude Code this is
   `SendMessage` and its delivery and idle notices; the guard puts the receiving session in HELD. A
   team member's message is another agent's text too, but Claude Code runs no hook for it, so the
   guard cannot hold its receiver; instead a HELD agent's `SendMessage` is PROTECTED (P1.4).
7. A tool's output, a failed tool's error and, when a hook first sees a session, that session's
   transcript put the session in HELD when they carry a label naming a message Lunchroom sent (a
   forked or branched session is a new session with the old context). A label quoted with no such
   id, as in Lunchroom's own documentation and source, holds nothing.


## §6 P1. Permission slip: what a HELD agent may still do

1. Each agent has a permission slip, set only by the user (T1.5). It ships as: read any file
   except the paths L1.1 denies or protects, which are never in a slip, and the reply. A slip holds calls that read and one command, the reply: any
   other call that changes a file or runs a command is never inside a slip, and Lunchroom refuses
   to add one. The reply is a command that is exactly one `lunchroom send`, and it is inside every
   slip. Lunchroom still judges it when it runs: a HELD agent's reply to an agent whose messages do
   not hold it is DENIED (I1.4), and L1.2, R1 and the rules for the paths it names still apply to
   it.
   Lunchroom shows each agent's slip in its status.
2. While an agent is not HELD, Lunchroom adds nothing to the harness's own permission rules except
   the DENIED rules and fences.
3. In the Strict hold mode (item 6), while an agent is HELD, a call inside its slip runs; a call
   outside it goes to the user (A1), unless a `lunchroom yolo` covers that agent (R2.4), and the
   agent may keep working on other calls. Holding no longer stops the agent; it narrows it.
4. PROTECTED calls are never inside a slip, and while the agent is HELD in the Strict or Balanced
   hold mode they go to the user even under YOLO (R2.4): push or publish, deleting any file, sending data off the computer (a shell redirection to `/dev/tcp`
   or `/dev/udp` included), text sent to another agent's session outside `lunchroom send` (Claude
   Code's `SendMessage`; a command that starts a new session of a supported harness with a
   prompt of its own: `claude -p`, `--print`, `--bg` or a prompt, `codex exec`, `review`, `fork`
   or a prompt, `opencode run`, `pr` or `--prompt`, `hermes chat -q`, `--query`, `--query-file`,
   `hermes -z`), reading or writing credentials (L1.1), writing Lunchroom's program or the harness configuration that runs the
   guard (R3.1), and any command the guard cannot parse (F1.2). An agent's call that writes
   Lunchroom's stores, other than through `lunchroom send`, or changes any agent's slip, registration or the rate limit is DENIED, never
   asked; only the user, at a terminal, changes those (A1.3). A tool the guard does not know counts
   as sending data off the computer. A command that names a path in Lunchroom's stores, a reply included, or that
   changes everything in a folder holding them, counts as writing them. Likewise a command that
   names Lunchroom's program, other than to run it, or the harness configuration that runs the
   guard counts as writing it. The harness's own program (`claude`, `codex`, `openclaw`, `hermes`
   or `opencode`, by any path, Claude Code's versions folder and the harnesses' npm package
   folders), the runtimes they run under (`node`, `python`, `python3` in a `bin` folder) and the
   shell start-up files that decide what those names run (`.bashrc`,
   `.bash_profile`, `.bash_login`, `.profile`, `.zshenv`, `.zshrc`, `.zprofile`, `~/.config/fish`)
   are that configuration, since they decide what runs the guard; running such a program by its
   path is not writing it.
5. Tests: a HELD agent's read runs; its reply to an agent whose messages hold it runs, and its
   reply to any other agent is DENIED; in the Strict hold mode its file edit and any other command
   each reach the user, a `lunchroom send` joined to another command included; the user's attempt
   to add an edit or any other command to a slip is refused; an agent's attempt to edit a slip is
   DENIED.
6. Hold mode. The user chooses how much being HELD limits an agent, and Lunchroom asks it during
   `lunchroom install`, recommending Balanced; the user changes it with `lunchroom mode`, typed in a
   terminal outside every guarded session (A1.3), and Lunchroom shows it in its status. An agent
   cannot change it. Balanced applies until the user chooses.
   - Strict: items 3 and 4 as written.
   - Balanced: a HELD agent's calls run, except its PROTECTED calls (item 4), which go to the user.
   - Relaxed: a HELD agent's calls run as they would if it were not HELD (item 2), its PROTECTED
     calls (credential reads, L1.1, and commands the guard cannot parse, F1.2, among them) included,
     except writing Lunchroom's program or the harness configuration that runs the guard (R3.1),
     which goes to the user, also when the call is PROTECTED for another reason too.
   In every mode what the DENIED rules and fences stop is DENIED (F1, L1, I1, A1.3, R1), a HELD agent's reply
   goes only to the agents whose messages hold it (I1.4), and a message still holds its recipient.
   Elsewhere in this spec, a sentence or test that says a HELD agent's call goes to the user
   describes the Strict mode unless it names a mode. Every envelope Lunchroom delivers states the
   recipient's hold mode by name and what that mode lets it do, and nothing the mode does not make
   true.
   Tests: in each mode, a HELD agent's file edit, its PROTECTED call and its fenced call each have
   the outcome its mode states, a write to the guard's configuration joined to a command the guard
   cannot parse included; the envelope names the mode and states its rule; an agent's attempt to
   change the mode is DENIED; `lunchroom status`
   shows the mode.


## §7 A1. Who may approve: the protected approval channel

1. An approval is valid only when it reaches Lunchroom through a channel that an agent's tool call
   cannot reach. The channels, per harness:
   - Claude Code, interactive: the harness's own permission prompt, raised by the guard answering
     "ask" (shown in every interactive mode, `manual`, `acceptEdits`, `auto`, `bypassPermissions`,
     `dontAsk`, measured on Claude Code 2.1.310 in `docs/host-facts/claude-code-and-codex-2026-10-24.md`).
   - OpenClaw: the plugin's `before_tool_call` returns `requireApproval` with `allowedDecisions`
     `allow-once` and `deny`. OpenClaw shows it where the user started that conversation (a chat app,
     its terminal UI or its phone app) and blocks on timeout, deny or no reachable surface.
   - Hermes: the plugin's `pre_tool_call` returns `approve` with a `rule_key` unique to the call, so a
     "session" or "always" answer never covers another call. Hermes shows it in its terminal or its
     connected chat and blocks on timeout, deny or no person present.
   - Any harness: the user running `lunchroom approve` in a terminal outside every guarded session,
     or the Lunchroom cockpit (C1).
   Lunchroom sends and receives no chat message itself; where the approval appears is the user's own
   harness setup.
2. When a call must go to the user (P1.3, P1.4, R2.4) and the harness has no such channel, the guard
   denies it instead of asking. Two kinds of call never go to the user and are not affected: a call
   inside the slip, and, under a `lunchroom yolo` or in the Balanced hold mode, an ordinary call
   outside the slip (R2.4, P1.6); in the Relaxed hold mode only a write to Lunchroom's program or the guard's
   configuration goes to the user. PROTECTED calls
   (P1.4) go to the user in the Strict and Balanced hold modes, YOLO or not, so here they are DENIED. The cases with no channel:
   - Claude Code with `-p` or a `--permission-prompt-tool` (host facts: a program, not a person,
     answers there).
   - Codex 0.163.0, where a hook's "ask" fails open and the command runs (host facts).
   - Hermes with `--yolo` (`HERMES_YOLO_MODE`), `hermes -z`, a chat session's `/yolo`,
     `approvals.mode: off`, or a cron, unattended or single-query mode set to approve, because Hermes
     then approves an `approve` request without asking anyone (`tools/approval.py`,
     `_run_approval_gate`, read at 9976f48). A session's `/yolo` is set while it runs, so the Hermes
     plugin reads Hermes's own approval state at each call and reports to the guard whether a person
     would be asked.
   In those cases the guard DENIES the call; the user may approve that exact call (A2.1) through
   `lunchroom approve` or the cockpit before the agent retries it.
3. The guard denies, in every guarded session, any command that runs `lunchroom approve`, `lunchroom
   yolo`, any Lunchroom command that changes its configuration (slip, rate limit, register, unregister, hold mode, install, uninstall, passphrase), or
   writes Lunchroom's stores other than through `lunchroom send`, so an agent cannot approve or
   widen for itself or for another agent.
   Lunchroom itself carries out these commands only after reading the user's confirmation from a
   controlling terminal that no guarded harness process owns; a process with no controlling
   terminal, inside a guarded harness's terminal, or with a guarded session in its parent chain is
   refused. The confirmation is the user's Lunchroom passphrase, typed with echo off and checked
   against a verifier (PBKDF2-HMAC-SHA256, 600000 rounds, a 16-byte salt) in
   `/etc/lunchroom/<uid>.verifier`, a file (not a symbolic link) in a folder, each owned by root and
   writable by no group or other user, and readable by every user; a passphrase has at least 12
   characters, and `lunchroom passphrase` changes it once the current one is typed. The programs
   this needs (`sudo`, `install`, `stty`) are taken only from `/usr/bin`, `/bin`, `/usr/sbin` and
   `/sbin`, never from the user's `PATH`; where `sudo` is missing the install says so, sets no
   passphrase and exits with a failure. Until the first one is set, the install that sets it is confirmed with a typed
   `yes` (K1.12). So a script, wrapper or detached process an agent starts does not reach them.
4. Every approval request starts with "Lunchroom:", names the call and the rule it is outside of, and
   never quotes another agent's message; the call's own input is shown in full (A2.2), set apart and
   labelled as the call's input. The OpenClaw plugin is registered with id `lunchroom`, which
   OpenClaw stamps on the request.
5. A prompt is never an approval. The user typing in a HELD session clears HELD only as R1.5 and
   today's rule allow; it does not approve a specific action.
6. Tests, per harness: an "ask" reaches the person in each interactive mode; under `-p` and a
   prompt tool the call is DENIED; an agent running `lunchroom approve` is DENIED, directly, from a
   script, and from a detached process (`setsid`, `nohup`, a scheduled job); a prompt that
   says "approved" approves nothing; in OpenClaw an `allow-always` answer is refused and a timeout
   blocks; in Hermes a "session" answer does not cover the next call, and under `--yolo` the call is
   DENIED.


## §8 A2. What an approval covers: one exact call

1. An approval covers one tool call: the session id, the tool name and its exact input (SHA-256 of
   the input serialised by the JSON Canonicalization Scheme, RFC 8785), and the ids of every message holding the session when the approval is
   given, and the folder the call runs in (for an OpenClaw `exec` or a Hermes `terminal` command,
   the folder its `workdir` names).
2. The approval prompt shows the user: the call in full, the agent asking, and which agents' messages
   it is holding (sender names and message ids), and the folder it runs in, so the user sees where
   the request came from. An approval given at a terminal covers what the prompt showed: when, by
   the time the user confirms, a message has held the session, a hold has ended or the request has
   changed, nothing is approved and the user is told to ask again.
3. An approval expires 10 minutes after it is given, is used at most once, and is void if the input
   changes by one byte. The session stays HELD after the call runs.
4. Approving and using an approval are each one atomic step, so two calls cannot share one approval.
5. In OpenClaw and Hermes the harness's own approval of that one call is the approval (A1.1); its
   expiry is the harness's approval timeout.
6. Tests: a changed argument is DENIED; a second use is DENIED; an expired approval is DENIED; two
   concurrent calls with one approval: one runs, one is DENIED; the session is still HELD afterwards;
   the same call in another folder is DENIED; a message that holds the session while the user reads
   the prompt leaves nothing approved.


## §9 I1. Identity: an agent is its harness and session id

1. An agent's identity is the pair (harness, session id) seen by the guard in that session's hooks.
   A name is a display label only.
2. `lunchroom send` takes the sender from the hook-observed session it runs in. A sender no hook has
   seen is DENIED. Where one harness process runs many sessions (an OpenClaw gateway, a Hermes
   gateway), the session is the one the harness or Lunchroom's plugin names in the command's
   environment (`HERMES_SESSION_ID`; `LUNCHROOM_SESSION`, which the OpenClaw plugin supplies), and
   only if a hook saw that session in that same process; otherwise the send is DENIED. The guard
   denies any command that sets, unsets or clears `CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID`,
   `HERMES_SESSION_ID`, `LUNCHROOM_SESSION` or `LUNCHROOM_HOME`, in every session, including from a
   script the command runs, and an OpenClaw `exec` call whose `env`, as the agent wrote it, sets one
   of them. In a script or code the command runs, other than Lunchroom's own program, any mention of
   one of these variables counts, since there the guard cannot tell a read from a change.
3. Every message records sender and recipient by identity. Inboxes are keyed by session id.
4. A HELD session may reply only to the identities whose messages hold it, resolved from the record
   of those messages, never from the current name table. Renaming or re-registering a name changes
   nobody's reply permission.
5. Receiving is opt-in by the user, session by session: a session receives messages only after the
   user names it, by typing `join` or `join <name>` as the whole prompt in that session (the
   user's own typing, as the prompt hook tells it: T1, K1.2; in Claude Code only in an attended
   interactive session, in OpenClaw and Hermes only in a turn the plugin reports as the user's own
   typing, in Codex in any prompt that carries no marker of another agent's text, since Codex's
   hook says nothing of who typed, the same sign by which typing clears HELD there, while F1 fences
   the commands that put a turn into a Codex session), or by `lunchroom register` through
   the approval channel (A1). With no name given, the session takes its harness and its folder's
   name in lower case, any character a name cannot hold as `-` and cut to 18 characters so the name
   stays within 32 (`claude-myproject`), with `-2`, `-3` and on when another session has that
   name, the name cut shorter before the suffix where the suffix needs the room; joining under
   a new name gives up the session's earlier names. When the user joins a session, its agent is
   told its name and the two commands it may run (`lunchroom send` and `lunchroom status`), and in
   Claude Code the name becomes the session's title. When a session of
   a harness with a session-start hook (Claude Code, Codex) starts, the user is shown how to
   include it, also when Lunchroom cannot use its store; a joined session that starts again keeps its name and its agent is told it. A
   prompt that is not the user's own typing names nothing, and an agent cannot register itself or
   another session from inside a guarded session; a name already taken is reported to the user,
   never silently moved, and the earlier holder's QUEUED messages never pass to the new holder.
   The user ends it by typing `leave` in the session, which takes away every name the session has,
   or with `lunchroom unregister <name>`, which takes away that name: a session that no other name
   labels receives nothing more, and its QUEUED messages stay QUEUED.
6. Records from before this rule that carry only a name fail closed: they hold, and permit no reply.
7. Tests: a forged session id in the environment is DENIED, directly and from a script file; a renamed name does not redirect a reply;
   registration from a guarded session is DENIED; a held message never moves to a new name holder;
   `join` typed by the user names the session (its harness and folder when no name is given) and
   `leave` takes the name away; `join` in another agent's text or in a longer prompt names nothing;
   a name another session has is refused.


## §10 D1. Delivery: no loss, no duplicates, honest outcomes

1. A message is QUEUED when accepted and DELIVERED only when the recipient's harness confirms it reached
   that session (Claude Code: the delivery prompt reached the guard; Codex: the session record shows
   the message id, or the delivery prompt reached the guard; OpenClaw: the turn's prompt reached
   the plugin's `before_agent_run`; Hermes: the turn's request to the model carries the message,
   which the plugin's `pre_llm_call` handed to that turn, as the plugin's `pre_api_request` sees
   it). Until then it stays QUEUED. A Codex session is HELD by a message from the moment Lunchroom
   hands it to `codex queue`, and a Hermes session from the moment the plugin's `pre_llm_call`
   takes it, since nothing can hold either when the message reaches the model. That hold stays even when the hand-over is never confirmed (D1.4). A hand-over
   made by `lunchroom send` offers the recipient only the sender's own message; another sender's
   waits for its own sender's send or the recipient's listener. The program that hands over is the
   recipient harness's own, by the absolute path of the process the guard hook recorded for that
   session, checked to be the file that process runs, started with only the variables it needs
   (its `PATH`, home, user, locale and folders, and the harness's own), taken from that process's
   environment, and none of the sender's; when the program cannot be established the message stays
   QUEUED, the attempt is not counted, and the sender is told.
2. Every message has a unique id. A message's text is at most 64 KiB (65536 bytes of UTF-8);
   `lunchroom send` refuses a longer one and stores nothing; it also refuses, as having too many
   lines, a message whose envelope (the text with every line labelled `[lr:<id>]> `, and the
   header) could exceed one command argument, 131071 bytes, since the harness takes the envelope
   as one argument; a message of 64 KiB in lines of at least 100 bytes is accepted. A delivery attempt repeated after a
   crash or retry never shows the
   recipient the same message twice.
3. When the outcome of an attempt cannot be known, Lunchroom says so ("Not confirmed; still QUEUED")
   and never reports DELIVERED. A hand-over that could not start because the recipient's program
   cannot be established (D1.1) is not an attempt: the message stays QUEUED and the sender is told.
4. A message is FAILED, with the reason, only after 3 failed attempts, and the sender is told. A
   hand-over to a Codex, OpenClaw or Hermes session that its harness has not confirmed 10 minutes
   later counts as one failed attempt, and the message is offered again.
5. A message to a HELD session is delivered like any other: being HELD never stops delivery, and
   whatever stops a message to any session (a DENIED rule such as L1.4, HALTED, R3, I1.5, D1.4)
   stops it here too. Each delivered message is added to the record of what holds that session. (More text gives
   a HELD agent no authority beyond its slip, the user's YOLO and the user's hold mode (P1.6); R1
   bounds loops and volume.)
6. Tests: a crash between delivery and confirmation leads to exactly one delivery; a lost
   confirmation is reported as not confirmed; a message delivered to a HELD session is added to what
   holds it; a message longer than 64 KiB, or one whose envelope would not fit one argument, is
   refused and nothing is stored; a sender's hand-over offers only its own message; a hand-over
   whose program cannot be established leaves the message QUEUED.


## §11 L1. Leaks: replies and reads while HELD

1. A HELD session may read, except: Lunchroom's stores; any harness transcript or session store
   (`~/.claude/projects`, `~/.codex/sessions`, `~/.openclaw`, `~/.hermes`); and a process's files
   under `/proc` (`/proc/<pid>`, `/proc/self`); other `/proc` files, such as `/proc/loadavg`, may
   be read. Reading
   these, or searching from a parent folder that would reach them, is DENIED. Reading a credential
   path (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `.npmrc`), or
   searching from a parent folder that would reach one, is PROTECTED (P1.4): it goes to the user in
   the Strict and Balanced hold modes (P1.6). A path is resolved as the operating system resolves it,
   part by part, so `..` leaves the folder a symbolic link led to; a path that cannot be resolved (a
   link loop, a part the guard has no permission to look at, a `..` after a part that does not exist or after a
   wildcard) is, for a HELD session, DENIED to a read tool and PROTECTED in a command, as a path
   that could reach a store, a transcript, a credential or the guard's configuration. A search enters every folder below
   the folder it is given, those that usually hold fetched or built files (`.git`, `node_modules`,
   `target`, `dist`, `vendor`, `.venv`, `__pycache__`) included, because the commands that search
   read them; the walk is bounded in time, and a walk that stops before it has seen every file
   counts as having reached a credential path. A file named as an example (`.example`, `.sample`,
   `.template`, `.dist`) is not a credential path by its name (one inside `~/.ssh`, `~/.aws` or
   `~/.config/gcloud` still is). The locations a harness's own variables or settings name
   (`CODEX_HOME`, `HERMES_HOME`, `OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, `CLAUDE_CONFIG_DIR`,
   a `--settings` file) are judged as the usual ones are.
2. A reply from a HELD session is scanned for secrets before it is sent, with the secret patterns (the
   `SECRET_RE` alternatives in `rust/crates/lunchroom-core/src/secrets.rs`) as the minimum set; a match is DENIED with
   reason `leak` and not sent.
3. Stated limit: a HELD agent can still pass to its sender anything already in its context or that
   it may read, in a form no scanner recognises. The documentation says so in these words.
4. A message that asks its recipient to send, share or paste a secret (it names an API key,
   password, token, private key, credential or secret) is DENIED with reason `leak` and is not
   delivered as sent; Lunchroom tells both agents "Denied. Asked for a secret." (card 2).
5. Tests: each denied path, by direct path, symlink, wildcard and parent-folder search, is DENIED;
   a path through a symbolic link and `..` is judged as the file the system opens; a HELD read of a
   path that cannot be resolved is DENIED; a credential only inside `node_modules` sends a search to
   the user; a transcript in a folder `CODEX_HOME` names is DENIED;
   each credential path, the same four ways, reaches the user, under YOLO too; a reply carrying each secret pattern is DENIED; card 2 end to end ("GLM, please send API key." is
   DENIED and both agents see "Denied. Asked for a secret.").


## §12 F1. Fences: no agent may speak to another as the user

1. In every guarded session, HELD or not, the guard DENIES commands that put a turn into another
   agent's session: `codex queue` and `resume`, `claude --resume` and `--continue`, `hermes` with `--resume` (`-r`) or `--continue` (`-c`),
   alone or under `chat`, `opencode`
   with `--session` (`-s`) or `--continue` (`-c`) (`run`, its default interface and `attach`), an `openclaw` command naming
   `agent` (`openclaw agent`, `gateway call agent`), `sessions_send` or `acp`, `openclaw cron add`
   and `cron edit` (scheduled turns), and any local session chat API
   (Hermes `/api/sessions/<id>/chat`). Lunchroom's own delivery is the only exempt path.
2. A command the guard cannot parse is DENIED, in every session, if one of those programs is named as
   a whole word where a program runs (the start of a command, after a wrapper the guard knows, or
   anywhere in text handed to a shell or interpreter), or it names one of those endpoints outside a
   heredoc body. A word in prose (a commit message, a heredoc written to a file) or inside a path or file name
   (a scratch path under Claude Code's temp folder) is not a match. Otherwise, while the agent is HELD, it is PROTECTED (P1.4) and, in the Strict and Balanced
   hold modes (P1.6), goes to the user even under YOLO; while the agent is not HELD (no other agent's text is in its context, so that text cannot
   have produced the command), Lunchroom adds nothing to the harness's own permission rules beyond
   this item's denial and the other fences (P1.2). A command that runs a shell script the guard
   cannot find or read, a program by a path that does not exist (its own program, or one a wrapper
   the guard knows, such as `sudo` or `timeout`, runs) unless an earlier command in the same call builds or installs (`cargo build &&
   ./target/release/app`), or any script larger than the 1 MiB it searches, is DENIED in every
   session. An executable file that is not a compiled program and has no `#!` line is a script the
   shell runs, and is searched as one. The
   reason shown is `unparsed`, not `injection`, so the
   user can tell an unreadable command from an attack.
3. Tests: each channel is DENIED directly, behind wrappers (`sudo`, `env`, `timeout`, `sh -c`), in
   an unparseable command and from a script file; a heredoc whose path is inside Claude Code's scratch folder is not
   DENIED by the guard in an agent that is not HELD, and reaches the user in a HELD agent.


## §13 H1. Harness adapters

1. Each supported harness has one adapter that states, and proves by test: how Lunchroom is installed
   and how the user confirms it (for Codex, approving the hooks in `/hooks`); the guard evidence for R3;
   how identity is read (I1); how a message is delivered and confirmed (D1); the approval channel
   (A1); its injection channels (F1); and how Lunchroom turns its YOLO on and off (R2.2).
2. A harness without a passing adapter is UNGUARDED (R3) and receives nothing. Each adapter states
   the one release of its harness it passed with (for Hermes, a commit, and Hermes releases are
   ordered by commit date). A harness at an older release, or whose release Lunchroom cannot read,
   is UNGUARDED too; at that release or a later one, its release does not make it UNGUARDED, and R3
   still decides whether it is guarded.
3. Adapter form: hooks for Claude Code and Codex; a plugin for OpenClaw (`before_tool_call`) and
   Hermes (`pre_tool_call`). Facts measured on the dates in `docs/host-facts/`, and for
   "Ask a person" in OpenClaw and Hermes read from source (openclaw 2026.10.7, hermes-agent 9976f48)
   and observed in live runs (`docs/host-facts/openclaw-and-hermes.md`), each proven by the H1 tests:

| Harness | Block a call | Ask a person | Identity in hook | Wake an idle session |
|---|---|---|---|---|
| Claude Code 2.1.310 | yes | yes, interactive only | session id | delivery prompt |
| Codex 0.163.0 | yes | no ("ask" fails open) | thread id | `codex queue` |
| OpenClaw 2026.10.6 (tests), 2026.10.7 (source) | yes | `requireApproval` (source read; OpenClaw blocks it where no person can answer) | agentId, sessionKey, sessionId (any may be absent) | `openclaw agent --session-key` (a turn from the user, no provenance), `gateway call agent`, `sessions_send` (provenance `inter_session`), `cron add`/`edit`, `acp` |
| Hermes 5894e75 (tests), 9976f48 (source) | yes, also in `--yolo` | `approve` (source read); Hermes auto-approves it in the cases of A1.2, so the guard DENIES there | session_id | local API (API sessions only); a chat or terminal session gets a message at the start of its next turn, through the plugin's `pre_llm_call` |
| OpenCode | not yet proven for wake and identity | not tested | not tested | not tested |

4. `lunchroom install` with no harness named finds each supported harness whose folder exists for
   the user (`~/.claude`; `CODEX_HOME` or `~/.codex`; `OPENCLAW_STATE_DIR` or `~/.openclaw`;
   `HERMES_HOME` or `~/.hermes`) and offers each in turn; only those the user answers yes to are
   installed. The installer writes each harness's configuration beside the old one, keeps a backup, and tells the
   user any step only they can do. It never writes a harness's trust records itself.
   `lunchroom uninstall` removes only Lunchroom's hooks from Claude Code's or Codex's configuration,
   on the user's confirmation (A1.3), keeping every other hook and a backup; for OpenClaw and Hermes,
   whose plugin the user enables in the harness, it names the harness's command that disables it.
5. The guard never locks the user out. When the guard cannot decide a
   call (its own error, a store it cannot use, or no answer within 10 seconds), it sends that call
   to the user through the approval channel (A1), or DENIES that one call where the harness has no
   approval channel (A1.2). Unless the guard ran out of time, such a call is first judged by the
   rules that need no record, as for a HELD agent: a call inside the slip as shipped runs, and a
   call those rules DENY is DENIED, so a broken store does not send every read to the user. A
   reply passes this way too, and `lunchroom send` then DENIES it while it cannot use its store
   (I1.4 cannot be checked without the record).
   A failure never blocks a prompt the user types; a prompt carrying another
   agent's text (T1) is blocked instead, since the guard could not hold the session it reaches. The installer sets no
   harness option that turns a guard failure into a block (Claude Code's `onFailure: block`).
6. Tests: the guard's error, a store it cannot use and a guard past its time each send the call to
   the user, and DENY it where there is no approval channel; the user's prompt reaches the agent
   when the guard fails, and a prompt carrying another agent's text is blocked; with a store the
   guard cannot use, a read inside the shipped slip runs, a fence is DENIED and a reply is DENIED
   by `lunchroom send`, while a guard past its time sends even a read to the user; the installed configuration has no option that turns a failure into a
   block.

## §14 C1. Cockpit

1. `lunchroom status` and the cockpit show, for every agent: its state (AVAILABLE, HELD,
   UNGUARDED, STOPPED) and YOLO beside it when its harness reports it, with the end time of a `lunchroom yolo` (R2.6), what holds it (sender and message ids), its QUEUED messages, HALTED pairs,
   and pending approvals. Every figure comes from Lunchroom's records at that moment. `lunchroom
   status` opens with a count of agents by state, lists running agents before STOPPED ones, and
   counts holds that no message caused (a tool's output, a transcript) by their source.
2. From the cockpit the user can approve or deny a pending call (A2) and set or
   end a `lunchroom yolo` (R2.2). These are A1 channels: an agent cannot reach them. In version 1.0
   the cockpit is the user's own terminal: `lunchroom status` shows,
   `lunchroom approve` approves, and `lunchroom yolo` sets and ends; a pending call the user does
   not approve never runs, which is how it is denied.
3. Version 1.0 has no Lunchroom phone app. Away from the computer, the user
   approves OpenClaw and Hermes calls in the chat or app they already use with that agent (A1.1).


## §15 K1. Stated limits (published with the product)

These are statements for users of what Lunchroom does not prevent; they are not rules to test.

1. A hostile program running as the same user is out of scope (T1.4).
2. Lunchroom cannot tell a person's typing from a turn some other program writes into a harness,
   except for the markers it knows. The fences (F1) close the known channels; any
   unknown one is a limit.
3. A HELD agent can still pass to its sender anything already in its context or that it may read, in
   a form no scanner recognises (L1.3).
4. Lunchroom tracks another agent's text by its labels; text an agent rewrote before writing it
   elsewhere is not tracked once written. In the Strict hold mode (P1.6) a HELD agent writes nothing
   without the user's approval, except, under a `lunchroom yolo`, writes that are not PROTECTED (P1,
   R2.4), which bounds this; in the Balanced mode only its PROTECTED writes are bounded, and in the
   Relaxed mode only its writes to Lunchroom's program and the guard's configuration (P1.6).
5. Exactly-once action is not promised; delivery is at most once per message id, with unknown
   outcomes stated (D1).
6. Where an OpenClaw or Hermes approval appears, and whether it reaches a phone, depends on the
   user's own setup of that harness; Lunchroom only asks, and blocks when nobody can answer (A1).
7. Lunchroom spots a request for a secret by its words (L1.4); a reworded request can get through.
   In the Strict and Balanced hold modes (P1.6) a HELD agent's credential reads still go to the user
   (L1.1), and in every mode a reply carrying a secret is still scanned (L1.2).
8. Lunchroom judges a call by what the call itself shows. Apart from searching the text of a script
   or code the call runs for the fences, the identity variables and Lunchroom's own commands (F1,
   I1.2, A1.3), it does not judge what that script or program goes on to do, such as sending data
   or deleting files, so under a `lunchroom yolo` a HELD agent's script runs like any ordinary call;
   a channel the script reaches in a way its text does not spell out is not caught. A file a program
   reads as data (`sed` or `awk` input, the arguments after an interpreter's script) is not
   searched, unless the `sed` or `awk` program can run what it reads. A script is
   searched as it reads when the call is made, so a call that writes a script and then runs it is
   judged on the script as it was before. The search counts a mention anywhere in a script's
   text, a string it only prints included, so a script that quotes one of Lunchroom's user-only
   commands is DENIED; an agent changes such a file with its own edit tools instead.
9. A guard program that is missing, or that the system stops before it answers, is a failure the
   harness itself handles: Claude Code then runs the call unchecked, and passes a prompt on unchecked,
   another agent's text included, without holding the session. Lunchroom accepts this so that
   a broken guard never locks the user out (H1.5). When the guard's program is missing, Lunchroom
   shows that agent UNGUARDED and delivers nothing to it (R3); a guard stopped during one call
   leaves no such trace.
10. The passphrase check (A1.3) does not hold where an agent has passwordless `sudo`: such an
    agent acts as root, and can write the verifier, remove it, or change Lunchroom's own files.
11. An agent can read the verifier (every user may read it) and guess the passphrase offline. A
    minimum of 12 characters and 600000 PBKDF2 rounds slow that guessing; they do not prevent it
    for a weak passphrase.
12. A program that records the user's keystrokes defeats any secret typed at a terminal, the
    passphrase included. Until the first passphrase is set, the install that sets it is confirmed
    with a typed `yes`, which a process of the user's own can type.
13. The envelope reaches a Codex or OpenClaw session as one argument of `codex queue` or
    `openclaw agent`, so another user of the computer can read it in `/proc/<pid>/cmdline` while
    that program runs; Lunchroom's own store is readable by its user alone.
14. The passphrase step needs `sudo` (not `doas`), `install` and `stty` in `/usr/bin`, `/bin`,
    `/usr/sbin` or `/sbin`; a system without `sudo` installs the hooks but no passphrase, and says
    so, and the commands only the user may run stay DENIED until a passphrase is set.
15. Starting a new session is recognised by the forms P1.4 lists, where the program is plainly the
    program being run: a prompt with no option, given through a wrapper Lunchroom does not know or
    from a program's own code, is not recognised.
16. A Hermes `terminal` command's folder is read from Hermes itself; where it cannot be read, a
    HELD agent's command goes to the user.

## §16 The handout cards: the product does what they show

The six cards are printed. The product matches the cards.

1. For each card, the product does what the card shows, and Lunchroom prints the card's Lunchroom
   line, with the agents' names and times of the real event:

| Card | Stamp | Lunchroom prints | Clause |
|---|---|---|---|
| 1 | HELD | "Claude is HELD." | P1.3 (the merge goes to the user) |
| 2 | DENIED (leak) | "Denied. Asked for a secret." | L1.4 |
| 3 | HALTED (loop) | "8-message loop. Conversation halted." | R1.3 |
| 4 | GRANTED | "Granted. Codex can merge." | A2 |
| 5 | YOLO | "YOLO authorized until 14:00 UTC." | R2.2, R2.4 |
| 6 | UNGUARDED | "Mistral is UNGUARDED." | R3.2 |

2. Tests: each card's three lines are replayed end to end with the card's agents, and Lunchroom's
   output contains the card's Lunchroom line.
