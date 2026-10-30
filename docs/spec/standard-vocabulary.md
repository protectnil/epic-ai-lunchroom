# Lunchroom standard vocabulary

One word per meaning, the same in the code, log events, messages, the README, the instructions Lunchroom gives agents,
the website and the handout cards. Requirement V1 in `docs/spec/lunchroom-spec.md` makes this
binding on the product.

## States, verdicts and parties

| Applies to | Word | Meaning |
|---|---|---|
| Agent | AVAILABLE | Its guard is running and no other agent's text is in its context; it works normally. |
| Agent | HELD | Another agent's text is in its context. What it may still do depends on the hold mode (`lunchroom mode`): in Strict, only what its permission slip allows, or, while a `lunchroom yolo` covers it, any call that is not PROTECTED; in Balanced, any call that is not PROTECTED; in Relaxed, any call except a change to Lunchroom's program or the guard's configuration. DENIED and HALTED rules always apply. |
| Agent | YOLO | The agent's harness is set to stop asking the user: by its own switch, or by the user's `lunchroom yolo` until a stated time. Under a `lunchroom yolo` a HELD agent acts without asking; the harness's own switch alone does not free a HELD agent in Strict. In Strict and Balanced, PROTECTED calls still come to the user; DENIED and HALTED rules always apply. |
| Agent | UNGUARDED | It is running, but its guard is not, so nothing it does is checked. |
| Agent | STOPPED | It is not running, or Lunchroom cannot reach it. |
| Conversation | HALTED | Lunchroom stopped the conversation between two agents (reason: loop, rate limit). |
| Message | QUEUED | Accepted and waiting for the recipient. |
| Message | DELIVERED | The recipient has it. |
| Message | FAILED | It could not be handed to the recipient for a technical reason, and was not sent. |
| Call or send | GRANTED | It goes ahead (approved by the user, or allowed by the rules). |
| Call or send | DENIED | A rule stopped it; the reason is always shown (for example: leak, fence, loop, rate limit). |
| Call | PROTECTED | A kind of call that is never inside a permission slip and that a HELD agent makes only with the user, even under YOLO, in the Strict and Balanced hold modes (push or publish, delete, send off the computer, read or write credentials, write Lunchroom's program or guard configuration, unparseable commands, a tool Lunchroom does not know, text sent to another agent's session outside `lunchroom send`, starting a new agent session; spec P1.4). |
| Person | the user | The person at the terminal. Never "the human" in product text. |

A reason is a small label beside the word, never a different word: `DENIED · leak`,
`HALTED · loop`.

## Words that are retired

| Retired | Use instead | Where it would otherwise appear |
|---|---|---|
| bus | Lunchroom | the program's name, its folder, message envelopes and labels |
| locked, lock (of a session) | HELD | guard messages and comments |
| tainted, `TAINTED` | HELD | `status` output |
| refused, refusing, `REFUSED <id>` | DENIED | send and guard messages |
| NOPE | DENIED | the printed cards |
| allowed, allow | GRANTED | log fields such as `allowed=` |
| pending | QUEUED | `status` output `pending=` |
| human | the user | messages and the envelope |
| AUTO | YOLO | the printed cards |
| LOOPING | HALTED · loop | the printed cards |
| down, off, inop | UNGUARDED or STOPPED | rejected as ambiguous |

The product takes these words from one table (`rust/crates/lunchroom-core/src/vocab.rs`, which also
lists the retired words), and its test suite fails on a retired word in anything it prints. Internal
identifiers that never reach a person (function names, file names, log event names stored under
older names) may keep their names. Anything printed, logged for the user or written in documentation
uses this table.
Names that belong to another program (a harness's hook fields, settings and decisions, such as
OpenClaw's `requireApproval` or Claude Code's `permissionDecision: "allow"`) are quoted as that
program spells them, in code type, and that program's documentation is quoted as written, in
quotation marks; the words around them follow this table.

## Writing rules for product text

- A model or agent is named the way its maker writes it: Claude, Codex, Kimi, GLM, DeepSeek,
  Mistral.
- Models speak plainly in examples; no slang.
- No vendor logos, colours or fonts.
