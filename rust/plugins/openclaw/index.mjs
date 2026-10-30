// Lunchroom's OpenClaw plugin (spec §13 H1; host facts docs/host-facts/openclaw-and-hermes.md).
//
// It hands each OpenClaw event to Lunchroom's guard program and turns the guard's answer into
// OpenClaw's: a call that goes ahead returns nothing; one that goes to the user returns
// `requireApproval` (OpenClaw blocks it where no person can answer); a DENIED call returns
// `block`. The guard answers within its own deadline; a guard that cannot decide, its program
// missing included, sends the call to the user, or DENIES it where nobody can answer (H1.5); the
// user's own typing is never blocked.
// `before_agent_run` and `agent_end` run only with `hooks.allowConversationAccess: true` for this
// plugin in `openclaw.json`; without it Lunchroom counts the session UNGUARDED and sends it nothing.
// `lunchroom install openclaw` writes this file with the program's path in place of the marker.

import { spawn } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PROGRAM = "__LUNCHROOM_PROGRAM__";
// The guard answers within its own 10-second deadline (H1.5); this limit is reached only when the
// system stops the guard before it answers.
const DEADLINE_MS = 12000;
const PLUGIN_FILE = fileURLToPath(import.meta.url);

// OpenClaw's own version (H1.2): the `openclaw` package's package.json above the gateway's entry
// script (the package's bin is `openclaw.mjs` at its root). Empty when it cannot be read, which
// Lunchroom counts as a version its adapter was not built for.
export function openclawVersion(entry = process.argv[1]) {
  try {
    let dir = dirname(realpathSync(entry));
    for (let i = 0; i < 8; i += 1) {
      const file = join(dir, "package.json");
      if (existsSync(file)) {
        const pkg = JSON.parse(readFileSync(file, "utf8"));
        if (pkg.name === "openclaw") return String(pkg.version || "");
      }
      const up = dirname(dir);
      if (up === dir) break;
      dir = up;
    }
  } catch {
    // Unreadable: no version.
  }
  return "";
}
const HARNESS_VERSION = openclawVersion();

// Labels only Lunchroom's envelope carries: a prompt with one holds another agent's text (T1).
const ENVELOPE_LABELS = ["[LUNCHROOM MESSAGE", "[END LUNCHROOM MESSAGE", "[lr:"];

// One guard run, without blocking the gateway's event loop: its exit code, standard output and
// standard error; `missing` when the program is not there to run; `failed` when it could not
// decide, input it could not be given included.
export function runGuard(mode, input, program = PROGRAM) {
  let body;
  try {
    body = JSON.stringify({ ...input, plugin_file: PLUGIN_FILE, harness_version: HARNESS_VERSION });
  } catch (e) {
    return Promise.resolve({ failed: `unreadable input: ${e.message}` });
  }
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timer;
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(r);
    };
    const child = spawn(program, mode, { stdio: ["pipe", "pipe", "pipe"] });
    timer = setTimeout(() => {
      child.kill("SIGTERM");
      finish({ failed: "no answer in time" });
    }, DEADLINE_MS);
    child.stdout.setEncoding("utf8").on("data", (d) => { stdout += d; });
    child.stderr.setEncoding("utf8").on("data", (d) => { stderr += d; });
    child.stdin.on("error", () => {});
    child.on("error", (e) => finish(e.code === "ENOENT" ? { missing: true } : { failed: String(e.code || e.message) }));
    child.on("close", (status, signal) => {
      if (status === null) return finish({ failed: `stopped by ${signal}` });
      // The guard answers with exit 0 or 2 (H1.5); any other exit is a guard that could not decide.
      if (status !== 0 && status !== 2) return finish({ failed: `exit ${status}` });
      return finish({ status, stdout, stderr });
    });
    child.stdin.end(body);
  });
}

// The session this event belongs to: OpenClaw's session key, which `openclaw agent
// --session-key` names when Lunchroom delivers to it.
export function sessionOf(ctx) {
  return (ctx && ctx.sessionKey) || "";
}

// The guard's answer; `null` when its output cannot be read, which is a guard that could not
// decide, never a call that goes ahead.
function decision(stdout) {
  try {
    const out = JSON.parse(stdout.trim() || "{}");
    const h = out.hookSpecificOutput || {};
    return { decision: h.permissionDecision || "", reason: h.permissionDecisionReason || "" };
  } catch {
    return null;
  }
}

// Whether a person can answer OpenClaw's approval in each run, by run id, from the run's
// `before_agent_run` context: OpenClaw blocks an approval at once in a run whose trigger is not
// "user" or that has no initiating channel (dist/agent-tools.before-tool-call-CReBJLEA.mjs:829-841).
// A run the plugin has not seen counts as one where nobody can answer (A1.2).
export const surfaces = new Map();

export function personCanAnswer(ctx) {
  const trigger = ((ctx && ctx.trigger) || "").trim();
  const channel = ((ctx && (ctx.channel || ctx.channelId || ctx.messageProvider)) || "").trim();
  return (trigger === "" || trigger === "user") && channel !== "";
}

// What the rules that need no record DENY in every session (F1.1, F1.2, I1.2, P1.4), for a call
// the guard could not judge: OpenClaw's tools that put a turn into another session, and a call
// whose text names Lunchroom, a harness program, a session chat API or an identity variable, are
// blocked, never asked. Quotes, backslashes and backticks are removed before the match, so a split
// spelling is read as the word it spells.
const NO_RECORD_DENY =
  /\b(lunchroom|hermes|codex|claude|opencode|openclaw|acp|sessions_send|CLAUDE_CODE_SESSION_ID|CODEX_THREAD_ID|HERMES_SESSION_ID|LUNCHROOM_SESSION|LUNCHROOM_HOME)\b|\/api\/sessions\//i;
const FENCED_TOOLS = ["sessions_send", "openclaw", "acp"];

export function deniedWithoutRecord(event) {
  const params = event.params || {};
  if (FENCED_TOOLS.includes(event.toolName)) return true;
  if (event.toolName === "automations" && ["add", "update"].includes(params.action)) return true;
  try {
    const text = JSON.stringify(params);
    return NO_RECORD_DENY.test(text) || NO_RECORD_DENY.test(text.replace(/[\\"'`]/g, ""));
  } catch {
    // Parameters that cannot be read cannot be shown free of those rules.
    return true;
  }
}

// Sessions another agent's text reached that the guard could not judge (a tool's output with
// Lunchroom's labels): the plugin sends each of their calls to the user until the guard has judged
// a turn the user typed (T1, H1.5).
export const unjudged = new Set();

// The user's answer to each call Lunchroom sent to them, by tool call id, until the call ends.
// Only "allow-once" counts as the user's yes. OpenClaw itself turns an answer outside
// `allowedDecisions`, such as "allow-always", into "timeout", which blocks the call, before it
// reports it here (dist/agent-tools.before-tool-call-CReBJLEA.mjs:801-803, 870-874).
export const answers = new Map();

function approval(description, toolCallId = "") {
  if (toolCallId) answers.set(toolCallId, "");
  return {
    requireApproval: {
      title: "Lunchroom",
      description,
      allowedDecisions: ["allow-once", "deny"],
      timeoutMs: 120000,
      pluginId: "lunchroom",
      onResolution: (decision) => {
        if (toolCallId) answers.set(toolCallId, decision);
      },
    },
  };
}

// The tool input the guard judges. An `exec` command runs in its own `workdir` (OpenClaw's
// `cwd: params.workdir`, dist/bash-tools.exec-runtime-Ckwb9gZp.mjs:422), else in the workspace, so
// the input sent carries the absolute directory the command runs in: the guard classifies against
// it and an approval, which covers the exact input (A2.1), covers that directory too. A `~` is
// the user's home as OpenClaw's shell reads it; a relative one is the workspace's.
export function judgedInput(event, ctx) {
  const params = event.params || {};
  if (event.toolName !== "exec") return params;
  const workspace = (ctx && ctx.workspaceDir) || process.cwd();
  const given = typeof params.workdir === "string" ? params.workdir.trim() : "";
  let dir = workspace;
  if (given === "~" || given.startsWith("~/")) dir = join(homedir(), given.slice(1));
  else if (given !== "") dir = isAbsolute(given) ? given : resolve(workspace, given);
  return { ...params, workdir: dir };
}

function base(event, ctx, hookEventName) {
  return {
    harness: "openclaw",
    hook_event_name: hookEventName,
    session_id: sessionOf(ctx),
    cwd: (ctx && ctx.workspaceDir) || process.cwd(),
  };
}

// before_tool_call: the guard's answer as OpenClaw's.
export async function beforeToolCall(event, ctx, program = PROGRAM) {
  const channel = surfaces.get((ctx && ctx.runId) || "") === true;
  // A call the guard cannot judge goes to the user where a person can answer, else it is DENIED;
  // one the rules needing no record DENY is DENIED.
  // The request shows the call in full (A1.4).
  const notJudged = (why) => {
    if (deniedWithoutRecord(event)) return { block: true, blockReason: `Lunchroom: DENIED. ${why}` };
    return channel ? approval(`Lunchroom: ${why}${shown(event, ctx)}`) : { block: true, blockReason: `Lunchroom: ${why}` };
  };
  // What the plugin knows that the guard's record may not: no session, or another agent's text
  // that reached the session unjudged. The guard still answers for the call when it can.
  let held = "";
  if (!sessionOf(ctx)) held = "could not tell which session this call belongs to.";
  else if (unjudged.has(sessionOf(ctx))) held = "could not check another agent's text that reached this session.";
  if (held && deniedWithoutRecord(event)) return notJudged(held);
  const unable = (what) => notJudged(held ? `${held} (${what})` : `could not check this call: ${what}.`);
  const run = await runGuard(["guard", "pretool"], {
    ...base(event, ctx, "PreToolUse"),
    tool_name: event.toolName,
    tool_input: judgedInput(event, ctx),
    tool_use_id: event.toolCallId || event.runId || "",
    // A1.1, A1.2: whether a person can answer OpenClaw's approval in this run.
    approval_channel: channel,
  }, program);
  if (run.missing || run.failed) {
    return unable(run.failed || "its program is missing");
  }
  if (run.status === 2) {
    return { block: true, blockReason: run.stderr.trim() || "Lunchroom: DENIED" };
  }
  const d = decision(run.stdout);
  if (!d) return unable("its answer could not be read");
  // A1.2: with nobody to ask, a call for the user is DENIED, whatever the guard answered.
  if (d.decision === "ask") {
    return channel
      ? approval(d.reason, event.toolCallId || "")
      : { block: true, blockReason: d.reason || "Lunchroom: DENIED" };
  }
  // The guard lets it run, but the plugin knows what the guard's record may not: the user decides.
  return held ? notJudged(held) : undefined;
}

// A call in full, set apart as the call's input (A1.4, A2.2).
function shown(event, ctx) {
  let body;
  try {
    body = JSON.stringify(judgedInput(event, ctx), null, 2);
  } catch {
    body = "(its input could not be written out)";
  }
  return `\n\nThe call's input, in full (${event.toolName}):\n${body}`;
}

// Everything a finished tool call shows the model: its result and, for a failed call, its error
// (`after_tool_call` carries both, dist/builtin-openclaw-Ci5YBsOb.mjs:7155-7175). With only one of
// them present it is that one; with both, an object holding both, so the guard and the label check
// see another agent's text in either channel.
export function modelVisible(event) {
  const hasResult = event.result !== undefined && event.result !== null;
  const hasError = event.error !== undefined && event.error !== null;
  if (hasError && hasResult) return { result: event.result, error: event.error };
  if (hasError) return event.error;
  return hasResult ? event.result : null;
}

// after_tool_call: another agent's text in a tool's output holds the session (T1). A call the
// user was asked about carries its id only when the user allowed it, so Lunchroom never reports
// a refused call as approved (card 4).
export async function afterToolCall(event, ctx, program = PROGRAM) {
  const id = event.toolCallId || "";
  const answer = answers.get(id);
  answers.delete(id);
  if (!sessionOf(ctx)) return;
  const run = await runGuard(["guard", "posttool"], {
    ...base(event, ctx, "PostToolUse"),
    tool_name: event.toolName,
    tool_input: judgedInput(event, ctx),
    tool_use_id: answer === undefined || answer === "allow-once" ? id : "",
    tool_response: modelVisible(event),
  }, program);
  if (run.failed || run.missing) {
    // Output that cannot be written out cannot be shown free of the labels either.
    let output;
    try {
      const seen = modelVisible(event);
      output = typeof seen === "string" ? seen : JSON.stringify(seen);
    } catch {
      output = ENVELOPE_LABELS[0];
    }
    if (ENVELOPE_LABELS.some((l) => String(output).includes(l))) unjudged.add(sessionOf(ctx));
  }
}

// Whether a turn's text is the user's own typing (T1): the owner's, in a run whose trigger is the
// user's (as `personCanAnswer` reads it), not from another session or the system, and without
// Lunchroom's labels, which only its own delivery turn carries.
export function isTyped(event, ctx) {
  const kind = ctx && ctx.inputProvenance && ctx.inputProvenance.kind;
  const trigger = ((ctx && ctx.trigger) || "").trim();
  return (
    event.senderIsOwner === true &&
    (trigger === "" || trigger === "user") &&
    kind !== "inter_session" &&
    kind !== "internal_system" &&
    !ENVELOPE_LABELS.some((l) => String(event.prompt || "").includes(l))
  );
}

// A handler that throws fails closed (H1.5): the session is recorded as holding text the guard did
// not judge, and `onError` gives the answer.
export function failClosed(handler, onError) {
  const fail = (event, ctx, e) => {
    try {
      if (sessionOf(ctx)) unjudged.add(sessionOf(ctx));
    } catch {
      // No session to record.
    }
    return onError(event, ctx, e);
  };
  return (event, ctx) => {
    try {
      return Promise.resolve(handler(event, ctx)).catch((e) => fail(event, ctx, e));
    } catch (e) {
      return Promise.resolve(fail(event, ctx, e));
    }
  };
}

// before_agent_run: the turn's prompt reaches the guard. Lunchroom's delivery is confirmed here
// and a repeated one is blocked; the user's own turn clears HELD; another session's text holds.
// When the guard cannot judge it, or its program is missing, a prompt that is not the user's own
// typing, or that carries Lunchroom's labels, is blocked, since nothing could hold the session it
// reaches (H1.5, T1); the user's own typing still goes on.
export async function beforeAgentRun(event, ctx, program = PROGRAM) {
  if (ctx && ctx.runId) surfaces.set(ctx.runId, personCanAnswer(ctx));
  if (!sessionOf(ctx)) return { outcome: "pass" };
  const prompt = event.prompt || "";
  const typed = isTyped(event, ctx);
  const run = await runGuard(["guard", "prompt"], {
    ...base(event, ctx, "UserPromptSubmit"),
    prompt,
    prompt_id: (ctx && ctx.runId) || "",
    user_typed: typed,
  }, program);
  if (run.status === 2) {
    return { outcome: "block", reason: run.stderr.trim() || "Lunchroom: blocked" };
  }
  if (typed && run.status === 0) unjudged.delete(sessionOf(ctx));
  const notJudged = run.failed || run.missing;
  if (notJudged && (!typed || ENVELOPE_LABELS.some((l) => prompt.includes(l)))) {
    const why = run.failed || "its program is missing";
    return { outcome: "block", reason: `Lunchroom could not check this prompt: ${why}.` };
  }
  return { outcome: "pass" };
}

// agent_end: the turn is over; the next waiting message goes to the session (D1.1).
export async function agentEnd(event, ctx, program = PROGRAM) {
  if (ctx && ctx.runId) surfaces.delete(ctx.runId);
  if (!sessionOf(ctx)) return;
  await runGuard(["listen", "--once"], base(event, ctx, "Stop"), program);
}

// resolve_exec_env: the session's name for `lunchroom send` in this exec command (I1.2).
export function resolveExecEnv(event, ctx) {
  const session = (event && event.sessionKey) || sessionOf(ctx);
  return session ? { LUNCHROOM_SESSION: `openclaw:${session}` } : {};
}

// The entry `definePluginEntry` (openclaw/plugin-sdk/plugin-entry) would build, written out so the
// plugin needs nothing from OpenClaw's package: the same fields, and an empty config schema.
export default {
  id: "lunchroom",
  name: "Lunchroom",
  description: "Lunchroom's guard: agents talk, the user decides who acts.",
  configSchema: {
    safeParse(value) {
      if (value === undefined) return { success: true, data: undefined };
      if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length) {
        return { success: false, error: { issues: [{ path: [], message: "config must be empty" }] } };
      }
      return { success: true, data: value };
    },
    jsonSchema: { type: "object", additionalProperties: false, properties: {} },
  },
  register(api) {
    api.on("before_tool_call", failClosed(beforeToolCall, (event, ctx, e) => ({
      block: true,
      blockReason: `Lunchroom: DENIED. could not check this call: ${e && e.message}.`,
    })));
    api.on("after_tool_call", failClosed(afterToolCall, () => undefined));
    api.on("before_agent_run", failClosed(beforeAgentRun, (event, ctx, e) => {
      // The user's own typing still goes on (H1.5); any other text is blocked.
      let typed = false;
      try {
        typed = isTyped(event, ctx);
      } catch {
        // Not shown to be the user's.
      }
      return typed ? { outcome: "pass" } : { outcome: "block", reason: `Lunchroom could not check this prompt: ${e && e.message}.` };
    }));
    api.on("agent_end", failClosed(agentEnd, () => undefined));
    api.on("resolve_exec_env", (event, ctx) => resolveExecEnv(event, ctx));
  },
};
