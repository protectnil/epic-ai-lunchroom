// Lunchroom's OpenClaw plugin, run against a stand-in guard program (node --test).
// Spec: §13 H1 (the adapter), H1.5 (no lockout), §7 A1.1 (OpenClaw's approval), §9 I1.2 (the
// session named in an exec command), §10 D1.1 (delivery confirmed in `before_agent_run`).

import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import plugin, {
  openclawVersion,
  personCanAnswer,
  surfaces,
  afterToolCall,
  agentEnd,
  beforeAgentRun,
  beforeToolCall,
  failClosed,
  isTyped,
  unjudged,
  judgedInput,
  modelVisible,
  resolveExecEnv,
} from "./index.mjs";

const dir = mkdtempSync(join(tmpdir(), "lunchroom-openclaw-"));
const STUB = join(dir, "lunchroom");
const IN = join(dir, "in.json");
const ARGS = join(dir, "args.txt");
writeFileSync(
  STUB,
  `#!/bin/sh
printf '%s\\n' "$@" > '${ARGS}'
cat > '${IN}'
case "$STUB_MODE" in
  deny) echo "Lunchroom: DENIED · fence" >&2; exit 2 ;;
  ask) printf '%s' '{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"Lunchroom: s1 is HELD."}}' ;;
  signal) kill -TERM $$ ;;
  exit1) exit 1 ;;
  slow) sleep 1 ;;
  garbage) printf 'not json' ;;
esac
exit 0
`,
);
chmodSync(STUB, 0o755);
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));

function mode(m) {
  process.env.STUB_MODE = m;
}
function sent() {
  return JSON.parse(readFileSync(IN, "utf8"));
}
function args() {
  return readFileSync(ARGS, "utf8").trim().split("\n");
}

const ctx = { sessionKey: "agent:main:a", workspaceDir: "/w", runId: "r1" };
// The run began from the user in a chat channel: a person can answer OpenClaw's approval.
surfaces.set("r1", true);
const exec = { toolName: "exec", params: { command: "ls" }, toolCallId: "t1" };

test("a call the guard lets run returns nothing, and the guard sees the call as OpenClaw sent it", async () => {
  mode("allow");
  assert.equal(await beforeToolCall(exec, ctx, STUB), undefined);
  assert.deepEqual(args(), ["guard", "pretool"]);
  const input = sent();
  assert.equal(input.harness, "openclaw");
  assert.equal(input.session_id, "agent:main:a");
  assert.equal(input.cwd, "/w");
  assert.equal(input.tool_name, "exec");
  // A1.1/A2.1: the directory the command runs in is part of the input the guard judges.
  assert.deepEqual(input.tool_input, { command: "ls", workdir: "/w" });
  assert.equal(input.approval_channel, true);
  await beforeToolCall(exec, { ...ctx, runId: "unseen" }, STUB);
  assert.equal(sent().approval_channel, false);
  assert.equal(input.plugin_file, fileURLToPath(new URL("./index.mjs", import.meta.url)));
});

test("a DENIED call is blocked with the guard's reason", async () => {
  mode("deny");
  assert.deepEqual(await beforeToolCall(exec, ctx, STUB), {
    block: true,
    blockReason: "Lunchroom: DENIED · fence",
  });
});

test("a call that goes to the user asks through OpenClaw, allowing this one call only (A1.1)", async () => {
  mode("ask");
  const out = await beforeToolCall(exec, ctx, STUB);
  assert.equal(out.requireApproval.description, "Lunchroom: s1 is HELD.");
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(out.requireApproval.pluginId, "lunchroom");
});

test("a call for the user is DENIED in a run where nobody can answer (A1.2)", async () => {
  mode("ask");
  assert.deepEqual(await beforeToolCall(exec, { ...ctx, runId: "unseen" }, STUB), {
    block: true,
    blockReason: "Lunchroom: s1 is HELD.",
  });
});

test("a guard that cannot answer sends the call to the user, or DENIES it where nobody can answer (H1.5)", async () => {
  mode("signal");
  const out = await beforeToolCall(exec, ctx, STUB);
  assert.match(out.requireApproval.description, /^Lunchroom: could not check this call/);
  assert.match((await beforeToolCall(exec, { runId: "r1" }, STUB)).requireApproval.description, /which session/);
  const none = await beforeToolCall(exec, { ...ctx, runId: "unseen" }, STUB);
  assert.equal(none.block, true);
  assert.match(none.blockReason, /^Lunchroom: could not check this call/);
  assert.equal((await beforeToolCall(exec, {}, STUB)).block, true);
});

test("a person can answer only in a user's run with an initiating channel (A1.1, A1.2)", async () => {
  assert.equal(personCanAnswer({ trigger: "user", channel: "telegram" }), true);
  assert.equal(personCanAnswer({ channelId: "c1" }), true);
  assert.equal(personCanAnswer({ trigger: "user", messageProvider: "webchat" }), true);
  assert.equal(personCanAnswer({ trigger: "user" }), false);
  assert.equal(personCanAnswer({ trigger: "cron", channel: "telegram" }), false);
  assert.equal(personCanAnswer({ trigger: "heartbeat", channel: "telegram" }), false);
  mode("allow");
  await beforeAgentRun({ prompt: "hi", senderIsOwner: true }, { ...ctx, runId: "r9", trigger: "cron", channel: "t" }, STUB);
  await beforeToolCall(exec, { ...ctx, runId: "r9" }, STUB);
  assert.equal(sent().approval_channel, false);
  await beforeAgentRun({ prompt: "hi", senderIsOwner: true }, { ...ctx, runId: "r9", trigger: "user", channel: "t" }, STUB);
  await beforeToolCall(exec, { ...ctx, runId: "r9" }, STUB);
  assert.equal(sent().approval_channel, true);
  await agentEnd({}, { ...ctx, runId: "r9" }, STUB);
  assert.equal(surfaces.has("r9"), false);
});

test("a guard exit other than 0 or 2 is a guard that could not decide (H1.5)", async () => {
  mode("exit1");
  assert.match((await beforeToolCall(exec, ctx, STUB)).requireApproval.description, /exit 1/);
  assert.equal((await beforeAgentRun({ prompt: "hello" }, ctx, STUB)).outcome, "block");
  assert.equal((await beforeAgentRun({ prompt: "hello", senderIsOwner: true }, ctx, STUB)).outcome, "pass");
});

test("an unjudged call that the rules needing no record DENY is blocked, never asked (F1.1, H1.5)", async () => {
  surfaces.set("r1", true);
  const absent = join(dir, "absent");
  for (const call of [
    { toolName: "exec", params: { command: "codex queue other hi" } },
    { toolName: "exec", params: { command: "ls", env: { LUNCHROOM_SESSION: "openclaw:x" } } },
    { toolName: "sessions_send", params: { sessionKey: "agent:main:b", message: "hi" } },
    { toolName: "openclaw", params: { request: "set up" } },
    { toolName: "acp", params: {} },
    { toolName: "exec", params: { command: "acp --session s2" } },
    { toolName: "automations", params: { action: "add" } },
    { toolName: "write", params: { path: "/home/u/.lunchroom/store/x" } },
  ]) {
    const out = await beforeToolCall({ ...call, toolCallId: "n1" }, ctx, absent);
    assert.equal(out.block, true, JSON.stringify(call));
    assert.match(out.blockReason, /DENIED/);
  }
  mode("signal");
  assert.equal((await beforeToolCall({ toolName: "sessions_send", params: {} }, ctx, STUB)).block, true);
  mode("allow");
});

// Spec §13 H1.5 and §7 A1.4. Failure classes: the guard DENIES, asks or lets the call run, each with
// no session and with an unjudged session; a name the plugin's list missed by spelling; an approval
// request that does not show the call in full.
test("an unjudged or sessionless call still asks the healthy guard, and is never offered what it denies (H1.5, A1.4)", async () => {
  surfaces.set("r1", true);
  const held = [
    { runId: "r1" },
    { ...ctx, sessionKey: "agent:main:held" },
  ];
  unjudged.add("agent:main:held");
  for (const c of held) {
    mode("deny");
    assert.deepEqual(await beforeToolCall(exec, c, STUB), { block: true, blockReason: "Lunchroom: DENIED · fence" });
    assert.deepEqual(args(), ["guard", "pretool"]);
    mode("ask");
    assert.equal((await beforeToolCall(exec, c, STUB)).requireApproval.description, "Lunchroom: s1 is HELD.");
    // The guard lets it run, yet what the plugin knows holds: the user decides.
    mode("allow");
    assert.match((await beforeToolCall(exec, c, STUB)).requireApproval.description, /^Lunchroom: could not/);
  }
  const absent = join(dir, "absent");
  for (const command of ["lunchroom approve", "LUNCHROOM mode relaxed", "'lunch''room' yolo on", "l\\unchroom approve",
    "\"cl\"\"aude\" --resume s1", "cla'ud'e --resume s1", "hermes chat --resume s1"]) {
    for (const c of held) {
      mode("ask");
      const out = await beforeToolCall({ toolName: "exec", params: { command }, toolCallId: "n2" }, c, STUB);
      assert.equal(out.block, true, command);
      assert.match(out.blockReason, /DENIED/);
      const gone = await beforeToolCall({ toolName: "exec", params: { command }, toolCallId: "n2" }, c, absent);
      assert.equal(gone.block, true, command);
    }
  }
  unjudged.delete("agent:main:held");
});

test("an approval request for a call the guard could not judge shows the call in full (A1.4)", async () => {
  surfaces.set("r1", true);
  const command = `cat ${"x".repeat(600)} > /tmp/out`;
  const call = { toolName: "exec", params: { command, workdir: "/d" }, toolCallId: "f1" };
  for (const [c, program] of [[ctx, join(dir, "absent")], [{ runId: "r1" }, STUB]]) {
    mode("allow");
    const d = (await beforeToolCall(call, c, program)).requireApproval.description;
    assert.ok(d.startsWith("Lunchroom: "), d.slice(0, 40));
    assert.ok(d.includes(command));
    assert.ok(d.includes('"workdir": "/d"'));
    assert.ok(d.includes("exec"));
  }
});

test("a missing guard program sends the call to the user, or DENIES it where nobody can answer (H1.5)", async () => {
  surfaces.set("r1", true);
  const absent = join(dir, "absent");
  assert.match((await beforeToolCall(exec, ctx, absent)).requireApproval.description, /its program is missing/);
  assert.equal((await beforeToolCall(exec, { ...ctx, runId: "unseen" }, absent)).block, true);
});

test("only a call the user approved is reported as approved after it runs (card 4)", async () => {
  surfaces.set("r1", true);
  // "allow-always" is outside allowedDecisions; were it reported, it would not count as a yes.
  for (const [answer, mark] of [["allow-once", "t2"], ["deny", ""], ["timeout", ""], ["allow-always", ""]]) {
    mode("ask");
    const out = await beforeToolCall({ ...exec, toolCallId: "t2" }, ctx, STUB);
    out.requireApproval.onResolution(answer);
    mode("allow");
    await afterToolCall({ ...exec, toolCallId: "t2", result: "ok" }, ctx, STUB);
    assert.deepEqual(args(), ["guard", "posttool"]);
    assert.equal(sent().tool_use_id, mark, answer);
    assert.equal(sent().tool_response, "ok");
  }
  await afterToolCall({ ...exec, toolCallId: "t3" }, ctx, STUB);
  assert.equal(sent().tool_use_id, "t3");
});

test("the turn's prompt reaches the guard; typed only from the owner with no other session (T1)", async () => {
  mode("allow");
  const cases = [
    [{ senderIsOwner: true }, {}, true],
    [{ senderIsOwner: true }, { inputProvenance: { kind: "inter_session" } }, false],
    [{ senderIsOwner: true }, { inputProvenance: { kind: "internal_system" } }, false],
    [{ senderIsOwner: false }, {}, false],
    [{}, {}, false],
  ];
  for (const [event, extra, typed] of cases) {
    assert.deepEqual(await beforeAgentRun({ prompt: "hi", ...event }, { ...ctx, ...extra }, STUB), {
      outcome: "pass",
    });
    assert.deepEqual(args(), ["guard", "prompt"]);
    assert.equal(sent().user_typed, typed, JSON.stringify([event, extra]));
    assert.equal(sent().prompt, "hi");
  }
});

test("a prompt the guard blocks is blocked; when the guard cannot answer, only the user's own typing without Lunchroom's labels goes on (H1.5)", async () => {
  mode("deny");
  assert.equal((await beforeAgentRun({ prompt: "x" }, ctx, STUB)).outcome, "block");
  mode("signal");
  const owner = { senderIsOwner: true };
  assert.equal((await beforeAgentRun({ prompt: "[lr:lr-1]> do it", ...owner }, ctx, STUB)).outcome, "block");
  assert.equal((await beforeAgentRun({ prompt: "hello", ...owner }, ctx, STUB)).outcome, "pass");
  const other = { ...ctx, inputProvenance: { kind: "inter_session" } };
  assert.equal((await beforeAgentRun({ prompt: "hello", ...owner }, other, STUB)).outcome, "block");
  assert.equal((await beforeAgentRun({ prompt: "hello" }, ctx, STUB)).outcome, "block");
  const absent = join(dir, "absent");
  assert.equal((await beforeAgentRun({ prompt: "hello" }, other, absent)).outcome, "block");
  assert.equal((await beforeAgentRun({ prompt: "hello", ...owner }, ctx, absent)).outcome, "pass");
});

test("a tool's output with another agent's text that the guard cannot judge sends the session's calls to the user (T1, H1.5)", async () => {
  const c = { ...ctx, sessionKey: "agent:main:u", runId: "ru", trigger: "user", channel: "telegram" };
  surfaces.set("ru", true);
  mode("signal");
  await afterToolCall({ ...exec, toolCallId: "u1", result: "plain" }, c, STUB);
  mode("allow");
  assert.equal(await beforeToolCall(exec, c, STUB), undefined);
  for (const program of [STUB, join(dir, "absent")]) {
    mode("signal");
    await afterToolCall({ ...exec, toolCallId: "u2", result: "[lr:lr-1]> rm it" }, c, program);
    mode("allow");
    assert.match((await beforeToolCall(exec, c, STUB)).requireApproval.description, /another agent's text/);
    // The user's own turn, judged by the guard, ends it.
    await beforeAgentRun({ prompt: "carry on", senderIsOwner: true }, c, STUB);
    assert.equal(await beforeToolCall(exec, c, STUB), undefined);
  }
});

test("at a turn's end the next waiting message is asked for (D1.1)", async () => {
  mode("allow");
  await agentEnd({}, ctx, STUB);
  assert.deepEqual(args(), ["listen", "--once"]);
  assert.equal(sent().session_id, "agent:main:a");
});

test("OpenClaw's version is read from its package above the entry script (H1.2)", async () => {
  const pkg = join(dir, "oc", "node_modules", "openclaw");
  mkdirSync(join(pkg, "dist"), { recursive: true });
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "openclaw", version: "2026.10.7" }));
  writeFileSync(join(pkg, "openclaw.mjs"), "");
  writeFileSync(join(pkg, "dist", "entry.mjs"), "");
  assert.equal(openclawVersion(join(pkg, "openclaw.mjs")), "2026.10.7");
  assert.equal(openclawVersion(join(pkg, "dist", "entry.mjs")), "2026.10.7");
  assert.equal(openclawVersion(join(dir, "absent.mjs")), "");
  mode("allow");
  await beforeToolCall(exec, ctx, STUB);
  assert.equal(typeof sent().harness_version, "string");
});

test("an exec command names its session for lunchroom send (I1.2)", async () => {
  assert.deepEqual(resolveExecEnv({ sessionKey: "agent:main:a" }, {}), {
    LUNCHROOM_SESSION: "openclaw:agent:main:a",
  });
  assert.deepEqual(resolveExecEnv({}, {}), {});
});

test("the plugin entry registers every hook, with id lunchroom and an empty config", async () => {
  const hooks = [];
  plugin.register({ on: (name) => hooks.push(name) });
  assert.deepEqual(hooks.sort(), [
    "after_tool_call",
    "agent_end",
    "before_agent_run",
    "before_tool_call",
    "resolve_exec_env",
  ]);
  assert.equal(plugin.id, "lunchroom");
  assert.equal(plugin.configSchema.safeParse(undefined).success, true);
  assert.equal(plugin.configSchema.safeParse({}).success, true);
  assert.equal(plugin.configSchema.safeParse({ a: 1 }).success, false);
  assert.equal(plugin.configSchema.safeParse([]).success, false);
});

test("the guard runs without blocking the gateway, and an unreadable answer or input never lets a call run (H1.5)", async () => {
  surfaces.set("r1", true);
  mode("slow");
  let ticked = false;
  setTimeout(() => { ticked = true; }, 50);
  assert.equal(await beforeToolCall(exec, ctx, STUB), undefined);
  assert.equal(ticked, true);
  mode("garbage");
  assert.match((await beforeToolCall(exec, ctx, STUB)).requireApproval.description, /could not be read/);
  mode("allow");
  const loop = { command: "ls" };
  loop.self = loop;
  const out = await beforeToolCall({ toolName: "exec", params: loop }, ctx, STUB);
  assert.equal(out.block, true);
  assert.match(out.blockReason, /DENIED.*unreadable input/);
});

// Spec §7 A2.1: "An approval covers one tool call: the session id, the tool name and its exact input".
// Failure classes: workdir absent (the workspace), absolute, relative, `~`, padded, non-string; a
// non-exec tool; the input sent to the guard (judged and bound) carries the directory.
test("an exec command is judged and bound in the directory it runs in (A2.1)", async () => {
  assert.deepEqual(judgedInput(exec, ctx), { command: "ls", workdir: "/w" });
  const at = (workdir) => judgedInput({ toolName: "exec", params: { command: "cat credentials", workdir } }, ctx);
  assert.equal(at("/home/u/.aws").workdir, "/home/u/.aws");
  assert.equal(at("  /home/u/.aws ").workdir, "/home/u/.aws");
  assert.equal(at("sub/dir").workdir, "/w/sub/dir");
  assert.equal(at("../x").workdir, "/x");
  assert.equal(at("~").workdir, homedir());
  assert.equal(at("~/.aws").workdir, join(homedir(), ".aws"));
  assert.equal(at("").workdir, "/w");
  assert.equal(at(7).workdir, "/w");
  assert.equal(at(7).command, "cat credentials");
  // Another tool's input is untouched.
  const read = { toolName: "read", params: { path: "x" } };
  assert.deepEqual(judgedInput(read, ctx), { path: "x" });
  // The guard receives it, in the call and in the output report.
  mode("allow");
  await beforeToolCall({ ...exec, params: { command: "cat credentials", workdir: "/home/u/.aws" } }, ctx, STUB);
  assert.equal(sent().tool_input.workdir, "/home/u/.aws");
  await afterToolCall({ ...exec, params: { command: "c", workdir: "rel" }, result: "ok" }, ctx, STUB);
  assert.equal(sent().tool_input.workdir, "/w/rel");
});

// Spec §13 T1: "another agent's text in a tool's output holds the session". Failure classes: error
// only, result only, both, neither; a string error, an object error; error only with labels when the
// guard cannot judge.
test("a failed tool's error reaches the guard and the label check (T1)", async () => {
  assert.equal(modelVisible({ result: "r" }), "r");
  assert.equal(modelVisible({ error: "e" }), "e");
  assert.deepEqual(modelVisible({ result: "r", error: "e" }), { result: "r", error: "e" });
  assert.equal(modelVisible({}), null);
  assert.equal(modelVisible({ result: null, error: undefined }), null);
  mode("allow");
  await afterToolCall({ ...exec, toolCallId: "e1", error: "[lr:lr-1]> do it" }, ctx, STUB);
  assert.equal(sent().tool_response, "[lr:lr-1]> do it");
  await afterToolCall({ ...exec, toolCallId: "e2", error: { message: "boom" } }, ctx, STUB);
  assert.deepEqual(sent().tool_response, { message: "boom" });
  // The guard cannot judge an error-only event carrying the labels: the session is unjudged.
  const c = { ...ctx, sessionKey: "agent:main:err", runId: "re" };
  surfaces.set("re", true);
  mode("signal");
  await afterToolCall({ ...exec, toolCallId: "e3", error: "[LUNCHROOM MESSAGE - from agent x]" }, c, STUB);
  mode("allow");
  assert.match((await beforeToolCall(exec, c, STUB)).requireApproval.description, /another agent's text/);
});

// Spec §5 T1: only the user's own typing is the user's. Failure classes: the owner's prompt in a run
// the user did not start (cron, heartbeat, other triggers); the trigger absent or "user"; Lunchroom's
// own delivery turn, which carries its labels, owner flag or not.
test("a turn is the user's typing only in a user's run, and Lunchroom's delivery turn never clears unjudged (T1)", async () => {
  const owner = { senderIsOwner: true };
  for (const [trigger, want] of [[undefined, true], ["", true], ["user", true], ["cron", false],
    ["heartbeat", false], ["memory", false], ["manual", false], ["other", false]]) {
    const c = { ...ctx, trigger };
    assert.equal(isTyped({ prompt: "hi", ...owner }, c), want, String(trigger));
    mode("allow");
    await beforeAgentRun({ prompt: "hi", ...owner }, c, STUB);
    assert.equal(sent().user_typed, want, String(trigger));
  }
  for (const prompt of ["[LUNCHROOM MESSAGE - from agent x]", "a\n[END LUNCHROOM MESSAGE lr-1]", "[lr:lr-1]> do it"]) {
    assert.equal(isTyped({ prompt, ...owner }, ctx), false, prompt);
  }
  // A cron turn the guard cannot judge is blocked, never passed as the user's typing.
  mode("signal");
  assert.equal((await beforeAgentRun({ prompt: "hi", ...owner }, { ...ctx, trigger: "cron" }, STUB)).outcome, "block");
  // The delivery turn, judged by the guard, leaves the session unjudged; the user's own turn clears it.
  const c = { ...ctx, sessionKey: "agent:main:d", runId: "rd", trigger: "user", channel: "telegram" };
  surfaces.set("rd", true);
  mode("signal");
  await afterToolCall({ ...exec, toolCallId: "d1", result: "[lr:lr-1]> rm it" }, c, STUB);
  mode("allow");
  assert.ok(unjudged.has("agent:main:d"));
  await beforeAgentRun({ prompt: "[LUNCHROOM MESSAGE - from agent x]\n[END LUNCHROOM MESSAGE lr-1]", ...owner }, c, STUB);
  assert.ok(unjudged.has("agent:main:d"));
  assert.match((await beforeToolCall(exec, c, STUB)).requireApproval.description, /another agent's text/);
  await beforeAgentRun({ prompt: "carry on", ...owner }, c, STUB);
  assert.equal(unjudged.has("agent:main:d"), false);
});

// Spec §13 H1.5. Failure classes: each hook throws (a getter that throws, input JSON cannot hold);
// the throwing hook records the session as unjudged; the user's own typing still goes on; a failure
// before the output is read is still recorded.
test("a hook that throws fails closed after recording the session as unjudged (H1.5)", async () => {
  const boom = () => { throw new Error("boom"); };
  const hooks = {};
  plugin.register({ on: (name, fn) => { hooks[name] = fn; } });
  const c = { ...ctx, sessionKey: "agent:main:t", runId: "rt", trigger: "user", channel: "telegram" };
  surfaces.set("rt", true);
  // before_tool_call: blocked, session recorded.
  const out = await hooks.before_tool_call({ get toolName() { return boom(); }, params: {} }, c);
  assert.equal(out.block, true);
  assert.match(out.blockReason, /^Lunchroom: DENIED/);
  assert.ok(unjudged.has("agent:main:t"));
  unjudged.delete("agent:main:t");
  // after_tool_call: nothing returned, session recorded.
  assert.equal(await hooks.after_tool_call({ get toolName() { return boom(); } }, c), undefined);
  assert.ok(unjudged.has("agent:main:t"));
  unjudged.delete("agent:main:t");
  // before_agent_run: a prompt that is not shown to be the user's is blocked; the user's own typing passes.
  const other = await hooks.before_agent_run({ get prompt() { return boom(); }, senderIsOwner: false }, c);
  assert.equal(other.outcome, "block");
  assert.ok(unjudged.has("agent:main:t"));
  let reads = 0;
  const typedEvent = { senderIsOwner: true, get prompt() { if (reads++ === 0) boom(); return "hi"; } };
  assert.deepEqual(await hooks.before_agent_run(typedEvent, c), { outcome: "pass" });
  unjudged.delete("agent:main:t");
  // agent_end: swallowed.
  assert.equal(await hooks.agent_end({}, { get sessionKey() { return boom(); }, runId: "rt" }), undefined);
  // Output the guard cannot be given and that cannot be written out is recorded as unjudged.
  const circular = {};
  circular.self = circular;
  await afterToolCall({ ...exec, toolCallId: "z1", result: circular }, c, STUB);
  assert.ok(unjudged.has("agent:main:t"));
  unjudged.delete("agent:main:t");
  // A handler that fails with no session records nothing and still answers.
  assert.equal((await failClosed(boom, () => "answered")({}, undefined)), "answered");
});
