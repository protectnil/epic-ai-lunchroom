"""Lunchroom's Hermes plugin, run against a stand-in of Hermes's approval gate (python3 -m unittest).

Spec: §13 H1 (the adapter), §7 A1.1, A1.2 and §7::18 (the plugin reads Hermes's own
approval state at each call), H1.5 (no lockout), §5 T1 (whose text a turn is), §10 D1.1 (a turn
takes the next message). The stand-in gate keeps the names and meanings of ``tools/approval.py``
at hermes-agent 9976f48: ``_yolo_active``, ``approval_context._get_approval_mode``, ``_presence``,
``is_approval_bypass_active_for_session``, ``get_current_session_key``.
"""

import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.environ.get("CARGO_TARGET_DIR") or os.path.join(HERE, "..", "..", "target")
BUILT = os.environ.get("LUNCHROOM_TEST_PROGRAM") or os.path.join(TARGET, "release", "lunchroom")


class Gate(types.ModuleType):
    """Hermes's approval gate for one session: process ``--yolo``, the session's ``/yolo``,
    ``approvals.mode``, an unattended turn (``hermes -z``) and the surfaces present."""

    def __init__(self):
        super().__init__("tools.approval")
        self.frozen = False
        self.session_yolo = set()
        self.mode = "manual"
        self.unattended = False
        self.surfaces = (True, False, False)
        # "cron", "single_query", or "unattended" (an API or webhook platform with no notifier).
        self.context = ""
        self.key = "k1"
        self.approval_context = types.SimpleNamespace(_get_approval_mode=lambda: self.mode)

    def _yolo_active(self):
        return self.frozen or self.key in self.session_yolo or self.unattended

    def is_approval_bypass_active_for_session(self, key):
        return self.frozen or key in self.session_yolo or self.mode == "off"

    def get_current_session_key(self, default=""):
        return self.key or default

    def _presence(self, callback):
        # tools/approval.py 933-966: a single-query or cron context clears every surface; an
        # unattended platform with nobody to answer drops the ask surface.
        cli, gateway, ask = self.surfaces
        if self.context in ("cron", "single_query"):
            cli = gateway = ask = False
        elif self.context == "unattended":
            ask = False
        return (callback, cli, gateway, ask)


def load_plugin(gate):
    tools = types.ModuleType("tools")
    tools.approval = gate
    sys.modules["tools"] = tools
    sys.modules["tools.approval"] = gate
    spec = importlib.util.spec_from_file_location("lunchroom_hermes", os.path.join(HERE, "__init__.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STUB = """#!/bin/sh
printf '%s\\n' "$@" > "$STUB_ARGS"
cat > "$STUB_IN"
case "$STUB_MODE" in
  deny) echo "Lunchroom: DENIED . fence" >&2; exit 2 ;;
  ask) printf '%s' '{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"Lunchroom: h1 is HELD."}}' ;;
  deliver) printf '%s\\n' "${STUB_TEXT:-lunchroom delivery: 1 message}" >&2; exit 2 ;;
  signal) kill -TERM $$ ;;
  exit1) exit 1 ;;
  garbage) printf 'not json' ;;
esac
exit 0
"""


class PluginWithStandInGuard(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lunchroom-hermes-")
        self.program = os.path.join(self.dir, "lunchroom")
        with open(self.program, "w") as f:
            f.write(STUB)
        os.chmod(self.program, stat.S_IRWXU)
        os.environ["STUB_IN"] = os.path.join(self.dir, "in.json")
        os.environ["STUB_ARGS"] = os.path.join(self.dir, "args.txt")
        os.environ["STUB_MODE"] = "allow"
        os.environ.pop("STUB_TEXT", None)
        self.gate = Gate()
        self.plugin = load_plugin(self.gate)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def sent(self):
        with open(os.environ["STUB_IN"]) as f:
            return json.load(f)

    def args(self):
        with open(os.environ["STUB_ARGS"]) as f:
            return f.read().split()

    def call(self, **extra):
        kwargs = dict(tool_name="terminal", args={"command": "ls"}, session_id="h1", tool_call_id="c1")
        kwargs.update(extra)
        return self.plugin.on_pre_tool_call(program=self.program, **kwargs)

    def test_call_reaches_the_guard_as_hermes_sent_it(self):
        self.assertIsNone(self.call())
        self.assertEqual(self.args(), ["guard", "pretool"])
        sent = self.sent()
        self.assertEqual(sent["harness"], "hermes")
        self.assertEqual(sent["session_id"], "h1")
        self.assertEqual(sent["tool_name"], "terminal")
        # A2.1: the directory the command runs in is part of the input the guard judges.
        # The session's own folder after a `cd` is unknown to the plugin, and the input says so.
        self.assertEqual(sent["tool_input"], {"command": "ls", "workdir_unknown": True})
        self.assertEqual(sent["tool_use_id"], "c1")
        self.assertIs(sent["approval_channel"], True)
        self.assertIs(sent["harness_yolo"], False)
        self.assertEqual(sent["plugin_file"], os.path.join(HERE, "__init__.py"))

    def test_denied_call_is_blocked_with_the_guards_reason(self):
        os.environ["STUB_MODE"] = "deny"
        self.assertEqual(self.call(), {"action": "block", "message": "Lunchroom: DENIED . fence"})

    def test_call_for_the_user_is_denied_where_nobody_can_be_asked(self):
        os.environ["STUB_MODE"] = "ask"
        self.gate.session_yolo.add("k1")
        self.assertEqual(self.call(), {"action": "block", "message": "Lunchroom: h1 is HELD."})

    def test_call_for_the_user_asks_with_a_rule_key_unique_to_the_call(self):
        os.environ["STUB_MODE"] = "ask"
        first = self.call(tool_call_id="c1")
        second = self.call(tool_call_id="c2")
        self.assertEqual(first["action"], "approve")
        self.assertEqual(first["message"], "Lunchroom: h1 is HELD.")
        self.assertNotEqual(first["rule_key"], second["rule_key"])
        self.assertNotEqual(self.call(tool_call_id="")["rule_key"], self.call(tool_call_id="")["rule_key"])
        self.assertNotEqual(self.call(tool_call_id="c1")["rule_key"], self.call(tool_call_id="c1")["rule_key"])

    def test_version_is_reported_from_hermes_version_information(self):
        info = types.ModuleType("hermes_cli.version_info")
        info.get_version_info = lambda: types.SimpleNamespace(commit="9976f4857b72439d79016354d7b6e1a3ee952e2f",
                                                              commit_date=1793038003, base_version="unknown")
        sys.modules["hermes_cli"] = types.ModuleType("hermes_cli")
        sys.modules["hermes_cli.version_info"] = info
        try:
            self.call()
            self.assertEqual(self.sent()["harness_version"],
                             "9976f4857b72439d79016354d7b6e1a3ee952e2f@1793038003")
            info.get_version_info = lambda: types.SimpleNamespace(commit=None, commit_date=None,
                                                                  base_version="2026.9.24")
            self.call()
            self.assertEqual(self.sent()["harness_version"], "2026.9.24")
        finally:
            sys.modules.pop("hermes_cli.version_info", None)
            sys.modules.pop("hermes_cli", None)
        self.call()
        self.assertEqual(self.sent()["harness_version"], "")

    def test_each_no_person_setting_is_reported_and_yolo_is_reported(self):
        # A1.2: every Hermes case where nobody is asked.
        for name, change in [
            ("--yolo", lambda g: setattr(g, "frozen", True)),
            ("/yolo", lambda g: g.session_yolo.add("k1")),
            ("approvals.mode: off", lambda g: setattr(g, "mode", "off")),
            ("hermes -z", lambda g: setattr(g, "unattended", True)),
            ("no surface", lambda g: setattr(g, "surfaces", (False, False, False))),
        ]:
            self.gate.__init__()
            change(self.gate)
            self.call()
            self.assertIs(self.sent()["approval_channel"], False, name)
        for surfaces in [(False, True, False), (False, False, True)]:
            self.gate.__init__()
            self.gate.surfaces = surfaces
            self.call()
            self.assertIs(self.sent()["approval_channel"], True, surfaces)
        # R2.1: Hermes's own YOLO is --yolo, a session's /yolo or approvals.mode: off.
        for name, change, on in [
            ("--yolo", lambda g: setattr(g, "frozen", True), True),
            ("/yolo", lambda g: g.session_yolo.add("k1"), True),
            ("off", lambda g: setattr(g, "mode", "off"), True),
            ("hermes -z", lambda g: setattr(g, "unattended", True), False),
        ]:
            self.gate.__init__()
            change(self.gate)
            self.call()
            self.assertIs(self.sent()["harness_yolo"], on, name)

    def test_cron_single_query_and_unattended_contexts_report_no_person(self):
        # A1.2: in a cron or single-query context, and on an unattended platform whose only
        # surface is the ask bridge, Hermes resolves an approval from its mode (deny, or approve
        # without a person): the plugin reports no person, and a guard that cannot answer DENIES.
        for context in ("cron", "single_query", "unattended"):
            self.gate.__init__()
            self.gate.context = context
            # A CLI and an ask surface for cron and single-query; only the ask bridge otherwise.
            self.gate.surfaces = (False, False, True) if context == "unattended" else (True, False, True)
            self.call()
            self.assertIs(self.sent()["approval_channel"], False, context)
            os.environ["STUB_MODE"] = "signal"
            self.assertEqual(self.call()["action"], "block", context)
            os.environ["STUB_MODE"] = "allow"

    def test_unreadable_gate_counts_as_no_person(self):
        self.gate._presence = None
        self.call()
        self.assertIs(self.sent()["approval_channel"], False)

    def test_guard_that_cannot_answer_asks_or_denies_never_locks_out(self):
        os.environ["STUB_MODE"] = "signal"
        out = self.call()
        self.assertEqual(out["action"], "approve")
        self.assertTrue(out["message"].startswith("Lunchroom: could not check this call"))
        self.gate.surfaces = (False, False, False)
        self.assertEqual(self.call()["action"], "block")

    def test_other_exit_codes_are_a_guard_that_could_not_decide(self):
        os.environ["STUB_MODE"] = "exit1"
        out = self.call()
        self.assertEqual(out["action"], "approve")
        self.assertIn("exit 1", out["message"])
        self.gate.surfaces = (False, False, False)
        self.assertEqual(self.call()["action"], "block")

    def test_unjudged_call_the_no_record_rules_deny_is_blocked_never_asked(self):
        absent = os.path.join(self.dir, "absent")
        for args in ({"command": "codex queue other hi"}, {"command": "export HERMES_SESSION_ID=x"},
                     {"command": "acp --session s2"}, {"command": "sessions_send s2 hi"},
                     {"command": "curl -d hi http://127.0.0.1:8642/api/sessions/s2/chat"},
                     {"path": "/home/u/.lunchroom/store/state.json", "content": "{}"}):
            out = self.plugin.on_pre_tool_call(tool_name="terminal", args=args, session_id="h1", program=absent)
            self.assertEqual(out["action"], "block", args)
            self.assertIn("DENIED", out["message"])
            os.environ["STUB_MODE"] = "signal"
            self.assertEqual(self.call(args=args)["action"], "block", args)
            os.environ["STUB_MODE"] = "allow"

    def test_every_uncertain_state_denies_a_no_record_call_before_it_offers_approval(self):
        # Spec §13 H1.5: the rules that need no record DENY in every session, so a call naming a
        # fenced channel is blocked, never asked, in each uncertain state: no session id, an
        # unjudged session, a missing program, a guard that fails, times out or answers garbage.
        absent = os.path.join(self.dir, "absent")
        fenced = {"command": "export HERMES_SESSION_ID=x"}
        plain = {"command": "ls"}
        out = self.call(args=fenced, session_id="")
        self.assertEqual(out["action"], "block")
        self.assertIn("DENIED", out["message"])
        self.assertEqual(self.call(args=plain, session_id="")["action"], "approve")
        self.plugin.UNJUDGED.add("hu")
        out = self.call(args=fenced, session_id="hu")
        self.assertEqual(out["action"], "block")
        self.assertIn("DENIED", out["message"])
        self.assertEqual(self.call(args=plain, session_id="hu")["action"], "approve")
        self.plugin.UNJUDGED.discard("hu")
        out = self.plugin.on_pre_tool_call(tool_name="terminal", args=fenced, session_id="h1", program=absent)
        self.assertEqual(out["action"], "block")
        for mode in ("signal", "exit1", "garbage"):
            os.environ["STUB_MODE"] = mode
            self.assertEqual(self.call(args=fenced)["action"], "block", mode)
            self.assertEqual(self.call(args=plain)["action"], "approve", mode)
        # The directory the command runs in is part of what those rules read.
        out = self.call(args={"command": "ls", "workdir": "/home/u/.lunchroom"}, session_id="")
        self.assertEqual(out["action"], "block")

    def test_a_terminal_command_is_judged_and_bound_in_the_directory_it_runs_in(self):
        # Spec §8 A2.1: "An approval covers one tool call: the session id, the tool name and its
        # exact input". Failure classes: workdir absolute, padded, `~`, normalised; absent, empty,
        # non-string and relative (the session's own folder, unknown to the plugin); a marker the
        # agent wrote itself; a tool that is not a terminal; the output report.
        home = os.path.expanduser("~")
        for given, want in (
            ("/home/u/.aws", {"workdir": "/home/u/.aws"}),
            ("  /home/u/.aws ", {"workdir": "/home/u/.aws"}),
            ("/home/u/x/../.aws", {"workdir": "/home/u/.aws"}),
            ("~", {"workdir": home}),
            ("~/.aws", {"workdir": os.path.join(home, ".aws")}),
            ("sub/dir", {"workdir_unknown": True}),
            ("", {"workdir_unknown": True}),
            ("  ", {"workdir_unknown": True}),
            (7, {"workdir_unknown": True}),
            (None, {"workdir_unknown": True}),
        ):
            self.call(args={"command": "cat credentials", "workdir": given})
            self.assertEqual(self.sent()["tool_input"], dict({"command": "cat credentials"}, **want), given)
        # No workdir at all, and a marker the agent wrote beside an absolute workdir: the plugin's
        # reading wins, since the agent cannot declare its folder known.
        self.call(args={"command": "cat credentials"})
        self.assertEqual(self.sent()["tool_input"], {"command": "cat credentials", "workdir_unknown": True})
        self.call(args={"command": "c", "workdir": "/d", "workdir_unknown": True})
        self.assertEqual(self.sent()["tool_input"], {"command": "c", "workdir": "/d"})
        self.call(tool_name="read_file", args={"path": "x"})
        self.assertEqual(self.sent()["tool_input"], {"path": "x"})
        self.plugin.on_post_tool_call(tool_name="terminal", args={"command": "c", "workdir": "/d"}, result="ok",
                                      session_id="h1", status="ok", program=self.program)
        self.assertEqual(self.sent()["tool_input"], {"command": "c", "workdir": "/d"})

    def test_a_terminal_command_without_an_absolute_workdir_is_judged_in_the_sessions_own_folder(self):
        # Spec §8 A2.1. Hermes 9976f48 tools/terminal_tool.py: "explicit ``workdir`` > the session's
        # own cwd record > ``default_cwd``" (993); get_session_cwd (277); session key
        # `get_current_session_key(default="") or task_id` (1494-1496); default
        # `overrides.get("cwd") or get_session_cwd(task_id) or config["cwd"]` (1183-1187).
        # Failure classes: a recorded folder; none recorded (override, then task record, then
        # config); relative and empty workdir; an absolute workdir wins; a recorded folder that is
        # not absolute; a failing read; the output report after a `cd` moved the folder.
        state = {"session": {}, "overrides": {}, "config": {"cwd": "/cfg"}, "fail": False}

        def get_session_cwd(key):
            if state["fail"]:
                raise RuntimeError("unreadable")
            return state["session"].get(key)

        terminal = types.ModuleType("tools.terminal_tool")
        terminal.get_session_cwd = get_session_cwd
        terminal.resolve_task_overrides = lambda task_id: state["overrides"].get(task_id, {})
        terminal._get_env_config = lambda: state["config"]
        sys.modules["tools.terminal_tool"] = terminal
        self.addCleanup(sys.modules.pop, "tools.terminal_tool", None)
        judged = lambda **kw: self.plugin.judged_input("terminal", dict({"command": "cat credentials"}, **kw), "t1")
        # Nothing recorded: the configured default.
        self.assertEqual(judged()["workdir"], "/cfg")
        state["overrides"]["t1"] = {"cwd": "/ovr"}
        self.assertEqual(judged()["workdir"], "/ovr")
        state["overrides"] = {}
        state["session"]["t1"] = "/task"
        self.assertEqual(judged()["workdir"], "/task")
        # The session's own record (key from the gate, "k1") wins, after a `cd ~/.aws`.
        state["session"]["k1"] = "/home/u/.aws"
        self.assertEqual(judged(), {"command": "cat credentials", "workdir": "/home/u/.aws"})
        self.assertEqual(judged(workdir="")["workdir"], "/home/u/.aws")
        self.assertEqual(judged(workdir=7)["workdir"], "/home/u/.aws")
        self.assertEqual(judged(workdir="sub/../x")["workdir"], "/home/u/.aws/x")
        self.assertEqual(judged(workdir="/abs")["workdir"], "/abs")
        # The input the guard is given carries it, and the report reuses what was judged.
        self.call(args={"command": "cd /; ls"}, task_id="t1", tool_call_id="c9")
        self.assertEqual(self.sent()["tool_input"], {"command": "cd /; ls", "workdir": "/home/u/.aws"})
        state["session"]["k1"] = "/"
        self.plugin.on_post_tool_call(tool_name="terminal", args={"command": "cd /; ls"}, result="ok",
                                      session_id="h1", tool_call_id="c9", status="ok", task_id="t1",
                                      program=self.program)
        self.assertEqual(self.sent()["tool_input"], {"command": "cd /; ls", "workdir": "/home/u/.aws"})
        self.assertNotIn("c9", self.plugin.JUDGED)
        # Not an absolute folder, or unreadable: the folder is unknown.
        state["session"]["k1"] = "rel/dir"
        self.assertEqual(judged(), {"command": "cat credentials", "workdir_unknown": True})
        state["fail"] = True
        self.assertEqual(judged(), {"command": "cat credentials", "workdir_unknown": True})
        self.assertEqual(judged(workdir="/abs")["workdir"], "/abs")

    def test_an_unjudged_or_sessionless_call_still_asks_the_healthy_guard_and_is_never_offered_what_it_denies(self):
        # Spec §13 H1.5 and §7 A1.4. Failure classes: the guard DENIES (exit 2), asks, or lets the
        # call run, each with no session id and with an unjudged session; names the plugin's list
        # missed by spelling (quoted, split, upper case, `lunchroom approve`).
        self.plugin.UNJUDGED.add("hu")
        for session in ("", "hu"):
            os.environ["STUB_MODE"] = "deny"
            out = self.call(args={"command": "ls"}, session_id=session)
            self.assertEqual(out, {"action": "block", "message": "Lunchroom: DENIED . fence"}, session)
            self.assertEqual(self.args(), ["guard", "pretool"])
            os.environ["STUB_MODE"] = "ask"
            out = self.call(args={"command": "ls"}, session_id=session)
            self.assertEqual(out["action"], "approve")
            self.assertIn("h1 is HELD", out["message"])
            self.gate.surfaces = (False, False, False)
            self.assertEqual(self.call(args={"command": "ls"}, session_id=session)["action"], "block")
            self.gate.surfaces = (True, False, False)
            # The guard lets it run, yet what the plugin knows holds: the user decides.
            os.environ["STUB_MODE"] = "allow"
            self.assertEqual(self.call(args={"command": "ls"}, session_id=session)["action"], "approve")
        absent = os.path.join(self.dir, "absent")
        for command in ("lunchroom approve", "lunchroom yolo on", "LUNCHROOM mode relaxed", "'lunch''room' approve",
                        "l\\unchroom approve", "\"cl\"\"aude\" --resume s1", "cla'ud'e --resume s1",
                        "hermes chat --resume s1", "sessions_send s2 hi"):
            for session in ("", "hu"):
                self.plugin.UNJUDGED.add("hu")
                os.environ["STUB_MODE"] = "ask"
                out = self.call(args={"command": command}, session_id=session)
                self.assertEqual(out["action"], "block", command)
                self.assertIn("DENIED", out["message"])
                out = self.plugin.on_pre_tool_call(tool_name="terminal", args={"command": command},
                                                   session_id=session, program=absent)
                self.assertEqual(out["action"], "block", command)
                self.assertIn("DENIED", out["message"])

    def test_an_approval_request_for_a_call_the_guard_could_not_judge_shows_the_call_in_full(self):
        # Spec §7 A1.4: the request starts "Lunchroom:", and the call's own input is shown in full.
        command = "cat " + "x" * 600 + " > /tmp/out"
        absent = os.path.join(self.dir, "absent")
        for session, program in (("h1", absent), ("", self.program), ("hu", self.program)):
            self.plugin.UNJUDGED.add("hu")
            out = self.plugin.on_pre_tool_call(tool_name="terminal", args={"command": command, "workdir": "/d"},
                                               session_id=session, program=program)
            self.assertEqual(out["action"], "approve", session)
            self.assertTrue(out["message"].startswith("Lunchroom: "), out["message"][:40])
            self.assertIn(command, out["message"])
            self.assertIn('"workdir": "/d"', out["message"])
            self.assertIn("terminal", out["message"])

    def test_missing_program_sends_the_call_to_the_user_or_denies_it(self):
        absent = os.path.join(self.dir, "absent")
        out = self.plugin.on_pre_tool_call(tool_name="terminal", args={}, session_id="h1", program=absent)
        self.assertEqual(out["action"], "approve")
        self.assertIn("its program is missing", out["message"])
        self.gate.surfaces = (False, False, False)
        out = self.plugin.on_pre_tool_call(tool_name="terminal", args={}, session_id="h1", program=absent)
        self.assertEqual(out["action"], "block")

    def test_no_session_goes_to_the_user_or_is_denied(self):
        self.assertEqual(self.call(session_id="")["action"], "approve")
        self.gate.surfaces = (False, False, False)
        self.assertEqual(self.call(session_id="")["action"], "block")

    def test_blocked_or_cancelled_call_is_not_reported_as_run(self):
        os.remove(os.environ["STUB_IN"]) if os.path.exists(os.environ["STUB_IN"]) else None
        for status in ("blocked", "cancelled"):
            self.plugin.on_post_tool_call(tool_name="terminal", args={}, result="x", session_id="h1",
                                          tool_call_id="c1", status=status, program=self.program)
            self.assertFalse(os.path.exists(os.environ["STUB_IN"]), status)
        self.plugin.on_post_tool_call(tool_name="terminal", args={"command": "ls"}, result="out",
                                      session_id="h1", tool_call_id="c1", status="ok", program=self.program)
        self.assertEqual(self.args(), ["guard", "posttool"])
        self.assertEqual(self.sent()["tool_response"], "out")

    def test_turn_text_is_typed_only_on_this_computers_surfaces(self):
        log = []
        real = self.plugin.run_guard

        def spy(args, payload, program=None):
            log.append((args, payload))
            return real(args, payload, program)

        self.plugin.run_guard = spy
        for platform, typed in [("cli", True), ("tui", True), ("desktop", True), ("telegram", False),
                                ("api_server", False), ("cron", False), ("", False)]:
            log.clear()
            self.plugin.on_pre_llm_call(session_id="h1", user_message="hi", platform=platform,
                                        turn_id="t1", program=self.program)
            # The prompt reaches the guard first; then the listener runs.
            self.assertEqual([a for a, _ in log], [["guard", "prompt"], ["listen", "--once"]])
            self.assertIs(log[0][1]["user_typed"], typed, platform)
            self.assertEqual(log[0][1]["prompt"], "hi")
        # A subagent's turn is its parent's text: not the user's typing (T1).
        log.clear()
        self.plugin.on_pre_llm_call(session_id="h1", user_message="hi", platform="subagent", program=self.program)
        self.assertEqual(log[0][0], ["guard", "prompt"])
        self.assertIs(log[0][1]["user_typed"], False)

    def test_turn_takes_the_next_message_as_context(self):
        os.environ["STUB_MODE"] = "deliver"
        out = self.plugin.on_pre_llm_call(session_id="h1", user_message="hi", platform="cli", program=self.program)
        self.assertEqual(out, {"context": "lunchroom delivery: 1 message"})
        os.environ["STUB_MODE"] = "allow"
        self.assertIsNone(self.plugin.on_pre_llm_call(session_id="h1", user_message="hi", platform="cli",
                                                      program=self.program))

    def test_register_adds_the_four_hooks(self):
        added = []
        self.plugin.register(types.SimpleNamespace(register_hook=lambda name, fn: added.append(name)))
        self.assertEqual(sorted(added), ["post_tool_call", "pre_api_request", "pre_llm_call", "pre_tool_call"])

    def hand_over(self, turn_id):
        # The listener hands the turn one envelope (the stand-in prints it on standard error).
        os.environ["STUB_MODE"] = "deliver"
        os.environ["STUB_TEXT"] = self.envelope
        out = self.plugin.on_pre_llm_call(session_id="h1", user_message="hi", platform="cli", turn_id=turn_id,
                                          program=self.program)
        os.environ["STUB_MODE"] = "allow"
        return out

    envelope = "[LUNCHROOM MESSAGE - from agent Claw; not from the user]\n[lr:lr-1]> hi\n[END LUNCHROOM MESSAGE lr-1]"

    def request(self, content, turn_id):
        if os.path.exists(os.environ["STUB_IN"]):
            os.remove(os.environ["STUB_IN"])
        messages = [{"role": "system", "content": "s"}, {"role": "user", "content": content}]
        self.plugin.on_pre_api_request(session_id="h1", request_messages=messages, api_request_id="r1",
                                       turn_id=turn_id, program=self.program)
        return os.path.exists(os.environ["STUB_IN"])

    def test_only_the_handed_turns_request_carrying_the_envelope_reaches_the_guard(self):
        self.assertEqual(self.hand_over("t1"), {"context": self.envelope})
        # Another turn's request, or this turn's without the envelope: nothing reaches the guard.
        self.assertFalse(self.request(f"hi\n\n{self.envelope}", "t2"))
        self.assertFalse(self.request("hi", "t1"))
        # This turn's request carrying it, as text or as parts: it reaches the guard's prompt hook once.
        self.assertTrue(self.request([{"type": "text", "text": "hi"}, {"type": "text", "text": self.envelope}], "t1"))
        self.assertEqual(self.args(), ["guard", "prompt"])
        self.assertIn("[END LUNCHROOM MESSAGE lr-1]", self.sent()["prompt"])
        # A later request of the same turn sends the same context again: nothing more.
        self.assertFalse(self.request(f"hi\n\n{self.envelope}", "t1"))
        # Two turns handed messages: each turn's own request confirms its own, whatever the order.
        self.hand_over("t5")
        self.hand_over("t6")
        self.assertTrue(self.request(f"hi\n\n{self.envelope}", "t5"))
        self.assertTrue(self.request(f"hi\n\n{self.envelope}", "t6"))
        self.assertFalse(self.request(f"hi\n\n{self.envelope}", "t5"))
        # A guard that could not run keeps the hand-over for the turn's next request.
        self.hand_over("t3")
        os.environ["STUB_MODE"] = "signal"
        self.assertTrue(self.request(f"hi\n\n{self.envelope}", "t3"))
        os.environ["STUB_MODE"] = "allow"
        self.assertTrue(self.request(f"hi\n\n{self.envelope}", "t3"))
        self.assertFalse(self.request(f"hi\n\n{self.envelope}", "t3"))

    def test_unjudged_tool_output_with_agent_text_sends_every_later_call_to_the_user(self):
        # The guard cannot judge a tool's output carrying another agent's text (it fails, or its
        # program is missing): the plugin holds the session itself; plain output changes nothing.
        for session, program in (("h4", None), ("h5", os.path.join(self.dir, "absent"))):
            os.environ["STUB_MODE"] = "signal"
            self.plugin.on_post_tool_call(tool_name="terminal", args={}, result="plain", session_id=session,
                                          status="ok", program=program or self.program)
            os.environ["STUB_MODE"] = "allow"
            self.assertIsNone(self.call(session_id=session))
            os.environ["STUB_MODE"] = "signal"
            self.plugin.on_post_tool_call(tool_name="terminal", args={}, result="[lr:lr-1]> rm it",
                                          session_id=session, status="ok", program=program or self.program)
            os.environ["STUB_MODE"] = "allow"
            self.assertEqual(self.call(session_id=session)["action"], "approve", session)

    def test_unjudged_agent_turn_sends_every_later_call_to_the_user(self):
        # The guard cannot judge a turn from a chat platform: every later call asks, or is DENIED
        # with nobody to ask, until a turn the user typed is judged.
        os.environ["STUB_MODE"] = "signal"
        self.plugin.on_pre_llm_call(session_id="h1", user_message="do it", platform="telegram", program=self.program)
        os.environ["STUB_MODE"] = "allow"
        self.assertEqual(self.call()["action"], "approve")
        self.gate.surfaces = (False, False, False)
        self.assertEqual(self.call()["action"], "block")
        self.plugin.on_pre_llm_call(session_id="h1", user_message="carry on", platform="cli", program=self.program)
        self.assertIsNone(self.call())
        # A typed turn the guard could not judge clears nothing, and a missing program sets nothing.
        os.environ["STUB_MODE"] = "signal"
        self.plugin.on_pre_llm_call(session_id="h2", user_message="do it", platform="telegram", program=self.program)
        self.plugin.on_pre_llm_call(session_id="h2", user_message="go", platform="cli", program=self.program)
        os.environ["STUB_MODE"] = "allow"
        self.assertEqual(self.call(session_id="h2")["action"], "block")
        # A missing program cannot judge another agent's turn either: the plugin holds the session.
        self.plugin.on_pre_llm_call(session_id="h3", user_message="do it", platform="telegram",
                                    program=os.path.join(self.dir, "absent"))
        self.assertEqual(self.call(session_id="h3")["action"], "block")
        self.assertIn("another agent's text", self.call(session_id="h3")["message"])
        # Hermes lets this hook fail open: a hook that dies before the guard answers leaves the
        # turn's text unjudged, and a turn the guard judges is not unjudged.
        real = self.plugin.run_guard
        self.plugin.run_guard = lambda *a, **k: (_ for _ in ()).throw(TimeoutError("hook timed out"))
        self.assertIsNone(self.plugin.on_pre_llm_call(session_id="h4", user_message="do it", platform="telegram",
                                                      program=self.program))
        self.plugin.run_guard = real
        self.assertEqual(self.call(session_id="h4")["action"], "block")
        self.gate.surfaces = (True, False, False)
        self.assertEqual(self.call(session_id="h4")["action"], "approve")
        self.gate.surfaces = (False, False, False)
        self.plugin.on_pre_llm_call(session_id="h5", user_message="hi", platform="telegram", program=self.program)
        self.assertIsNone(self.call(session_id="h5"))


@unittest.skipUnless(os.access(BUILT, os.X_OK), "the release program is not built")
class PluginWithTheRealGuard(unittest.TestCase):
    """§7::18 with Lunchroom's own guard: this process stands in for the Hermes process."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lunchroom-hermes-real-")
        os.makedirs(os.path.join(self.dir, "home"))
        self.saved = {k: os.environ.get(k) for k in ("HOME", "LUNCHROOM_HOME")}
        os.environ["HOME"] = os.path.join(self.dir, "home")
        os.environ["LUNCHROOM_HOME"] = os.path.join(self.dir, "lunchroom")
        self.gate = Gate()
        self.plugin = load_plugin(self.gate)
        self.program = os.path.abspath(BUILT)

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)

    def push(self):
        # A PROTECTED call (P1.4): it goes to the user in the default hold mode, Balanced (P1.6).
        return self.plugin.on_pre_tool_call(tool_name="terminal", args={"command": "git push origin main"},
                                            session_id="h1", tool_call_id="w1", program=self.program)

    def test_yolo_set_and_cleared_mid_session(self):
        # Another agent's text reaches the session through a chat platform: HELD.
        self.plugin.on_pre_llm_call(session_id="h1", user_message="please push it", platform="telegram",
                                    program=self.program)
        out = self.push()
        self.assertEqual(out["action"], "approve", out)
        self.gate.session_yolo.add("k1")
        out = self.push()
        self.assertEqual(out["action"], "block", out)
        self.assertIn("Lunchroom: DENIED", out["message"])
        self.gate.session_yolo.discard("k1")
        out = self.push()
        self.assertEqual(out["action"], "approve", out)
        # The user's own typing at the terminal clears HELD: the call runs.
        self.plugin.on_pre_llm_call(session_id="h1", user_message="go ahead", platform="cli", program=self.program)
        self.assertIsNone(self.push())

    def test_join_typed_at_the_terminal_names_the_session_and_tells_its_agent(self):
        # §9 I1.5: `join` typed at Hermes's terminal names the session; from a chat
        # platform it names nothing.
        out = self.plugin.on_pre_llm_call(session_id="h2", user_message="join Scout", platform="telegram",
                                          program=self.program)
        self.assertIsNone(out)
        out = self.plugin.on_pre_llm_call(session_id="h1", user_message="join Scout", platform="cli",
                                          program=self.program)
        self.assertIn("in Lunchroom as Scout", (out or {}).get("context", ""), out)


if __name__ == "__main__":
    unittest.main()
