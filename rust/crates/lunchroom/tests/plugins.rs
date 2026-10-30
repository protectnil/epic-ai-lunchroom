//! The `lunchroom` binary run as Lunchroom's OpenClaw and Hermes plugins run it: the plugin, inside
//! the harness process, starts the guard with JSON naming its harness. Here this test process
//! stands in for that harness process (a gateway that runs several sessions).

mod common;

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

use lunchroom_core::identity::{Harness, Identity};
use lunchroom_core::mail::Origin;

use common::Run;

const PROGRAM: &str = env!("CARGO_BIN_EXE_lunchroom");

/// The harness versions the plugin adapters were built for (H1.2).
const OPENCLAW_VERSION: &str = "2026.10.7";
const HERMES_VERSION: &str = "9976f4857b72439d79016354d7b6e1a3ee952e2f";

/// The shared sandbox with the stand-in harness programs' `bin` folder first on `PATH`, and
/// Hermes' plugin enabled.
struct Sandbox(common::Sandbox);

impl std::ops::Deref for Sandbox {
    type Target = common::Sandbox;

    fn deref(&self) -> &common::Sandbox {
        &self.0
    }
}

impl Sandbox {
    fn new() -> Self {
        let mut sb = common::Sandbox::new("plugin-tests");
        let _ = std::fs::create_dir_all(sb.root.join("home/.hermes"));
        let _ = std::fs::create_dir_all(sb.root.join("bin"));
        // Hermes has Lunchroom's plugin enabled (`hermes plugins enable lunchroom`).
        let _ = std::fs::write(
            sb.root.join("home/.hermes/config.yaml"),
            "plugins:\n  enabled:\n    - lunchroom\n",
        );
        sb.path = format!("{}:/usr/bin:/bin", sb.root.join("bin").display());
        // P1.6: these tests were written for the Strict hold mode, which the user chose here.
        Self(sb.strict())
    }

    /// The plugin file `lunchroom install` writes, with this test's program in it.
    fn plugin_file(&self, harness: &str) -> PathBuf {
        let (name, line) = if harness == "openclaw" {
            ("index.mjs", format!("const PROGRAM = \"{PROGRAM}\";\n"))
        } else {
            ("__init__.py", format!("PROGRAM = \"{PROGRAM}\"\n"))
        };
        let file = self.root.join(format!("plugin-{harness}")).join(name);
        if !file.exists() {
            let _ = std::fs::create_dir_all(file.parent().unwrap_or(&self.root));
            let _ = std::fs::write(&file, line);
        }
        file
    }

    /// A hook input from Lunchroom's plugin for `harness` and `session`.
    fn input(&self, harness: &str, session: &str, event: &str, extra: &Value) -> String {
        let version = if harness == "openclaw" {
            OPENCLAW_VERSION
        } else {
            HERMES_VERSION
        };
        let mut v = json!({
            "harness": harness, "session_id": session, "hook_event_name": event,
            "cwd": self.home().join("project"),
            "plugin_file": self.plugin_file(harness), "harness_version": version,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, val) in e {
                o.insert(k.clone(), val.clone());
            }
        }
        v.to_string()
    }

    fn pretool(
        &self,
        harness: &str,
        session: &str,
        tool: &str,
        input: &Value,
        channel: bool,
    ) -> Run {
        let text = self.input(
            harness,
            session,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": input, "tool_use_id": "t1",
                    "approval_channel": channel}),
        );
        self.run(&["guard", "pretool"], &text, &[])
    }

    fn prompt(&self, harness: &str, session: &str, text: &str, typed: bool) -> Run {
        let input = self.input(
            harness,
            session,
            "UserPromptSubmit",
            &json!({"prompt": text, "prompt_id": "p1", "user_typed": typed}),
        );
        self.run(&["guard", "prompt"], &input, &[])
    }

    /// `lunchroom send` from `session`, as its harness runs it: the session's hook runs first in this
    /// process (a gateway runs one harness), then the send, with the session named as that
    /// harness names it (OpenClaw's plugin: `LUNCHROOM_SESSION`; Hermes: `HERMES_SESSION_ID`).
    fn send_as(&self, harness: &str, session: &str, to: &str, text: &str) -> Run {
        self.send_as_with(harness, session, to, text, &[])
    }

    /// As [`Sandbox::send_as`], with `extra` also set in the sender's environment.
    fn send_as_with(
        &self,
        harness: &str,
        session: &str,
        to: &str,
        text: &str,
        extra: &[(&str, String)],
    ) -> Run {
        let tool = if harness == "openclaw" {
            "read"
        } else {
            "read_file"
        };
        let hook = self.pretool(harness, session, tool, &json!({"path": "/tmp/x"}), true);
        assert_eq!(hook.code, Some(0), "{}", hook.stderr);
        let named = if harness == "openclaw" {
            ("LUNCHROOM_SESSION", format!("openclaw:{session}"))
        } else {
            ("HERMES_SESSION_ID", session.to_owned())
        };
        let mut env = vec![named, ("OPENCLAW_SHELL", "exec".to_owned())];
        env.extend(extra.iter().cloned());
        self.run(&["send", to, text], "", &env)
    }

    fn name(&self, name: &str, who: &Identity) {
        let named = self.store().and_then(|s| {
            s.update(|m| m.register(name, who, Origin::User, None).ok())
                .ok()
        });
        assert!(named.is_some(), "{name}");
    }

    fn held(&self, who: &Identity) -> Option<bool> {
        self.store()
            .and_then(|s| s.read().ok())
            .map(|m| m.is_held(who))
    }

    fn state(&self, id: &str) -> Option<&'static str> {
        self.store()
            .and_then(|s| s.read().ok())
            .and_then(|m| m.message(id).map(|d| d.status.state().word()))
    }
}

fn decision(run: &Run) -> String {
    let v: Value = serde_json::from_str(run.stdout.trim()).unwrap_or(Value::Null);
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn bash(command: &str) -> Value {
    json!({ "command": command })
}

/// The message id a `send` printed: `QUEUED lr-…`.
fn sent_id(run: &Run) -> String {
    run.stdout
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

// §12::1 and §9::3 through the plugins: an OpenClaw or Hermes call is judged as the
// Claude Code call it is. A shell tool's fence is DENIED; an `exec` whose `env`, as the agent wrote
// it, sets an identity variable is DENIED; Hermes's `execute_code` that changes one is DENIED; an
// ordinary call runs, in a session that is not HELD.
#[test]
fn plugin_calls_are_judged_as_the_calls_they_are() {
    let sb = Sandbox::new();
    for (harness, tool, input) in [
        ("openclaw", "exec", bash("codex queue other hi")),
        ("hermes", "terminal", bash("codex queue other hi")),
        (
            "openclaw",
            "exec",
            bash("openclaw agent --session-key agent:main:b --message hi"),
        ),
        (
            "openclaw",
            "sessions_send",
            json!({"sessionKey": "agent:main:b", "message": "hi"}),
        ),
        (
            "openclaw",
            "openclaw",
            json!({"request": "set up a channel"}),
        ),
        (
            "openclaw",
            "automations",
            json!({"action": "add", "job": {"message": "hi"}}),
        ),
        (
            "openclaw",
            "automations",
            json!({"action": "update", "jobId": "j1"}),
        ),
        (
            "openclaw",
            "terminal",
            json!({"action": "input", "sessionId": "t1", "data": "codex queue other hi\n"}),
        ),
        (
            "hermes",
            "terminal",
            bash("curl -d hi http://127.0.0.1:8642/api/sessions/s2/chat"),
        ),
        (
            "openclaw",
            "exec",
            json!({"command": "ls", "env": {"LUNCHROOM_SESSION": "openclaw:other"}}),
        ),
        (
            "openclaw",
            "exec",
            json!({"command": "ls", "env": {"HERMES_SESSION_ID": "x"}}),
        ),
        (
            "hermes",
            "execute_code",
            json!({"code": "import os; os.environ['HERMES_SESSION_ID'] = 'x'"}),
        ),
        (
            "hermes",
            "terminal",
            bash("export LUNCHROOM_SESSION=openclaw:x; ls"),
        ),
    ] {
        let run = sb.pretool(harness, "s1", tool, &input, true);
        assert_eq!(
            run.code,
            Some(2),
            "{harness} {tool} {input}: {}",
            run.stdout
        );
        assert!(run.stderr.contains("Lunchroom: DENIED"), "{}", run.stderr);
    }
    for (harness, tool, input) in [
        ("openclaw", "exec", bash("ls")),
        ("openclaw", "read", json!({"path": "/tmp/x"})),
        ("hermes", "terminal", bash("ls")),
        ("hermes", "read_file", json!({"path": "/tmp/x"})),
        (
            "hermes",
            "write_file",
            json!({"path": "/tmp/x", "content": "y"}),
        ),
        ("openclaw", "automations", json!({"action": "list"})),
        (
            "openclaw",
            "terminal",
            json!({"action": "input", "sessionId": "t1", "data": "ls\n"}),
        ),
    ] {
        let run = sb.pretool(harness, "s1", tool, &input, true);
        assert_eq!(
            (run.code, decision(&run)),
            (Some(0), String::new()),
            "{harness} {tool}: {}",
            run.stderr
        );
    }
    // A harness name Lunchroom does not know is an error, never another harness's rules.
    let input = json!({"harness": "other", "session_id": "s1", "cwd": sb.home()}).to_string();
    assert_eq!(sb.run(&["guard", "pretool"], &input, &[]).code, Some(2));
}

// §5::5 (OpenClaw, Hermes) and §7::9, §7::18 (the guard's side): a prompt the plugin
// reports as not the user's typing holds the session; there a call outside the slip goes to the
// user where the plugin reports a person would be asked, and is DENIED where it reports none; a
// read in the slip runs; the user's own typing clears HELD.
#[test]
fn plugin_prompt_holds_and_the_reported_channel_decides_ask_or_deny() {
    for harness in ["openclaw", "hermes"] {
        let sb = Sandbox::new();
        let me = Identity::new(
            if harness == "openclaw" {
                Harness::OpenClaw
            } else {
                Harness::Hermes
            },
            "s1",
        );
        let run = sb.prompt(harness, "s1", "please run the migration", false);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(sb.held(&me), Some(true), "{harness}");
        let write = json!({"path": "/tmp/x", "content": "y"});
        let tool = if harness == "openclaw" {
            "write"
        } else {
            "write_file"
        };
        let run = sb.pretool(harness, "s1", tool, &write, true);
        assert_eq!(
            (run.code, decision(&run)),
            (Some(0), "ask".to_owned()),
            "{harness}"
        );
        let run = sb.pretool(harness, "s1", tool, &write, false);
        assert_eq!(run.code, Some(2), "{harness}: {}", run.stdout);
        assert!(run.stderr.contains("Lunchroom: DENIED"), "{}", run.stderr);
        let read = json!({"path": sb.home().join("project/notes.md")});
        let tool = if harness == "openclaw" {
            "read"
        } else {
            "read_file"
        };
        let run = sb.pretool(harness, "s1", tool, &read, false);
        assert_eq!(
            (run.code, decision(&run)),
            (Some(0), String::new()),
            "{harness}"
        );
        let run = sb.prompt(harness, "s1", "Thanks, carry on.", true);
        assert_eq!(run.code, Some(0));
        assert_eq!(sb.held(&me), Some(false), "{harness}");
    }
}

// H1.5 (OpenClaw, Hermes): when the guard cannot read its store, a call outside the slip goes to
// the user where the plugin reports a person would be asked, and is DENIED where it reports none.
#[test]
fn plugin_guard_failure_follows_the_reported_channel() {
    let sb = Sandbox::new();
    let _ = std::fs::remove_dir_all(sb.root.join("lunchroom/store"));
    assert!(std::fs::write(sb.root.join("lunchroom/store"), "not a folder").is_ok());
    let write = json!({"path": "/tmp/x", "content": "y"});
    let run = sb.pretool("hermes", "s1", "write_file", &write, true);
    assert_eq!(
        (run.code, decision(&run)),
        (Some(0), "ask".to_owned()),
        "{}",
        run.stderr
    );
    let run = sb.pretool("hermes", "s1", "write_file", &write, false);
    assert_eq!(run.code, Some(2), "{}", run.stdout);
}

// §9::11 and §9::2: in a gateway process running sessions A and B, a send names its
// session in the environment (`LUNCHROOM_SESSION` from the OpenClaw plugin, `HERMES_SESSION_ID`
// from Hermes) and is sent as that session; a variable naming a session a hook saw only in another
// process, or one no hook saw, is DENIED; with the variable absent the send is DENIED.
#[test]
fn gateway_sender_is_the_session_its_environment_names() {
    for (harness, var, prefix) in [
        ("openclaw", "LUNCHROOM_SESSION", "openclaw:"),
        ("hermes", "HERMES_SESSION_ID", ""),
    ] {
        let sb = Sandbox::new();
        let kind = if harness == "openclaw" {
            Harness::OpenClaw
        } else {
            Harness::Hermes
        };
        sb.name("Claude", &Identity::new(Harness::ClaudeCode, "c1"));
        for session in ["A", "B"] {
            let run = sb.pretool(harness, session, "read", &json!({"path": "/tmp/x"}), true);
            assert_eq!(run.code, Some(0), "{}", run.stderr);
        }
        // Session D's hook runs in another process (a shell this process starts).
        let input = sb.input(
            harness,
            "D",
            "PreToolUse",
            &json!({"tool_name": "read", "tool_input": {"path": "/tmp/x"}, "approval_channel": true}),
        );
        let in_file = sb.root.join("in-d.json");
        let _ = std::fs::write(&in_file, input);
        let other = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("\"{PROGRAM}\" guard pretool < \"{}\"", in_file.display()),
            ])
            .env_clear()
            .env("HOME", sb.home())
            .env("LUNCHROOM_HOME", sb.root.join("lunchroom"))
            .env("PATH", "/usr/bin:/bin")
            .status();
        assert!(other.is_ok_and(|s| s.success()));
        for session in ["A", "B"] {
            let named = format!("{prefix}{session}");
            let run = sb.run(&["send", "Claude", "hello"], "", &[(var, named)]);
            assert_eq!(run.code, Some(0), "{harness} {session}: {}", run.stderr);
            let id = sent_id(&run);
            let from = sb
                .store()
                .and_then(|s| s.read().ok())
                .and_then(|m| m.message(&id).map(|d| d.from.clone()));
            assert_eq!(from, Some(Identity::new(kind, session)), "{harness}");
        }
        for named in [format!("{prefix}D"), format!("{prefix}Z")] {
            let run = sb.run(&["send", "Claude", "hello"], "", &[(var, named.clone())]);
            assert_eq!(run.code, Some(3), "{harness} {named}: {}", run.stdout);
        }
        let run = sb.run(&["send", "Claude", "hello"], "", &[]);
        assert_eq!(run.code, Some(3), "{harness} absent: {}", run.stdout);
        // Another harness's variable names nothing: inherited when this harness was started from
        // another's session (measured live: a Hermes gateway started from Claude Code carries
        // `CLAUDE_CODE_SESSION_ID`), the send is still from the session this harness's own
        // variable names; alone, it names no session here, so the send is DENIED.
        let (other_var, other_value) = if harness == "openclaw" {
            ("HERMES_SESSION_ID", "A".to_owned())
        } else {
            ("LUNCHROOM_SESSION", "openclaw:A".to_owned())
        };
        let run = sb.run(
            &["send", "Claude", "inherited"],
            "",
            &[
                (var, format!("{prefix}A")),
                ("CLAUDE_CODE_SESSION_ID", "c9".to_owned()),
                ("CODEX_THREAD_ID", "x9".to_owned()),
                (other_var, other_value.clone()),
            ],
        );
        assert_eq!(run.code, Some(0), "{harness} inherited: {}", run.stderr);
        let id = sent_id(&run);
        let from = sb
            .store()
            .and_then(|s| s.read().ok())
            .and_then(|m| m.message(&id).map(|d| d.from.clone()));
        assert_eq!(from, Some(Identity::new(kind, "A")), "{harness}");
        let run = sb.run(
            &["send", "Claude", "hello"],
            "",
            &[(other_var, other_value)],
        );
        assert_eq!(run.code, Some(3), "{harness} {other_var}: {}", run.stdout);
        // This harness's own variable naming another harness's session is DENIED.
        if harness == "openclaw" {
            let run = sb.run(
                &["send", "Claude", "hello"],
                "",
                &[("LUNCHROOM_SESSION", "hermes:A".to_owned())],
            );
            assert_eq!(run.code, Some(3), "openclaw naming hermes: {}", run.stdout);
        }
    }
}

/// `openclaw.json` in the sandbox user's state folder, JSON5, with or without conversation access.
fn configure_openclaw(sb: &Sandbox, access: bool) {
    let dir = sb.home().join(".openclaw");
    let _ = std::fs::create_dir_all(&dir);
    let text = format!(
        "// written by the test\n{{\n  plugins: {{\n    entries: {{\n      lunchroom: {{ enabled: true, \
         hooks: {{ allowConversationAccess: {access}, }}, }},\n    }},\n  }},\n}}\n"
    );
    let _ = std::fs::write(dir.join("openclaw.json"), text);
}

/// A stand-in `openclaw` first on `PATH`: it records its arguments and environment, then exits.
fn stand_in_openclaw(sb: &Sandbox) {
    let file = sb.root.join("bin/openclaw");
    let log = sb.root.join("openclaw-calls.txt");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{log}'\nenv >> '{log}'\nexit 0\n",
        log = log.display()
    );
    let _ = std::fs::write(&file, script);
    // The hand-over runs the program the gateway process runs: a copy of `bash` here (`gateway`),
    // which takes `agent` for a script and finds this one on the gateway's `PATH`.
    let subcommand = sb.root.join("bin/agent");
    let _ = std::fs::write(
        &subcommand,
        format!("#!/bin/sh\nexec '{}' agent \"$@\"\n", file.display()),
    );
    let _ = Command::new("/bin/chmod")
        .args(["755"])
        .arg(&file)
        .arg(&subcommand)
        .status();
}

/// A stand-in OpenClaw gateway that has run one guard hook, alive until dropped.
struct Gateway(std::process::Child);

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A copy of `bash` named `openclaw`, so the hook it starts is recorded under a process running a
/// program of that name, as under a gateway. It runs the guard on `input`, then stays alive.
fn gateway(sb: &Sandbox, input: &str, n: u32) -> Option<Gateway> {
    gateway_with(sb, input, n, &[])
}

/// As [`gateway`], with `env` also in the gateway process's own environment.
fn gateway_with(sb: &Sandbox, input: &str, n: u32, env: &[(&str, &str)]) -> Option<Gateway> {
    let dir = sb.root.join("gateway");
    let _ = std::fs::create_dir_all(&dir);
    let fake = dir.join("openclaw");
    if !fake.exists() {
        std::fs::copy(common::which("bash")?, &fake).ok()?;
    }
    let input_file = sb.root.join(format!("gateway-{n}.json"));
    let done = sb.root.join(format!("gateway-{n}.done"));
    std::fs::write(&input_file, input).ok()?;
    // The last `true` keeps `bash` from replacing itself with `sleep`.
    let script = "\"$LR\" guard pretool < \"$IN\" > /dev/null; echo $? > \"$DONE\"; sleep 60; true";
    // A binary just copied can fail to start with "Text file busy" (see `codex_session`).
    let mut child = None;
    for _ in 0..50 {
        let started = Command::new(&fake)
            .args(["-c", script])
            .env_clear()
            .env("HOME", sb.home())
            .env("LUNCHROOM_HOME", sb.lunchroom())
            .env("PATH", &sb.path)
            .env("LR", PROGRAM)
            .env("IN", &input_file)
            .env("DONE", &done)
            .envs(env.iter().copied())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match started {
            Ok(c) => {
                child = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    let gateway = Gateway(child?);
    for _ in 0..500 {
        if std::fs::read_to_string(&done).is_ok_and(|code| code.trim() == "0") {
            return Some(gateway);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    None
}

// §10::1 (OpenClaw) and R3.1: a message to a guarded OpenClaw session goes to it
// through `openclaw agent --session-key` without the agent's `OPENCLAW_SHELL`; the turn's prompt
// reaching the plugin's `before_agent_run` confirms it (DELIVERED) and holds the session; the same
// prompt again is blocked. Without conversation access the session is UNGUARDED and gets nothing.
#[test]
fn openclaw_delivery_through_openclaw_agent_and_before_agent_run() {
    let sb = Sandbox::new();
    stand_in_openclaw(&sb);
    configure_openclaw(&sb, false);
    let key = "agent:main:lr1";
    let oc = Identity::new(Harness::OpenClaw, key);
    sb.name("Claw", &oc);
    sb.name("Hermes", &Identity::new(Harness::Hermes, "h1"));
    let hook = sb.input(
        "openclaw",
        key,
        "PreToolUse",
        &json!({"tool_name": "read", "tool_input": {"path": "/tmp/x"}, "approval_channel": true}),
    );
    let first_gateway = gateway(&sb, &hook, 1);
    assert!(first_gateway.is_some());
    assert_eq!(
        sb.pretool(
            "hermes",
            "h1",
            "read_file",
            &json!({"path": "/tmp/x"}),
            true
        )
        .code,
        Some(0)
    );
    // The sender's own `exec` shell is `OPENCLAW_SHELL=exec`; Lunchroom's delivery runs without it.
    let send = |text: &str| sb.send_as("hermes", "h1", "Claw", text);
    let run = send("Before access.");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stdout.contains("Claw is UNGUARDED."), "{}", run.stdout);
    assert!(!sb.root.join("openclaw-calls.txt").exists());
    configure_openclaw(&sb, true);
    // The first message is still QUEUED; `agent_end`'s listener hands it over now.
    let stop = sb.input("openclaw", key, "Stop", &json!({}));
    let run = sb.run(&["listen", "--once"], &stop, &[]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let calls = std::fs::read_to_string(sb.root.join("openclaw-calls.txt")).unwrap_or_default();
    assert!(
        calls.contains(&format!("agent\n--session-key\n{key}\n--message\n")),
        "{calls}"
    );
    assert!(
        calls.contains("[LUNCHROOM MESSAGE - from agent Hermes"),
        "{calls}"
    );
    assert!(!calls.contains("OPENCLAW_SHELL"), "{calls}");
    let first = sb
        .store()
        .and_then(|s| s.read().ok())
        .and_then(|m| m.handed_over_ids(&oc).first().cloned())
        .unwrap_or_default();
    assert_eq!(sb.state(&first), Some("QUEUED"));
    assert_eq!(sb.held(&oc), Some(false));
    // The turn's prompt reaches the plugin's `before_agent_run`.
    let prompt = calls
        .split("--message\n")
        .nth(1)
        .and_then(|rest| rest.split("\nHOME=").next())
        .unwrap_or_default()
        .to_owned();
    let run = sb.prompt("openclaw", key, &prompt, true);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(sb.state(&first), Some("DELIVERED"));
    assert_eq!(sb.held(&oc), Some(true));
    let run = sb.prompt("openclaw", key, &prompt, true);
    assert_eq!(run.code, Some(2), "{}", run.stdout);
    // A later message goes over at once from `lunchroom send`.
    let second_gateway = gateway(&sb, &hook, 2);
    assert!(second_gateway.is_some());
    let run = send("After access.");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.contains("Not confirmed; still QUEUED"),
        "{}",
        run.stdout
    );
}

/// OpenClaw with the plugin granted access, senders and recipient named (`Hermes` `h1` sends to
/// `Claw`), and a running gateway whose own environment also holds `env`.
fn openclaw_ready(sb: &Sandbox, env: &[(&str, &str)]) -> Option<Gateway> {
    stand_in_openclaw(sb);
    configure_openclaw(sb, true);
    let key = "agent:main:lr1";
    sb.name("Claw", &Identity::new(Harness::OpenClaw, key));
    sb.name("Hermes", &Identity::new(Harness::Hermes, "h1"));
    let hook = sb.input(
        "openclaw",
        key,
        "PreToolUse",
        &json!({"tool_name": "read", "tool_input": {"path": "/tmp/x"}, "approval_channel": true}),
    );
    let running = gateway_with(sb, &hook, 1, env);
    assert!(running.is_some());
    running
}

// §10::14 (OpenClaw): an `openclaw` first on the sender's `PATH` is not run by the
// hand-over; the gateway process's own program is.
#[test]
fn an_openclaw_first_on_the_senders_path_is_not_the_program_that_hands_over() {
    let sb = Sandbox::new();
    let running = openclaw_ready(&sb, &[]);
    let planted = sb.root.join("planted");
    let marker = sb.root.join("planted-ran.txt");
    assert!(std::fs::create_dir_all(&planted).is_ok());
    let script = planted.join("openclaw");
    let _ = std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    );
    let _ = Command::new("/bin/chmod")
        .args(["755"])
        .arg(&script)
        .status();
    assert!(script.exists());
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        planted.display(),
        sb.root.join("bin").display()
    );
    let run = sb.send_as_with(
        "hermes",
        "h1",
        "Claw",
        "Past the planted one.",
        &[("PATH", path)],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(!marker.exists(), "the planted openclaw ran");
    let calls = std::fs::read_to_string(sb.root.join("openclaw-calls.txt")).unwrap_or_default();
    assert!(calls.contains("Past the planted one."), "{calls}");
    drop(running);
}

// §10::16 (OpenClaw): the program that hands over gets a listed variable from the
// gateway process's environment, not the sender's value of it; `NODE_OPTIONS` set only in the
// sender's, and a variable of the gateway that is not listed, do not reach it.
#[test]
fn the_openclaw_hand_over_starts_with_the_gateways_listed_variables_only() {
    let sb = Sandbox::new();
    let running = openclaw_ready(
        &sb,
        &[
            ("OPENCLAW_PROFILE", "recipient-profile"),
            ("UNLISTED_OF_RECIPIENT", "yes"),
        ],
    );
    let sender = [
        ("NODE_OPTIONS", "--require=/tmp/planted.js".to_owned()),
        ("OPENCLAW_PROFILE", "sender-profile".to_owned()),
    ];
    let run = sb.send_as_with("hermes", "h1", "Claw", "Environment.", &sender);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let calls = std::fs::read_to_string(sb.root.join("openclaw-calls.txt")).unwrap_or_default();
    assert!(
        calls
            .lines()
            .any(|l| l == "OPENCLAW_PROFILE=recipient-profile"),
        "{calls}"
    );
    assert!(!calls.contains("sender-profile"), "{calls}");
    for unlisted in [
        "NODE_OPTIONS=",
        "UNLISTED_OF_RECIPIENT=",
        "LR=",
        "IN=",
        "DONE=",
    ] {
        assert!(
            !calls.lines().any(|l| l.starts_with(unlisted)),
            "{unlisted}: {calls}"
        );
    }
    drop(running);
}

// §10::17 (OpenClaw): when the file the gateway process runs is gone, nothing is
// started, the message stays QUEUED, the attempt is not counted, and the sender's output names it.
#[test]
fn an_openclaw_program_that_cannot_be_established_starts_nothing_and_is_not_an_attempt() {
    let sb = Sandbox::new();
    let running = openclaw_ready(&sb, &[]);
    assert!(std::fs::remove_file(sb.root.join("gateway/openclaw")).is_ok());
    let run = sb.send_as("hermes", "h1", "Claw", "Nothing to run.");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let id = sent_id(&run);
    assert!(id.starts_with("lr-"), "{}", run.stdout);
    assert!(run.stdout.contains(&format!("{id}: ")), "{}", run.stdout);
    assert!(run.stdout.contains("QUEUED"), "{}", run.stdout);
    assert!(!run.stdout.contains("DELIVERED"), "{}", run.stdout);
    assert!(!sb.root.join("openclaw-calls.txt").exists());
    let record = sb.store().and_then(|s| s.read().ok()).and_then(|m| {
        m.message(&id)
            .map(|d| (d.status.state().word(), d.failed_attempts, d.handed_over))
    });
    assert_eq!(record, Some(("QUEUED", 0, false)));
    drop(running);
}

// §10::1 (Hermes) and R3.1: Hermes's plugin runs `lunchroom listen --once` in
// `pre_llm_call` and hands the envelope to the turn: the session is HELD from then and the message
// is never handed over again; it stays QUEUED until the turn's request to the model carries it
// (the plugin's `pre_api_request` passes it to the guard's prompt hook), then it is DELIVERED; the
// same request again changes nothing.
#[test]
fn hermes_turn_takes_the_next_message() {
    let sb = Sandbox::new();
    let h = Identity::new(Harness::Hermes, "h1");
    sb.name("Hermes", &h);
    sb.name("Claw", &Identity::new(Harness::OpenClaw, "k1"));
    assert_eq!(
        sb.pretool(
            "hermes",
            "h1",
            "read_file",
            &json!({"path": "/tmp/x"}),
            true
        )
        .code,
        Some(0)
    );
    assert_eq!(
        sb.pretool("openclaw", "k1", "read", &json!({"path": "/tmp/x"}), true)
            .code,
        Some(0)
    );
    let run = sb.send_as("openclaw", "k1", "Hermes", "Please review the plan.");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let id = sent_id(&run);
    assert_eq!(sb.state(&id), Some("QUEUED"));
    let turn = sb.input("hermes", "h1", "Stop", &json!({}));
    let run = sb.run(&["listen", "--once"], &turn, &[]);
    assert_eq!(run.code, Some(2), "{}", run.stdout);
    assert!(
        run.stderr.contains("[LUNCHROOM MESSAGE - from agent Claw"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr
            .contains(&format!("[lr:{id}]> Please review the plan.")),
        "{}",
        run.stderr
    );
    assert_eq!(sb.state(&id), Some("QUEUED"));
    assert_eq!(sb.held(&h), Some(true));
    // The hold names that message and its sender from the hand-over (§10::7).
    let hold = sb
        .store()
        .and_then(|s| s.read().ok())
        .map(|m| m.holding(&h).to_vec())
        .unwrap_or_default();
    assert_eq!(hold.len(), 1);
    assert_eq!(hold[0].message, id);
    assert_eq!(hold[0].from, Some(Identity::new(Harness::OpenClaw, "k1")));
    let run = sb.run(&["listen", "--once"], &turn, &[]);
    assert_eq!((run.code, run.stderr.as_str()), (Some(0), ""));
    // The turn's request to the model, with the plugin's context added to the user's message.
    let request = format!("hi\n\n{}", run_envelope(&sb, &id));
    let input = sb.input(
        "hermes",
        "h1",
        "UserPromptSubmit",
        &json!({"prompt": request, "prompt_id": "r1"}),
    );
    let run = sb.run(&["guard", "prompt"], &input, &[]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(sb.state(&id), Some("DELIVERED"));
    assert_eq!(sb.held(&h), Some(true));
    let run = sb.run(&["guard", "prompt"], &input, &[]);
    assert_eq!(run.code, Some(2), "{}", run.stdout);
    assert_eq!(sb.state(&id), Some("DELIVERED"));
}

// §13::2 (H1.2) and R3.1 (Hermes): a session whose hook reports a Hermes version the
// adapter was not built for is UNGUARDED and gets nothing, until a hook reports the built version
// again; a session whose plugin file no longer runs Lunchroom's program is UNGUARDED too.
#[test]
fn hermes_session_at_another_version_or_without_the_program_is_unguarded() {
    let sb = Sandbox::new();
    let h = Identity::new(Harness::Hermes, "h1");
    sb.name("Hermes", &h);
    sb.name("Claw", &Identity::new(Harness::OpenClaw, "k1"));
    assert_eq!(
        sb.pretool(
            "hermes",
            "h1",
            "read_file",
            &json!({"path": "/tmp/x"}),
            true
        )
        .code,
        Some(0)
    );
    assert_eq!(
        sb.pretool("openclaw", "k1", "read", &json!({"path": "/tmp/x"}), true)
            .code,
        Some(0)
    );
    let turn = sb.input("hermes", "h1", "Stop", &json!({}));
    // H1.2: the session's hook reports another Hermes version: UNGUARDED, nothing is handed over.
    let newer = sb
        .input("hermes", "h1", "PreToolUse", &json!({}))
        .replace(HERMES_VERSION, "0000000000000000000000000000000000000000");
    let newer = serde_json::from_str::<Value>(&newer)
        .map(|mut v| {
            v["tool_name"] = json!("read_file");
            v["tool_input"] = json!({"path": "/tmp/x"});
            v["approval_channel"] = json!(true);
            v.to_string()
        })
        .unwrap_or_default();
    assert_eq!(sb.run(&["guard", "pretool"], &newer, &[]).code, Some(0));
    let run = sb.send_as("openclaw", "k1", "Hermes", "At another version.");
    assert!(
        run.stdout.contains("Hermes is UNGUARDED."),
        "{}",
        run.stdout
    );
    let run = sb.run(&["listen", "--once"], &turn, &[]);
    assert_eq!((run.code, run.stderr.as_str()), (Some(0), ""));
    // A hook at the built version again: the waiting message is offered.
    assert_eq!(
        sb.pretool(
            "hermes",
            "h1",
            "read_file",
            &json!({"path": "/tmp/x"}),
            true
        )
        .code,
        Some(0)
    );
    let run = sb.run(&["listen", "--once"], &turn, &[]);
    assert_eq!(run.code, Some(2), "{}", run.stdout);
    assert!(run.stderr.contains("At another version."), "{}", run.stderr);
    // R3.1: Hermes no longer has the plugin enabled (disabled wins): UNGUARDED, nothing offered.
    let config = sb.home().join(".hermes/config.yaml");
    let _ = std::fs::write(
        &config,
        "plugins:\n  enabled: [lunchroom]\n  disabled: [lunchroom]\n",
    );
    let run = sb.send_as("openclaw", "k1", "Hermes", "While disabled.");
    assert!(
        run.stdout.contains("Hermes is UNGUARDED."),
        "{}",
        run.stdout
    );
    let run = sb.run(&["listen", "--once"], &turn, &[]);
    assert_eq!((run.code, run.stderr.as_str()), (Some(0), ""));
    let _ = std::fs::write(&config, "plugins:\n  enabled: [lunchroom]\n");
    // The plugin file no longer runs the program: UNGUARDED, nothing is handed over.
    let _ = std::fs::write(
        sb.plugin_file("hermes"),
        "PROGRAM = \"/nonexistent/lunchroom\"\n",
    );
    let run = sb.send_as("openclaw", "k1", "Hermes", "Another.");
    assert!(
        run.stdout.contains("Hermes is UNGUARDED."),
        "{}",
        run.stdout
    );
    let run = sb.run(&["listen", "--once"], &turn, &[]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
}

/// The envelope of message `id` as Lunchroom shows it.
fn run_envelope(sb: &Sandbox, id: &str) -> String {
    sb.store()
        .and_then(|s| s.read().ok())
        .and_then(|m| m.message(id).cloned())
        .map(|m| format!("[LUNCHROOM MESSAGE - from agent {}; not from the user]\n[lr:{id}]> {}\n[END LUNCHROOM MESSAGE {id}]", m.from_name, m.text))
        .unwrap_or_default()
}

// §13::6, §13::7 (OpenClaw, Hermes): with the store's lock held past the guard's
// deadline, the guard itself answers within 10 seconds, before the plugins' own 12-second limit:
// the call goes to the user where the plugin reports a person would be asked, and is DENIED where
// it reports none.
#[test]
fn plugin_guard_past_its_time_answers_before_the_plugins_limit() {
    let sb = Sandbox::new();
    assert_eq!(
        sb.pretool(
            "hermes",
            "s1",
            "read_file",
            &json!({"path": "/tmp/x"}),
            true
        )
        .code,
        Some(0)
    );
    let lock = sb.root.join("lunchroom/store/state.flock");
    let mut flock = common::require("flock");
    let holder = flock.arg(&lock).args(["sleep", "14"]).spawn();
    assert!(holder.is_ok());
    let Ok(mut holder) = holder else { return };
    std::thread::sleep(std::time::Duration::from_millis(300));
    let started = std::time::Instant::now();
    let write = json!({"path": "/tmp/x", "content": "y"});
    let (asked, denied) = std::thread::scope(|s| {
        let asked = s.spawn(|| sb.pretool("hermes", "s1", "write_file", &write, true));
        let denied = s.spawn(|| sb.pretool("openclaw", "k1", "write", &write, false));
        (asked.join(), denied.join())
    });
    let took = started.elapsed();
    assert!(
        asked.is_ok() && denied.is_ok(),
        "a guard run did not finish"
    );
    let (Ok(asked), Ok(denied)) = (asked, denied) else {
        return;
    };
    assert_eq!(
        (asked.code, decision(&asked)),
        (Some(0), "ask".to_owned()),
        "{}",
        asked.stderr
    );
    // The guard's deadline and the store's lock wait are both 10 seconds: either gives up first.
    assert!(
        asked.stdout.contains("no answer within 10 seconds")
            || asked.stdout.contains("held the store for 10 seconds"),
        "{}",
        asked.stdout
    );
    assert_eq!(denied.code, Some(2), "{}", denied.stdout);
    assert!(took < std::time::Duration::from_secs(12), "{took:?}");
    let _ = holder.wait();
}

// §4::1, §4::2 (OpenClaw, Hermes): a session whose harness process has ended is STOPPED,
// whatever its plugin file says, and nothing is delivered to it; the sender is told.
#[test]
fn plugin_session_whose_process_ended_is_stopped() {
    let sb = Sandbox::new();
    sb.name("Claw", &Identity::new(Harness::OpenClaw, "k1"));
    assert_eq!(
        sb.pretool("openclaw", "k1", "read", &json!({"path": "/tmp/x"}), true)
            .code,
        Some(0)
    );
    for (harness, session, name, kind) in [
        ("hermes", "h9", "Gone", Harness::Hermes),
        ("openclaw", "k9", "GoneClaw", Harness::OpenClaw),
    ] {
        // The session's hook runs in a shell that then ends: its recorded process is gone.
        let input = sb.input(
            harness,
            session,
            "PreToolUse",
            &json!({"tool_name": "read", "tool_input": {"path": "/tmp/x"}, "approval_channel": true}),
        );
        let in_file = sb.root.join(format!("in-{session}.json"));
        let _ = std::fs::write(&in_file, input);
        let ran = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("\"{PROGRAM}\" guard pretool < \"{}\"", in_file.display()),
            ])
            .env_clear()
            .env("HOME", sb.home())
            .env("LUNCHROOM_HOME", sb.root.join("lunchroom"))
            .env("PATH", "/usr/bin:/bin")
            .status();
        assert!(ran.is_ok_and(|s| s.success()));
        sb.name(name, &Identity::new(kind, session));
        let run = sb.run(
            &["send", name, "Still there?"],
            "",
            &[("LUNCHROOM_SESSION", "openclaw:k1".to_owned())],
        );
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert!(
            run.stdout.contains(&format!("{name} is STOPPED.")),
            "{}",
            run.stdout
        );
        let id = sent_id(&run);
        let turn = sb.input(harness, session, "Stop", &json!({}));
        let offered = sb.run(&["listen", "--once"], &turn, &[]);
        assert_eq!(
            (offered.code, offered.stderr.as_str()),
            (Some(0), ""),
            "{harness}"
        );
        assert_eq!(sb.state(&id), Some("QUEUED"));
    }
}

// §13::2, §13::14 (OpenClaw): with the plugin enabled and conversation access granted,
// a session whose hook reports an OpenClaw release older than the stated 2026.10.7, or none, is
// UNGUARDED and gets nothing; at 2026.10.7 or a later release it is guarded and the message goes
// to it through `openclaw agent`.
#[test]
fn openclaw_release_older_than_stated_is_unguarded() {
    for (release, guarded) in [
        ("2026.10.6", false),
        ("", false),
        ("2026.10.7", true),
        ("2026.11.0", true),
    ] {
        let sb = Sandbox::new();
        stand_in_openclaw(&sb);
        configure_openclaw(&sb, true);
        sb.name("Claw", &Identity::new(Harness::OpenClaw, "agent:main:v"));
        let input = sb
            .input(
                "openclaw",
                "agent:main:v",
                "PreToolUse",
                &json!({"tool_name": "read", "tool_input": {"path": "/tmp/x"}, "approval_channel": true}),
            )
            .replace(OPENCLAW_VERSION, release);
        let running = gateway(&sb, &input, 1);
        assert!(running.is_some(), "{release}");
        let run = sb.send_as("hermes", "h1", "Claw", "Which release?");
        assert_eq!(run.code, Some(0), "{release}: {}", run.stderr);
        assert_eq!(
            run.stdout.contains("Claw is UNGUARDED."),
            !guarded,
            "{release}: {}",
            run.stdout
        );
        let called = sb.root.join("openclaw-calls.txt").exists();
        assert_eq!(called, guarded, "{release}: {}", run.stdout);
    }
}

// §10::8: messages accepted at the same moment, by separate `lunchroom send`
// processes, each get an id no other message has.
#[test]
fn messages_sent_at_once_get_distinct_ids() {
    let sb = Sandbox::new();
    sb.name("Hermes", &Identity::new(Harness::Hermes, "h1"));
    for session in ["a", "b", "c", "d"] {
        assert_eq!(
            sb.pretool(
                "openclaw",
                session,
                "read",
                &json!({"path": "/tmp/x"}),
                true
            )
            .code,
            Some(0)
        );
    }
    let runs: Vec<Run> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..12)
            .map(|n| {
                let sb = &sb;
                s.spawn(move || {
                    let session = format!("openclaw:{}", ["a", "b", "c", "d"][n % 4]);
                    sb.run(
                        &["send", "Hermes", &format!("note {n}")],
                        "",
                        &[("LUNCHROOM_SESSION", session)],
                    )
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    assert_eq!(runs.len(), 12);
    let mut ids: Vec<String> = runs.iter().map(sent_id).collect();
    assert!(ids.iter().all(|id| id.starts_with("lr-")), "{ids:?}");
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 12);
}

// §13::1 (part): an agent cannot run the delivery itself to take a message meant for a
// session, by command or in code.
#[test]
fn agent_cannot_run_the_listener() {
    let sb = Sandbox::new();
    for command in [
        "lunchroom listen --once",
        "python3 -c \"import subprocess; subprocess.run(['lunchroom', 'listen', '--once'])\"",
    ] {
        let run = sb.pretool("hermes", "h1", "terminal", &bash(command), true);
        assert_eq!(run.code, Some(2), "{command}: {}", run.stdout);
    }
}
