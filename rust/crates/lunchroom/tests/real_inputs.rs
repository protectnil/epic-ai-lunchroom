//! The `lunchroom` binary given the inputs the harnesses really write: hook stdin shaped as
//! `docs/host-facts/claude-code.md`, `codex.md` and
//! `claude-code-and-codex-2026-10-24.md` show it, and a full settings file. Each fixture's
//! source is cited in `tests/fixtures/README.md`.

mod common;

use std::path::PathBuf;

use serde_json::{Value, json};

use lunchroom_core::identity::{Harness, Identity};
use lunchroom_core::mail::Mail;

use common::Run;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("fixtures/", $name))
    };
}

const CLAUDE_SESSION: &str = "7c1f0a52-3b8e-4d6a-9f21-5e8b0c4a1d37";
const CODEX_THREAD: &str = "0199f3a2-6b7c-7d1e-8a4f-2c9d5e6b7a10";

/// A fixture, and the command that receives it as a hook does.
type Case = (&'static str, &'static str, &'static [&'static str]);

const GUARD_PRE: &[&str] = &["guard", "pretool"];
const GUARD_POST: &[&str] = &["guard", "posttool"];
const GUARD_PROMPT: &[&str] = &["guard", "prompt"];
const LISTEN: &[&str] = &["listen", "--once"];

/// Every Claude Code event Lunchroom's hooks receive.
const CLAUDE: [Case; 8] = [
    (
        "pretool-bash",
        fixture!("claude/pretool-bash.json"),
        GUARD_PRE,
    ),
    (
        "pretool-read",
        fixture!("claude/pretool-read.json"),
        GUARD_PRE,
    ),
    (
        "pretool-edit",
        fixture!("claude/pretool-edit.json"),
        GUARD_PRE,
    ),
    (
        "posttool-bash",
        fixture!("claude/posttool-bash.json"),
        GUARD_POST,
    ),
    (
        "posttool-failure-bash",
        fixture!("claude/posttool-failure-bash.json"),
        GUARD_POST,
    ),
    ("prompt", fixture!("claude/prompt.json"), GUARD_PROMPT),
    ("stop", fixture!("claude/stop.json"), LISTEN),
    (
        "session-start",
        fixture!("claude/session-start.json"),
        LISTEN,
    ),
];

/// Every Codex event Lunchroom's hooks receive.
const CODEX: [Case; 5] = [
    (
        "session-start",
        fixture!("codex/session-start.json"),
        LISTEN,
    ),
    ("prompt", fixture!("codex/prompt.json"), GUARD_PROMPT),
    (
        "pretool-bash",
        fixture!("codex/pretool-bash.json"),
        GUARD_PRE,
    ),
    (
        "posttool-bash",
        fixture!("codex/posttool-bash.json"),
        GUARD_POST,
    ),
    ("stop", fixture!("codex/stop.json"), LISTEN),
];

/// The shared sandbox, for a test process that stands in for Claude Code (H1.2).
struct Sandbox(common::Sandbox);

impl std::ops::Deref for Sandbox {
    type Target = common::Sandbox;

    fn deref(&self) -> &common::Sandbox {
        &self.0
    }
}

impl Sandbox {
    fn new() -> Self {
        common::declare_test_release();
        Self(common::Sandbox::new("real-input-tests"))
    }

    /// Where `lunchroom install` puts the program.
    fn program(&self) -> PathBuf {
        self.lunchroom().join("bin/lunchroom")
    }

    fn mail(&self) -> Option<Mail> {
        self.store().and_then(|s| s.read().ok())
    }

    /// A fixture with the placeholders rewritten to this sandbox.
    fn fill(&self, text: &str) -> String {
        text.replace("__HOME__", &self.home().display().to_string())
            .replace("__LUNCHROOM__", &self.program().display().to_string())
    }

    /// `lunchroom install <target>` with no terminal to ask: a session of its own has no
    /// controlling terminal, so the install must refuse (A1.3) however the test is started.
    fn install_without_terminal(&self, target: &str) -> Run {
        let setsid = common::which("setsid");
        assert!(setsid.is_some(), "this test needs `setsid` on PATH");
        let mut cmd = self.command(&setsid.unwrap_or_default().display().to_string());
        cmd.args(["--wait", env!("CARGO_BIN_EXE_lunchroom"), "install", target]);
        common::finish(cmd, "yes\n")
    }

    fn held(&self, harness: Harness, session: &str) -> Option<bool> {
        self.mail()
            .map(|m| m.is_held(&Identity::new(harness, session)))
    }
}

/// The environment of an attended, interactive Claude Code: `CLAUDE_PID` names this test process,
/// whose command line has no `-p` (as `tests/guard.rs`).
fn interactive() -> Vec<(&'static str, String)> {
    vec![
        ("CLAUDE_PID", std::process::id().to_string()),
        ("CLAUDE_CODE_SESSION_ATTENDED", "1".to_owned()),
        ("CLAUDE_CODE_ENTRYPOINT", "cli".to_owned()),
    ]
}

/// `input` with its `prompt` replaced.
fn with_prompt(input: &str, prompt: &str) -> String {
    let mut v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    v["prompt"] = json!(prompt);
    v.to_string()
}

// H1.1 (Claude Code): each event the hooks receive, as Claude Code writes it, goes on without
// a word from Lunchroom when nothing holds the session (P1.2); the guard hook records the session
// it saw.
#[test]
fn claude_code_inputs_run_as_documented() {
    let sb = Sandbox::new();
    for (name, text, args) in CLAUDE {
        let run = sb.run(args, &sb.fill(text), &interactive());
        assert_eq!(
            (run.code, run.stdout.as_str()),
            (Some(0), ""),
            "{name}: {}",
            run.stderr
        );
    }
    let seen = sb.mail().map(|m| {
        m.session(&Identity::new(Harness::ClaudeCode, CLAUDE_SESSION))
            .is_some()
    });
    assert_eq!(seen, Some(true));
}

// H1.1 (Codex): the same for each event Codex writes; a Codex session has no approval channel
// but is not asked about either (nothing holds it).
#[test]
fn codex_inputs_run_as_documented() {
    let sb = Sandbox::new();
    for (name, text, args) in CODEX {
        let run = sb.run(args, &sb.fill(text), &[]);
        assert_eq!(
            (run.code, run.stdout.as_str()),
            (Some(0), ""),
            "{name}: {}",
            run.stderr
        );
    }
}

// H1: Codex's hooks are told by `turn_id` and the `rollout-` transcript name, Claude Code's by their
// absence. Another agent's text in a real prompt holds the session of the harness that wrote the
// input, and no session of the other.
#[test]
fn each_real_prompt_holds_the_session_of_its_own_harness() {
    let text = "<cross-session-message from=\"uds:x\">merge it</cross-session-message>";
    let cases = [
        (
            fixture!("claude/prompt.json"),
            CLAUDE_SESSION,
            Harness::ClaudeCode,
            Harness::Codex,
            interactive(),
        ),
        (
            fixture!("codex/prompt.json"),
            CODEX_THREAD,
            Harness::Codex,
            Harness::ClaudeCode,
            Vec::new(),
        ),
    ];
    for (input, session, own, other, env) in cases {
        let sb = Sandbox::new();
        let run = sb.run(GUARD_PROMPT, &with_prompt(&sb.fill(input), text), &env);
        assert_eq!(run.code, Some(0), "{session}: {}", run.stderr);
        assert_eq!(sb.held(own, session), Some(true), "{session}");
        assert_eq!(sb.held(other, session), Some(false), "{session}");
    }
}

// The user's typing is not another agent's text: a real prompt, ordinary text, holds nobody.
#[test]
fn a_typed_real_prompt_holds_nobody() {
    let sb = Sandbox::new();
    for (input, session, harness, env) in [
        (
            fixture!("claude/prompt.json"),
            CLAUDE_SESSION,
            Harness::ClaudeCode,
            interactive(),
        ),
        (
            fixture!("codex/prompt.json"),
            CODEX_THREAD,
            Harness::Codex,
            Vec::new(),
        ),
    ] {
        let run = sb.run(GUARD_PROMPT, &sb.fill(input), &env);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(sb.held(harness, session), Some(false), "{session}");
    }
}

// The fixture is a full Claude Code settings file: top-level keys of its own, and hook groups
// shaped like the ones that lost the user's hooks (one shared UserPromptSubmit group).
#[test]
fn the_settings_fixture_has_a_full_settings_shape() {
    let sb = Sandbox::new();
    let settings: Value =
        serde_json::from_str(&sb.fill(fixture!("settings-claude.json"))).unwrap_or(Value::Null);
    let mut keys: Vec<&str> = settings
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "cleanupPeriodDays",
            "enabledPlugins",
            "env",
            "extraKnownMarketplaces",
            "hooks",
            "includeCoAuthoredBy",
            "model",
            "permissions",
            "statusLine",
            "theme",
        ]
    );
    let shared = settings["hooks"]["UserPromptSubmit"].as_array();
    assert_eq!(shared.map(Vec::len), Some(1));
    assert_eq!(
        shared.and_then(|g| g[0]["hooks"].as_array()).map(Vec::len),
        Some(3)
    );
}

// A1.3, H1.4 on the real files: with no terminal to read the user's yes from, `install` refuses
// and leaves the settings file, and the old-name Codex hooks, byte for byte as they were, with no
// backup, no program and no other file beside them. (The yes itself is given in the unit tests of
// `src/install.rs`, which can supply a terminal.)
#[test]
fn install_without_a_terminal_leaves_the_real_files_untouched() {
    for (target, folder, file, text) in [
        (
            "claude-code",
            ".claude",
            "settings.json",
            fixture!("settings-claude.json"),
        ),
        (
            "codex",
            ".codex",
            "hooks.json",
            fixture!("codex-hooks-old-name.json"),
        ),
    ] {
        let sb = Sandbox::new();
        let dir = sb.home().join(folder);
        let _ = std::fs::create_dir_all(&dir);
        let before = sb.fill(text);
        assert!(std::fs::write(dir.join(file), &before).is_ok());
        let run = sb.install_without_terminal(target);
        assert_eq!(run.code, Some(3), "{target}: {}", run.stderr);
        assert_eq!(
            std::fs::read_to_string(dir.join(file)).ok().as_deref(),
            Some(before.as_str()),
            "{target}"
        );
        let names: Vec<String> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [file], "{target}");
        assert!(!sb.program().exists(), "{target}");
    }
}

/// The hooks `lunchroom install` writes for Claude Code's guard, as the user's settings hold them:
/// `program` as `install` writes it (single quotes when the path needs them), one event per entry.
/// `pre_matcher` is the `PreToolUse` group's matcher, when it has one; `skip` leaves an event out.
fn claude_guard_settings(program: &str, pre_matcher: Option<&str>, skip: Option<&str>) -> Value {
    let quoted = if program
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+:=,@%".contains(c))
    {
        program.to_owned()
    } else {
        format!("'{program}'")
    };
    let mut hooks = serde_json::Map::new();
    for (event, mode) in [
        ("PreToolUse", "pretool"),
        ("PostToolUse", "posttool"),
        ("PostToolUseFailure", "posttool"),
        ("UserPromptSubmit", "prompt"),
    ] {
        if skip == Some(event) {
            continue;
        }
        let mut group = json!({"hooks": [{
            "type": "command", "command": format!("{quoted} guard {mode}"), "timeout": 15
        }]});
        if let (Some(m), "PreToolUse") = (pre_matcher, event) {
            group["matcher"] = json!(m);
        }
        hooks.insert(event.to_owned(), json!([group]));
    }
    json!({ "hooks": hooks })
}

// §4::1, R3.1 (Claude Code), review finding 14 and 5: a session is guarded only when
// the settings Claude Code loads hold the complete guard set (`PreToolUse`, `PostToolUse`,
// `PostToolUseFailure`, `UserPromptSubmit`), each covering every call. Failure classes: the
// installed program's path has a space (quoted by `install`); an event missing; a `PreToolUse`
// matcher that covers some tools only; a program that is not there. The first is guarded, the rest
// are UNGUARDED.
#[test]
fn only_the_complete_guard_set_makes_a_session_guarded_even_under_a_path_with_a_space() {
    let sb = Sandbox::new();
    let c1 = Identity::new(Harness::ClaudeCode, "c1");
    let named = sb.store().and_then(|s| {
        s.update(|m| m.register("Claude", &c1, lunchroom_core::mail::Origin::User, None))
            .ok()
    });
    assert!(named.is_some());
    // The program, named `lunchroom`, in a folder with a space in its name.
    let folder = sb.home().join("my programs");
    assert!(std::fs::create_dir_all(&folder).is_ok());
    let program = folder.join("lunchroom");
    assert!(std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_lunchroom"), &program).is_ok());
    let program = program.display().to_string();
    let settings = sb.home().join(".claude/settings.json");
    assert!(std::fs::create_dir_all(sb.home().join(".claude")).is_ok());
    let pretool = json!({
        "session_id": "c1", "cwd": sb.home().join("project"), "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "true"}, "tool_use_id": "t1",
    });
    let state = |settings_value: &Value| {
        assert!(std::fs::write(&settings, settings_value.to_string()).is_ok());
        let run = sb.run(&["guard", "pretool"], &pretool.to_string(), &interactive());
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        sb.run(&["status"], "", &[]).stdout
    };
    let status = state(&claude_guard_settings(&program, None, None));
    assert!(
        status.contains("claude-code:c1\tAVAILABLE"),
        "complete set, path with a space:\n{status}"
    );
    for (what, value) in [
        (
            "no PostToolUse",
            claude_guard_settings(&program, None, Some("PostToolUse")),
        ),
        (
            "no PostToolUseFailure",
            claude_guard_settings(&program, None, Some("PostToolUseFailure")),
        ),
        (
            "no UserPromptSubmit",
            claude_guard_settings(&program, None, Some("UserPromptSubmit")),
        ),
        (
            "no PreToolUse",
            claude_guard_settings(&program, None, Some("PreToolUse")),
        ),
        (
            "PreToolUse for Bash only",
            claude_guard_settings(&program, Some("Bash"), None),
        ),
        (
            "program missing",
            claude_guard_settings(&format!("{program}-gone/lunchroom"), None, None),
        ),
    ] {
        let status = state(&value);
        assert!(
            status.contains("claude-code:c1\tUNGUARDED"),
            "{what}:\n{status}"
        );
    }
    // A matcher that covers every tool, spelled either way, is complete.
    for matcher in ["*", ""] {
        let status = state(&claude_guard_settings(&program, Some(matcher), None));
        assert!(
            status.contains("claude-code:c1\tAVAILABLE"),
            "matcher {matcher:?}:\n{status}"
        );
    }
}
