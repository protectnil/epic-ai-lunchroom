//! The Claude Code adapter's guard evidence (R3.1, H1.1 item 2).
//!
//! A Claude Code session is guarded when a guard hook recorded it in its current Claude Code process
//! (the process still runs under the same `<pid>:<start time>`) and a settings file that Claude Code
//! loads for it still runs Lunchroom's complete guard set, `PreToolUse`, `PostToolUse`,
//! `PostToolUseFailure` and `UserPromptSubmit`, each covering every call (`configured_with`): the
//! managed `/etc/claude-code/managed-settings.json`, the user's `settings.json` (in
//! `CLAUDE_CONFIG_DIR`, or `~/.claude`), the project's `.claude/settings.json` and
//! `.claude/settings.local.json` in the folder it ran in, as `--setting-sources` leaves them, or a
//! file or text given to that process with `--settings`, unless `--bare` or `disableAllHooks`
//! switches the hooks off. A session no hook recorded, or whose process has ended, is STOPPED; one
//! that runs without that configuration is UNGUARDED.
//!
//! OpenClaw and Hermes load Lunchroom's plugin into the harness process, and the plugin starts the
//! guard; the guard records the plugin's file. Such a session is guarded while that file still
//! runs a Lunchroom program that is there to run, and, for OpenClaw, which applies plugin settings
//! to a running gateway, while `openclaw.json` still enables the plugin with conversation access
//! (`before_agent_run`, which confirms deliveries and sees another agent's text, runs only then).
//! Host facts: `docs/host-facts/openclaw-and-hermes.md`.

use std::path::{Path, PathBuf};

use serde_json::Value;

use lunchroom_core::identity::{Harness, Identity};
use lunchroom_core::mail::{Evidence, Mail};

use crate::process;

/// The evidence for `who`'s guard. Every harness first needs its recorded process still running
/// under the same `<pid>:<start time>` (else STOPPED); then its adapter's configuration and a
/// release its adapter passes (H1.2).
#[must_use]
pub fn evidence(mail: &Mail, who: &Identity, home: &Path) -> Evidence {
    evidence_with(&PASSED_WITH, mail, who, home)
}

/// `evidence` against the list `passed` of passing adapters and their releases.
fn evidence_with(passed: &[(Harness, &str)], mail: &Mail, who: &Identity, home: &Path) -> Evidence {
    let Some(record) = mail.session(who) else {
        return Evidence::NotRunning;
    };
    let Some(pid) = record
        .process
        .split(':')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
    else {
        return Evidence::NotRunning;
    };
    if process::key(pid).as_deref() != Some(record.process.as_str()) {
        return Evidence::NotRunning;
    }
    let guarded = match who.harness {
        Harness::ClaudeCode => {
            configured(pid, &record.cwd, home)
                && passes_with(
                    passed,
                    who.harness,
                    &process_version(who.harness, pid).unwrap_or_default(),
                )
        }
        Harness::Codex => {
            codex_configured(pid, &record.cwd, home, mail.guard_fingerprint(who))
                && passes_with(
                    passed,
                    who.harness,
                    &process_version(who.harness, pid).unwrap_or_default(),
                )
        }
        // The release the plugin reported with its guard hook (H1.2), its file still running the
        // guard (R3.1), and the harness still enabling the plugin.
        Harness::OpenClaw => {
            passes_with(
                passed,
                who.harness,
                plugin_release(mail.guard_fingerprint(who)),
            ) && plugin_runs_guard(mail.guard_fingerprint(who))
                && openclaw_enables(pid, home)
        }
        Harness::Hermes => {
            passes_with(
                passed,
                who.harness,
                plugin_release(mail.guard_fingerprint(who)),
            ) && plugin_runs_guard(mail.guard_fingerprint(who))
                && hermes_enables(pid, home)
        }
    };
    if guarded {
        Evidence::Guarded
    } else {
        Evidence::RunningUnguarded
    }
}

/// Codex's folder for the session in process `pid`: its `CODEX_HOME`, or `~/.codex`.
#[must_use]
pub fn codex_home_of(pid: u32, home: &Path) -> PathBuf {
    process_env(pid, "CODEX_HOME").map_or_else(|| home.join(".codex"), PathBuf::from)
}

/// Codex's folder for `who`'s session, from the process a guard hook recorded it in.
#[must_use]
pub fn recorded_codex_home(mail: &Mail, who: &Identity, home: &Path) -> PathBuf {
    mail.session(who)
        .and_then(|r| {
            r.process
                .split(':')
                .next()
                .and_then(|p| p.parse::<u32>().ok())
        })
        .map_or_else(|| home.join(".codex"), |pid| codex_home_of(pid, home))
}

/// The hook events Lunchroom installs for Codex, as `hooks.json` names them and as the keys of
/// `config.toml`'s `[hooks.state."…"]` tables do.
const CODEX_EVENTS: [(&str, &str); 5] = [
    ("PreToolUse", "pre_tool_use"),
    ("PostToolUse", "post_tool_use"),
    ("UserPromptSubmit", "user_prompt_submit"),
    ("SessionStart", "session_start"),
    ("Stop", "stop"),
];

/// The guard hooks Codex needs from Lunchroom, as `lunchroom install` writes them for Codex: the
/// event and the guard's mode, the same standard as [`CLAUDE_GUARD_HOOKS`] (Codex has no
/// `PostToolUseFailure`). With one missing, a message would reach a session whose protection is
/// partial.
const CODEX_GUARD_HOOKS: [(&str, &str); 4] = [
    ("PreToolUse", "pretool"),
    ("PostToolUse", "posttool"),
    ("UserPromptSubmit", "prompt"),
    ("SessionStart", "start"),
];

/// Codex (measured, codex-cli 0.163.0): the fingerprint of Lunchroom's trusted hooks for the
/// session in process `pid`: a `hooks.json` Codex reads for it (`<CODEX_HOME>/hooks.json`, or the
/// project's `.codex/hooks.json`) holds every one of [`CODEX_GUARD_HOOKS`] (each in a group whose
/// matcher covers every tool, synchronous, its program there to run), and `config.toml` holds the user's trust for
/// every Lunchroom hook in that file (`[hooks.state."<hooks.json>:<event>:<group>:<hook>"]` with a
/// `trusted_hash`, not disabled): a hook the user declined runs nothing, so one declined hook
/// leaves the session unguarded. The fingerprint is, for each hook, the file, its position and
/// definition, and that `trusted_hash`. Codex computes the hash itself and runs no hook whose
/// current definition the user has not trusted, so a guard hook that ran proves the trust then;
/// Lunchroom records this fingerprint when its guard runs, and the session is guarded only while
/// the fingerprint is unchanged.
#[must_use]
pub fn codex_guard_fingerprint(pid: u32, cwd: &Path, home: &Path) -> Option<String> {
    codex_fingerprint_in(&codex_home_of(pid, home), pid, cwd)
}

fn codex_fingerprint_in(codex_home: &Path, pid: u32, cwd: &Path) -> Option<String> {
    let config = std::fs::read_to_string(codex_home.join("config.toml")).unwrap_or_default();
    [codex_home.join("hooks.json"), cwd.join(".codex/hooks.json")]
        .iter()
        .find_map(|file| {
            let hooks = read_json(file)?;
            if !CODEX_GUARD_HOOKS
                .iter()
                .all(|(event, mode)| has_guard_hook(&hooks, event, mode, pid, cwd))
            {
                return None;
            }
            let mut trusted = Vec::new();
            for (state, g, h, hook) in lunchroom_hooks_in(&hooks) {
                let key = format!("{}:{state}:{g}:{h}", file.display());
                let hash = trusted_hash(&config, &key)?;
                trusted.push(format!("{key}|{hook}|{hash}"));
            }
            Some(trusted.join("\n"))
        })
}

/// Every Lunchroom hook in a Codex `hooks.json`, as its event's `config.toml` name, its group and
/// position, and its definition.
fn lunchroom_hooks_in(hooks: &Value) -> Vec<(&'static str, usize, usize, &Value)> {
    let mut out = Vec::new();
    for (event, state) in CODEX_EVENTS {
        for (g, group) in hooks["hooks"][event]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            for (h, hook) in group["hooks"].as_array().into_iter().flatten().enumerate() {
                if is_lunchroom_hook(hook) {
                    out.push((state, g, h, hook));
                }
            }
        }
    }
    out
}

/// A hook whose command runs Lunchroom's program, its path quoted or not.
fn is_lunchroom_hook(hook: &Value) -> bool {
    lunchroom_command(hook).is_some()
}

/// The program and the arguments of a hook command that runs a Lunchroom program, its path quoted
/// or not. `lunchroom install` quotes a path that needs it and reads installed commands back with
/// the same parser (`install::program_and_args`), so every path `install` writes reads the same
/// here (R3.1): a path with a space is the program, not a prefix of it.
fn lunchroom_command(hook: &Value) -> Option<(&str, &str)> {
    let command = hook["command"].as_str()?;
    let (program, args) = crate::install::program_and_args(command);
    // A quoted word ends at its closing quote: `'/p/lunchroom'guard` is one word to the shell.
    let word_ends = command
        .strip_prefix('\'')
        .and_then(|quoted| quoted.get(program.len() + 1..))
        .is_none_or(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace));
    (word_ends && program.rsplit('/').next() == Some("lunchroom")).then_some((program, args))
}

/// The program of a hook whose command is exactly Lunchroom's `guard <mode>`.
fn guard_program<'a>(hook: &'a Value, mode: &str) -> Option<&'a str> {
    let (program, args) = lunchroom_command(hook)?;
    (args == format!("guard {mode}")).then_some(program)
}

/// The Codex session in process `pid` is guarded: its trusted guard is the one recorded.
fn codex_configured(pid: u32, cwd: &Path, home: &Path, recorded: Option<&str>) -> bool {
    recorded.is_some_and(|r| codex_guard_fingerprint(pid, cwd, home).as_deref() == Some(r))
}

/// The program a Lunchroom plugin file runs: its `PROGRAM = "<path>"` line (`const PROGRAM` in
/// OpenClaw's plugin), as `lunchroom install` writes it.
#[must_use]
pub fn plugin_program(text: &str) -> Option<&str> {
    text.lines().find_map(|l| {
        let rest = l.trim_start();
        let rest = rest.strip_prefix("const ").unwrap_or(rest);
        rest.strip_prefix("PROGRAM = \"")?
            .strip_suffix("\";")
            .or_else(|| rest.strip_prefix("PROGRAM = \"")?.strip_suffix('"'))
    })
}

/// H1.2: the version each adapter passed with; that version and later ones are guarded, an older
/// or unreadable one is UNGUARDED. Claude Code, Codex and OpenClaw by
/// their release numbers; Hermes, a source install of which reports a commit and its date, by the
/// commit the adapter passed with or a later commit date (host facts:
/// `docs/host-facts/openclaw-and-hermes.md`).
const PASSED_WITH: [(Harness, &str); 4] = [
    (Harness::ClaudeCode, "2.1.310"),
    (Harness::Codex, "0.163.0"),
    (Harness::OpenClaw, "2026.10.7"),
    (Harness::Hermes, HERMES_PASSED_COMMIT),
];
const HERMES_PASSED_COMMIT: &str = "9976f4857b72439d79016354d7b6e1a3ee952e2f";
/// The commit date of `HERMES_PASSED_COMMIT` (seconds since the Unix epoch, `git log -1 --format=%ct`).
const HERMES_PASSED_DATE: u64 = 1_793_038_003;

/// The release number at the start of `text` (`2.1.310`, `0.164.0-x86_64-…`, `2026.10.7`).
fn release(text: &str) -> Option<Vec<u64>> {
    let digits: String = text
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Option<Vec<u64>> = digits
        .trim_end_matches('.')
        .split('.')
        .map(|p| p.parse().ok())
        .collect();
    parts.filter(|p| p.len() >= 2)
}

/// Codex's npm packages: `@openai/codex` and its platform builds.
const CODEX_PACKAGES: [&str; 7] = [
    "@openai/codex",
    "@openai/codex-linux-x64",
    "@openai/codex-linux-arm64",
    "@openai/codex-darwin-x64",
    "@openai/codex-darwin-arm64",
    "@openai/codex-win32-x64",
    "@openai/codex-win32-arm64",
];

/// The release of `harness`'s program at `path`, as that harness's own install shows it: Claude
/// Code's native install keeps each release at `…/claude/versions/<release>`, and an npm install
/// has the `@anthropic-ai/claude-code` package's `package.json` above its program; Codex keeps a
/// daemon release at `…/.codex/…/releases/<release>-<target>/…`, and its npm packages are named
/// `@openai/codex` or one of its platform builds (`@openai/codex-linux-x64` and the like). A path
/// or package of anything else gives none.
#[must_use]
pub fn version_from_path(harness: Harness, path: &Path) -> Option<String> {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let (packages, from_path): (&[&str], Option<String>) = match harness {
        Harness::ClaudeCode => (
            &["@anthropic-ai/claude-code"],
            parts
                .windows(3)
                .find(|w| w[0] == "claude" && w[1] == "versions" && release(&w[2]).is_some())
                .map(|w| w[2].clone()),
        ),
        Harness::Codex => (
            &CODEX_PACKAGES,
            parts.iter().position(|p| p == ".codex").and_then(|at| {
                parts[at..]
                    .windows(2)
                    .find(|w| w[0] == "releases" && release(&w[1]).is_some())
                    .map(|w| w[1].clone())
            }),
        ),
        Harness::OpenClaw | Harness::Hermes => return None,
    };
    if from_path.is_some() {
        return from_path;
    }
    let mut dir = path.parent();
    for _ in 0..8 {
        let Some(d) = dir else { break };
        if let Some(v) = read_json(&d.join("package.json"))
            .filter(|p| p["name"].as_str().is_some_and(|n| packages.contains(&n)))
            .and_then(|p| p["version"].as_str().map(str::to_owned))
            .filter(|v| release(v).is_some())
        {
            return Some(v);
        }
        dir = d.parent();
    }
    None
}

/// The release of `harness` running as process `pid`, from its own install alone: its program's
/// path (its binary, or the script a runtime runs) or its package's `package.json` above it.
fn process_version(harness: Harness, pid: u32) -> Option<String> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let script = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|raw| {
            raw.split(|b| *b == 0)
                .nth(1)
                .map(|a| PathBuf::from(String::from_utf8_lossy(a).into_owned()))
        })
        .filter(|p| p.is_absolute());
    exe.iter()
        .chain(script.iter())
        .find_map(|p| version_from_path(harness, p))
}

/// The record a plugin harness's guard hook leaves: the plugin's file and the harness's version.
#[must_use]
pub fn plugin_fingerprint(file: &Path, version: &str) -> String {
    format!("{}\n{version}", file.display())
}

/// A 40-character hexadecimal git commit.
fn is_commit(text: &str) -> bool {
    text.len() == 40 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// H1.2: `version` is the release the adapter for `harness` states in the list `passed` of passing
/// adapters, or a later one; a harness missing from the list has no passing adapter, so no release
/// of it passes. Hermes's release, as its plugin reports it,
/// is a 40-character commit, alone (passing only as the stated commit) or with its commit date
/// after `@` (passing at or after the stated date); anything else cannot be read.
fn passes_with(passed: &[(Harness, &str)], harness: Harness, version: &str) -> bool {
    if harness == Harness::Hermes {
        if !passed.iter().any(|(h, _)| *h == Harness::Hermes) {
            return false;
        }
        return match version.split_once('@') {
            None => is_commit(version) && version == HERMES_PASSED_COMMIT,
            Some((commit, date)) => {
                is_commit(commit)
                    && date.parse::<u64>().is_ok_and(|d| {
                        d >= HERMES_PASSED_DATE
                            && (d > HERMES_PASSED_DATE || commit == HERMES_PASSED_COMMIT)
                    })
            }
        };
    }
    let Some(have) = release(version) else {
        return false;
    };
    passed
        .iter()
        .find(|(h, _)| *h == harness)
        .and_then(|(_, v)| release(v))
        .is_some_and(|stated| have >= stated)
}

/// The harness release a plugin harness's guard hook recorded with its plugin file (H1.2); empty
/// when none was recorded.
fn plugin_release(recorded: Option<&str>) -> &str {
    recorded
        .and_then(|r| r.split_once('\n'))
        .map_or("", |(_, version)| version)
}

/// R3.1: the plugin file a guard hook recorded still runs a Lunchroom program, at an absolute path,
/// that is there to run.
fn plugin_runs_guard(recorded: Option<&str>) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Some((file, _)) = recorded.and_then(|r| r.split_once('\n')) else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(file) else {
        return false;
    };
    plugin_program(&text).is_some_and(|program| {
        let path = Path::new(program);
        path.is_absolute()
            && path.file_name().is_some_and(|n| n == "lunchroom")
            && std::fs::metadata(path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// `~/…` with the user's home.
fn expand(path: &str, home: &Path) -> PathBuf {
    path.strip_prefix("~/")
        .map_or_else(|| PathBuf::from(path), |rest| home.join(rest))
}

/// The value of `key` in a `.env` file.
fn dotenv(file: &Path, key: &str) -> Option<String> {
    std::fs::read_to_string(file)
        .ok()?
        .lines()
        .find_map(|l| {
            let l = l.trim();
            let l = l.strip_prefix("export ").unwrap_or(l);
            l.strip_prefix(key)?
                .strip_prefix('=')
                .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_owned())
        })
        .filter(|v| !v.is_empty())
}

/// The `openclaw.json` the gateway in process `pid` reads (OpenClaw `docs/help/environment.md`:
/// these variables may be set in the trusted `.env` of the state folder, `~/.openclaw/.env` by
/// default): `OPENCLAW_CONFIG_PATH` from the gateway's environment, the state folder's `.env` or
/// `~/.openclaw/.env`, else `openclaw.json` in the state folder (`OPENCLAW_STATE_DIR` from the
/// gateway's environment or `~/.openclaw/.env`, default `~/.openclaw`).
fn openclaw_config(pid: u32, home: &Path) -> PathBuf {
    openclaw_config_from(&|k| process_env(pid, k), home)
}

fn openclaw_config_from(env: &dyn Fn(&str) -> Option<String>, home: &Path) -> PathBuf {
    let default_dotenv = home.join(".openclaw/.env");
    let state = env("OPENCLAW_STATE_DIR")
        .or_else(|| dotenv(&default_dotenv, "OPENCLAW_STATE_DIR"))
        .map_or_else(|| home.join(".openclaw"), |d| expand(&d, home));
    env("OPENCLAW_CONFIG_PATH")
        .or_else(|| dotenv(&state.join(".env"), "OPENCLAW_CONFIG_PATH"))
        .or_else(|| dotenv(&default_dotenv, "OPENCLAW_CONFIG_PATH"))
        .map_or_else(|| state.join("openclaw.json"), |p| expand(&p, home))
}

// protocol-words:begin (OpenClaw's own `openclaw.json` key; never shown to a person)
const OPENCLAW_ALLOW_LIST: &str = "allow";
// protocol-words:end

/// The OpenClaw gateway in process `pid` has Lunchroom's plugin enabled with conversation access:
/// plugins are on, `lunchroom` is not denied and is allowed where an allow list is set, its entry
/// is enabled, and `hooks.allowConversationAccess` is `true`. A file that cannot be read counts
/// as not enabled.
fn openclaw_enables(pid: u32, home: &Path) -> bool {
    std::fs::read_to_string(openclaw_config(pid, home))
        .ok()
        .and_then(|t| json5(&t))
        .is_some_and(|config| openclaw_config_enables(&config))
}

/// `openclaw.json`'s settings enable Lunchroom's plugin with conversation access.
#[must_use]
pub fn openclaw_config_enables(config: &Value) -> bool {
    let plugins = &config["plugins"];
    let listed = |key: &str| {
        plugins[key]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "lunchroom"))
    };
    let allow_set = plugins[OPENCLAW_ALLOW_LIST]
        .as_array()
        .is_some_and(|a| !a.is_empty());
    let entry = &plugins["entries"]["lunchroom"];
    plugins["enabled"] != Value::Bool(false)
        && !listed("deny")
        && (!allow_set || listed(OPENCLAW_ALLOW_LIST))
        && entry["enabled"] == Value::Bool(true)
        && entry["hooks"]["allowConversationAccess"] == Value::Bool(true)
}

/// Hermes in process `pid` has Lunchroom's plugin enabled: `lunchroom` is in `plugins.enabled`
/// and not in `plugins.disabled` (a disable wins) in `<HERMES_HOME>/config.yaml`, `HERMES_HOME`
/// from the process's environment, default `~/.hermes` (Hermes `hermes_cli/plugins_discovery.py`
/// 112-131, 289-299). A file that cannot be read counts as not enabled.
fn hermes_enables(pid: u32, home: &Path) -> bool {
    let hermes_home =
        process_env(pid, "HERMES_HOME").map_or_else(|| home.join(".hermes"), |d| expand(&d, home));
    std::fs::read_to_string(hermes_home.join("config.yaml"))
        .ok()
        .and_then(|t| hermes_plugin_lists(&t))
        .is_some_and(|(enabled, disabled)| {
            enabled.iter().any(|n| n == "lunchroom") && !disabled.iter().any(|n| n == "lunchroom")
        })
}

/// One YAML scalar: without a trailing comment and its quotes.
fn yaml_scalar(text: &str) -> String {
    let text = text.split(" #").next().unwrap_or_default().trim();
    text.trim_matches('"').trim_matches('\'').to_owned()
}

/// The `plugins.enabled` and `plugins.disabled` lists of a Hermes `config.yaml`, in block style
/// (`- name` lines) or flow style (`[a, b]`); `None` when the `plugins` section is written in a
/// form this reader does not read (so the session is not counted as guarded).
#[must_use]
pub fn hermes_plugin_lists(text: &str) -> Option<(Vec<String>, Vec<String>)> {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let content = |l: &str| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#')
    };
    let lines: Vec<&str> = text.lines().filter(|l| content(l)).collect();
    let Some(start) = lines
        .iter()
        .position(|l| indent(l) == 0 && l.trim_end().starts_with("plugins:"))
    else {
        return Some((Vec::new(), Vec::new()));
    };
    if !yaml_scalar(&lines[start]["plugins:".len()..]).is_empty() {
        return None;
    }
    let body: Vec<&str> = lines[start + 1..]
        .iter()
        .take_while(|l| indent(l) > 0)
        .copied()
        .collect();
    let mut lists = (Vec::new(), Vec::new());
    let child = body.first().map_or(0, |l| indent(l));
    let mut k = 0;
    while k < body.len() {
        let line = body[k];
        k += 1;
        if indent(line) != child {
            continue;
        }
        let (key, rest) = line.trim().split_once(':')?;
        let target = match key.trim() {
            "enabled" => &mut lists.0,
            "disabled" => &mut lists.1,
            _ => continue,
        };
        let rest = rest.split(" #").next().unwrap_or_default().trim();
        if let Some(flow) = rest.strip_prefix('[') {
            let flow = flow.strip_suffix(']')?;
            target.extend(flow.split(',').map(yaml_scalar).filter(|s| !s.is_empty()));
        } else if rest.is_empty() {
            while k < body.len() && indent(body[k]) > child {
                let item = body[k].trim().strip_prefix('-')?;
                target.push(yaml_scalar(item));
                k += 1;
            }
        } else {
            return None;
        }
    }
    Some(lists)
}

/// A JSON5 text (comments, trailing commas, single-quoted strings, unquoted keys) as JSON.
#[must_use]
pub fn json5(text: &str) -> Option<Value> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut k = 0;
    // Skips whitespace and comments from `k`; the index of the next other character.
    let skip = |mut k: usize| -> usize {
        loop {
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if chars.get(k) == Some(&'/') && chars.get(k + 1) == Some(&'/') {
                while k < chars.len() && chars[k] != '\n' {
                    k += 1;
                }
            } else if chars.get(k) == Some(&'/') && chars.get(k + 1) == Some(&'*') {
                k += 2;
                while k + 1 < chars.len() && !(chars[k] == '*' && chars[k + 1] == '/') {
                    k += 1;
                }
                k += 2;
            } else {
                return k;
            }
        }
    };
    while k < chars.len() {
        let c = chars[k];
        if c == '"' || c == '\'' {
            out.push('"');
            k += 1;
            while k < chars.len() && chars[k] != c {
                if chars[k] == '\\' && k + 1 < chars.len() {
                    match chars[k + 1] {
                        '\'' => out.push('\''),
                        '\n' => {}
                        e => {
                            out.push('\\');
                            out.push(e);
                        }
                    }
                    k += 2;
                    continue;
                }
                if chars[k] == '"' {
                    out.push('\\');
                }
                out.push(chars[k]);
                k += 1;
            }
            out.push('"');
            k += 1;
        } else if c == '/' && matches!(chars.get(k + 1), Some('/' | '*')) {
            k = skip(k);
        } else if c == ',' && matches!(chars.get(skip(k + 1)), Some('}' | ']')) {
            k += 1;
        } else if c.is_alphabetic() || c == '_' || c == '$' {
            let start = k;
            while k < chars.len()
                && (chars[k].is_alphanumeric() || chars[k] == '_' || chars[k] == '$')
            {
                k += 1;
            }
            let word: String = chars[start..k].iter().collect();
            if chars.get(skip(k)) == Some(&':') {
                out.push('"');
                out.push_str(&word);
                out.push('"');
            } else {
                out.push_str(&word);
            }
        } else {
            out.push(c);
            k += 1;
        }
    }
    serde_json::from_str(&out).ok()
}

/// A variable in process `pid`'s starting environment.
fn process_env(pid: u32, name: &str) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    raw.split(|b| *b == 0).find_map(|kv| {
        let kv = String::from_utf8_lossy(kv);
        kv.strip_prefix(&format!("{name}="))
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    })
}

/// The `trusted_hash` under `[hooks.state."<key>"]` in `config.toml`, unless that hook is
/// disabled (`enabled = false`).
fn trusted_hash(config: &str, key: &str) -> Option<String> {
    let header = format!("[hooks.state.\"{key}\"]");
    let start = config.find(&header)?;
    let body = &config[start + header.len()..];
    let section = body.split("\n[").next().unwrap_or_default();
    let value = |k: &str| {
        section.lines().find_map(|l| {
            let (name, v) = l.split_once('=')?;
            (name.trim() == k).then(|| v.trim().trim_matches('"').to_owned())
        })
    };
    if value("enabled").as_deref() == Some("false") {
        return None;
    }
    value("trusted_hash").filter(|h| !h.is_empty())
}

/// R3.1: the program a guard hook runs is there to run: an executable file at its absolute path,
/// at a relative path from the session's working folder (where the harness's shell runs it), or,
/// for a bare name, in a folder of the harness process's `PATH`. A guard whose program is missing
/// runs nothing, so its session is not guarded.
fn program_present(hook: &Value, pid: u32, cwd: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Some((program, _)) = lunchroom_command(hook) else {
        return false;
    };
    let runnable = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.starts_with('/') {
        return runnable(Path::new(program));
    }
    if program.contains('/') {
        return runnable(&cwd.join(program));
    }
    process_env(pid, "PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| runnable(&dir.join(program))))
}

/// Claude Code's managed settings file.
const MANAGED_SETTINGS: &str = "/etc/claude-code/managed-settings.json";

/// The hooks Claude Code needs from Lunchroom's guard, as `lunchroom install` writes them: the
/// event and the guard's mode. `PreToolUse` decides each call; `PostToolUse` and
/// `PostToolUseFailure` (Claude Code's event for a tool that failed) see each result; and
/// `UserPromptSubmit` sees the prompt that holds the session and confirms a delivery (D1.1). With
/// one missing, a message would reach a session whose protection is partial.
const CLAUDE_GUARD_HOOKS: [(&str, &str); 4] = [
    ("PreToolUse", "pretool"),
    ("PostToolUse", "posttool"),
    ("PostToolUseFailure", "posttool"),
    ("UserPromptSubmit", "prompt"),
];

/// The session in process `pid` is guarded: the hooks Claude Code actually runs for it include
/// every one of [`CLAUDE_GUARD_HOOKS`].
fn configured(pid: u32, cwd: &Path, home: &Path) -> bool {
    let config_dir =
        process_env(pid, "CLAUDE_CONFIG_DIR").map_or_else(|| home.join(".claude"), PathBuf::from);
    configured_with(
        &cmdline_args(pid),
        &config_dir,
        Path::new(MANAGED_SETTINGS),
        pid,
        cwd,
    )
}

/// `configured` for a Claude Code process started with `args`, whose user settings are in
/// `config_dir` and whose managed settings are `managed`.
///
/// Claude Code merges hook entries across settings levels, so the hooks that run are the union of
/// the levels it loads (<https://code.claude.com/docs/en/hooks.md>, "Hook entries merge across
/// settings levels"): the user, project and local levels named by `--setting-sources` (all three
/// without it), the `--settings` files, and the managed level. Nothing runs under `--bare`.
/// `disableAllHooks` is read as the value left after precedence (local over project over user,
/// `--settings` over those); when true it leaves only the managed hooks, which only a
/// `disableAllHooks` in managed settings stops. The managed `allowManagedHooksOnly` leaves only
/// the managed hooks too.
fn configured_with(
    args: &[String],
    config_dir: &Path,
    managed: &Path,
    pid: u32,
    cwd: &Path,
) -> bool {
    if args.iter().any(|a| a == "--bare") {
        return false;
    }
    let managed = read_json(managed);
    let managed_flag = |key: &str| managed.as_ref().and_then(|m| m[key].as_bool());
    if managed_flag("disableAllHooks") == Some(true) {
        return false;
    }
    let loaded = setting_sources(args);
    let mut levels: Vec<Value> = [
        ("user", config_dir.join("settings.json")),
        ("project", cwd.join(".claude/settings.json")),
        ("local", cwd.join(".claude/settings.local.json")),
    ]
    .into_iter()
    .filter(|(name, _)| {
        loaded
            .as_ref()
            .is_none_or(|l| l.iter().any(|s| s.as_str() == *name))
    })
    .filter_map(|(_, path)| read_json(&path))
    .collect();
    levels.extend(settings_flag(args, cwd));
    let others_off = levels
        .iter()
        .rev()
        .find_map(|v| v["disableAllHooks"].as_bool())
        == Some(true);
    let mut running: Vec<Value> = managed.clone().into_iter().collect();
    if !others_off && managed_flag("allowManagedHooksOnly") != Some(true) {
        running.extend(levels);
    }
    CLAUDE_GUARD_HOOKS.iter().all(|(event, mode)| {
        running
            .iter()
            .any(|v| has_guard_hook(v, event, mode, pid, cwd))
    })
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// The arguments process `pid` was started with.
fn cmdline_args(pid: u32) -> Vec<String> {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return Vec::new();
    };
    let mut args: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    // The last argument ends in a NUL, which leaves one empty piece after it.
    if args.last().is_some_and(String::is_empty) {
        args.pop();
    }
    args
}

/// The values of option `name` in `args`, given as `name value` or `name=value`.
fn option_values<'a>(args: &'a [String], name: &'a str) -> impl Iterator<Item = &'a str> {
    args.iter().enumerate().filter_map(move |(k, a)| {
        if a == name {
            args.get(k + 1).map(String::as_str)
        } else {
            a.strip_prefix(name)?.strip_prefix('=')
        }
    })
}

/// The settings levels named by `--setting-sources` (`user`, `project`, `local`), or `None` when
/// the process was given none and Claude Code loads all three.
fn setting_sources(args: &[String]) -> Option<Vec<String>> {
    option_values(args, "--setting-sources").last().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// The settings given to a process started with `args` as `--settings <file or JSON text>`.
fn settings_flag(args: &[String], cwd: &Path) -> Vec<Value> {
    option_values(args, "--settings")
        .filter_map(|given| {
            if given.trim_start().starts_with('{') {
                serde_json::from_str(given).ok()
            } else {
                let path = PathBuf::from(given);
                read_json(&if path.is_absolute() {
                    path
                } else {
                    cwd.join(path)
                })
            }
        })
        .collect()
}

/// `settings` holds a hook of `event` that runs Lunchroom's `guard <mode>` on every occurrence of
/// the event: its group's matcher is absent, empty or `*` (any other matcher is a tool name or a
/// pattern, which leaves the calls it does not match unchecked; `UserPromptSubmit` has no
/// matcher), and the hook is a synchronous command with no `if` filter whose program is there to
/// run.
fn has_guard_hook(settings: &Value, event: &str, mode: &str, pid: u32, cwd: &Path) -> bool {
    settings["hooks"][event]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|group| {
            event == "UserPromptSubmit"
                || match &group["matcher"] {
                    Value::Null => true,
                    Value::String(m) => m.is_empty() || m == "*",
                    _ => false,
                }
        })
        .flat_map(|g| g["hooks"].as_array().into_iter().flatten())
        .any(|h| {
            guard_program(h, mode).is_some()
                && h["type"] == "command"
                && h["if"].is_null()
                && h["async"].as_bool() != Some(true)
                && h["asyncRewake"].as_bool() != Some(true)
                && program_present(h, pid, cwd)
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // R3.1 (OpenClaw): `openclaw.json` is JSON5; comments, trailing commas, single-quoted strings
    // and unquoted keys read as JSON, a `//` inside a string is text, and a file that is not JSON5
    // reads as nothing (the session is then not guarded).
    #[test]
    fn json5_reads_openclaw_settings() {
        let text = r#"// OpenClaw settings
{
  plugins: {
    /* the guard */
    entries: { 'lunchroom': { enabled: true, hooks: { allowConversationAccess: true, }, }, },
    load: { paths: ["https://example.com//x", 'it\'s'], },
  },
}
"#;
        let v = json5(text);
        assert_eq!(
            v,
            Some(json!({"plugins": {
                "entries": {"lunchroom": {"enabled": true, "hooks": {"allowConversationAccess": true}}},
                "load": {"paths": ["https://example.com//x", "it's"]},
            }}))
        );
        assert_eq!(json5("{ plugins: "), None);
        assert_eq!(json5("{\"a\": 1,}"), Some(json!({"a": 1})));
    }

    // R3.1 (OpenClaw): guarded only while the plugin is on, not denied, allowed where an allow list
    // is set, enabled, and granted conversation access.
    #[test]
    fn openclaw_settings_enable_the_guard_only_with_conversation_access() {
        let on = json!({"plugins": {"entries": {"lunchroom": {
            "enabled": true, "hooks": {"allowConversationAccess": true}}}}});
        assert!(openclaw_config_enables(&on));
        let mut cases = Vec::new();
        for (path, value) in [
            ("/plugins/enabled", json!(false)),
            ("/plugins/deny", json!(["lunchroom"])),
            ("/plugins/allow", json!(["other"])),
            ("/plugins/entries/lunchroom/enabled", json!(false)),
            (
                "/plugins/entries/lunchroom/hooks/allowConversationAccess",
                json!(false),
            ),
        ] {
            let mut c = on.clone();
            if let Some(parent) = path.rsplit_once('/').and_then(|(p, _)| c.pointer_mut(p)) {
                let key = path.rsplit('/').next().unwrap_or_default();
                parent[key] = value;
            }
            cases.push((path, c));
        }
        let mut no_access = on.clone();
        if let Some(h) = no_access.pointer_mut("/plugins/entries/lunchroom/hooks") {
            *h = json!({});
        }
        cases.push(("no grant", no_access));
        cases.push(("no entry", json!({"plugins": {}})));
        for (what, config) in &cases {
            assert!(!openclaw_config_enables(config), "{what}");
        }
        let mut allowed = on;
        allowed["plugins"]["allow"] = json!(["lunchroom", "other"]);
        assert!(openclaw_config_enables(&allowed));
    }

    // H1.2: the version each adapter passed with and later ones pass;
    // an older version, an unreadable one and none do not.
    #[test]
    fn the_passed_version_and_later_ones_pass() {
        for (harness, version) in [
            (Harness::ClaudeCode, "2.1.310"),
            (Harness::ClaudeCode, "2.1.311"),
            (Harness::ClaudeCode, "2.2.0"),
            (Harness::ClaudeCode, "3.0.0"),
            (Harness::Codex, "0.163.0"),
            (Harness::Codex, "0.164.0-x86_64-unknown-linux-musl"),
            (Harness::Codex, "0.163.0-linux-x64"),
            (Harness::OpenClaw, "2026.10.7"),
            (Harness::OpenClaw, "2026.10.8"),
            (Harness::OpenClaw, "2027.1.1"),
            (Harness::Hermes, "9976f4857b72439d79016354d7b6e1a3ee952e2f"),
            (
                Harness::Hermes,
                "9976f4857b72439d79016354d7b6e1a3ee952e2f@1793038003",
            ),
            (
                Harness::Hermes,
                "0123456789abcdef0123456789abcdef01234567@1793038004",
            ),
        ] {
            assert!(
                passes_with(&PASSED_WITH, harness, version),
                "{harness:?} {version}"
            );
        }
        for (harness, version) in [
            (Harness::ClaudeCode, "2.1.309"),
            (Harness::ClaudeCode, "2.0.999"),
            (Harness::ClaudeCode, "unknown"),
            (Harness::ClaudeCode, ""),
            (Harness::Codex, "0.162.9"),
            (Harness::OpenClaw, "2026.10.6"),
            (Harness::OpenClaw, "2026.9.30"),
            (Harness::OpenClaw, "2026"),
            (Harness::Hermes, "9976f48"),
            (
                Harness::Hermes,
                "0123456789abcdef0123456789abcdef01234567@1793038002",
            ),
            (Harness::Hermes, "0123456789abcdef0123456789abcdef01234567"),
            (Harness::Hermes, "2026.10.7"),
            (Harness::Hermes, ""),
            (Harness::Hermes, "not-a-commit@1793038004"),
            (
                Harness::Hermes,
                "9976f4857b72439d79016354d7b6e1a3ee952e2f@not-a-date",
            ),
            (Harness::Hermes, "9976f4857b72439d79016354d7b6e1a3ee952e2f@"),
            (Harness::Hermes, "@1793038004"),
        ] {
            assert!(
                !passes_with(&PASSED_WITH, harness, version),
                "{harness:?} {version}"
            );
        }
    }

    // §13::2 (a2), §13::14 (3): a harness whose adapter has not passed (missing from the
    // list of passing adapters) is not passed at any release, the stated one and later ones
    // included; with it in the list, the same releases pass.
    #[test]
    fn a_harness_whose_adapter_has_not_passed_passes_at_no_release() {
        let without: Vec<(Harness, &str)> = PASSED_WITH
            .iter()
            .copied()
            .filter(|(h, _)| *h != Harness::OpenClaw && *h != Harness::Hermes)
            .collect();
        for (harness, version) in [
            (Harness::OpenClaw, "2026.10.7"),
            (Harness::OpenClaw, "2027.1.1"),
            (Harness::Hermes, "9976f4857b72439d79016354d7b6e1a3ee952e2f"),
            (
                Harness::Hermes,
                "0123456789abcdef0123456789abcdef01234567@1893038004",
            ),
        ] {
            assert!(
                !passes_with(&without, harness, version),
                "{harness:?} {version}"
            );
            assert!(
                passes_with(&PASSED_WITH, harness, version),
                "{harness:?} {version}"
            );
        }
    }

    // H1.2: a harness's release is read from its own install: its install's path, or its own
    // package's `package.json` above its program; another program's path or package gives none.
    #[test]
    fn versions_are_read_from_the_harness_own_install() {
        let claude = Harness::ClaudeCode;
        let codex = Harness::Codex;
        assert_eq!(
            version_from_path(
                claude,
                Path::new("/home/u/.local/share/claude/versions/2.1.310")
            ),
            Some("2.1.310".to_owned())
        );
        let daemon = Path::new(
            "/home/u/.codex/packages/app-server-daemon/releases/0.164.0-x86_64-unknown-linux-musl/bin/codex",
        );
        assert_eq!(
            version_from_path(codex, daemon),
            Some("0.164.0-x86_64-unknown-linux-musl".to_owned())
        );
        // Another harness's install, or a look-alike folder, is not this harness's release.
        assert_eq!(version_from_path(claude, daemon), None);
        for other in [
            "/tmp/x/versions/9.9.9",
            "/tmp/x/claude-other/versions/9.9.9",
            "/tmp/releases/9.9.9-x/bin/codex",
        ] {
            assert_eq!(version_from_path(claude, Path::new(other)), None, "{other}");
            assert_eq!(version_from_path(codex, Path::new(other)), None, "{other}");
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/version-unit")
            .join(std::process::id().to_string());
        let codex_bin = root.join("node_modules/@openai/codex/bin");
        let other_bin = root.join("node_modules/other/bin");
        let _ = std::fs::create_dir_all(&codex_bin);
        let _ = std::fs::create_dir_all(&other_bin);
        let _ = std::fs::write(
            root.join("node_modules/@openai/codex/package.json"),
            r#"{"name": "@openai/codex", "version": "0.163.0"}"#,
        );
        let _ = std::fs::write(
            root.join("node_modules/other/package.json"),
            r#"{"name": "other", "version": "99.0.0"}"#,
        );
        assert_eq!(
            version_from_path(codex, &codex_bin.join("codex.js")),
            Some("0.163.0".to_owned())
        );
        assert_eq!(version_from_path(claude, &codex_bin.join("codex.js")), None);
        assert_eq!(version_from_path(codex, &other_bin.join("x.js")), None);
        // A look-alike package name gives no release.
        let fake = root.join("node_modules/@anthropic-ai/claude-code-other");
        let _ = std::fs::create_dir_all(fake.join("bin"));
        let _ = std::fs::write(
            fake.join("package.json"),
            r#"{"name": "@anthropic-ai/claude-code-other", "version": "99.0.0"}"#,
        );
        assert_eq!(version_from_path(claude, &fake.join("bin/cli.js")), None);
        assert_eq!(version_from_path(claude, Path::new("/usr/bin/sleep")), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    // R3.1 (OpenClaw): the configuration file is found where OpenClaw finds it: the gateway's
    // environment first, then the state folder's `.env`, then `~/.openclaw/.env`.
    #[test]
    fn openclaw_config_is_found_where_openclaw_finds_it() {
        let home = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/openclaw-config-unit")
            .join(std::process::id().to_string());
        let _ = std::fs::create_dir_all(home.join(".openclaw"));
        let _ = std::fs::create_dir_all(home.join("state"));
        let none = |_: &str| None;
        assert_eq!(
            openclaw_config_from(&none, &home),
            home.join(".openclaw/openclaw.json")
        );
        let _ = std::fs::write(home.join(".openclaw/.env"), "OPENCLAW_STATE_DIR=~/state\n");
        assert_eq!(
            openclaw_config_from(&none, &home),
            home.join("state/openclaw.json")
        );
        let _ = std::fs::write(
            home.join("state/.env"),
            "export OPENCLAW_CONFIG_PATH=\"~/state/custom.json\"\n",
        );
        assert_eq!(
            openclaw_config_from(&none, &home),
            home.join("state/custom.json")
        );
        let env = |k: &str| (k == "OPENCLAW_CONFIG_PATH").then(|| "/etc/oc.json".to_owned());
        assert_eq!(
            openclaw_config_from(&env, &home),
            PathBuf::from("/etc/oc.json")
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    // R3.1 (Hermes): the plugin lists of `config.yaml`, block and flow style, with comments and
    // quotes; a disable wins; a `plugins` section in a form not read gives nothing.
    #[test]
    fn hermes_plugin_lists_read_both_yaml_styles() {
        let block = "model: x\nplugins:\n  # ours\n  enabled:\n    - lunchroom\n    - 'other'\n  disabled: []\nnext: 1\n";
        assert_eq!(
            hermes_plugin_lists(block),
            Some((vec!["lunchroom".to_owned(), "other".to_owned()], Vec::new()))
        );
        let flow = "plugins:\n  enabled: [\"lunchroom\", other]  # set by hermes\n  disabled: [lunchroom]\n";
        assert_eq!(
            hermes_plugin_lists(flow),
            Some((
                vec!["lunchroom".to_owned(), "other".to_owned()],
                vec!["lunchroom".to_owned()]
            ))
        );
        assert_eq!(
            hermes_plugin_lists("model: x\n"),
            Some((Vec::new(), Vec::new()))
        );
        assert_eq!(
            hermes_plugin_lists("plugins: {enabled: [lunchroom]}\n"),
            None
        );
        assert_eq!(
            hermes_plugin_lists("plugins:\n  enabled: lunchroom\n"),
            None
        );
    }

    // §13::2 (a2), §13::14 (3) through the evidence itself: a live OpenClaw session in
    // this process, its plugin file running a Lunchroom program, `openclaw.json` enabling the plugin
    // with conversation access, its hook having reported release R. With OpenClaw among the passing
    // adapters it is guarded at the stated release and a later one; with OpenClaw's adapter not
    // among them it is UNGUARDED at both (so the listener and delivery, which act only on a guarded
    // session, give it nothing and its messages stay QUEUED).
    #[test]
    fn a_session_whose_adapter_has_not_passed_is_unguarded_at_any_release() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/evidence-unit")
            .join(std::process::id().to_string());
        let home = root.join("home");
        let _ = std::fs::create_dir_all(home.join(".openclaw"));
        let _ = std::fs::write(
            home.join(".openclaw/openclaw.json"),
            "{plugins: {entries: {lunchroom: {enabled: true, hooks: {allowConversationAccess: true}}}}}",
        );
        let bin = root.join("bin");
        let _ = std::fs::create_dir_all(&bin);
        let _ = std::fs::copy("/bin/true", bin.join("lunchroom"));
        let plugin = root.join("index.mjs");
        let _ = std::fs::write(
            &plugin,
            format!("const PROGRAM = \"{}\";\n", bin.join("lunchroom").display()),
        );
        let process = crate::process::key(std::process::id()).unwrap_or_default();
        let who = Identity::new(Harness::OpenClaw, "agent:main:x");
        let without: Vec<(Harness, &str)> = PASSED_WITH
            .iter()
            .copied()
            .filter(|(h, _)| *h != Harness::OpenClaw)
            .collect();
        for release in ["2026.10.7", "2026.11.0"] {
            let mut mail = Mail::default();
            mail.observe_process(&process, &root, &who);
            mail.record_guard_fingerprint(&who, Some(plugin_fingerprint(&plugin, release)));
            assert_eq!(
                evidence_with(&PASSED_WITH, &mail, &who, &home),
                Evidence::Guarded,
                "{release}"
            );
            assert_eq!(
                evidence_with(&without, &mail, &who, &home),
                Evidence::RunningUnguarded,
                "{release}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // R3.1 (Codex): the session is guarded only while the user has trusted every Lunchroom hook in
    // `hooks.json`, all five events; one declined (no trust entry, or `enabled = false`) leaves it
    // unguarded, and the fingerprint carries every hook's trust.
    #[test]
    fn a_lunchroom_hook_is_known_by_its_program_quoted_or_not() {
        for command in [
            "/home/u/.lunchroom/bin/lunchroom guard pretool",
            "'/home/u v/.lunchroom/bin/lunchroom' guard pretool",
        ] {
            assert!(is_lunchroom_hook(&json!({"command": command})), "{command}");
        }
        assert!(!is_lunchroom_hook(
            &json!({"command": "/x/other guard pretool"})
        ));
    }

    // R3.1, review finding 14: the guard's program is read from the command as `install` writes
    // it, quoted or not; a path with a space is one program; only exactly `guard <mode>` is a
    // guard; a program not named `lunchroom` is no guard.
    #[test]
    fn a_guard_command_is_read_as_install_writes_it() {
        let hook = |c: &str| json!({"command": c});
        for (command, mode, program) in [
            (
                "/h/.lunchroom/bin/lunchroom guard pretool",
                "pretool",
                "/h/.lunchroom/bin/lunchroom",
            ),
            (
                "'/h/my home/.lunchroom/bin/lunchroom' guard posttool",
                "posttool",
                "/h/my home/.lunchroom/bin/lunchroom",
            ),
            (
                "'/h/my home/lunchroom'   guard prompt",
                "prompt",
                "/h/my home/lunchroom",
            ),
            ("lunchroom guard pretool", "pretool", "lunchroom"),
        ] {
            assert_eq!(
                guard_program(&hook(command), mode),
                Some(program),
                "{command}"
            );
        }
        for (command, mode) in [
            ("/h/my home/lunchroom guard pretool", "pretool"),
            ("'/h/lunchroom' guard pretool", "posttool"),
            ("'/h/lunchroom' guard pretool --x", "pretool"),
            ("'/h/lunchroom' guard", "pretool"),
            ("'/h/lunchroom'guard pretool", "pretool"),
            ("'/h/other' guard pretool", "pretool"),
            ("'/h/my home/lunchroom guard pretool", "pretool"),
            ("", "pretool"),
        ] {
            assert_eq!(guard_program(&hook(command), mode), None, "{command}");
        }
        assert_eq!(guard_program(&json!({}), "pretool"), None);
        assert_eq!(guard_program(&json!({"command": 7}), "pretool"), None);
    }

    /// A scratch folder with a program named `lunchroom` in a folder whose name has a space, and
    /// the hook groups for `hooks` (event, matcher, mode) that run it.
    struct Claude {
        root: PathBuf,
        program: String,
    }

    impl Claude {
        fn new(name: &str) -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/claude-evidence-unit")
                .join(format!("{}-{name}", std::process::id()));
            let bin = root.join("my bin");
            let _ = std::fs::create_dir_all(&bin);
            let _ = std::fs::create_dir_all(root.join("project/.claude"));
            let _ = std::fs::create_dir_all(root.join("config"));
            let _ = std::fs::copy("/bin/true", bin.join("lunchroom"));
            let program = bin.join("lunchroom").display().to_string();
            Self { root, program }
        }

        /// The settings of the hooks `events` (event, mode), each in a group with `matcher`.
        fn settings(&self, events: &[(&str, &str)], matcher: Option<&str>) -> Value {
            let mut hooks = serde_json::Map::new();
            for (event, mode) in events {
                let mut group = json!({"hooks": [{
                    "type": "command", "command": format!("'{}' guard {mode}", self.program)
                }]});
                if let Some(m) = matcher {
                    group["matcher"] = json!(m);
                }
                hooks.insert((*event).to_owned(), json!([group]));
            }
            json!({"hooks": hooks})
        }

        fn write(&self, relative: &str, value: &Value) {
            let _ = std::fs::write(self.root.join(relative), value.to_string());
        }

        /// `configured_with` for a process given `args`, against this folder's settings.
        fn guarded(&self, args: &[&str]) -> bool {
            let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
            configured_with(
                &args,
                &self.root.join("config"),
                &self.root.join("managed.json"),
                std::process::id(),
                &self.root.join("project"),
            )
        }

        fn clear(&self) {
            for file in [
                "config/settings.json",
                "project/.claude/settings.json",
                "project/.claude/settings.local.json",
                "managed.json",
            ] {
                let _ = std::fs::remove_file(self.root.join(file));
            }
        }
    }

    impl Drop for Claude {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    const FULL: [(&str, &str); 4] = [
        ("PreToolUse", "pretool"),
        ("PostToolUse", "posttool"),
        ("PostToolUseFailure", "posttool"),
        ("UserPromptSubmit", "prompt"),
    ];

    // R3.1, review finding 5 and 14: a session is guarded only when the complete guard set runs,
    // each hook covering every call. The guard's program is under a path with a space, quoted as
    // `install` writes it. Failure classes: one event of the set missing (each in turn); a
    // matcher that covers some tools only (a name, a list, a pattern); an `if` filter; a hook
    // that runs in the background or is not a command; the set spread over several settings
    // files (the levels merge); an event listed but with nothing in it.
    #[test]
    fn claude_is_guarded_only_by_the_complete_guard_set_covering_every_call() {
        let c = Claude::new("set");
        c.write("config/settings.json", &c.settings(&FULL, None));
        assert!(
            c.guarded(&[]),
            "complete set, program under a path with a space"
        );
        for missing in FULL {
            let rest: Vec<_> = FULL.iter().copied().filter(|e| *e != missing).collect();
            c.write("config/settings.json", &c.settings(&rest, None));
            assert!(!c.guarded(&[]), "without {missing:?}");
        }
        // The set spread over the user's and the project's settings is the merged set.
        c.write("config/settings.json", &c.settings(&FULL[..2], None));
        c.write(
            "project/.claude/settings.json",
            &c.settings(&FULL[2..], None),
        );
        assert!(c.guarded(&[]), "merged levels");
        c.clear();
        // Matchers: absent, empty and `*` cover every tool; anything else does not.
        for (matcher, covers) in [
            (None, true),
            (Some(""), true),
            (Some("*"), true),
            (Some("Bash"), false),
            (Some("Bash|Edit"), false),
            (Some("^Notebook"), false),
            (Some("mcp__.*"), false),
        ] {
            c.write("config/settings.json", &c.settings(&FULL, matcher));
            // `UserPromptSubmit` has no matcher; the three tool events do.
            assert_eq!(c.guarded(&[]), covers, "matcher {matcher:?}");
        }
        // Only the `PreToolUse` matcher narrowed: still not guarded; only `UserPromptSubmit`
        // given one: guarded, since Claude Code ignores a matcher there.
        let mut narrowed = c.settings(&FULL, None);
        narrowed["hooks"]["PostToolUseFailure"][0]["matcher"] = json!("Bash");
        c.write("config/settings.json", &narrowed);
        assert!(!c.guarded(&[]), "PostToolUseFailure for Bash only");
        let mut ignored = c.settings(&FULL, None);
        ignored["hooks"]["UserPromptSubmit"][0]["matcher"] = json!("Bash");
        c.write("config/settings.json", &ignored);
        assert!(
            c.guarded(&[]),
            "a UserPromptSubmit matcher is ignored by Claude Code"
        );
        for (field, value) in [
            ("if", json!("Bash(rm *)")),
            ("async", json!(true)),
            ("asyncRewake", json!(true)),
            ("type", json!("http")),
        ] {
            for event in [
                "PreToolUse",
                "PostToolUse",
                "PostToolUseFailure",
                "UserPromptSubmit",
            ] {
                let mut v = c.settings(&FULL, None);
                v["hooks"][event][0]["hooks"][0][field] = value.clone();
                c.write("config/settings.json", &v);
                assert!(!c.guarded(&[]), "{event} with {field}");
            }
        }
        let mut empty = c.settings(&FULL, None);
        empty["hooks"]["PostToolUse"] = json!([{"hooks": []}]);
        c.write("config/settings.json", &empty);
        assert!(!c.guarded(&[]), "an empty group");
        // The same set with an unquoted path with a space is not one program: not guarded.
        let mut unquoted = c.settings(&FULL, None);
        for event in [
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "UserPromptSubmit",
        ] {
            let mode = if event == "UserPromptSubmit" {
                "prompt"
            } else if event == "PreToolUse" {
                "pretool"
            } else {
                "posttool"
            };
            unquoted["hooks"][event][0]["hooks"][0]["command"] =
                json!(format!("{} guard {mode}", c.program));
        }
        c.write("config/settings.json", &unquoted);
        assert!(!c.guarded(&[]), "unquoted path with a space");
    }

    // R3.1, review finding 5: the guarded state follows the configuration Claude Code actually
    // loads. Failure classes: `--bare` (no hooks); `--setting-sources` leaving out the level that
    // holds the set; `disableAllHooks` (precedence, and managed hooks surviving it); a managed
    // `disableAllHooks` or `allowManagedHooksOnly`; `--settings` as a file or as text, spaced or
    // joined by `=`.
    #[test]
    fn claude_is_guarded_only_in_the_configuration_it_loads() {
        let c = Claude::new("loaded");
        let full = c.settings(&FULL, None);
        c.write("config/settings.json", &full);
        assert!(c.guarded(&["claude"]));
        assert!(!c.guarded(&["claude", "--bare"]), "--bare runs no hooks");
        // The level that holds the set must be one the process loads.
        assert!(c.guarded(&["claude", "--setting-sources", "user,project"]));
        assert!(c.guarded(&["claude", "--setting-sources=local, user"]));
        assert!(!c.guarded(&["claude", "--setting-sources", "project,local"]));
        assert!(!c.guarded(&["claude", "--setting-sources="]));
        c.clear();
        c.write("project/.claude/settings.local.json", &full);
        assert!(!c.guarded(&["claude", "--setting-sources", "user,project"]));
        assert!(c.guarded(&["claude", "--setting-sources", "local"]));
        c.clear();
        // `--settings`, as text and as a file (absolute, or relative to the session's folder).
        let text = full.to_string();
        assert!(c.guarded(&["claude", "--settings", &text]));
        let joined = format!("--settings={text}");
        assert!(c.guarded(&[joined.as_str()]));
        c.write("flag.json", &full);
        let file = c.root.join("flag.json").display().to_string();
        assert!(c.guarded(&["claude", "--settings", &file]));
        c.write("project/rel.json", &full);
        assert!(c.guarded(&["claude", "--settings", "rel.json"]));
        assert!(!c.guarded(&["claude", "--settings", "{not json"]));
        c.clear();
        // disableAllHooks: the value left after precedence decides.
        let mut off = full.clone();
        off["disableAllHooks"] = json!(true);
        c.write("config/settings.json", &off);
        assert!(!c.guarded(&[]), "user disableAllHooks");
        c.write(
            "project/.claude/settings.json",
            &json!({"disableAllHooks": false}),
        );
        assert!(c.guarded(&[]), "the project's false is the value left");
        c.write(
            "project/.claude/settings.local.json",
            &json!({"disableAllHooks": true}),
        );
        assert!(!c.guarded(&[]), "the local true is the value left");
        let flag_false = json!({"disableAllHooks": false}).to_string();
        assert!(
            c.guarded(&["--settings", &flag_false]),
            "--settings over local"
        );
        let flag_true = json!({"disableAllHooks": true}).to_string();
        assert!(!c.guarded(&["--settings", &flag_true]));
        c.clear();
        // Managed hooks survive a lower level's disableAllHooks, and only managed settings stop
        // them; `allowManagedHooksOnly` drops every other level's hooks.
        c.write("config/settings.json", &json!({"disableAllHooks": true}));
        c.write("managed.json", &full);
        assert!(
            c.guarded(&[]),
            "managed set survives the user's disableAllHooks"
        );
        let mut managed_off = full.clone();
        managed_off["disableAllHooks"] = json!(true);
        c.write("managed.json", &managed_off);
        assert!(!c.guarded(&[]), "managed disableAllHooks");
        c.write("config/settings.json", &full);
        assert!(
            !c.guarded(&[]),
            "managed disableAllHooks over a full user set"
        );
        let mut only = json!({"allowManagedHooksOnly": true});
        c.write("managed.json", &only);
        assert!(
            !c.guarded(&[]),
            "the user's set is dropped under allowManagedHooksOnly"
        );
        only["hooks"] = full["hooks"].clone();
        c.write("managed.json", &only);
        assert!(
            c.guarded(&[]),
            "the managed set runs under allowManagedHooksOnly"
        );
        // Part of the set managed, the rest the user's: merged.
        c.clear();
        c.write("managed.json", &c.settings(&FULL[..1], None));
        c.write("config/settings.json", &c.settings(&FULL[1..], None));
        assert!(c.guarded(&[]), "managed and user merged");
    }

    #[test]
    fn codex_is_guarded_only_when_every_lunchroom_hook_is_trusted() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/codex-trust-unit")
            .join(std::process::id().to_string());
        let codex_home = root.join("home/.codex");
        let _ = std::fs::create_dir_all(&codex_home);
        let bin = root.join("bin");
        let _ = std::fs::create_dir_all(&bin);
        let _ = std::fs::copy("/bin/true", bin.join("lunchroom"));
        let program = bin.join("lunchroom").display().to_string();
        let hook = |mode: &str| json!([{"hooks": [{"type": "command", "command": format!("{program} {mode}")}]}]);
        let file = codex_home.join("hooks.json");
        let _ = std::fs::write(
            &file,
            json!({"hooks": {
                "PreToolUse": hook("guard pretool"),
                "PostToolUse": hook("guard posttool"),
                "UserPromptSubmit": hook("guard prompt"),
                "SessionStart": hook("guard start"),
                "Stop": hook("listen --once"),
                "PermissionRequest": [{"hooks": [{"type": "command", "command": "/x/other"}]}],
            }})
            .to_string(),
        );
        let events = [
            "pre_tool_use",
            "post_tool_use",
            "user_prompt_submit",
            "session_start",
            "stop",
        ];
        let entry = |event: &str, extra: &str| {
            format!(
                "[hooks.state.\"{}:{event}:0:0\"]\ntrusted_hash = \"sha256:{event}\"\n{extra}\n",
                file.display()
            )
        };
        let fingerprint = |config: &str| {
            let _ = std::fs::write(codex_home.join("config.toml"), config);
            codex_fingerprint_in(&codex_home, std::process::id(), &root)
        };
        let all: String = events.iter().map(|e| entry(e, "enabled = true")).collect();
        let full = fingerprint(&all);
        assert!(
            full.as_ref()
                .is_some_and(|f| events.iter().all(|e| f.contains(&format!("sha256:{e}"))))
        );
        for declined in events {
            let without: String = events
                .iter()
                .filter(|e| **e != declined)
                .map(|e| entry(e, "enabled = true"))
                .collect();
            assert_eq!(fingerprint(&without), None, "{declined} has no entry");
            let disabled: String = events
                .iter()
                .map(|e| {
                    entry(
                        e,
                        if *e == declined {
                            "enabled = false"
                        } else {
                            ""
                        },
                    )
                })
                .collect();
            assert_eq!(fingerprint(&disabled), None, "{declined} is disabled");
        }
        // A changed trust hash changes the fingerprint.
        let rehashed = all.replace("sha256:stop", "sha256:other");
        assert!(fingerprint(&rehashed).is_some_and(|f| Some(&f) != full.as_ref()));
        let _ = std::fs::remove_dir_all(&root);
    }

    // R3.1 (Codex), review finding 6: Codex counts as guarded only with the whole guard set
    // `install` writes for it (pretool, posttool, prompt, start), each in a group whose matcher
    // covers every tool, as Claude Code does (`CLAUDE_GUARD_HOOKS`): a trusted `PreToolUse` alone,
    // a missing event, a narrowed matcher, a wrong mode or an asynchronous hook is unguarded.
    #[test]
    fn codex_is_guarded_only_with_the_whole_guard_hook_set() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/codex-set-unit")
            .join(std::process::id().to_string());
        let codex_home = root.join("home/.codex");
        let _ = std::fs::create_dir_all(&codex_home);
        let bin = root.join("bin");
        let _ = std::fs::create_dir_all(&bin);
        let copied = std::fs::copy("/bin/true", bin.join("lunchroom"));
        assert!(copied.is_ok(), "{copied:?}");
        let program = bin.join("lunchroom").display().to_string();
        let file = codex_home.join("hooks.json");
        let events = [
            ("PreToolUse", "pre_tool_use", "guard pretool"),
            ("PostToolUse", "post_tool_use", "guard posttool"),
            ("UserPromptSubmit", "user_prompt_submit", "guard prompt"),
            ("SessionStart", "session_start", "guard start"),
        ];
        let config = events.iter().fold(String::new(), |mut s, (_, state, _)| {
            use std::fmt::Write as _;
            let _ = write!(
                s,
                "[hooks.state.\"{}:{state}:0:0\"]\ntrusted_hash = \"sha256:{state}\"\n",
                file.display()
            );
            s
        });
        let _ = std::fs::write(codex_home.join("config.toml"), config);
        // The hooks file with `change` applied to the group of `event` (None drops the event).
        let guarded = |event: &str, change: &dyn Fn(&mut Value)| {
            let mut hooks = serde_json::Map::new();
            for (name, _, args) in events {
                let mut group = json!({"hooks": [{
                    "type": "command", "command": format!("{program} {args}"),
                }]});
                if name == event {
                    change(&mut group);
                }
                if !group.is_null() {
                    hooks.insert(name.to_owned(), json!([group]));
                }
            }
            let _ = std::fs::write(&file, json!({"hooks": hooks}).to_string());
            codex_fingerprint_in(&codex_home, std::process::id(), &root).is_some()
        };
        assert!(guarded("", &|_| {}), "the whole set, trusted");
        for (event, _, _) in events {
            assert!(!guarded(event, &|g| *g = Value::Null), "{event} missing");
            for matcher in ["Bash", "Bash|Edit", "^.*$", "mcp__.*"] {
                let narrowed = guarded(event, &|g| g["matcher"] = json!(matcher));
                // `UserPromptSubmit` has no matcher in Codex either.
                assert_eq!(narrowed, event == "UserPromptSubmit", "{event} {matcher}");
            }
            for matcher in ["", "*"] {
                assert!(
                    guarded(event, &|g| g["matcher"] = json!(matcher)),
                    "{event} {matcher:?}"
                );
            }
            assert!(
                !guarded(event, &|g| g["hooks"][0]["async"] = json!(true)),
                "{event} async"
            );
            assert!(
                !guarded(event, &|g| g["hooks"][0]["if"] = json!("Bash(ls)")),
                "{event} if"
            );
            assert!(
                !guarded(event, &|g| g["hooks"][0]["command"] =
                    json!(format!("{program} listen --once"))),
                "{event} runs no guard"
            );
        }
        // Every event runs the guard of another event's mode: no event is satisfied by a sibling.
        assert!(!guarded("UserPromptSubmit", &|g| {
            g["hooks"][0]["command"] = json!(format!("{program} guard pretool"));
        }));
        let _ = std::fs::remove_dir_all(&root);
    }

    // R3.1 (OpenClaw, Hermes): the program a plugin file runs is read from its `PROGRAM` line.
    #[test]
    fn plugin_program_reads_the_installed_path() {
        assert_eq!(
            plugin_program("// x\nconst PROGRAM = \"/h/.lunchroom/bin/lunchroom\";\n"),
            Some("/h/.lunchroom/bin/lunchroom")
        );
        assert_eq!(
            plugin_program("import os\nPROGRAM = \"/h/.lunchroom/bin/lunchroom\"\n"),
            Some("/h/.lunchroom/bin/lunchroom")
        );
        assert_eq!(plugin_program("PROGRAMS = 1\n"), None);
        let recorded = "/nonexistent/plugin.py\n9976f4857b72439d79016354d7b6e1a3ee952e2f";
        assert!(!plugin_runs_guard(Some(recorded)));
        assert!(!plugin_runs_guard(None));
        assert!(!plugin_runs_guard(Some("/nonexistent/plugin.py")));
        assert_eq!(
            plugin_release(Some(recorded)),
            "9976f4857b72439d79016354d7b6e1a3ee952e2f"
        );
        assert_eq!(plugin_release(Some("/x/plugin.py")), "");
        assert_eq!(plugin_release(None), "");
    }
}
