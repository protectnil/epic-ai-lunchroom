//! Where Lunchroom keeps its files, and what the process can see of its environment.
//!
//! `HOME` names the user's home; `LUNCHROOM_HOME` names Lunchroom's folder (default
//! `~/.lunchroom`). The guard denies any command that changes `LUNCHROOM_HOME` or the session id
//! variables (I1.2), so an agent cannot point the guard elsewhere.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lunchroom_core::paths::{Layout, normalize};

/// `p` as the classifier compares paths: absolute, with symlinks followed where it exists and
/// `.` and `..` resolved, so a store reached by another spelling of the same folder is still
/// Lunchroom's store.
fn resolve(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        normalize(&p.to_string_lossy(), &cwd, Path::new("/"))
    })
}

/// The process's view of where it runs.
#[derive(Debug, Clone)]
pub struct Env {
    pub home: PathBuf,
    pub lunchroom_home: PathBuf,
    /// The Claude Code process that started this one (`CLAUDE_PID`), when there is one.
    pub claude_pid: Option<u32>,
    /// `CLAUDE_CODE_SESSION_ATTENDED`.
    pub attended: Option<String>,
    /// `CLAUDE_CODE_ENTRYPOINT`.
    pub entrypoint: Option<String>,
    /// `CLAUDE_CODE_SESSION_ID`, as Claude Code sets it in its Bash tool's commands.
    pub claude_session: Option<String>,
    /// `CODEX_THREAD_ID`, as Codex sets it in an agent's commands (measured, codex-cli 0.163.0).
    pub codex_thread: Option<String>,
    /// Codex's folder: `CODEX_HOME`, or `~/.codex`.
    pub codex_home: PathBuf,
    /// Hermes's folder: `HERMES_HOME`, or `~/.hermes`.
    pub hermes_home: PathBuf,
    /// `HERMES_SESSION_ID`, as Hermes sets it in an agent's terminal commands (source, 9976f48).
    pub hermes_session: Option<String>,
    /// `LUNCHROOM_SESSION`, `<harness>:<session id>`, as Lunchroom's OpenClaw plugin sets it in an
    /// agent's `exec` commands (I1.2).
    pub lunchroom_session: Option<String>,
    /// Seconds since the Unix epoch.
    pub now: u64,
}

impl Env {
    /// The environment of this process.
    ///
    /// # Errors
    /// When `HOME` is unset or empty.
    pub fn from_process() -> Result<Self, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let home = resolve(&PathBuf::from(var("HOME").ok_or("HOME is not set")?));
        let lunchroom_home =
            resolve(&var("LUNCHROOM_HOME").map_or_else(|| home.join(".lunchroom"), PathBuf::from));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let codex_home = var("CODEX_HOME").map_or_else(|| home.join(".codex"), PathBuf::from);
        let hermes_home = var("HERMES_HOME").map_or_else(|| home.join(".hermes"), PathBuf::from);
        Ok(Self {
            home,
            lunchroom_home,
            claude_pid: var("CLAUDE_PID").and_then(|p| p.parse().ok()),
            attended: var("CLAUDE_CODE_SESSION_ATTENDED"),
            entrypoint: var("CLAUDE_CODE_ENTRYPOINT"),
            claude_session: var("CLAUDE_CODE_SESSION_ID"),
            codex_thread: var("CODEX_THREAD_ID"),
            hermes_session: var("HERMES_SESSION_ID"),
            lunchroom_session: var("LUNCHROOM_SESSION"),
            codex_home,
            hermes_home,
            now,
        })
    }

    /// The folder of Lunchroom's crash-safe store.
    #[must_use]
    pub fn store_dir(&self) -> PathBuf {
        self.lunchroom_home.join("store")
    }

    /// Where Lunchroom and the harnesses keep their files, for the classifier.
    #[must_use]
    pub fn layout(&self) -> Layout {
        let mut layout = Layout::for_home(&self.home);
        layout.program_dir = self.lunchroom_home.join("bin");
        layout.lunchroom_home.clone_from(&self.lunchroom_home);
        if let Ok(exe) = std::env::current_exe() {
            layout.programs.push(exe);
        }
        Locations::gather(self).apply(&mut layout);
        layout
    }
}

/// The variables that move a harness's folder or configuration away from its usual place.
const LOCATION_VARS: [&str; 5] = [
    "CODEX_HOME",
    "HERMES_HOME",
    "OPENCLAW_STATE_DIR",
    "OPENCLAW_CONFIG_PATH",
    "CLAUDE_CONFIG_DIR",
];

/// Where the harnesses keep their files when not in the usual places (L1.1, P1.4). The guard is a
/// child of the harness, so its own environment usually names them; but a hook can be started with
/// less than the harness has, and a location can be set where only the agent's commands see it. So
/// every place that names one is read, and all the places found are protected together with the
/// usual ones (never instead of them):
/// - the guard's own environment, and the folders `Env` read from it;
/// - the starting environment and `--settings` of each ancestor process and of `CLAUDE_PID`;
/// - the `env` block of Claude Code's settings (`~/.claude`, `CLAUDE_CONFIG_DIR`, each `--settings`
///   file or text), which Claude Code gives its Bash tool's commands;
/// - OpenClaw's `.env` files, where it may be set (`OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`).
///
/// A location an agent sets inside one command (`CODEX_HOME=/x codex ...`) moves nothing the
/// running harness uses, so it is not a harness location; the command's own paths are judged as
/// any other.
#[derive(Default)]
struct Locations {
    /// (variable, the absolute path it names).
    vars: Vec<(String, PathBuf)>,
    /// Settings files given to Claude Code with `--settings`.
    settings: Vec<PathBuf>,
}

impl Locations {
    fn gather(env: &Env) -> Self {
        let mut found = Self::default();
        let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        for name in LOCATION_VARS {
            if let Some(v) = std::env::var(name).ok().filter(|v| !v.is_empty()) {
                found.add(name, &v, &here, &env.home);
            }
        }
        found.vars.extend([
            ("CODEX_HOME".to_owned(), env.codex_home.clone()),
            ("HERMES_HOME".to_owned(), env.hermes_home.clone()),
        ]);
        let mut pids = ancestors();
        pids.extend(env.claude_pid);
        for pid in pids {
            found.read_process(pid, env);
        }
        // Claude Code's settings files may set any of them for its commands.
        let mut files = vec![env.home.join(".claude/settings.json")];
        files.extend(
            found
                .vars
                .iter()
                .filter(|(n, _)| n == "CLAUDE_CONFIG_DIR")
                .map(|(_, d)| d.join("settings.json")),
        );
        files.extend(found.settings.clone());
        for file in files {
            if let Ok(text) = std::fs::read_to_string(&file) {
                found.read_settings_text(&text, env);
            }
        }
        found.read_openclaw_dotenv(env);
        found
    }

    fn add(&mut self, name: &str, value: &str, base: &Path, home: &Path) {
        let path = if value == "~" {
            home.to_path_buf()
        } else if let Some(rest) = value.strip_prefix("~/") {
            home.join(rest)
        } else {
            base.join(value)
        };
        let entry = (name.to_owned(), path);
        if !self.vars.contains(&entry) {
            self.vars.push(entry);
        }
    }

    /// The location variables in process `pid`'s starting environment, and its `--settings`.
    fn read_process(&mut self, pid: u32, env: &Env) {
        let base =
            std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|_| PathBuf::from("/"));
        if let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) {
            for kv in raw.split(|b| *b == 0) {
                let kv = String::from_utf8_lossy(kv);
                if let Some((name, value)) = kv.split_once('=')
                    && LOCATION_VARS.contains(&name)
                    && !value.is_empty()
                {
                    self.add(name, value, &base, &env.home);
                }
            }
        }
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return;
        };
        let args: Vec<String> = raw
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        for (k, a) in args.iter().enumerate() {
            let given = if a == "--settings" {
                args.get(k + 1).cloned()
            } else {
                a.strip_prefix("--settings=").map(str::to_owned)
            };
            let Some(given) = given else { continue };
            if given.trim_start().starts_with('{') {
                self.read_settings_text(&given, env);
            } else {
                self.settings.push(base.join(given));
            }
        }
    }

    /// The `env` block of a Claude Code settings file or text.
    fn read_settings_text(&mut self, text: &str, env: &Env) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return;
        };
        for name in LOCATION_VARS {
            if let Some(v) = value["env"][name].as_str().filter(|v| !v.is_empty()) {
                self.add(name, v, &env.home, &env.home);
            }
        }
    }

    /// OpenClaw reads its location variables from the `.env` of its state folder, by default
    /// `~/.openclaw/.env`; a state folder named there has a `.env` of its own.
    fn read_openclaw_dotenv(&mut self, env: &Env) {
        for _ in 0..3 {
            let mut dirs = vec![env.home.join(".openclaw")];
            dirs.extend(
                self.vars
                    .iter()
                    .filter(|(n, _)| n == "OPENCLAW_STATE_DIR")
                    .map(|(_, d)| d.clone()),
            );
            let before = self.vars.len();
            for dir in dirs {
                for name in ["OPENCLAW_STATE_DIR", "OPENCLAW_CONFIG_PATH"] {
                    if let Some(v) = dotenv(&dir.join(".env"), name) {
                        self.add(name, &v, &dir, &env.home);
                    }
                }
            }
            if self.vars.len() == before {
                break;
            }
        }
    }

    /// Registers each location with the classifier, spelled as given and as it really is.
    fn apply(&self, layout: &mut Layout) {
        for (name, path) in &self.vars {
            for p in spellings(path) {
                match name.as_str() {
                    "CODEX_HOME" => layout.add_codex_home(&p),
                    "HERMES_HOME" => layout.add_hermes_home(&p),
                    "OPENCLAW_STATE_DIR" => layout.add_openclaw_state(&p),
                    "OPENCLAW_CONFIG_PATH" => layout.add_openclaw_config(&p),
                    "CLAUDE_CONFIG_DIR" => layout.add_claude_config_dir(&p),
                    _ => {}
                }
            }
        }
        for file in &self.settings {
            for p in spellings(file) {
                layout.add_claude_settings(&p);
            }
        }
    }
}

/// `path` lexically normal, and as the filesystem has it (symlinks followed) when that differs, so
/// a location reached through a link is the location.
fn spellings(path: &Path) -> Vec<PathBuf> {
    let root = Path::new("/");
    let mut out = vec![normalize(&path.to_string_lossy(), root, root)];
    let real = resolve(path);
    if !out.contains(&real) {
        out.push(real);
    }
    out
}

/// The processes above this one, nearest first, up to (not including) `init`.
fn ancestors() -> Vec<u32> {
    let mut out = Vec::new();
    let mut pid = std::process::id();
    for _ in 0..32 {
        let Some(parent) = parent_pid(pid).filter(|p| *p > 1) else {
            break;
        };
        out.push(parent);
        pid = parent;
    }
    out
}

/// `PPid` of process `pid`, from `/proc/<pid>/stat` (the name in it may hold spaces and `)`).
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.get(stat.rfind(')')? + 2..)?;
    rest.split(' ').nth(1)?.parse().ok()
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
