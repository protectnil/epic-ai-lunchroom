//! Classifies one Claude Code tool call against Lunchroom's fixed rules.
//!
//! Spec: §6 P1.1 (a slip holds only reads), P1.4 (the PROTECTED kinds; an agent's write to
//! Lunchroom's stores is DENIED), §11 L1.1 (denied and credential paths, resolved, by direct path,
//! symlink, wildcard and parent-folder search), §12 F1.1–F1.2 (fences; unparsed commands), §7 A1.3
//! (an agent's `lunchroom approve`, `yolo` and configuration commands are DENIED), §9 I1.2 (no
//! command sets, unsets or clears the identity variables).
//!
//! Rules that hold in every session are always checked. The rest change nothing for an agent that
//! is not HELD (P1.2), so they are checked only while it is HELD, which keeps the guard's
//! file-system work off every call such an agent makes.
//!
//! What the guard judges is the call itself (spec §15 K1.8). A script the call runs, and code it
//! hands to a program such as `python -c`, are searched only for the rules that are DENIED in every
//! session (fences, identity, Lunchroom commands; a shell script the reader can read also for
//! Lunchroom's stores).

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::fs::{Fs, Script, WalkEnd, fnmatch};
use crate::paths::{Layout, absolute, literal_prefix, normalize};
use crate::policy::{Call, CallClass, DenyReason, ProtectedKind, ProtectedKinds};
use crate::shell::{self, Parsed, Word};

/// The guard's view of one agent at the moment of a call.
#[derive(Clone, Copy)]
pub struct Guard<'a> {
    /// Where Lunchroom and the harnesses keep their files.
    pub layout: &'a Layout,
    /// The file system.
    pub fs: &'a dyn Fs,
    /// Another agent's text is in this agent's context.
    pub held: bool,
}

impl std::fmt::Debug for Guard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("layout", self.layout)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

/// Tools that only read Lunchroom-internal or harness-internal lists.
const SLIP_TOOLS: [&str; 4] = ["ToolSearch", "TaskList", "TaskGet", "ListAgents"];

/// Tools that change the session's own state or start work, and send nothing off the computer.
const ORDINARY_TOOLS: [&str; 12] = [
    "Agent",
    "Task",
    "TodoWrite",
    "TaskCreate",
    "TaskUpdate",
    "TaskStop",
    "AskUserQuestion",
    "Skill",
    "EnterPlanMode",
    "ExitPlanMode",
    "SendMessage",
    "ReadNotifications",
];

/// Tools that send data off the computer.
const NETWORK_TOOLS: [&str; 2] = ["WebFetch", "WebSearch"];

/// Programs that put a turn into another agent's session (F1.1).
const FENCE_PROGRAMS: [&str; 5] = ["codex", "claude", "opencode", "openclaw", "hermes"];

/// Commands of `claude` and `codex` that take no prompt: a first word that is none of these starts
/// a new session on that prompt (P1.4).
const NOT_A_PROMPT: [&str; 41] = [
    // claude
    "agents",
    "attach",
    "config",
    "migrate-installer",
    "auth",
    // protocol-words:begin (Claude Code's own command name)
    "auto-mode",
    // protocol-words:end
    "doctor",
    "gateway",
    "import",
    "install",
    "logs",
    "mcp",
    "plugin",
    "plugins",
    "purge",
    "respawn",
    "rm",
    "setup-token",
    "stop",
    "kill",
    "ultrareview",
    "update",
    "upgrade",
    // codex
    "login",
    "logout",
    "app-server",
    "exec-server",
    "migrate-rollouts",
    "migrate-nfs-db",
    "remote-control",
    "completion",
    "sandbox",
    "debug",
    "apply",
    "a",
    "archive",
    "delete",
    "unarchive",
    "features",
    "help",
    "cloud",
];

/// The name of Lunchroom's program. A link under another name is found by its real path.
const LUNCHROOM_NAMES: [&str; 1] = ["lunchroom"];

/// Lunchroom commands an agent may run; every other one is the user's alone (A1.3).
const LUNCHROOM_OPEN: [&str; 8] = [
    "send",
    "status",
    "codex-threads",
    "help",
    "version",
    "--help",
    "-h",
    "--version",
];

/// Variables that carry an agent's identity (I1.2).
const IDENTITY_VARS: [&str; 5] = [
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "HERMES_SESSION_ID",
    "LUNCHROOM_SESSION",
    "LUNCHROOM_HOME",
];

const SHELLS: [&str; 8] = ["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];

/// Programs that run code given as an argument.
const INTERPRETERS: [&str; 19] = [
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "perl",
    "ruby",
    "php",
    "deno",
    "bun",
    "lua",
    "Rscript",
    "osascript",
    "pwsh",
    "tclsh",
    "awk",
    "gawk",
    "mawk",
    "sed",
];

const NETWORK_PROGRAMS: [&str; 31] = [
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ftp",
    "lftp",
    "gh",
    "aws",
    "gcloud",
    "az",
    "http",
    "https",
    "xh",
    "rclone",
    "s3cmd",
    "mail",
    "mailx",
    "sendmail",
    "mutt",
    "dig",
    "nslookup",
    "host",
    "ping",
    "traceroute",
];

const GIT_NETWORK: [&str; 8] = [
    "fetch",
    "pull",
    "clone",
    "ls-remote",
    "send-email",
    "request-pull",
    "submodule",
    "svn",
];

const PUBLISHERS: [&str; 17] = [
    "npm", "pnpm", "yarn", "bun", "cargo", "gem", "twine", "poetry", "flit", "hatch", "docker",
    "podman", "helm", "vsce", "ovsx", "dotnet", "nuget",
];

const DELETERS: [&str; 7] = [
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "srm",
    "trash",
    "trash-put",
];

/// Programs that change everything below a folder they are given.
const RECURSIVE_WRITE: [&str; 9] = [
    "rm", "rmdir", "shred", "chmod", "chown", "chgrp", "chattr", "setfacl", "mv",
];

/// `find` actions that change or run something.
const FIND_ACTIONS: [&str; 5] = ["-delete", "-exec", "-execdir", "-ok", "-okdir"];

/// Programs that search below the working folder when given no folder.
const SEARCHERS: [&str; 8] = ["rg", "ag", "ack", "fd", "fdfind", "tree", "du", "find"];

/// Programs that search below a folder only when told to recurse (`-r`, `-R`, `--recursive`).
const RECURSE_ON_FLAG: [&str; 5] = ["grep", "egrep", "fgrep", "zgrep", "ls"];

/// The `grep` family: the first word that is not an option is the pattern, unless `-e` or `-f`
/// gives it.
const GREPS: [&str; 4] = ["grep", "egrep", "fgrep", "zgrep"];

/// Programs that read everything below a folder they are given, and nothing when given none.
const COPIERS: [&str; 5] = ["tar", "zip", "cp", "rsync", "scp"];

/// Lunchroom commands that only the user may run, as they are spotted in code (A1.3).
const LUNCHROOM_USER_ONLY: [&str; 15] = [
    "approve",
    "repair",
    "mode",
    "yolo",
    "register",
    "unregister",
    "slip",
    "rate",
    // Sets the passphrase that every command of this list asks for (A1.3).
    "passphrase",
    "guard",
    // Delivery runs only from the harness's own hook: an agent that ran it could take another
    // session's message (D1.1, I1.2).
    "listen",
    "rename",
    "config",
    // Write the program and the harness configuration that runs the guard (H1.4, A1.3).
    "install",
    "uninstall",
];

/// Options whose value the program runs as a command, from the programs' manuals (2026-10-27): their
/// values are judged as code, written separately, after `=`, or (one-letter options) attached. Any
/// other option's value is data. `less`'s `+` command and the words after `git bisect run` and
/// `git submodule foreach` are judged the same way; `sed` is judged as an interpreter (its
/// script, `e` command included).
const COMMAND_OPTIONS: [(&str, &[&str]); 10] = [
    (
        "git",
        &[
            // A configuration value such as `core.pager` is run.
            "-c",
            "-x",
            "--exec",
            "--extcmd",
            "--upload-pack",
            "--receive-pack",
            "--tree-filter",
            "--env-filter",
            "--index-filter",
            "--msg-filter",
            "--commit-filter",
            "--parent-filter",
            "--tag-name-filter",
        ],
    ),
    ("rg", &["--pre", "--hostname-bin"]),
    (
        "tar",
        &[
            "-I",
            "--use-compress-program",
            "--to-command",
            "-F",
            "--info-script",
            "--new-volume-script",
            "--checkpoint-action",
            "--rsh-command",
            "--rmt-command",
        ],
    ),
    ("sort", &["--compress-program"]),
    ("man", &["-P", "--pager", "-H", "--html"]),
    ("wget", &["-e", "--execute"]),
    ("cargo", &["--config"]),
    // `-o ProxyCommand=…` runs a command.
    ("ssh", &["-o"]),
    ("scp", &["-o"]),
    ("sftp", &["-o"]),
];

/// Programs that run none of their arguments as commands, except through [`COMMAND_OPTIONS`]. After
/// any other program, the words that follow are judged as if that program could run them (an
/// unknown wrapper).
const NEVER_RUNS: [&str; 73] = [
    "rg",
    "git",
    "sed",
    "sort",
    "man",
    "less",
    "wget",
    "cargo",
    "tar",
    "echo",
    "printf",
    "cat",
    "ls",
    "grep",
    "egrep",
    "fgrep",
    "wc",
    "head",
    "tail",
    "uniq",
    "cut",
    "tr",
    "test",
    "[",
    "true",
    "false",
    "touch",
    "mkdir",
    "file",
    "stat",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "which",
    "type",
    "more",
    "jq",
    "diff",
    "cmp",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "md5sum",
    "b2sum",
    "cksum",
    "du",
    "readelf",
    "objdump",
    "nm",
    "strings",
    "xxd",
    "od",
    "hexdump",
    "nl",
    "tac",
    "rev",
    "fold",
    "tee",
    "mv",
    "cp",
    "ln",
    "chmod",
    "chown",
    "curl",
    "cd",
    "pwd",
    "date",
    "rm",
    "gh",
    "lunchroom",
];

/// How deep `sh -c` strings and scripts are followed.
const MAX_NESTING: usize = 4;

/// The most severe class seen so far (the one shown), and every PROTECTED kind seen: the policy
/// follows the kinds, so choosing a class to show never discards a restriction (P1.6, R3.1).
struct Acc {
    class: CallClass,
    kinds: ProtectedKinds,
    /// A command, or text a script or code would run, starts a new agent session
    /// ([`starts_session`]). Kept apart from `kinds` because a script is classified as an agent
    /// that is not HELD would be (K1.8): it is PROTECTED only for a HELD agent, decided at the end
    /// of the call.
    new_session: bool,
}

const fn rank(c: CallClass) -> u8 {
    match c {
        CallClass::InSlip => 0,
        CallClass::Ordinary => 1,
        // F1.2: when text in the command could not be read, `unparsed` is the reason shown within
        // its class, whichever rule ran first. A DENIED call stays above every PROTECTED one; a
        // denial under another rule (P1.4's store writes) keeps its own reason.
        CallClass::Protected(ProtectedKind::Unparsed) => 3,
        CallClass::Protected(_) => 2,
        CallClass::Denied(DenyReason::Unparsed) => 5,
        CallClass::Denied(_) => 4,
    }
}

impl Acc {
    const fn new(class: CallClass) -> Self {
        let call = Call::of(class);
        Self {
            class: call.class,
            kinds: call.kinds,
            new_session: false,
        }
    }

    fn raise(&mut self, c: CallClass) {
        // Every PROTECTED kind is remembered, whichever class ends up shown.
        if let CallClass::Protected(kind) = c {
            self.kinds = self.kinds.with(kind);
        }
        if rank(c) > rank(self.class) {
            self.class = c;
        }
    }

    const fn denied(&self) -> bool {
        matches!(self.class, CallClass::Denied(_))
    }

    const fn call(&self) -> Call {
        Call {
            class: self.class,
            kinds: self.kinds,
        }
    }
}

/// The paths one word may mean (see [`Guard::forms`]).
#[derive(Default)]
struct Forms {
    /// Every path, once.
    paths: Vec<PathBuf>,
    /// The folder to search from when a wildcard's matching was cut short.
    capped: Option<PathBuf>,
    /// The file could not be settled: it may be anywhere.
    unresolved: bool,
}

impl Forms {
    fn push(&mut self, p: PathBuf) {
        if !self.paths.contains(&p) {
            self.paths.push(p);
        }
    }
}

/// A path split before its first part with a wildcard: the folders before it, and that part with
/// all that follows.
fn split_wild(p: &Path) -> (PathBuf, PathBuf) {
    let (mut head, mut tail) = (PathBuf::new(), PathBuf::new());
    let mut wild = false;
    for c in p.components() {
        wild |= matches!(c, Component::Normal(s) if s.to_string_lossy().contains(['*', '?', '[']));
        if wild {
            tail.push(c.as_os_str());
        } else {
            head.push(c.as_os_str());
        }
    }
    (head, tail)
}

fn basename(t: &str) -> &str {
    Path::new(t)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(t)
}

/// `NAME=value`, or Bash's append form `NAME+=value`.
/// The word at a program's place in a piece of shell text, past any `NAME=value` (a quoted value
/// whole, spaces included), without its quotes.
fn program_word(piece: &str) -> Option<&str> {
    // The length of the shell word `s` starts with: to the first space outside quotes.
    let word_len = |s: &str| {
        let mut quote = None;
        let mut cs = s.char_indices();
        while let Some((k, c)) = cs.next() {
            match (quote, c) {
                (None, ' ' | '\t') => return k,
                (None, '"' | '\'') => quote = Some(c),
                (Some(q), c) if c == q => quote = None,
                (Some('"') | None, '\\') => {
                    cs.next();
                }
                _ => {}
            }
        }
        s.len()
    };
    let mut rest = piece.trim_start();
    while !rest.is_empty() {
        let n = word_len(rest);
        let word = &rest[..n];
        if !is_assignment(word) {
            return Some(word.trim_matches(['"', '\'']));
        }
        rest = rest[n..].trim_start();
    }
    None
}

fn is_assignment(w: &str) -> bool {
    let Some((name, _)) = w.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut cs = name.chars();
    cs.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_identity(t: &str) -> bool {
    IDENTITY_VARS.iter().any(|v| {
        t.strip_prefix(v)
            .is_some_and(|r| r.is_empty() || r.starts_with('=') || r.starts_with("+="))
    })
}

/// A local agent session chat API: `/api/sessions/<id>/chat` (F1.1).
fn names_chat_api(t: &str) -> bool {
    const KEY: &str = "/api/sessions/";
    let mut rest = t;
    while let Some(k) = rest.find(KEY) {
        let after = &rest[k + KEY.len()..];
        let id_len = after
            .find(|c: char| c == '/' || c.is_whitespace() || c == '\'' || c == '"')
            .unwrap_or(after.len());
        if id_len > 0 && after[id_len..].starts_with("/chat") {
            return true;
        }
        rest = after;
    }
    false
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || "._/~+@%,=-*?[]".contains(c)
}

fn is_path_char(c: char) -> bool {
    c != '=' && is_word_char(c)
}

/// The whole words of a text the shell reader could not read (F1.2: "as a whole word").
fn tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !is_word_char(c))
        .filter(|t| !t.is_empty())
        .collect()
}

/// The path-like strings in one word: the word, its parts, and each part from its first `/` or `~`.
fn candidates(text: &str) -> Vec<&str> {
    let mut all = vec![text];
    for part in text.split(|c: char| !is_path_char(c)) {
        all.push(part);
        if let Some(k) = part.find(['/', '~']) {
            all.push(&part[k..]);
        }
    }
    let mut out: Vec<&str> = Vec::new();
    for t in all {
        if !t.is_empty() && !t.starts_with('-') && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Every name a word may run as: its base name, or for a wildcard the known names it matches.
fn prog_names(w: &Word) -> Vec<&str> {
    let base = basename(&w.text);
    if !w.glob {
        return vec![base];
    }
    FENCE_PROGRAMS
        .iter()
        .chain(&LUNCHROOM_NAMES)
        .chain(&SHELLS)
        .chain(&INTERPRETERS)
        .chain(&NETWORK_PROGRAMS)
        .chain(&PUBLISHERS)
        .chain(&DELETERS)
        .chain(&RECURSIVE_WRITE)
        .chain(&SEARCHERS)
        .chain(&RECURSE_ON_FLAG)
        .chain(&COPIERS)
        .chain(&["git", "env", "printenv", "eval", "source"])
        .copied()
        .filter(|n| fnmatch(base, n))
        .collect()
}

/// One of `set` is among the options (`--name` or `--name=value`).
fn has_flag(args: &[&str], set: &[&str]) -> bool {
    args.iter()
        .any(|a| set.contains(&a.split('=').next().unwrap_or(a)))
}

/// One of `letters` is in a cluster of short options (`-rc`).
fn has_cluster(args: &[&str], letters: &[char]) -> bool {
    args.iter().any(|a| {
        a.strip_prefix('-')
            .is_some_and(|r| !r.starts_with('-') && r.chars().any(|c| letters.contains(&c)))
    })
}

/// One of the long options in `names` (each with the shortest prefix of it that counts) is among
/// the options, in any spelling `argparse` accepts (`--res`, `--resume=x`). Hermes does not turn
/// prefixes off.
fn has_abbrev(args: &[&str], names: &[(&str, usize)]) -> bool {
    args.iter().any(|a| {
        let name = a.split('=').next().unwrap_or(a);
        name.starts_with("--")
            && names
                .iter()
                .any(|(full, min)| name.len() >= *min && full.starts_with(name))
    })
}

/// A command that puts a turn into another agent's session (F1.1).
fn fence_args(prog: &str, args: &[&str]) -> bool {
    let flag = |set: &[&str]| has_flag(args, set);
    let cluster = |letters: &[char]| has_cluster(args, letters);
    match prog {
        "codex" => args.contains(&"queue") || args.contains(&"resume"),
        "claude" => flag(&["--resume", "--continue"]) || cluster(&['r', 'c']),
        // `--resume`/`-r <id|title|latest>` and `--continue`/`-c [name]` run the query of `chat -q`
        // or top-level `-z` in that session (`hermes_cli/oneshot.py:437-465`,
        // `hermes_cli/main.py:1403-1470,1511-1560`, hermes-agent 9976f48). No other long option
        // starts `--res` or `--co`.
        "hermes" => has_abbrev(args, &[("--resume", 5), ("--continue", 4)]) || cluster(&['r', 'c']),
        // `run`, the default interface (`--prompt`) and `attach` all take `-s`/`--session` and
        // `-c`/`--continue` to reach an existing session (`opencode --help`, 2026-10-26).
        "opencode" => flag(&["--session", "--continue"]) || cluster(&['s', 'c']),
        // F1.1: a command naming `agent` (`openclaw agent`, `gateway call agent`), `sessions_send`
        // or `acp` (which bridges prompts into a session), and `cron add`/`edit` (scheduled turns).
        // Word presence, not position: an option's value would shift positions.
        "openclaw" => {
            args.contains(&"agent")
                || args.contains(&"sessions_send")
                || args.contains(&"acp")
                || (args.contains(&"cron") && (args.contains(&"add") || args.contains(&"edit")))
        }
        _ => false,
    }
}

/// A command that starts a new agent session on a prompt of its own (P1.4): a harness's
/// non-interactive forms (`claude -p`, `codex exec`, `hermes chat -q`, `opencode run`) and a prompt
/// given on the command line. That session is guarded but not HELD, so it would run what its parent
/// may not. Resuming or continuing an existing one is a fence ([`fence_args`]), which ranks above.
///
/// `bare`: a prompt given with no option or command counts. It does for a command; it does not for
/// the words of a script or code, where a name followed by any word is prose (`claude is good`).
fn starts_session(prog: &str, args: &[&str], bare: bool) -> bool {
    let first = args.iter().find(|a| !a.starts_with('-'));
    match prog {
        // `claude [options] [command] [prompt]`: `-p`/`--print`, `--bg`, or a first word that is
        // not one of its commands. `--help` and `--version` start nothing.
        "claude" => {
            !has_flag(args, &["--help", "-h", "--version", "-v"])
                && (has_flag(args, &["--print", "--bg", "--background"])
                    || has_cluster(args, &['p'])
                    || (bare && first.is_some_and(|a| !NOT_A_PROMPT.contains(a))))
        }
        // `codex [OPTIONS] [PROMPT]`; `exec`, `e`, `review` and `fork` are not in `NOT_A_PROMPT`.
        "codex" => {
            !has_flag(args, &["--help", "-h", "--version", "-V"])
                && first.is_some_and(|a| {
                    if bare {
                        !NOT_A_PROMPT.contains(a)
                    } else {
                        matches!(*a, "exec" | "e" | "review" | "fork")
                    }
                })
        }
        // `opencode run [message..]`, `opencode pr <n>`, and the default interface's `--prompt`.
        "opencode" => has_flag(args, &["--prompt"]) || matches!(first, Some(&("run" | "pr"))),
        // `chat -q|--query|--query-file`, top-level `-z|--oneshot` (`hermes_cli/_parser.py:148,
        // 233-247`, hermes-agent 9976f48).
        "hermes" => {
            has_cluster(args, &['q', 'z'])
                || has_abbrev(
                    args,
                    &[("--query", 5), ("--query-file", 5), ("--oneshot", 3)],
                )
        }
        _ => false,
    }
}

/// What script or code text runs, as far as its words show it (F1, I1.2, A1.3; spec §15 K1.8),
/// judged statement by statement: an identity variable named or the environment cleared
/// ([`changes_identity`]), a channel's name followed later in the statement by its injecting word
/// (`codex` … `queue`), a Lunchroom command only the user may run, or a local session chat API. A
/// name alone (a comment, a message) is not a match.
fn code_rules(text: &str) -> Option<DenyReason> {
    // I1.2 first: an identity variable named, or the environment cleared, in any statement.
    if mentions_identity(text) {
        return Some(DenyReason::Fence);
    }
    for stmt in statements(text) {
        // Words with a letter or digit in them; quotes, commas and brackets between are skipped.
        let words: Vec<&str> = tokens(stmt)
            .into_iter()
            .filter(|t| t.chars().any(char::is_alphanumeric))
            .collect();
        for (k, t) in words.iter().enumerate() {
            let name = basename(t);
            let after = words.get(k + 1..).unwrap_or_default();
            if FENCE_PROGRAMS.contains(&name) && fence_args(name, after) {
                return Some(DenyReason::Fence);
            }
            // A Lunchroom command only the user may run, or one given an option first.
            // After help (`--help approve`) a user-only command still counts.
            let lead = after
                .iter()
                .take_while(|n| matches!(**n, "help" | "--help" | "-h" | "--version"))
                .count();
            if LUNCHROOM_NAMES.contains(&name)
                && after.get(lead).is_some_and(|n| {
                    LUNCHROOM_USER_ONLY.contains(n)
                        || (n.starts_with('-') && !LUNCHROOM_OPEN.contains(n))
                })
            {
                return Some(DenyReason::Configuration);
            }
        }
    }
    names_chat_api(text).then_some(DenyReason::Fence)
}

/// Script or code text names a program that starts a new agent session, in a statement, as
/// [`code_rules`] reads one ([`starts_session`] without a bare prompt).
fn code_starts_session(text: &str) -> bool {
    statements(text).into_iter().any(|stmt| {
        let words: Vec<&str> = tokens(stmt)
            .into_iter()
            .filter(|t| t.chars().any(char::is_alphanumeric))
            .collect();
        words.iter().enumerate().any(|(k, t)| {
            let name = basename(t);
            FENCE_PROGRAMS.contains(&name)
                && starts_session(name, words.get(k + 1..).unwrap_or_default(), false)
        })
    })
}

/// Every string in a tool's input, at any depth.
fn string_leaves<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|i| string_leaves(i, out)),
        Value::Object(map) => map.values().for_each(|i| string_leaves(i, out)),
        _ => {}
    }
}

/// Shell text with each heredoc's body lines removed: after a line holding `<<WORD` (`<<-`,
/// quoted or not), the lines up to the one that is `WORD` alone. A heredoc never closed takes the
/// rest of the text. A line of an unquoted body holding a substitution stays: the shell runs it.
fn without_heredoc_bodies(text: &str) -> String {
    let mut out = String::new();
    let mut closing: Vec<(String, bool)> = Vec::new();
    for line in text.lines() {
        if let Some((word, quoted)) = closing.first() {
            if line.trim_start_matches('\t') == word {
                closing.remove(0);
            } else if !quoted && (line.contains("$(") || line.contains('`')) {
                out.push_str(line);
                out.push('\n');
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
        let mut rest = line;
        while let Some(k) = rest.find("<<") {
            rest = &rest[k + 2..];
            if rest.starts_with('<') {
                // `<<<` is a here-string, not a heredoc.
                rest = &rest[1..];
                continue;
            }
            let raw: String = rest
                .trim_start_matches('-')
                .trim_start()
                .chars()
                .take_while(|c| !c.is_whitespace() && !";&|<>()".contains(*c))
                .collect();
            let word: String = raw
                .chars()
                .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            if !word.is_empty() {
                closing.push((word.clone(), word.len() != raw.len()));
            }
        }
    }
    out
}

/// Programs that run the text they are handed.
fn runs_text(name: &str) -> bool {
    SHELLS.contains(&name)
        || INTERPRETERS.contains(&name)
        || name.starts_with("python")
        || matches!(name, "eval" | "source" | "." | "ssh" | "su" | "watch")
}

/// A channel's name, or a Lunchroom command only the user may run, at the `live` positions.
fn names_channel(toks: &[&str], live: &[usize]) -> bool {
    live.iter().any(|&k| {
        let name = basename(toks[k]);
        FENCE_PROGRAMS.contains(&name)
            || (LUNCHROOM_NAMES.contains(&name)
                && toks.get(k + 1).is_some_and(|n| !LUNCHROOM_OPEN.contains(n)))
    })
}

/// The program file named at `args[k]` of `sed` or `awk`: the value of `-f` (and gawk's `-E` and
/// `-i`), written separately, after `=` or attached.
fn script_option_file<'a>(name: &str, args: &[&'a str], k: usize) -> Option<&'a str> {
    let options: &[&str] = if name == "sed" {
        &["-f", "--file"]
    } else {
        &["-f", "--file", "-E", "--exec", "-i", "--include"]
    };
    let a = args[k];
    if k > 0 && options.contains(&args[k - 1]) {
        return Some(a);
    }
    options.iter().find_map(|o| {
        if o.starts_with("--") {
            a.strip_prefix(*o).and_then(|r| r.strip_prefix('='))
        } else {
            a.strip_prefix(*o).filter(|r| !r.is_empty())
        }
    })
}

/// Whether a `sed` script holds the `e` command or the `e` flag of `s`, which run text. The
/// `/re/` addresses and the parts of `s` are skipped; text of `a`, `i`, `c` or `y` may show a
/// false `e`, which only makes the files searched.
fn sed_runs_text(script: &str) -> bool {
    // Reads up to the next unescaped `d`; false if there is none.
    fn skip(cs: &mut std::str::Chars, d: char) -> bool {
        while let Some(c) = cs.next() {
            if c == '\\' {
                cs.next();
            } else if c == d {
                return true;
            }
        }
        false
    }
    let mut cs = script.chars();
    while let Some(c) = cs.next() {
        match c {
            'e' => return true,
            '/' => {
                skip(&mut cs, '/');
            }
            's' => {
                let Some(d) = cs.next() else { return true };
                if !(skip(&mut cs, d) && skip(&mut cs, d)) {
                    return true;
                }
                let flags: String = cs
                    .by_ref()
                    .take_while(|f| !f.is_whitespace() && !matches!(f, ';' | '}'))
                    .collect();
                if flags.contains('e') {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether an `awk` program calls `system`, pipes (`print | "cmd"`, `"cmd" | getline`, `|&`) or
/// loads an extension. Text in strings is ignored; a `|` in a regex counts, which only makes the
/// files searched.
fn awk_runs_text(script: &str) -> bool {
    let code: String = script.split('"').step_by(2).collect();
    let code = code.replace("||", "").replace(char::is_whitespace, "");
    code.contains("system(") || code.contains("@load") || code.contains('|')
}

/// The argument an interpreter runs as its script: for `awk` and `sed` the file given to `-f`;
/// otherwise the first word that is not an option or an option's value (after `run` for `deno`
/// and `bun`), unless inline code (`-c`, `-e`, `-m` …) comes first.
fn interpreter_script<'a>(name: &str, args: &[&'a str]) -> Option<&'a str> {
    if name == "sed" {
        return option_value(args, &["-f", "--file"]);
    }
    // gawk's `-E` (`--exec`) names the program file as `-f` does.
    if matches!(name, "awk" | "gawk" | "mawk") {
        return option_value(args, &["-f", "--file", "-E", "--exec"]);
    }
    let mut k = 0;
    while let Some(a) = args.get(k) {
        match *a {
            "-c" | "-e" | "-E" | "-m" | "-p" | "-r" | "--eval" | "--print" | "-Command" => {
                return None;
            }
            "-W" | "-X" | "--require" | "--import" | "--loader" | "-I" => k += 2,
            "run" if matches!(name, "deno" | "bun") => k += 1,
            a if a.starts_with('-') => k += 1,
            a => return Some(a),
        }
    }
    None
}

/// The positions of the script files the shells and interpreters at `runnable` run: a shell's
/// first word that is not an option (none with `-c`), an interpreter's [`interpreter_script`].
/// Where a shell takes its commands from, read as the shell reads its arguments: options end at
/// the first operand, so a word after a script's name (`bash build.sh -clean`) is the script's.
enum ShellInput {
    /// `-c`: the operand at this index is the command text (none given: nothing runs).
    Text(Option<usize>),
    /// The script file at this index.
    Script(usize),
    /// No operand: commands come from standard input.
    Stdin,
}

fn shell_input(args: &[&str]) -> ShellInput {
    let mut dash_c = false;
    let mut k = 0;
    let operand = loop {
        match args.get(k) {
            Some(&("-o" | "-O" | "+o" | "+O" | "--rcfile" | "--init-file")) => k += 2,
            Some(&"--") => break args.get(k + 1).map(|_| k + 1),
            // `--command <text>`: the next word is the command text, whatever it starts with.
            Some(&"--command") => {
                dash_c = true;
                break args.get(k + 1).map(|_| k + 1);
            }
            Some(a) if a.starts_with('-') || a.starts_with('+') => {
                dash_c |= a
                    .strip_prefix('-')
                    .is_some_and(|r| !r.starts_with('-') && r.contains('c'));
                k += 1;
            }
            Some(_) => break Some(k),
            None => break None,
        }
    };
    match (dash_c, operand) {
        (true, k) => ShellInput::Text(k),
        (false, Some(k)) => ShellInput::Script(k),
        (false, None) => ShellInput::Stdin,
    }
}

fn script_positions(texts: &[&str], runnable: &[usize]) -> Vec<usize> {
    let mut out = Vec::new();
    for &p in runnable {
        let name = basename(texts[p]);
        let args = &texts[p + 1..];
        let script = if SHELLS.contains(&name) {
            match shell_input(args) {
                ShellInput::Script(k) => Some(k),
                ShellInput::Text(_) | ShellInput::Stdin => None,
            }
        } else if INTERPRETERS.contains(&name) || name.starts_with("python") {
            interpreter_script(name, args).and_then(|s| args.iter().position(|a| *a == s))
        } else {
            None
        };
        out.extend(script.map(|k| p + 1 + k));
    }
    out
}

/// I1.2 in script or code text: some statement names an identity variable or clears the
/// environment ([`changes_identity`]).
fn mentions_identity(text: &str) -> bool {
    statements(text).into_iter().any(changes_identity)
}

/// I1.2 in one statement of script or code: it names an identity variable, or it clears the whole
/// environment (`os.environ.clear()`, `clearenv`). Any mention counts, a read included: no list of
/// the ways a language can set a variable is complete, so the guard does not try to tell a read
/// from a change in code it does not run as shell.
fn changes_identity(stmt: &str) -> bool {
    let toks = tokens(stmt);
    let parts: Vec<&str> = toks
        .iter()
        .flat_map(|t| t.split(['.', '=', '[', ']']))
        .collect();
    IDENTITY_VARS.iter().any(|v| parts.contains(v))
        || parts.contains(&"clearenv")
        || parts
            .windows(2)
            .any(|w| matches!(w[0], "environ" | "env") && w[1] == "clear")
}

/// The statements of script or code text: split at a line end or `;` outside brackets, where the
/// line end is not escaped. A call spelled across lines inside brackets stays one statement.
fn statements(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut prev = ' ';
    for (i, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '\n' | ';' if depth == 0 && prev != '\\' => {
                out.push(&text[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
        prev = c;
    }
    out.push(&text[start..]);
    out
}

/// A1.3: Lunchroom's arguments run only an open command. Every option before the command must be
/// an open one (`--help`, `--version`); the command must be open; and with no command, or `help`,
/// no word after it may be a command only the user may run (`lunchroom --help approve`). The words
/// after `send` and the other open commands are their own arguments (a message's text).
fn lunchroom_args_open(args: &[&str]) -> bool {
    let cmd_at = args.iter().position(|a| !a.starts_with('-'));
    let options = &args[..cmd_at.unwrap_or(args.len())];
    if !options.iter().all(|o| LUNCHROOM_OPEN.contains(o)) {
        return false;
    }
    match cmd_at.map(|k| args[k]) {
        Some(cmd) if !LUNCHROOM_OPEN.contains(&cmd) => false,
        None | Some("help") => !args.iter().any(|a| LUNCHROOM_USER_ONLY.contains(a)),
        Some(_) => true,
    }
}

/// The paths a `grep` is given: its arguments that are not options, their values or the pattern.
/// The pattern is the first such word unless `-e`/`-f` (or `--regexp`/`--file`) gives it.
fn grep_path_operands<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut operands = Vec::new();
    let mut pattern_given = false;
    let mut skip_value = false;
    let mut ended = false;
    for &a in args {
        if skip_value {
            skip_value = false;
        } else if ended || a == "-" || !a.starts_with('-') {
            operands.push(a);
        } else if a == "--" {
            ended = true;
        } else if let Some(long) = a.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, false), |(n, _)| (n, true));
            pattern_given |= matches!(name, "regexp" | "file");
            skip_value = !attached
                && matches!(
                    name,
                    "regexp"
                        | "file"
                        | "after-context"
                        | "before-context"
                        | "context"
                        | "max-count"
                        | "directories"
                        | "devices"
                        | "include"
                        | "exclude"
                        | "exclude-from"
                        | "exclude-dir"
                        | "label"
                        | "binary-files"
                );
        } else {
            // A cluster of short options: the first one that takes a value ends it, the value being
            // the rest of the word or the next word.
            let cluster = &a[1..];
            if let Some(k) = cluster.find(|c| "efABCmdD".contains(c)) {
                pattern_given |= matches!(&cluster[k..=k], "e" | "f");
                skip_value = k + 1 == cluster.len();
            }
        }
    }
    if !pattern_given && !operands.is_empty() {
        operands.remove(0);
    }
    operands
}

/// The first `git` argument that is not an option: its subcommand.
fn git_subcommand<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut k = 0;
    while let Some(a) = args.get(k) {
        if matches!(
            *a,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
        ) {
            k += 2;
        } else if a.starts_with('-') {
            k += 1;
        } else {
            return Some(a);
        }
    }
    None
}

/// The PROTECTED kind of a program run with these arguments (P1.4), judged on its name.
fn protected_kind(prog: &str, args: &[&str]) -> Option<ProtectedKind> {
    if NETWORK_PROGRAMS.contains(&prog) {
        return Some(ProtectedKind::Network);
    }
    if prog == "git" {
        return match git_subcommand(args) {
            Some("push") => Some(ProtectedKind::PushOrPublish),
            Some("rm" | "clean") => Some(ProtectedKind::Delete),
            Some(s) if GIT_NETWORK.contains(&s) => Some(ProtectedKind::Network),
            _ => None,
        };
    }
    if PUBLISHERS.contains(&prog)
        && args
            .iter()
            .any(|a| matches!(*a, "publish" | "push" | "upload"))
    {
        return Some(ProtectedKind::PushOrPublish);
    }
    if DELETERS.contains(&prog)
        || (prog == "find" && args.contains(&"-delete"))
        || (prog == "gio" && matches!(args.first(), Some(&("trash" | "remove"))))
    {
        return Some(ProtectedKind::Delete);
    }
    // Printing the environment prints any token in it.
    let only_options = args.iter().all(|a| a.starts_with('-'));
    if prog == "printenv"
        || (matches!(prog, "export" | "declare" | "typeset") && only_options)
        || (prog == "set" && args.is_empty())
    {
        return Some(ProtectedKind::Credential);
    }
    None
}

/// Where a wrapper (`sudo`, `env`, `timeout`, ...) at `i` starts the program it runs.
fn wrapper_inner(texts: &[&str], i: usize) -> Option<usize> {
    let name = basename(texts[i]);
    let with_value: &[&str] = match name {
        "sudo" => &[
            "-u",
            "-g",
            "-h",
            "-p",
            "-C",
            "-D",
            "-r",
            "-t",
            "-U",
            "-T",
            "-R",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--chdir",
            "--role",
            "--type",
            "--other-user",
        ],
        "doas" => &["-u", "-C"],
        "env" => &["-u", "-C", "--unset", "--chdir"],
        "timeout" => &["-k", "-s", "--kill-after", "--signal"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p", "--class", "--classdata", "--pid"],
        "stdbuf" => &["-i", "-o", "-e", "--input", "--output", "--error"],
        "xargs" => &[
            "-I",
            "-L",
            "-n",
            "-P",
            "-s",
            "-d",
            "-E",
            "-a",
            "--max-args",
            "--max-procs",
            "--delimiter",
            "--arg-file",
            "--replace",
            "--max-lines",
            "--max-chars",
            "--eof",
        ],
        "exec" => &["-a"],
        "flock" => &["-w", "--timeout", "-E", "--conflict-exit-code"],
        "strace" => &[
            "-o", "-p", "-e", "-s", "-u", "-E", "-P", "-S", "-X", "-I", "-a", "-b",
        ],
        "ltrace" => &["-o", "-p", "-e", "-s", "-u", "-n", "-a"],
        "proxychains" | "proxychains4" => &["-f"],
        "nohup" | "setsid" | "time" | "command" | "builtin" | "chronic" | "unbuffer"
        | "caffeinate" | "taskset" | "busybox" | "valgrind" | "torsocks" | "firejail"
        | "unshare" | "dbus-run-session" | "chroot" => &[],
        _ => return None,
    };
    let mut j = i + 1;
    while let Some(a) = texts.get(j) {
        if *a == "--" {
            j += 1;
            break;
        }
        if name == "env" && is_assignment(a) {
            j += 1;
            continue;
        }
        if !a.starts_with('-') {
            break;
        }
        j += if with_value.contains(a) { 2 } else { 1 };
    }
    if matches!(name, "timeout" | "taskset" | "flock" | "chroot") {
        j += 1; // the duration, CPU mask, lock file or new root before the program
    }
    Some(j)
}

/// The positions in a command that hold the program it runs, through any wrappers.
/// The positions in a command that hold a program it runs: the command's own program, the program
/// each wrapper (`sudo`, `env`, `timeout`, ...) runs, and the programs `find -exec` runs. Sorted.
fn program_positions(texts: &[&str]) -> Vec<usize> {
    let mut out = Vec::new();
    let Some(start) = texts.iter().position(|t| !is_assignment(t)) else {
        return out;
    };
    let mut starts = vec![start];
    while let Some(mut i) = starts.pop() {
        while !out.contains(&i) {
            out.push(i);
            if basename(texts[i]) == "find" {
                for k in i + 1..texts.len() {
                    if matches!(texts[k], "-exec" | "-execdir" | "-ok" | "-okdir")
                        && k + 1 < texts.len()
                    {
                        starts.push(k + 1);
                    }
                }
            }
            match wrapper_inner(texts, i) {
                Some(j) if j < texts.len() => i = j,
                _ => break,
            }
        }
    }
    out.sort_unstable();
    out
}

/// The positions the always-DENIED rules judge as programs: the known program positions, and every
/// later word of a program that is not known never to run its arguments (`mywrap codex queue`).
fn runnable_positions(texts: &[&str], positions: &[usize]) -> Vec<usize> {
    (0..texts.len())
        .filter(|&i| {
            positions.contains(&i)
                || positions
                    .iter()
                    .rev()
                    .find(|&&p| p < i)
                    .is_some_and(|&p| !NEVER_RUNS.contains(&basename(texts[p])))
        })
        .collect()
}

/// Whether a command is a build or an install, through any wrapper: a program run by a path that
/// does not exist yet may be what it makes.
fn builds(texts: &[&str]) -> bool {
    program_positions(texts).into_iter().any(|p| {
        let args = &texts[p + 1..];
        // The first word that is not an option: the subcommand.
        let sub = args.iter().find(|a| !a.starts_with('-')).copied();
        match basename(texts[p]) {
            // Compilers and build tools make their output whatever they are asked.
            "make" | "ninja" | "tsc" | "gcc" | "g++" | "cc" | "c++" | "clang" | "clang++"
            | "rustc" => true,
            "cmake" => args.contains(&"--build"),
            "cargo" => matches!(sub, Some("build" | "b" | "install")),
            "go" => matches!(sub, Some("build" | "install")),
            "npm" | "pnpm" | "yarn" => {
                matches!(
                    sub,
                    None | Some("install" | "i" | "ci" | "add" | "build" | "run")
                )
            }
            "pip" | "pip3" => sub == Some("install"),
            name if name.starts_with("python") => {
                args.windows(2)
                    .any(|w| matches!(w, ["-m", "venv" | "virtualenv"]))
                    || args
                        .windows(3)
                        .any(|w| matches!(w, ["-m", "pip", "install"]))
            }
            _ => false,
        }
    })
}

/// The positions of the words that are text, not paths: the pattern a searcher is given, what
/// `echo` and `printf` print (a redirection's target is still a path) and a commit's message.
fn text_positions(words: &[Word], texts: &[&str], positions: &[usize]) -> Vec<usize> {
    let mut out = Vec::new();
    for &p in positions {
        let args = &texts[p + 1..];
        let text = match basename(texts[p]) {
            "echo" | "printf" => {
                out.extend((p + 1..texts.len()).filter(|&k| !words[k].redirect));
                None
            }
            "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack" => {
                option_value(args, &["-e", "--regexp"]).or_else(|| {
                    // Else the first operand, unless an option may carry the pattern or a file of them.
                    let other = args.iter().any(|a| {
                        matches!(*a, "--file" | "--files")
                            || (a.starts_with('-')
                                && !a.starts_with("--")
                                && a.contains(['e', 'f']))
                    });
                    args.iter().find(|a| !other && !a.starts_with('-')).copied()
                })
            }
            "git" if git_subcommand(args) == Some("commit") => {
                option_value(args, &["-m", "--message"])
            }
            _ => None,
        };
        // The first word that is that text (or `--opt=text`): the pattern or message itself.
        let at = text.and_then(|t| {
            args.iter()
                .position(|a| *a == t || a.strip_suffix(t).is_some_and(|r| r.ends_with('=')))
        });
        out.extend(at.map(|k| p + 1 + k));
    }
    out
}

/// The value of the first of `flags` in `args`, written separately or attached.
fn option_value<'a>(args: &[&'a str], flags: &[&str]) -> Option<&'a str> {
    for (k, a) in args.iter().enumerate() {
        for f in flags {
            if a == f {
                return args.get(k + 1).copied();
            }
            if let Some(v) = a.strip_prefix(f) {
                if f.starts_with("--") {
                    if let Some(v) = v.strip_prefix('=') {
                        return Some(v);
                    }
                } else if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

impl Guard<'_> {
    /// Classifies one Claude Code tool call made from `cwd`, as the one class
    /// [`Call::folded`] gives: a call that also raised the guard's configuration is shown as it.
    /// Prefer [`Guard::classify_call`], which keeps every kind for `decide_call`.
    #[must_use]
    pub fn classify(&self, tool: &str, input: &Value, cwd: &Path) -> CallClass {
        self.classify_call(tool, input, cwd).folded()
    }

    /// Classifies one Claude Code tool call made from `cwd`: the class to show and every PROTECTED
    /// kind the call raised (P1.6: the policy follows the kinds, not the class shown).
    #[must_use]
    pub fn classify_call(&self, tool: &str, input: &Value, cwd: &Path) -> Call {
        let field = |k: &str| input.get(k).and_then(Value::as_str);
        let mut acc = Acc::new(CallClass::InSlip);
        match tool {
            "Read" | "NotebookRead" | "LS" | "Grep" => {
                let key = match tool {
                    "Read" => "file_path",
                    "NotebookRead" => "notebook_path",
                    _ => "path",
                };
                let cwd_text = cwd.to_string_lossy();
                let raw = field(key).or(if tool == "Grep" {
                    Some(&*cwd_text)
                } else {
                    None
                });
                match raw {
                    Some(r) => self.read_path(r, cwd, tool == "Grep", &mut acc),
                    None => self.when_held(&mut acc, CallClass::Protected(ProtectedKind::Unparsed)),
                }
            }
            "Glob" => {
                let root = field("path").map_or_else(|| cwd.to_path_buf(), PathBuf::from);
                match field("pattern") {
                    Some(p) => self.glob_tool(p, &root, &mut acc),
                    None => self.when_held(&mut acc, CallClass::Protected(ProtectedKind::Unparsed)),
                }
            }
            "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
                acc.raise(CallClass::Ordinary);
                let key = if tool == "NotebookEdit" {
                    "notebook_path"
                } else {
                    "file_path"
                };
                match field(key) {
                    Some(p) => self.write_path(p, cwd, &mut acc),
                    None => self.when_held(&mut acc, CallClass::Protected(ProtectedKind::Unparsed)),
                }
            }
            "Bash" => {
                // §6 item 1: a reply, a command that is exactly one `lunchroom send`, is inside
                // every slip; its words are still judged below.
                if !field("command").is_some_and(|c| self.is_reply(c, cwd)) {
                    acc.raise(CallClass::Ordinary);
                }
                match field("command") {
                    Some(c) => self.shell_text(c, cwd, 0, &mut acc),
                    None => self.when_held(&mut acc, CallClass::Protected(ProtectedKind::Unparsed)),
                }
            }
            t if SLIP_TOOLS.contains(&t) => {}
            t if ORDINARY_TOOLS.contains(&t) => acc.raise(CallClass::Ordinary),
            t if NETWORK_TOOLS.contains(&t) => {
                acc.raise(CallClass::Ordinary);
                self.when_held(&mut acc, CallClass::Protected(ProtectedKind::Network));
            }
            _ => {
                acc.raise(CallClass::Ordinary);
                self.when_held(&mut acc, CallClass::Protected(ProtectedKind::UnknownTool));
                // P1.4: an unknown tool given a path in Lunchroom's stores may write it.
                let mut texts = Vec::new();
                string_leaves(input, &mut texts);
                for t in texts {
                    self.word_paths(t, cwd, false, &mut acc);
                }
            }
        }
        // P1.4: a command, script or code that starts a new agent session.
        if acc.new_session {
            self.when_held(&mut acc, CallClass::Protected(ProtectedKind::OtherSession));
        }
        acc.call()
    }

    fn when_held(&self, acc: &mut Acc, c: CallClass) {
        if self.held {
            acc.raise(c);
        }
    }

    fn home(&self) -> String {
        self.layout.home.to_string_lossy().into_owned()
    }

    /// The file `raw` opens, resolved as the operating system resolves it (L1.1: "Paths are
    /// resolved (symlinks, wildcards) before checking"): part by part, so `..` leaves the folder a
    /// link led to, not the folder holding the link.
    fn physical(&self, raw: &str, here: &Path) -> PathBuf {
        self.fs
            .resolve(&absolute(raw, here, &self.layout.home))
            .path
    }

    /// The paths `raw` may mean: the file it opens, the path as written (made absolute and
    /// lexically normal) and its real path, and for a wildcard every match and its real path. The
    /// wildcard is matched in the folder its literal part resolves to. `capped` is the folder to
    /// search from when the wildcard's matching was cut short; `unresolved` says the file could
    /// not be settled (a link loop, a part the guard may not look at, a `..` after a part that does
    /// not exist or after a wildcard), so it may be anywhere.
    fn forms(&self, raw: &str, cwd: &Path) -> Forms {
        let joined = absolute(raw, cwd, &self.layout.home);
        let lexical = normalize(raw, cwd, &self.layout.home);
        let mut f = Forms::default();
        if raw.contains(['*', '?', '[']) {
            let (head, tail) = split_wild(&joined);
            let base = self.fs.resolve(&head);
            f.unresolved = !base.complete;
            let mut pattern = base.path.clone();
            for c in tail.components() {
                match c {
                    Component::Normal(s) => pattern.push(s),
                    // The folders a wildcard matched are not known here, so the folder above one
                    // is not either: the path is unresolved (fail closed while HELD, P1.2).
                    Component::ParentDir => {
                        pattern.pop();
                        f.unresolved = true;
                    }
                    Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
                }
            }
            f.push(self.fs.real(&lexical));
            f.push(lexical);
            let e = self.fs.expand(&pattern);
            for m in e.matches {
                f.push(self.fs.real(&m));
                f.push(m);
            }
            if e.capped && f.capped.is_none() {
                f.capped = Some(literal_prefix(&pattern));
            }
        } else {
            let r = self.fs.resolve(&joined);
            f.unresolved = !r.complete;
            f.push(r.path);
            f.push(self.fs.real(&lexical));
            f.push(lexical);
        }
        f
    }

    /// A path the guard could not settle may be anywhere. While HELD, one a tool is known to read
    /// is DENIED (a read that cannot be resolved cannot be shown to avoid L1.1's paths, and the
    /// operating system would fail it too); one a shell word names, with no direction, may be
    /// read or written, so it is PROTECTED as everything it could be: unparsed text, a credential,
    /// the guard's configuration. Nothing changes for an agent that is not HELD (P1.2).
    fn unresolved(&self, reads: bool, acc: &mut Acc) {
        if !self.held {
            return;
        }
        if reads {
            self.denied_read(acc);
        } else {
            acc.raise(CallClass::Protected(ProtectedKind::Unparsed));
            acc.raise(CallClass::Protected(ProtectedKind::Credential));
            acc.raise(CallClass::Protected(ProtectedKind::GuardConfig));
        }
    }

    /// L1.1 for one path a HELD session reads.
    fn read_facts(&self, p: &Path, acc: &mut Acc) {
        let f = self.layout.facts(p);
        if f.store || f.transcript {
            self.denied_read(acc);
        } else if f.credential {
            acc.raise(CallClass::Protected(ProtectedKind::Credential));
        }
    }

    /// A read of a path L1.1 denies is never inside the slip: DENIED while HELD; for an agent that
    /// is not HELD it is an ordinary call, which runs (L1.1 holds only while HELD).
    fn denied_read(&self, acc: &mut Acc) {
        acc.raise(if self.held {
            CallClass::Denied(DenyReason::DeniedPath)
        } else {
            CallClass::Ordinary
        });
    }

    fn read_path(&self, raw: &str, cwd: &Path, search: bool, acc: &mut Acc) {
        let forms = self.forms(raw, cwd);
        for f in &forms.paths {
            self.read_facts(f, acc);
        }
        if search {
            for f in forms.paths.iter().filter(|f| self.fs.is_dir(f)) {
                self.search_from(f, acc);
            }
        }
        if let Some(prefix) = forms.capped {
            self.search_from(&prefix, acc);
        }
        if forms.unresolved {
            self.unresolved(true, acc);
        }
    }

    fn glob_tool(&self, pattern: &str, root: &Path, acc: &mut Acc) {
        let joined = absolute(pattern, root, &self.layout.home);
        let (head, tail) = split_wild(&joined);
        let base = self.fs.resolve(&head);
        // The folder the pattern starts in, as written and as the operating system reaches it.
        let start = literal_prefix(&normalize(pattern, root, &self.layout.home));
        self.search_from(&start, acc);
        self.search_from(&base.path, acc);
        // A `..` after a wildcard leaves a folder not yet known.
        if !base.complete || tail.components().any(|c| c == Component::ParentDir) {
            self.unresolved(true, acc);
        }
    }

    /// L1.1 for a search from `dir`: what it is, what lies below it, and (by a bounded walk) any
    /// credential file or link to a denied path inside it. A walk cut short counts as reaching a
    /// credential, so the search goes to the user. For an agent that is not HELD the walk is not
    /// made, because nothing it could find changes what happens to the call (P1.2); the search is
    /// then an ordinary call, not shown to be inside the slip.
    fn search_from(&self, dir: &Path, acc: &mut Acc) {
        self.read_facts(dir, acc);
        if self.layout.denied_below(dir) {
            self.denied_read(acc);
        }
        if self.layout.credential_root_below(dir) {
            acc.raise(CallClass::Protected(ProtectedKind::Credential));
        }
        if acc.denied() || !self.fs.is_dir(dir) {
            return;
        }
        if !self.held {
            acc.raise(CallClass::Ordinary);
            return;
        }
        let (mut denied, mut credential) = (false, false);
        let end = self.fs.walk(dir, &mut |p| {
            let f = self.layout.facts(p);
            denied |= f.store || f.transcript;
            credential |= f.credential;
            denied
        });
        if denied {
            self.denied_read(acc);
        } else if credential || end == WalkEnd::Capped {
            acc.raise(CallClass::Protected(ProtectedKind::Credential));
        }
    }

    /// P1.4 for one path a call writes.
    fn write_path(&self, raw: &str, cwd: &Path, acc: &mut Acc) {
        let forms = self.forms(raw, cwd);
        for f in &forms.paths {
            self.path_rules(f, false, acc);
        }
        if let Some(prefix) = forms.capped {
            self.capped_rules(&prefix, acc);
        }
        if forms.unresolved {
            self.unresolved(false, acc);
        }
    }

    /// The rules for one path a call reads or writes (the shell's words have no direction): a
    /// store is DENIED in every session; while HELD, transcripts are DENIED and credentials, guard
    /// configuration and Lunchroom's program (other than running it) are PROTECTED.
    fn path_rules(&self, p: &Path, runs_it: bool, acc: &mut Acc) {
        let f = self.layout.facts(p);
        if f.store {
            acc.raise(CallClass::Denied(DenyReason::Configuration));
        }
        if !self.held {
            return;
        }
        if f.transcript {
            acc.raise(CallClass::Denied(DenyReason::DeniedPath));
        }
        if f.credential {
            acc.raise(CallClass::Protected(ProtectedKind::Credential));
        }
        // A harness's program decides what runs the guard, as Lunchroom's program does (R3.1).
        if f.guard_config || ((f.program || f.harness_program) && !runs_it) {
            acc.raise(CallClass::Protected(ProtectedKind::GuardConfig));
        }
    }

    /// A wildcard cut short may match anything below its literal prefix.
    fn capped_rules(&self, prefix: &Path, acc: &mut Acc) {
        if self.layout.lunchroom_home.starts_with(prefix) || self.layout.facts(prefix).store {
            acc.raise(CallClass::Denied(DenyReason::Configuration));
        }
        if self.held {
            self.search_from(prefix, acc);
        }
    }

    fn word_paths(&self, text: &str, cwd: &Path, runs_it: bool, acc: &mut Acc) {
        for c in candidates(text) {
            let forms = self.forms(c, cwd);
            for f in &forms.paths {
                self.path_rules(f, runs_it && c == text, acc);
            }
            if let Some(prefix) = forms.capped {
                self.capped_rules(&prefix, acc);
            }
            if forms.unresolved {
                self.unresolved(false, acc);
            }
        }
    }

    /// F1.2: text the guard cannot read is judged by its words, with the reason `unparsed`, and
    /// while HELD it is PROTECTED. A program runs at the word that begins each piece of the text
    /// (after `;`, `&`, `|`, a line end, `$(` or a backquote, past any `NAME=value`). A channel's
    /// name or a user-only Lunchroom command counts there and after a wrapper, not in prose (a
    /// commit message, a heredoc written to a file); text handed to a shell or an interpreter
    /// counts in full, heredoc bodies included.
    fn unparsed(&self, text: &str, cwd: &Path, acc: &mut Acc) {
        let home = self.home();
        let text = text.replace("${HOME}", &home).replace("$HOME", &home);
        let head = without_heredoc_bodies(&text).replace("$(", "\n");
        let raw: Vec<&str> = head.split([';', '&', '|', '\n', '`']).collect();
        let pieces: Vec<Vec<&str>> = raw.iter().map(|p| tokens(p)).collect();
        let at: Vec<Vec<usize>> = pieces.iter().map(|t| program_positions(t)).collect();
        let fed = pieces
            .iter()
            .zip(&at)
            .any(|(t, ps)| ps.iter().any(|&p| runs_text(basename(t[p]))));
        let live = if fed { text.as_str() } else { head.as_str() };
        let toks = tokens(live);
        let named = if fed {
            names_channel(&toks, &(0..toks.len()).collect::<Vec<_>>())
        } else {
            (pieces.iter().zip(&at)).any(|(t, ps)| names_channel(t, &runnable_positions(t, ps)))
        };
        // F1.2: a whole word, not a word inside a path (`/tmp/claude-1000/x` is no match).
        if named
            || toks.iter().any(|t| *t == "sessions_send" || is_identity(t))
            || names_chat_api(live)
        {
            acc.raise(CallClass::Denied(DenyReason::Unparsed));
        }
        for t in toks {
            self.word_paths(t, cwd, false, acc);
        }
        // A path at a program's place that does not exist is DENIED, as in a command the guard
        // can read, unless an earlier piece builds.
        let mut built = false;
        for (piece, t) in raw.iter().zip(&pieces) {
            if !built
                && let Some(w) = program_word(piece).filter(|w| w.contains('/'))
                && !self.fs.exists(&self.physical(w, cwd))
            {
                acc.raise(CallClass::Denied(DenyReason::Unparsed));
            }
            built |= builds(t);
        }
        self.when_held(acc, CallClass::Protected(ProtectedKind::Unparsed));
    }

    fn shell_text(&self, text: &str, cwd: &Path, depth: usize, acc: &mut Acc) {
        if depth > MAX_NESTING {
            self.unparsed(text, cwd, acc);
            return;
        }
        let parsed = shell::parse(text, &self.home());
        // I1.2: text the command hands to a shell is code the command runs, where any mention
        // of an identity variable counts as a change; text it cannot parse shows `unparsed`
        // (F1.2).
        if depth > 0 && mentions_identity(text) {
            acc.raise(CallClass::Denied(if parsed == Parsed::Unparsed {
                DenyReason::Unparsed
            } else {
                DenyReason::Fence
            }));
        }
        match parsed {
            Parsed::Unparsed => self.unparsed(text, cwd, acc),
            Parsed::Commands(cmds) => {
                let mut here = cwd.to_path_buf();
                let mut built = false;
                for c in &cmds {
                    self.command(&c.words, text, &mut here, depth, &mut built, acc);
                }
            }
        }
    }

    /// `built`: an earlier command of the same text is a build or an install ([`builds`]); this
    /// command adds itself to it.
    fn command(
        &self,
        words: &[Word],
        full: &str,
        here: &mut PathBuf,
        depth: usize,
        built: &mut bool,
        acc: &mut Acc,
    ) {
        let texts: Vec<&str> = words.iter().map(|w| w.text.as_str()).collect();
        let positions = program_positions(&texts);
        let runnable = runnable_positions(&texts, &positions);
        for &p in &runnable {
            Self::program_rules(words, &texts, p, positions.contains(&p), acc);
            // A word an unknown wrapper is given may be a setting it applies or a URL it calls.
            if !positions.contains(&p) && (is_identity(texts[p]) || names_chat_api(texts[p])) {
                acc.raise(CallClass::Denied(DenyReason::Fence));
            }
            // A word an unknown wrapper may run is judged as code, its value too when it is
            // attached to a one-letter option (`-x 'codex queue …'`).
            if !positions.contains(&p) {
                let attached = texts[p]
                    .strip_prefix('-')
                    .filter(|r| !r.starts_with('-'))
                    .and_then(|r| r.get(1..));
                if let Some(r) = code_rules(texts[p]).or_else(|| attached.and_then(code_rules)) {
                    acc.raise(CallClass::Denied(r));
                }
            }
        }
        // Settings before the program: `CODEX_THREAD_ID=x cmd`, `GIT_SSH_COMMAND=... git`.
        let first = positions.first().copied().unwrap_or(texts.len());
        for a in &texts[..first] {
            if is_identity(a) {
                acc.raise(CallClass::Denied(DenyReason::Fence));
            }
            if let Some(r) = a.split_once('=').and_then(|(_, v)| code_rules(v)) {
                acc.raise(CallClass::Denied(r));
            }
        }
        for &i in &runnable {
            self.nested_at(words, i, full, here, depth, acc);
        }
        for &p in &runnable {
            // A link to a channel's program under another name.
            let stem = self
                .resolve(texts[p], here)
                .and_then(|r| r.file_stem().map(|s| s.to_string_lossy().into_owned()));
            if stem
                .as_deref()
                .is_some_and(|s| FENCE_PROGRAMS.contains(&s) && fence_args(s, &texts[p + 1..]))
            {
                acc.raise(CallClass::Denied(DenyReason::Fence));
            }
            acc.new_session |= stem.as_deref().is_some_and(|s| {
                FENCE_PROGRAMS.contains(&s)
                    && starts_session(s, &texts[p + 1..], positions.contains(&p))
            });
            self.lunchroom_at(&texts, p, here, acc);
            self.recursive_write_at(&texts, p, here, acc);
            self.shebang_at(&texts, p, here, depth, acc);
        }
        // F1.2: a program run by a path that does not exist can run only if this call makes it.
        // Judged at the command's own program and the programs wrappers the guard knows run
        // (`positions`); a path an unknown program is given (`docker run -v ./data:/d`,
        // `mywrap ./x`) is not known to run, and making every such argument exist would refuse
        // ordinary commands. A build or an install earlier in the text may make it
        // (`cargo build && ./target/release/app`); a redirection or any other command may not
        // (`echo x > s.sh && ./s.sh`).
        for &p in &positions {
            if !*built && texts[p].contains('/') && !self.fs.exists(&self.physical(texts[p], here))
            {
                acc.raise(CallClass::Denied(DenyReason::Unparsed));
            }
        }
        *built |= builds(&texts);
        // P1.4: a script a shell or interpreter runs is run, not named
        // (`python3 ~/.lunchroom/bin/lunchroom status`).
        let scripts = script_positions(&texts, &runnable);
        // A1.3: Lunchroom's program run by a shell or interpreter (`python3 …/lunchroom approve`)
        // is judged as if run directly.
        for &k in &scripts {
            self.lunchroom_at(&texts, k, here, acc);
        }
        let text = text_positions(words, &texts, &positions);
        for (k, w) in words.iter().enumerate().filter(|(k, _)| !text.contains(k)) {
            let runs_it = positions.contains(&k) || scripts.contains(&k);
            self.word_paths(&w.text, here, runs_it, acc);
        }
        if self.held {
            self.held_rules(words, &texts, &positions, &runnable, here, acc);
        }
        // `cd` changes where the commands after it run.
        if let Some(&p) = positions.first() {
            match (
                texts[p],
                texts
                    .get(p + 1..)
                    .and_then(|r| r.iter().find(|a| !a.starts_with('-'))),
            ) {
                ("cd" | "pushd", None) => here.clone_from(&self.layout.home),
                ("cd" | "pushd", Some(d)) => *here = normalize(d, here, &self.layout.home),
                ("popd", _) => self.when_held(acc, CallClass::Protected(ProtectedKind::Unparsed)),
                _ => {}
            }
            if texts[p] == "cd" && texts.get(p + 1) == Some(&"-") {
                self.when_held(acc, CallClass::Protected(ProtectedKind::Unparsed));
            }
        }
    }

    /// F1.1, I1.2: the program at position `p` puts a turn into another session, changes an
    /// identity variable, calls a local session chat API, or is given a command as an option value
    /// ([`COMMAND_OPTIONS`]: `git -c core.pager=...`, `ssh -o ProxyCommand=...`).
    fn program_rules(words: &[Word], texts: &[&str], p: usize, known: bool, acc: &mut Acc) {
        let args = &texts[p + 1..];
        let name = basename(texts[p]);
        let deny = |acc: &mut Acc, r| acc.raise(CallClass::Denied(r));
        if prog_names(&words[p]).iter().any(|n| fence_args(n, args)) {
            deny(acc, DenyReason::Fence);
        }
        // P1.4: judged for every agent and kept only for a HELD one at the end of the call. A bare
        // prompt counts only where the word is sure to be the program: an argument of another
        // program (`grep claude notes`, `tool send codex hi`) starts nothing.
        acc.new_session |= prog_names(&words[p])
            .iter()
            .any(|n| starts_session(n, args, known));
        // Builtins that set a variable named in an argument, a nameref's target
        // (`declare -n r=CODEX_THREAD_ID`) included.
        let sets = matches!(
            name,
            "export"
                | "declare"
                | "typeset"
                | "readonly"
                | "local"
                | "unset"
                | "read"
                | "printf"
                | "mapfile"
                | "readarray"
                | "getopts"
                | "let"
        );
        if sets && args.iter().any(|a| changes_identity(a)) {
            deny(acc, DenyReason::Fence);
        }
        if name == "env" {
            let end = wrapper_inner(texts, p)
                .unwrap_or(texts.len())
                .min(texts.len());
            let clears = |a: &&str| {
                matches!(*a, "-" | "--ignore-environment")
                    || a.strip_prefix('-')
                        .is_some_and(|r| !r.starts_with('-') && r.contains('i'))
            };
            if texts[p + 1..end].iter().any(|a| {
                // `--unset=NAME` and `-uNAME` name the variable in the same word.
                let unset = a
                    .strip_prefix("--unset=")
                    .or_else(|| a.strip_prefix("-u").filter(|r| !r.is_empty()));
                is_identity(a) || unset.is_some_and(is_identity) || clears(a)
            }) {
                deny(acc, DenyReason::Fence);
            }
        }
        if NETWORK_PROGRAMS.contains(&name) && args.iter().any(|a| names_chat_api(a)) {
            deny(acc, DenyReason::Fence);
        }
        let runs = COMMAND_OPTIONS
            .iter()
            .find(|(p, _)| *p == name)
            .map_or(&[][..], |(_, o)| *o);
        for (k, a) in args.iter().enumerate() {
            let after_flag = k > 0 && runs.contains(&args[k - 1]);
            // A one-letter option with its value attached (`tar -Iprog`).
            let attached = runs
                .iter()
                .find(|o| o.len() == 2 && a.len() > 2 && a.starts_with(*o) && !a.starts_with("--"))
                .map(|_| &a[2..]);
            let value = if attached.is_some() {
                attached
            } else if a.starts_with('-') {
                a.split_once('=')
                    .filter(|(o, _)| runs.contains(o))
                    .map(|(_, v)| v)
            } else if after_flag || (name == "less" && a.starts_with('+')) {
                Some(a.split_once('=').map_or(*a, |(_, v)| v))
            } else {
                None
            };
            // An attached value may be a setting (`-oProxyCommand=…`): its text after `=` too.
            let setting = value.and_then(|v| v.split_once('=')).map(|(_, v)| v);
            if let Some(r) = value
                .and_then(code_rules)
                .or_else(|| setting.and_then(code_rules))
            {
                deny(acc, r);
            }
        }
        if name == "git"
            && let Some(i) = args
                .windows(2)
                .position(|w| matches!(w, ["bisect", "run"] | ["submodule", "foreach"]))
            && let Some(r) = code_rules(&args[i + 2..].join(" "))
        {
            deny(acc, r);
        }
    }

    /// P1.4's kinds, and L1.1's searches, judged at the positions that may run a program.
    fn held_rules(
        &self,
        words: &[Word],
        texts: &[&str],
        positions: &[usize],
        runnable: &[usize],
        here: &Path,
        acc: &mut Acc,
    ) {
        for &i in runnable {
            let args = &texts[i + 1..];
            for n in prog_names(&words[i]) {
                if let Some(kind) = protected_kind(n, args) {
                    acc.raise(CallClass::Protected(kind));
                }
            }
            self.recursive_read_at(texts, i, here, acc);
        }
        // The shell opens a connection for a word naming one of these, a redirection's target too.
        if texts
            .iter()
            .any(|t| t.contains("/dev/tcp/") || t.contains("/dev/udp/"))
        {
            acc.raise(CallClass::Protected(ProtectedKind::Network));
        }
        // `env` with no program after it prints the environment.
        if positions
            .last()
            .is_some_and(|&p| basename(texts[p]) == "env" && wrapper_inner(texts, p).is_some())
        {
            acc.raise(CallClass::Protected(ProtectedKind::Credential));
        }
    }

    /// `sh -c`, `eval`, `env -S`, `su -c`, `watch`, `ssh`, scripts, a shell reading its commands
    /// from a pipe, and code given to an interpreter.
    fn nested_at(
        &self,
        words: &[Word],
        i: usize,
        full: &str,
        here: &Path,
        depth: usize,
        acc: &mut Acc,
    ) {
        let texts: Vec<&str> = words.iter().map(|w| w.text.as_str()).collect();
        let rest = &texts[i + 1..];
        for name in prog_names(&words[i]) {
            match name {
                n if SHELLS.contains(&n) => {
                    let runs = program_positions(&texts).contains(&i);
                    self.shell_at(rest, runs, full, here, depth, acc);
                }
                // Shell builtins: they run only as the command itself, never as another program's
                // argument (`find . -name x` names a folder).
                "source" | "." if program_positions(&texts).contains(&i) => {
                    if let Some(f) = rest.first() {
                        self.script_file(f, here, depth, acc);
                    }
                }
                "eval" | "ssh" => self.shell_text(&rest.join(" "), here, depth + 1, acc),
                "su" | "runuser" | "flock" | "script" => {
                    if let Some(s) = option_value(rest, &["--command", "-c"]) {
                        self.shell_text(s, here, depth + 1, acc);
                    }
                }
                "env" => {
                    if let Some(s) = option_value(rest, &["--split-string", "-S"]) {
                        self.shell_text(s, here, depth + 1, acc);
                    }
                }
                "watch" => {
                    let from = rest
                        .iter()
                        .position(|a| !a.starts_with('-'))
                        .unwrap_or(rest.len());
                    let skip =
                        usize::from(from > 0 && matches!(rest[from - 1], "-n" | "--interval"));
                    let cmd = rest.get(from + skip..).unwrap_or_default();
                    self.shell_text(&cmd.join(" "), here, depth + 1, acc);
                }
                n if INTERPRETERS.contains(&n) || n.starts_with("python") => {
                    // The script word is itself a runnable position, so `command` also judges it
                    // with `lunchroom_at` (`python3 …/lunchroom approve` is DENIED, A1.3).
                    if matches!(n, "awk" | "gawk" | "mawk" | "sed") {
                        // `sed` and `awk` read their files as data, which runs only when their
                        // program runs it (K1.8): then those files are searched like a script.
                        let data = !self.script_runs_data(n, rest, here);
                        for (k, a) in rest.iter().enumerate() {
                            self.code_text(a, acc);
                            let file = if data {
                                script_option_file(n, rest, k)
                            } else {
                                Some(*a)
                            };
                            if let Some(f) = file
                                && let Script::Text(t) = self.fs.script(&self.physical(f, here))
                            {
                                self.code_text(&t, acc);
                            }
                        }
                    } else {
                        // Any other interpreter runs inline code (`-c`, `-e`) and its script,
                        // which come first; the words after the script are its arguments, and
                        // the files among them are data (K1.8).
                        let end = interpreter_script(n, rest)
                            .and_then(|s| rest.iter().position(|a| *a == s))
                            .map_or(rest.len(), |k| k + 1);
                        for a in &rest[..end] {
                            self.code_text(a, acc);
                        }
                    }
                    // The script it runs, also when attached to its option (`awk -fprog.awk`).
                    // F1.2: one larger than the guard searches is DENIED. A data file is not a
                    // script; a name that is not a file is left to the interpreter, which
                    // resolves names its own way (`node app` loads `app.js`).
                    if let Some(s) = interpreter_script(n, rest) {
                        match self.fs.script(&self.physical(s, here)) {
                            Script::Text(t) => self.code_text(&t, acc),
                            Script::TooLarge => {
                                acc.raise(CallClass::Denied(DenyReason::Unparsed));
                            }
                            Script::Unreadable => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// `runs`: the shell is the program the command runs (not an argument of another program).
    fn shell_at(
        &self,
        rest: &[&str],
        runs: bool,
        full: &str,
        here: &Path,
        depth: usize,
        acc: &mut Acc,
    ) {
        match shell_input(rest) {
            ShellInput::Text(k) => {
                if let Some(s) = k.and_then(|k| rest.get(k)) {
                    self.shell_text(s, here, depth + 1, acc);
                }
            }
            ShellInput::Script(k) => self.script_file(rest[k], here, depth, acc),
            // No -c and no script: the shell reads its commands from its input, which the guard
            // cannot see.
            ShellInput::Stdin => {
                if runs {
                    self.unparsed(full, here, acc);
                }
            }
        }
    }

    /// Whether the `sed` or `awk` program in `args` can run the text it reads ([`sed_runs_text`],
    /// [`awk_runs_text`]): the `-e` texts, else the `-f` file (one the guard cannot read counts as
    /// running), else the first operand, which is not the value of `-F` or `-v`.
    fn script_runs_data(&self, name: &str, args: &[&str], here: &Path) -> bool {
        let exprs: Vec<&str> = (0..args.len())
            .filter_map(|k| {
                let prev = k.checked_sub(1).map(|j| args[j]);
                prev.filter(|p| matches!(*p, "-e" | "--expression" | "--source"))
                    .map(|_| args[k])
                    .or_else(|| args[k].strip_prefix("--expression="))
                    .or_else(|| args[k].strip_prefix("-e").filter(|r| !r.is_empty()))
            })
            .collect();
        let program = if !exprs.is_empty() {
            exprs.join("\n")
        } else if let Some(f) = interpreter_script(name, args) {
            match self.fs.script(&self.physical(f, here)) {
                Script::Text(t) => t,
                Script::TooLarge | Script::Unreadable => return true,
            }
        } else {
            let value = |k: usize| k > 0 && matches!(args[k - 1], "-F" | "-v");
            let operand = args
                .iter()
                .enumerate()
                .find(|&(k, a)| !a.starts_with('-') && !value(k));
            operand.map_or_else(String::new, |(_, a)| (*a).to_owned())
        };
        if name == "sed" {
            sed_runs_text(&program)
        } else {
            awk_runs_text(&program)
        }
    }

    /// A shell script the command runs: checked for the rules that hold in every session. What
    /// else it does is not judged (K1.8).
    /// F1.2: one the guard cannot find, read or search in full is DENIED (`unparsed`), wherever
    /// the shell may run, as channels are judged (`mywrap bash x.sh`). A bare name not in the
    /// working folder is looked up through `PATH`, as the shell does.
    fn script_file(&self, f: &str, here: &Path, depth: usize, acc: &mut Acc) {
        let mut script = self.fs.script(&self.physical(f, here));
        if script == Script::Unreadable
            && !f.contains('/')
            && let Some(p) = self.fs.which(f)
        {
            script = self.fs.script(&p);
        }
        match script {
            Script::Text(t) => self.shell_script(&t, here, depth, acc),
            Script::TooLarge | Script::Unreadable => {
                acc.raise(CallClass::Denied(DenyReason::Unparsed));
            }
        }
    }

    /// A shell script's text: one the reader can read is classified as an agent that is not HELD
    /// would be, keeping only a DENIED result; one it cannot is judged as code ([`code_rules`]).
    fn shell_script(&self, text: &str, here: &Path, depth: usize, acc: &mut Acc) {
        // I1.2: any mention of an identity variable in a script counts, parsed or not.
        if mentions_identity(text) {
            acc.raise(CallClass::Denied(DenyReason::Fence));
        }
        if shell::parse(text, &self.home()) == Parsed::Unparsed {
            self.code_text(text, acc);
            return;
        }
        let g = Guard {
            held: false,
            ..*self
        };
        let mut sub = Acc::new(CallClass::Ordinary);
        g.shell_text(text, here, depth + 1, &mut sub);
        if sub.denied() {
            acc.raise(sub.class);
        }
        acc.new_session |= sub.new_session;
    }

    /// Script or code text that is not a shell command (K1.8).
    /// Every rule of [`code_rules`], identity changes included.
    fn code_text(&self, text: &str, acc: &mut Acc) {
        let home = self.home();
        let text = text.replace("${HOME}", &home).replace("$HOME", &home);
        if let Some(r) = code_rules(&text) {
            acc.raise(CallClass::Denied(r));
        }
        acc.new_session |= code_starts_session(&text);
    }

    /// The real path of the program a word runs: by its path, or found through `PATH`.
    fn resolve(&self, w: &str, here: &Path) -> Option<PathBuf> {
        if w.contains('/') {
            Some(self.physical(w, here))
        } else {
            self.fs.which(w)
        }
    }

    /// A program run by path or found through `PATH` that is a script (a `#!` line).
    fn shebang_at(&self, texts: &[&str], p: usize, here: &Path, depth: usize, acc: &mut Acc) {
        let Some(path) = self
            .resolve(texts[p], here)
            .filter(|p| self.fs.runs_as_script(p))
        else {
            return;
        };
        let t = match self.fs.script(&path) {
            Script::Text(t) => t,
            // F1.2: a script it cannot read or search in full.
            Script::TooLarge | Script::Unreadable => {
                acc.raise(CallClass::Denied(DenyReason::Unparsed));
                return;
            }
        };
        // No `#!` line: the shell that started it runs it as a script of its own.
        if !t.starts_with("#!") {
            self.shell_script(&t, here, depth, acc);
            return;
        }
        {
            let first = t.lines().next().unwrap_or_default();
            let mut interp = first.trim_start_matches("#!").split_whitespace();
            let mut name = interp.next().map(basename);
            if name == Some("env") {
                name = interp.find(|a| !a.starts_with('-') && !is_assignment(a));
            }
            if name.is_some_and(|n| SHELLS.contains(&n)) {
                self.shell_script(&t, here, depth, acc);
            } else {
                self.code_text(&t, acc);
            }
        }
    }

    /// Whether the word names Lunchroom's program, by its name or its real path.
    fn is_lunchroom(&self, w: &str, here: &Path) -> bool {
        LUNCHROOM_NAMES.contains(&basename(w))
            || self
                .resolve(w, here)
                .is_some_and(|r| self.layout.facts(&r).program)
    }

    /// §6 item 1: the text is exactly one `lunchroom send`, with nothing before the program and
    /// no other command, separator or redirection. The program is found by its real path only, and
    /// must be Lunchroom's program itself: a program merely named `lunchroom`, or another program
    /// in Lunchroom's program folder, is not.
    fn is_reply(&self, text: &str, cwd: &Path) -> bool {
        let installed = self
            .fs
            .real(&self.layout.program_dir.join(LUNCHROOM_NAMES[0]));
        let real_program = |w: &str| {
            self.resolve(w, cwd)
                .is_some_and(|r| r == installed || self.layout.programs.contains(&r))
        };
        shell::single(text, &self.home()).is_some_and(|c| {
            matches!(c.words.as_slice(), [p, s, ..]
                if s.text == "send" && !p.glob && !s.glob && real_program(&p.text))
        })
    }

    /// A1.3: an agent runs only Lunchroom's open commands.
    fn lunchroom_at(&self, texts: &[&str], p: usize, here: &Path, acc: &mut Acc) {
        if self.is_lunchroom(texts[p], here) && !lunchroom_args_open(&texts[p + 1..]) {
            acc.raise(CallClass::Denied(DenyReason::Configuration));
        }
    }

    /// P1.4: a program that changes everything below a folder, given a folder holding Lunchroom's
    /// stores, writes them.
    fn recursive_write_at(&self, texts: &[&str], p: usize, here: &Path, acc: &mut Acc) {
        let name = basename(texts[p]);
        let args = &texts[p + 1..];
        let finds = name == "find" && args.iter().any(|a| FIND_ACTIONS.contains(a));
        if !RECURSIVE_WRITE.contains(&name) && !finds {
            return;
        }
        let mut operands: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        if finds && operands.is_empty() {
            operands.push(".");
        }
        for a in operands {
            let forms = self.forms(a, here);
            if forms
                .paths
                .iter()
                .any(|f| self.layout.lunchroom_home.starts_with(f))
                || forms
                    .capped
                    .is_some_and(|c| self.layout.lunchroom_home.starts_with(c))
            {
                acc.raise(CallClass::Denied(DenyReason::Configuration));
            }
        }
    }

    /// L1.1: a program that reads everything below the folders it is given, or below the working
    /// folder for a search given none.
    fn recursive_read_at(&self, texts: &[&str], i: usize, here: &Path, acc: &mut Acc) {
        let name = basename(texts[i]);
        let args = &texts[i + 1..];
        let recurse_flag = args.iter().any(|a| {
            *a == "--recursive"
                || a.strip_prefix('-').is_some_and(|r| {
                    !r.starts_with('-') && r.contains(if name == "ls" { 'R' } else { 'r' })
                })
                || (name != "ls"
                    && a.strip_prefix('-')
                        .is_some_and(|r| !r.starts_with('-') && r.contains('R')))
        });
        let searcher =
            SEARCHERS.contains(&name) || (RECURSE_ON_FLAG.contains(&name) && recurse_flag);
        if !searcher && !COPIERS.contains(&name) {
            return;
        }
        let greps = GREPS.contains(&name);
        let operands: Vec<&str> = if greps {
            grep_path_operands(args)
        } else {
            args.iter()
                .copied()
                .filter(|a| !a.starts_with('-'))
                .collect()
        };
        let mut roots: Vec<PathBuf> = Vec::new();
        for a in &operands {
            let forms = self.forms(a, here);
            roots.extend(forms.paths.into_iter().filter(|f| self.fs.is_dir(f)));
        }
        // `grep -r`, `du` and `ls -R` given only files read only those files; a word the shell
        // expands into the working folder (`*`, `$X`) may name its folders, so it still counts as
        // given none. Other searchers take patterns and expressions among their words, so for
        // them only a folder operand counts.
        let given = if greps || matches!(name, "du" | "ls") {
            !operands.is_empty()
                && (!roots.is_empty()
                    || !operands
                        .iter()
                        .any(|a| a.contains(['*', '?', '[', '$', '`', '{'])))
        } else {
            !roots.is_empty()
        };
        if !given && searcher {
            roots.push(here.to_path_buf());
        }
        for r in roots {
            self.search_from(&r, acc);
        }
    }
}

#[cfg(test)]
mod tests;
