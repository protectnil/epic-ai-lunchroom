//! The `lunchroom` commands an agent may run: `send` and `status`.
//!
//! Spec: §9 I1.2 (the sender is the hook-observed session the command runs in), §10 D1.1 (a message
//! is QUEUED when accepted), and the rules that stop a message (§2 R1, §11 L1, §9 I1.4, I1.5).

/// This build: `lunchroom <version> (<commit>)`, with `, modified` when built from uncommitted
/// sources, and the version alone when built with no git history (`build.rs`).
pub const VERSION: &str = env!("LUNCHROOM_VERSION");

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;

use lunchroom_core::identity::{Harness, Identity};
use lunchroom_core::mail::{MAX_MESSAGE_BYTES, Mail, SendRefusal};
use lunchroom_core::store::Store;
use lunchroom_core::vocab::{AgentState, MessageState, Reason, Verdict, Word};
use lunchroom_core::{cards, secrets};

use crate::evidence::evidence;
use crate::home::Env;
use crate::process;

/// What a command prints, where, and its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}

/// What the user is told when Lunchroom's store cannot be read.
pub(crate) fn unread(e: impl std::fmt::Display) -> String {
    format!("Lunchroom's store cannot be read: {e}")
}

/// What the user is told when Lunchroom's store cannot be updated.
pub(crate) fn unwritten(e: impl std::fmt::Display) -> String {
    format!("Lunchroom's store cannot be updated: {e}")
}

impl Outcome {
    pub(crate) const fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            code: 0,
        }
    }

    /// An error that is no verdict: a usage mistake, or a file or store that cannot be used.
    pub(crate) fn failed(text: &str, code: u8) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{text}\n"),
            code,
        }
    }

    pub(crate) fn denied(reason: &str, code: u8) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{} · {reason}\n", Verdict::Denied.word()),
            code,
        }
    }
}

/// Lunchroom's store; one that cannot be used DENIES what needs it, with the reason (H1.5).
fn store(env: &Env) -> Result<Store<Mail>, Outcome> {
    Store::open(&env.store_dir())
        .map_err(|e| Outcome::denied(&format!("Lunchroom's store cannot be opened: {e}"), 1))
}

/// Why the sender cannot be found.
enum NoSender {
    /// No harness process a hook has seen is above this command.
    Unseen,
    /// The environment names a session other than the one the hook saw (a forged id).
    Forged,
}

/// The session this command runs in, as a guard hook saw it (I1.2): the nearest process above this
/// one that a hook recorded, found through `/proc`, never from the environment. The environment's
/// session id, when set, must name that same session.
fn sender(mail: &Mail, env: &Env) -> Result<Identity, NoSender> {
    let (process, last) = process::ancestors(std::process::id())
        .into_iter()
        .skip(1)
        .find_map(|pid| {
            process::key(pid).and_then(|k| mail.process_session(&k).cloned().map(|who| (k, who)))
        })
        .ok_or(NoSender::Unseen)?;
    // I1.2: only the variable of the harness the command runs in names a session: Claude Code's
    // `CLAUDE_CODE_SESSION_ID`, Codex's `CODEX_THREAD_ID`, Hermes's `HERMES_SESSION_ID`, and
    // `LUNCHROOM_SESSION`, which Lunchroom's OpenClaw plugin supplies. Another harness's variable,
    // inherited when one harness is started from another's session, names nothing. In a process
    // that runs many sessions (an OpenClaw or Hermes gateway) the session is the one its variable
    // names, if a hook saw it in this very process; with none named, only a process that ran one
    // session gives one. In Claude Code and Codex the variable, when set, must name the session the
    // process shows.
    let own = match last.harness {
        Harness::OpenClaw => env.lunchroom_session.as_deref().map(Identity::parse),
        Harness::Hermes => env
            .hermes_session
            .as_deref()
            .map(|id| Some(Identity::new(Harness::Hermes, id))),
        Harness::ClaudeCode => env
            .claude_session
            .as_deref()
            .map(|id| Some(Identity::new(Harness::ClaudeCode, id))),
        Harness::Codex => env
            .codex_thread
            .as_deref()
            .map(|id| Some(Identity::new(Harness::Codex, id))),
    };
    let named = match own {
        Some(Some(who)) if who.harness == last.harness => Some(who),
        Some(_) => return Err(NoSender::Forged),
        None => None,
    };
    let me = match named {
        Some(who) if matches!(who.harness, Harness::ClaudeCode | Harness::Codex) => {
            if who != last {
                return Err(NoSender::Forged);
            }
            who
        }
        Some(who) if mail.seen_in_process(&process, &who) => who,
        Some(_) => return Err(NoSender::Forged),
        None if matches!(last.harness, Harness::OpenClaw | Harness::Hermes)
            && mail.sessions_in_process(&process) > 1 =>
        {
            return Err(NoSender::Unseen);
        }
        None => last,
    };
    Ok(me)
}

/// `lunchroom send <to> [--reply-to <id>] <text…>`; a text of `-` is read from standard input.
#[must_use]
#[allow(clippy::too_many_lines)] // one send: arguments, the text and its bounds, the store, the hand-over
pub fn send(args: &[String], env: &Env) -> Outcome {
    // `--reply-to <id>` may stand before or after the name; the text is everything after both
    // (R1.2: the id plays no part, and words of the text are never taken for it).
    let mut rest: Vec<&str> = Vec::new();
    let mut k = 0;
    while k < args.len() {
        if args[k] == "--reply-to" && rest.len() < 2 {
            k += 2;
            continue;
        }
        rest.push(&args[k]);
        k += 1;
    }
    let Some((to, words)) = rest.split_first().filter(|(_, w)| !w.is_empty()) else {
        return Outcome::failed("usage: lunchroom send <to> [--reply-to <id>] <text>", 2);
    };
    let mut text = words.join(" ");
    if text == "-" {
        match read_bounded(std::io::stdin()) {
            Ok(bytes) if bytes.len() > MAX_MESSAGE_BYTES => return too_long(),
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(read) => text = read,
                Err(_) => return Outcome::failed("the message text cannot be read", 2),
            },
            Err(_) => return Outcome::failed("the message text cannot be read", 2),
        }
    }
    if text.len() > MAX_MESSAGE_BYTES {
        return too_long();
    }
    if text.trim().is_empty() {
        return Outcome::denied("the message is empty", 2);
    }
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let result = store.update(|m| {
        let me = sender(m, env).map_err(Err)?;
        let from_name = m.name_of(&me).unwrap_or(&me.session).to_owned();
        m.send(&me, &from_name, to, &text, env.now).map_err(Ok)
    });
    match result {
        // H1.5: a send the store cannot take is DENIED with the reason.
        Err(e) => Outcome::denied(&unwritten(e), 1),
        Ok(Ok(accepted)) => {
            let mut out = format!("{} {}\n", MessageState::Queued.word(), accepted.id);
            if accepted.halted {
                out.push_str(&cards::loop_halted());
                out.push('\n');
            }
            // R3.2: a message to an UNGUARDED or STOPPED agent stays QUEUED, and the sender is told.
            if let Ok(mail) = store.read() {
                match mail.agent_state(&accepted.to, evidence(&mail, &accepted.to, &env.home)) {
                    AgentState::Unguarded => {
                        let _ = writeln!(out, "{}", cards::unguarded(to));
                    }
                    AgentState::Stopped => {
                        let _ = writeln!(out, "{}", cards::stopped(to));
                    }
                    _ => {}
                }
            }
            // D1.1 (Codex, OpenClaw): the message is handed to the session now, through
            // `codex queue` or `openclaw agent`. A Hermes session takes it at its next turn.
            let handed = match accepted.to.harness {
                Harness::Codex => Some(crate::codex::deliver(
                    env,
                    &store,
                    &accepted.to,
                    Some(&accepted.from),
                )),
                Harness::OpenClaw => Some(crate::openclaw::deliver(
                    env,
                    &store,
                    &accepted.to,
                    Some(&accepted.from),
                )),
                Harness::ClaudeCode | Harness::Hermes => None,
            };
            if let Some(handed) = handed {
                match handed {
                    Ok(crate::codex::Delivered::Confirmed(id)) => {
                        let _ = writeln!(out, "{} {id}", MessageState::Delivered.word());
                    }
                    // D1.4: the third failed attempt makes the message FAILED.
                    Ok(crate::codex::Delivered::Failed(id, reason, failed)) => {
                        let state = if failed {
                            MessageState::Failed
                        } else {
                            MessageState::Queued
                        };
                        let _ = writeln!(out, "{id}: {reason}; {}", state.word());
                    }
                    // D1.3: handed over, not yet seen in the session.
                    Ok(crate::codex::Delivered::Unconfirmed(id)) => {
                        let _ = writeln!(
                            out,
                            "{id}: Not confirmed; still {}",
                            MessageState::Queued.word()
                        );
                    }
                    Ok(crate::codex::Delivered::Nothing) | Err(_) => {}
                }
            }
            Outcome::ok(out)
        }
        Ok(Err(Ok(SendRefusal::UnknownName))) => unknown_name(&store, to),
        Ok(Err(Ok(refusal))) => refused(&refusal, to, &text),
        Ok(Err(Err(NoSender::Unseen))) => refused(&SendRefusal::UnseenSender, to, &text),
        Ok(Err(Err(NoSender::Forged))) => Outcome::denied(
            "the session id in this command's environment is not the session it runs in",
            3,
        ),
    }
}

/// No agent is named `to`: the refusal names the closest registered name, or all of them.
fn unknown_name(store: &Store<Mail>, to: &str) -> Outcome {
    let names: Vec<String> = store
        .read()
        .map(|m| m.names().map(|(n, _)| n.to_owned()).collect())
        .unwrap_or_default();
    let hint = match closest(to, &names) {
        Some(n) => format!("; did you mean {n}?"),
        None if names.is_empty() => "; no agent has a name yet".to_owned(),
        None => format!("; the names are: {}", names.join(", ")),
    };
    Outcome::denied(&format!("no agent is named {to}{hint}"), 3)
}

/// The registered name `to` stands for: the same name up to case and `_` for `-`,
/// or the only one within two edits.
fn closest(to: &str, names: &[String]) -> Option<String> {
    let norm = |s: &str| s.to_ascii_lowercase().replace('_', "-");
    if let Some(n) = names.iter().find(|n| norm(n) == norm(to)) {
        return Some(n.clone());
    }
    let near: Vec<&String> = names
        .iter()
        .filter(|n| edits(&norm(n), &norm(to)) <= 2)
        .collect();
    (near.len() == 1).then(|| near[0].clone())
}

/// The Levenshtein distance between `a` and `b`.
fn edits(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let here = row[j + 1];
            row[j + 1] = (here + 1)
                .min(row[j] + 1)
                .min(prev + usize::from(ca != *cb));
            prev = here;
        }
    }
    row[b.len()]
}

/// Reads at most [`MAX_MESSAGE_BYTES`] + 1 bytes of `from`: one more than the limit is enough to
/// show the text is over it, and the rest of the stream is never read.
fn read_bounded(from: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    from.take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn too_long() -> Outcome {
    Outcome::denied(
        &format!("the message is longer than {MAX_MESSAGE_BYTES} bytes"),
        2,
    )
}

fn refused(refusal: &SendRefusal, to: &str, text: &str) -> Outcome {
    match refusal {
        SendRefusal::TooLong => too_long(),
        SendRefusal::TooManyLines => Outcome::denied(
            "the message has too many lines: with each line labelled it would not fit one command argument",
            2,
        ),
        // Card 2: a message asking for a secret (L1.4): "Denied. Asked for a secret."
        SendRefusal::Denied(Reason::Leak) if secrets::asks_for_secret(text) => Outcome {
            stdout: String::new(),
            stderr: format!("{}\n", cards::asked_for_secret()),
            code: 7,
        },
        SendRefusal::UnseenSender => {
            Outcome::denied("this session has not been seen by a guard hook", 3)
        }
        SendRefusal::UnknownName => Outcome::denied(&format!("no agent is named {to}"), 3),
        SendRefusal::NotNamed => Outcome::denied(
            &format!(
                "{} has not named {to} to receive messages",
                Word::TheUser.text()
            ),
            3,
        ),
        SendRefusal::NotHolder => Outcome::denied(
            &format!(
                "a {} session may reply only to the agents whose messages hold it",
                AgentState::Held.word()
            ),
            7,
        ),
        SendRefusal::NameOnlyHolder => Outcome::denied(
            "the message holding this session names no agent to reply to",
            7,
        ),
        SendRefusal::Denied(Reason::Halted) => Outcome {
            stdout: String::new(),
            stderr: format!("{}\n", cards::conversation_halted()),
            code: 4,
        },
        // V1.2: a reason and, from the same table, what to do next.
        SendRefusal::Denied(reason) => Outcome::denied(
            &format!("{}: {}", reason.word(), reason.next_step()),
            if *reason == Reason::RateLimit { 5 } else { 7 },
        ),
    }
}

/// One agent's lines in `lunchroom status`.
fn agent_lines(
    lines: &mut String,
    mail: &Mail,
    name: &str,
    who: &Identity,
    state: AgentState,
    now: u64,
) {
    // R2.6: the harness's own YOLO as its guard last saw it, and a `lunchroom yolo`'s end time.
    let mut yolo = String::new();
    if let Some(end) = mail.yolo_until(who, now) {
        let day = end % 86_400;
        let _ = write!(
            yolo,
            "\t{} until {:02}:{:02} UTC",
            Word::Yolo.text(),
            day / 3600,
            day % 3600 / 60
        );
    }
    if mail.harness_yolo(who) {
        let _ = write!(yolo, "\t{} (the harness's own)", Word::Yolo.text());
    }
    // `deliveries` is the session's QUEUED messages, oldest first.
    let queued = mail.deliveries(who);
    let _ = writeln!(
        lines,
        "{name}\t{who}\t{}\t{} {}{yolo}",
        state.word(),
        MessageState::Queued.word(),
        queued.len()
    );
    // C1.1: what holds it. A hold by a message Lunchroom sent is listed with its sender and
    // message id; holds that no message caused (a tool's output, a transcript) are counted by
    // their source.
    let mut sources: BTreeMap<&str, usize> = BTreeMap::new();
    for h in mail.holding(who) {
        if mail.message(&h.message).is_some() {
            let _ = writeln!(
                lines,
                "  {} by {}\t{}",
                Word::Held.text(),
                h.from_name,
                h.message
            );
        } else {
            *sources.entry(&h.from_name).or_default() += 1;
        }
    }
    for (source, n) in sources {
        let _ = writeln!(
            lines,
            "  {} by {} ({n})",
            Word::Held.text(),
            source.replace('-', " ")
        );
    }
    // C1.1: calls waiting for the user's approval (`lunchroom approve` lists them).
    let waiting = mail.requests().iter().filter(|r| &r.session == who).count();
    if waiting > 0 {
        let _ = writeln!(
            lines,
            "  calls waiting for {}: {waiting}",
            Word::TheUser.text()
        );
    }
    // D1.3: an attempt whose confirmation has not arrived is reported as such, never DELIVERED.
    for d in queued.iter().filter(|d| d.presented_at.is_some()) {
        if let Some(said) = mail.attempt_unknown(&d.id) {
            let _ = writeln!(lines, "  {}\t{said}", d.id);
        }
    }
}

/// `lunchroom status`: each named agent, whether it is HELD, and its QUEUED messages.
#[must_use]
pub fn status(env: &Env) -> Outcome {
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match store.read() {
        Ok(m) => m,
        Err(e) => return Outcome::failed(&unread(e), 1),
    };
    // C1.1: the agents, live ones before STOPPED ones; R3.3: each state from the vocabulary table,
    // never AVAILABLE or HELD without the evidence.
    let mut agents: Vec<_> = mail
        .names()
        .map(|(name, who)| {
            let state = mail.agent_state(who, evidence(&mail, who, &env.home));
            (name, who, state)
        })
        .collect();
    agents.sort_by_key(|(_, _, state)| *state == AgentState::Stopped);
    let mut lines = String::new();
    // C1.1: one line first, how many agents and how many in each state.
    {
        let counts: Vec<String> = [
            AgentState::Available,
            AgentState::Held,
            AgentState::Unguarded,
            AgentState::Stopped,
        ]
        .into_iter()
        .filter_map(|s| {
            let n = agents.iter().filter(|(_, _, state)| *state == s).count();
            (n > 0).then(|| format!("{n} {}", s.word()))
        })
        .collect();
        let _ = writeln!(
            lines,
            "{} agent{}{}{}",
            agents.len(),
            if agents.len() == 1 { "" } else { "s" },
            if counts.is_empty() { "" } else { ": " },
            counts.join(", ")
        );
    }
    // P1.6: the hold mode in force.
    let _ = writeln!(lines, "hold mode: {}", mail.hold_mode().word());
    // P1.1: the slip, as shipped; every agent has this one and nothing can be added to it.
    if !agents.is_empty() {
        let _ = writeln!(lines, "slip: {SLIP}");
    }
    for (name, who, state) in agents {
        agent_lines(&mut lines, &mail, name, who, state, env.now);
    }
    // C1.1: each HALTED pair and why.
    let name = |key: &str| {
        mail.names()
            .find(|(_, who)| who.key() == key)
            .map_or_else(|| key.to_owned(), |(n, _)| n.to_owned())
    };
    for (a, b, reason) in mail.halted_pairs() {
        let _ = writeln!(
            lines,
            "{}\t{} and {}\t{}",
            Word::Halted.text(),
            name(a),
            name(b),
            reason.word()
        );
    }
    Outcome::ok(lines)
}

/// `lunchroom codex-threads [-n COUNT]`: the most recent Codex threads, newest first, from the
/// names of Codex's session files and its session index (thread names only; no session's
/// contents are read), each with the name it is registered under, for `lunchroom register`.
#[must_use]
pub fn codex_threads(args: &[String], env: &Env) -> Outcome {
    let limit = match args.iter().position(|a| a == "-n") {
        Some(k) => match args.get(k + 1).and_then(|n| n.parse::<usize>().ok()) {
            Some(n) => n,
            None => return Outcome::failed("usage: lunchroom codex-threads [-n COUNT]", 2),
        },
        None => 6,
    };
    // Thread id -> (start stamp from the file name, last change, seconds since the epoch).
    let mut threads: std::collections::BTreeMap<String, (String, u64)> =
        std::collections::BTreeMap::new();
    let mut dirs = vec![(env.codex_home.join("sessions"), 0)];
    while let Some((dir, depth)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && depth < 4 {
                dirs.push((path, depth + 1));
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name
                .strip_prefix("rollout-")
                .and_then(|n| n.strip_suffix(".jsonl"))
            else {
                continue;
            };
            // `<YYYY-MM-DDTHH-MM-SS>-<thread id, 36 characters>[...]`, as the prototype reads it.
            let Some((started, id)) = stem
                .get(..19)
                .zip(stem.get(20..56))
                .filter(|(_, id)| id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
                .map(|(t, id)| (t.to_owned(), id.to_owned()))
            else {
                continue;
            };
            let changed = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let newer = threads.get(&id).is_none_or(|(_, at)| changed > *at);
            if newer {
                threads.insert(id, (started, changed));
            }
        }
    }
    // Thread names, from Codex's session index; a later line is a newer rename.
    let mut names = std::collections::BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(env.codex_home.join("session_index.jsonl")) {
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if let (Some(id), Some(name)) = (v["id"].as_str(), v["thread_name"].as_str()) {
                names.insert(id.to_owned(), name.to_owned());
            }
        }
    }
    let registered = store(env).ok().and_then(|s| s.read().ok());
    let mut rows: Vec<(&String, &(String, u64))> = threads.iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1.1));
    let mut out = String::new();
    for (id, (started, changed)) in rows.into_iter().take(limit) {
        let title = names.get(id).map_or_else(
            || "(no name)".to_owned(),
            |n| {
                format!(
                    "\"{}\"",
                    n.chars().filter(|c| !c.is_control()).collect::<String>()
                )
            },
        );
        let name = registered
            .as_ref()
            .and_then(|m| m.name_of(&Identity::new(Harness::Codex, id)))
            .unwrap_or_default()
            .to_owned();
        let _ = writeln!(
            out,
            "{id}  started {started}  last-write {}  {title}  {name}",
            crate::delivery::utc(*changed)
        );
    }
    Outcome::ok(out)
}

/// The permission slip every agent has (P1.1): it ships as every read but the paths L1.1 denies or
/// protects, and the reply, and the user can add nothing that changes a file or runs a command.
pub const SLIP: &str =
    "read any file except the paths Lunchroom denies or protects; reply with lunchroom send";

#[cfg(test)]
mod tests {
    use super::*;

    // An unknown name is answered with the name meant: the same up to case and `_` for `-`, or
    // the only one within two edits; with two that close, none is named.
    #[test]
    fn an_unknown_name_is_answered_with_the_closest_one() {
        let names = ["code-review", "glm", "kimi"].map(str::to_owned);
        assert_eq!(
            closest("code_review", &names).as_deref(),
            Some("code-review")
        );
        assert_eq!(
            closest("Code-Review", &names).as_deref(),
            Some("code-review")
        );
        assert_eq!(
            closest("code-reveiw", &names).as_deref(),
            Some("code-review")
        );
        assert_eq!(closest("kimmi", &names).as_deref(), Some("kimi"));
        assert_eq!(closest("someone", &names), None);
        let two = ["ab1", "ab2"].map(str::to_owned);
        assert_eq!(closest("ab", &two), None);
        assert_eq!(edits("kitten", "sitting"), 3);
    }

    // A stream is read to the limit and one byte more, no further: an endless one still ends.
    #[test]
    fn a_message_read_from_standard_input_stops_one_byte_past_the_limit() {
        let bytes = read_bounded(std::io::repeat(b'a')).unwrap_or_default();
        assert_eq!(bytes.len(), MAX_MESSAGE_BYTES + 1);
        let at = vec![b'a'; MAX_MESSAGE_BYTES];
        assert_eq!(
            read_bounded(at.as_slice()).map(|b| b.len()).ok(),
            Some(MAX_MESSAGE_BYTES)
        );
    }

    // The refusal is a DENIED outcome that names the limit.
    #[test]
    fn the_over_limit_refusal_names_the_limit() {
        let out = too_long();
        assert!(
            out.stderr.starts_with(Verdict::Denied.word()),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains("65536 bytes"), "{}", out.stderr);
        assert_eq!(out.code, 2);
    }
}
