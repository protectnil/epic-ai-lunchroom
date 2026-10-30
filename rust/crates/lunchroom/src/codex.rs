//! Delivery into a Codex session (spec §10 D1, §13 H1.1 item 4): `codex queue --thread <id>
//! --message <envelope>`. Codex shows a queued message as the user's input, so Lunchroom holds the
//! session by the message before it is queued (failing safe, I1.4 still lets it reply to the
//! sender), and the message is DELIVERED when the guard's `UserPromptSubmit` hook sees its envelope
//! (D1.1) or its id appears in the thread's rollout file.
//!
//! Host facts: `docs/host-facts/codex.md`.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lunchroom_core::identity::Identity;
use lunchroom_core::mail::{AttemptOutcome, Evidence, MAX_ARG_BYTES, Mail, Message};
use lunchroom_core::store::Store;

use crate::delivery::envelope;
use crate::evidence::evidence;
use crate::home::Env;

/// How long `codex queue` may take before the attempt counts as failed.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long Lunchroom looks for the message in the thread's rollout file after queueing it.
const CONFIRM_WAIT: Duration = Duration::from_secs(10);

/// What one delivery attempt to a Codex session did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivered {
    /// Nothing was offered: no message waits, the session is not guarded (R3.2), or one is
    /// already in front of the harness.
    Nothing,
    /// Queued and seen in the thread: DELIVERED.
    Confirmed(String),
    /// Queued; not yet seen (Codex is mid-turn): it stays QUEUED until confirmed.
    Unconfirmed(String),
    /// `codex queue` failed; the attempt is counted (D1.4), and `true` when it was the third, so
    /// the message is FAILED.
    Failed(String, String, bool),
}

/// Offers the next waiting message for the Codex session `to`, if any, through `codex queue`.
///
/// # Errors
/// When the store cannot be used.
/// `by`: the sender whose `lunchroom send` makes this hand-over. It hands over only that sender's
/// own message, never another sender's, and looks for the message in the thread's rollout file for
/// a while. `None` from the session's own `Stop` hook: that hands over the next message whoever
/// sent it and does not wait, since the session takes the message only after that hook ends, and
/// its prompt hook confirms it then.
pub fn deliver(
    env: &Env,
    store: &Store<Mail>,
    to: &Identity,
    by: Option<&Identity>,
) -> Result<Delivered, String> {
    let wait = by.is_some();
    // The recipient's own Codex folder, from the process its guard hook ran in, for `codex queue`
    // and its rollout files.
    let codex_home = store.read().map_or_else(
        |_| env.codex_home.clone(),
        |m| crate::evidence::recorded_codex_home(&m, to, &env.home),
    );
    // D1.1: a message handed over earlier and now in the thread's session record is DELIVERED.
    let waiting = store
        .read()
        .map(|m| m.handed_over_ids(to))
        .unwrap_or_default();
    for id in waiting
        .iter()
        .filter(|id| in_rollout(&codex_home, &to.session, id))
    {
        confirm(store, to, id)?;
    }
    // The hold and the hand-over mark are kept before `codex queue` runs, in one update: a crash
    // after it can leave the message not confirmed, never handed over twice (D1.2).
    let next = update(store, |m| {
        if !guarded(m, env, to) {
            return None;
        }
        let process = m.session(to).map(|r| r.process.clone())?;
        let message = m.present_from(to, by, env.now)?;
        m.hold_before_delivery(to, &message.id);
        m.handed_over(&message.id);
        Some((
            message.id.clone(),
            envelope(&message, m.hold_mode()),
            process,
        ))
    })?;
    let Some((id, text, process)) = next else {
        return Ok(Delivered::Nothing);
    };
    // D1.2: a message already in the thread's session record is confirmed, never queued again.
    if in_rollout(&codex_home, &to.session, &id) {
        confirm(store, to, &id)?;
        return Ok(Delivered::Confirmed(id));
    }
    // The envelope is one command argument: one the system would refuse is a failed attempt, not a
    // spawn that cannot start.
    if !fits_one_argument(&text) {
        return failed(
            store,
            id,
            "the envelope does not fit one command argument".to_owned(),
        );
    }
    let handed = queue(&process, &to.session, &text, &codex_home, &env.home);
    // D1.3: `codex queue` gave no answer, so it is not known whether Codex took the message. It
    // stays handed over (never queued again, D1.2), reported not confirmed, and is not counted
    // as a failed attempt.
    if handed == Err(QueueError::Unknown) {
        return Ok(Delivered::Unconfirmed(id));
    }
    // A recipient's `codex` program that cannot be established says nothing about the recipient:
    // the message stays QUEUED, uncounted and not handed over, for a later attempt (D1.3).
    if let Err(QueueError::Missing(reason)) = handed {
        update(store, |m| m.hand_over_undone(&id))?;
        return Ok(Delivered::Failed(id, reason, false));
    }
    if let Err(QueueError::Failed(reason)) = handed {
        return failed(store, id, reason);
    }
    let start = Instant::now();
    while wait && start.elapsed() < CONFIRM_WAIT {
        if in_rollout(&codex_home, &to.session, &id) {
            confirm(store, to, &id)?;
            return Ok(Delivered::Confirmed(id));
        }
        // The guard's prompt hook in that session may have confirmed it first.
        if message_is(store, &id, |d| d.presented_at.is_none()) {
            return Ok(Delivered::Confirmed(id));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(Delivered::Unconfirmed(id))
}

/// Changes the store; an error says the store cannot be used.
pub(crate) fn update<R>(
    store: &Store<Mail>,
    change: impl FnOnce(&mut Mail) -> R,
) -> Result<R, String> {
    store.update(change).map_err(crate::cli::unwritten)
}

/// Whether a delivery to `to` may go on, after the hand-overs nobody confirmed in time count as
/// failed attempts, so a dead session does not keep its hold (D1.4).
pub(crate) fn guarded(m: &mut Mail, env: &Env, to: &Identity) -> bool {
    m.expire_handovers(env.now);
    evidence(m, to, &env.home) == Evidence::Guarded
}

/// The message `id` handed to `to` is DELIVERED.
fn confirm(store: &Store<Mail>, to: &Identity, id: &str) -> Result<(), String> {
    update(store, |m| {
        m.confirm(to, id);
    })
}

/// Whether the stored message `id` satisfies `test`; one that cannot be read does not.
pub(crate) fn message_is(
    store: &Store<Mail>,
    id: &str,
    test: impl FnOnce(&Message) -> bool,
) -> bool {
    store.read().ok().and_then(|m| m.message(id).map(test)) == Some(true)
}

/// The attempt to hand over the message `id` failed for `reason`; it is counted (D1.4).
pub(crate) fn failed(store: &Store<Mail>, id: String, reason: String) -> Result<Delivered, String> {
    let outcome = update(store, |m| m.attempt_failed(&id, &reason))?;
    Ok(Delivered::Failed(
        id,
        reason,
        outcome == Some(AttemptOutcome::Failed),
    ))
}

/// Why a `codex queue` did not plainly succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QueueError {
    /// The recipient's own `codex` program cannot be established or is gone: nothing was tried.
    Missing(String),
    /// It did not run, or it ran and exited with an error: Codex did not take the message.
    Failed(String),
    /// It gave no answer in time, or could not be waited for: the outcome is unknown.
    Unknown,
}

/// What a `codex queue` that could not start says about the delivery.
fn spawn_error(e: &std::io::Error) -> QueueError {
    if e.kind() == std::io::ErrorKind::NotFound {
        QueueError::Missing("the recipient's codex program was not found".to_owned())
    } else {
        QueueError::Failed(format!("codex queue could not start: {e}"))
    }
}

/// Whether `envelope` fits one command argument, with the NUL that ends it (`MAX_ARG_STRLEN`).
pub(crate) fn fits_one_argument(envelope: &str) -> bool {
    envelope.len() < MAX_ARG_BYTES
}

/// The program the harness process `process` (`<pid>:<start time>`, as a guard hook recorded it) is
/// running, by its absolute path, for Lunchroom to run in its place: never a name looked up on a
/// `PATH`, which a sender could point at a program of its own (it would be handed the recipient's
/// messages). The process must still be the one recorded, and the path must name the very file the
/// process runs (same device and inode as `/proc/<pid>/exe`), so a program put in its place, or one
/// the harness replaced since it started, is refused.
///
/// # Errors
/// Why the program cannot be established.
pub(crate) fn recipient_program(process: &str) -> Result<PathBuf, String> {
    let pid = process
        .split(':')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .ok_or("the recipient's process is not recorded")?;
    if crate::process::key(pid).as_deref() != Some(process) {
        return Err("the recipient's process has ended".to_owned());
    }
    let exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let path = std::fs::read_link(&exe)
        .map_err(|_| "the recipient's program cannot be read".to_owned())?;
    if same_file(&path, &exe) {
        Ok(path)
    } else {
        Err("the recipient's program is not the file it is running".to_owned())
    }
}

/// `path` is absolute, an executable file, and the same file (device and inode) as `running`.
fn same_file(path: &Path, running: &Path) -> bool {
    let (Ok(a), Ok(b)) = (std::fs::metadata(path), std::fs::metadata(running)) else {
        return false;
    };
    path.is_absolute()
        && a.is_file()
        && a.permissions().mode() & 0o111 != 0
        && (a.dev(), a.ino()) == (b.dev(), b.ino())
}

/// The variables among `keys` in the starting environment of the recipient's process `process`:
/// the child of a hand-over gets its environment from the recipient, never from the sender whose
/// process spawns it (a sender's `NODE_OPTIONS` or `LD_PRELOAD` must not reach it).
pub(crate) fn recipient_env(process: &str, keys: &[&str]) -> Vec<(String, String)> {
    let Some(raw) = process
        .split(':')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .and_then(|p| std::fs::read(format!("/proc/{p}/environ")).ok())
    else {
        return Vec::new();
    };
    raw.split(|b| *b == 0)
        .filter_map(|kv| {
            let kv = String::from_utf8_lossy(kv);
            let (k, v) = kv.split_once('=')?;
            keys.contains(&k).then(|| (k.to_owned(), v.to_owned()))
        })
        .collect()
}

/// Why a hand-over does not start when the recipient's environment cannot be read (D1.1).
pub(crate) const UNREADABLE_ENV: &str = "the recipient's environment cannot be read";

/// What a hand-over's program keeps of the recipient's environment besides what the harness's own
/// variables name.
pub(crate) const CHILD_ENV: [&str; 8] = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_CONFIG_HOME",
];

/// Runs the recipient's `codex queue` for one thread; an error names why it failed.
fn queue(
    process: &str,
    thread: &str,
    text: &str,
    codex_home: &Path,
    home: &Path,
) -> Result<(), QueueError> {
    let program = recipient_program(process).map_err(QueueError::Missing)?;
    let variables = recipient_env(process, &CHILD_ENV);
    if variables.is_empty() {
        return Err(QueueError::Missing(UNREADABLE_ENV.to_owned()));
    }
    let child = Command::new(&program)
        .args(["queue", "--thread", thread, "--message", text])
        .env_clear()
        .env("HOME", home)
        .envs(variables)
        .env("CODEX_HOME", codex_home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = child.map_err(|e| spawn_error(&e))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(QueueError::Failed(format!(
                    "codex queue exited {}",
                    status.code().unwrap_or(-1)
                )));
            }
            Ok(None) if start.elapsed() < QUEUE_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(QueueError::Unknown);
            }
            Err(_) => return Err(QueueError::Unknown),
        }
    }
}

/// The thread's rollout files: `<codex home>/sessions/**/rollout-*<thread>*.jsonl`.
fn rollouts(codex_home: &Path, thread: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dirs = vec![(codex_home.join("sessions"), 0)];
    while let Some((dir, depth)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() && depth < 4 {
                dirs.push((path, depth + 1));
            } else if name.starts_with("rollout-")
                && Path::new(&name)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
                && name.contains(thread)
            {
                out.push(path);
            }
        }
    }
    out
}

/// The message's envelope is in the thread's rollout file: some text there holds the envelope's
/// header line followed by the line `id: <id>`. A body line always starts with its `[lr:` label,
/// so no message's text can stand in for another's envelope (D1.2).
fn in_rollout(codex_home: &Path, thread: &str, id: &str) -> bool {
    let id_line = format!("id: {id}");
    let holds = |text: &str| {
        let lines: Vec<&str> = text.lines().collect();
        lines
            .windows(2)
            .any(|w| w[0].starts_with("[LUNCHROOM MESSAGE - from agent ") && w[1] == id_line)
    };
    // The envelope as text in the file, or as a string in one of its JSON lines.
    rollouts(codex_home, thread).iter().any(|p| {
        std::fs::read_to_string(p).is_ok_and(|t| {
            holds(&t)
                || t.lines()
                    .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                    .any(|v| any_string(&v, &holds))
        })
    })
}

/// Whether any string inside `v` satisfies `f`.
fn any_string(v: &serde_json::Value, f: &impl Fn(&str) -> bool) -> bool {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(a) => a.iter().any(|x| any_string(x, f)),
        serde_json::Value::Object(o) => o.values().any(|x| any_string(x, f)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::*;

    // §10::3 (Codex): a missing `codex` binary is not a failed delivery, so it is not
    // counted; any other start error is.
    #[test]
    fn a_missing_codex_binary_is_not_a_failed_attempt() {
        assert!(matches!(
            spawn_error(&Error::from(ErrorKind::NotFound)),
            QueueError::Missing(_)
        ));
        assert!(matches!(
            spawn_error(&Error::from(ErrorKind::PermissionDenied)),
            QueueError::Failed(_)
        ));
    }

    fn me() -> String {
        let key = crate::process::key(std::process::id());
        assert!(key.is_some());
        key.unwrap_or_default()
    }

    // §10::1 (Codex): the program a hand-over runs is the file the recipient's process
    // runs, by its absolute path, never a name found on a PATH.
    #[test]
    fn the_program_is_the_file_the_recipients_process_runs() {
        let program = recipient_program(&me());
        assert!(program.is_ok(), "{program:?}");
        let program = program.unwrap_or_default();
        assert!(program.is_absolute());
        assert_eq!(
            std::fs::read_link("/proc/self/exe").ok().as_deref(),
            Some(program.as_path())
        );
    }

    // §10::1 (Codex): a process that is not the recorded one (ended, its pid reused,
    // never recorded) gives no program.
    #[test]
    fn no_program_for_a_process_that_is_not_the_recorded_one() {
        let pid = std::process::id();
        for process in [
            format!("{pid}:1"),
            format!("{pid}"),
            format!("{}:1", u32::MAX),
            "x:1".to_owned(),
            String::new(),
        ] {
            assert!(recipient_program(&process).is_err(), "{process}");
        }
    }

    // §10::1 (Codex): a program a sender planted (a script of its own, a copy, a path
    // with a relative spelling, a file the process no longer runs) is not the recipient's program.
    #[test]
    fn a_planted_program_is_not_the_one_the_process_runs() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/codex-unit")
            .join(format!("plant-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let running = Path::new("/proc/self/exe");
        let planted = dir.join("codex");
        let _ = std::fs::write(&planted, "#!/bin/sh\ncat\n");
        let _ = std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755));
        assert!(planted.is_file());
        let own = std::fs::read_link(running).unwrap_or_default();
        assert!(same_file(&own, running));
        assert!(!same_file(&planted, running));
        assert!(!same_file(Path::new("codex"), running));
        assert!(!same_file(&dir.join("missing"), running));
        let mut deleted = own.clone().into_os_string();
        deleted.push(" (deleted)");
        assert!(!same_file(Path::new(&deleted), running));
        // Not executable: not a program.
        let _ = std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o644));
        assert!(!same_file(&planted, &planted));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // §10::1 (Codex): the program's environment comes from the recipient's process and
    // holds only the listed variables; a sender's `NODE_OPTIONS`, `LD_PRELOAD` or `PATH` is not in
    // it, and a process that is not running gives none.
    #[test]
    fn the_environment_is_the_recipients_and_only_what_is_listed() {
        let env = recipient_env(&me(), &CHILD_ENV);
        assert!(env.iter().all(|(k, _)| CHILD_ENV.contains(&k.as_str())));
        assert!(
            recipient_env(&me(), &["NODE_OPTIONS", "LD_PRELOAD"])
                .iter()
                .all(|(k, _)| k == "NODE_OPTIONS" || k == "LD_PRELOAD")
        );
        assert!(!CHILD_ENV.contains(&"NODE_OPTIONS") && !CHILD_ENV.contains(&"LD_PRELOAD"));
        assert_eq!(
            recipient_env(&format!("{}:1", u32::MAX), &CHILD_ENV),
            Vec::new()
        );
    }

    // §10::1 (Codex): an envelope fits when it is one byte short of the system's limit
    // for one argument (the NUL ends it), and does not at the limit.
    #[test]
    fn an_envelope_must_be_short_of_the_argument_limit() {
        assert!(fits_one_argument(&"a".repeat(MAX_ARG_BYTES - 1)));
        assert!(!fits_one_argument(&"a".repeat(MAX_ARG_BYTES)));
    }

    // §10::1 (Codex): only the message's id line in the thread's rollout file confirms
    // it; the message's text there without its id does not, nor does another thread's file.
    #[test]
    fn only_the_message_id_in_the_threads_rollout_confirms() {
        let home = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/codex-unit")
            .join(std::process::id().to_string());
        let dir = home.join("sessions/2026/10/27");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("rollout-2026-10-27T00-00-00-x1.jsonl");
        let _ = std::fs::write(&file, "{\"text\": \"[lr:lr-00000007]> Please review.\"}\n");
        assert!(!in_rollout(&home, "x1", "lr-00000007"));
        // Another message's body naming this id, on its own line or after an escaped `\n`, does
        // not confirm it.
        for body in [
            "[LUNCHROOM MESSAGE - from agent X; not from the user]\\nid: lr-00000006\\n[lr:lr-00000006]> id: lr-00000007",
            "[lr:lr-00000006]> a\\\\nid: lr-00000007",
            "id: lr-00000007",
        ] {
            let _ = std::fs::write(&file, format!("{{\"text\": \"{body}\"}}\n"));
            assert!(!in_rollout(&home, "x1", "lr-00000007"), "{body}");
        }
        let _ = std::fs::write(
            &file,
            "{\"text\": \"[LUNCHROOM MESSAGE - from agent X; not from the user]\\nid: lr-00000007\\nsent: t\"}\n",
        );
        assert!(in_rollout(&home, "x1", "lr-00000007"));
        assert!(!in_rollout(&home, "x2", "lr-00000007"));
        let _ = std::fs::remove_dir_all(&home);
    }
}
