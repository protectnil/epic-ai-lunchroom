//! The commands only the user may run: `lunchroom approve`, `register`, `unregister`, `rate` and
//! `passphrase`.
//!
//! Spec: §7 A1.1 (the user approves through `lunchroom approve` in a terminal outside every guarded
//! session), A1.3 (each runs only on the user's passphrase from such a terminal; the guard also
//! DENIES an agent's command that runs one), §8 A2.1–A2.2 (the approval covers one exact call; the
//! prompt shows it in full), §9 I1.5 (naming a session; a taken name is reported, never moved
//! silently), §2 R1.7 (the user sets the rate limit).

use std::fmt::Write as _;

use lunchroom_core::approvals::visible;
use lunchroom_core::cards;
use lunchroom_core::identity::{Harness, Identity};
use lunchroom_core::jcs::shown;
use lunchroom_core::loops::Limits;
use lunchroom_core::mail::{Mail, Origin, RegisterRefusal, valid_name};
use lunchroom_core::passphrase::{self, Verifier};
use lunchroom_core::policy::HoldMode;
use lunchroom_core::store::Store;
use lunchroom_core::vocab::Word;

use crate::cli::Outcome;
use crate::home::Env;
use crate::terminal::{
    ITERATIONS, NO_SECRET_READ, NO_VERIFIER, System, check, confirm, trusted_verifier,
    verifier_shown,
};

fn store(env: &Env) -> Result<Store<Mail>, Outcome> {
    Store::open(&env.store_dir())
        .map_err(|e| Outcome::failed(&format!("Lunchroom's store cannot be opened: {e}"), 1))
}

fn read(store: &Store<Mail>) -> Result<Mail, Outcome> {
    store
        .read()
        .map_err(|e| Outcome::failed(&crate::cli::unread(e), 1))
}

/// `lunchroom approve` lists the calls waiting for the user; `lunchroom approve <n>` approves the
/// n-th one's exact call, on the user's confirmation.
#[must_use]
pub fn approve(args: &[String], env: &Env, sys: &mut dyn System) -> Outcome {
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    let Some(arg) = args.first() else {
        let mut out = String::new();
        for (n, r) in mail.requests().iter().enumerate() {
            let _ = writeln!(
                out,
                "{}. {} ({}) {} {}",
                n + 1,
                visible(&r.agent),
                visible(&r.session.to_string()),
                visible(&r.tool),
                shown(&r.input)
            );
        }
        return Outcome::ok(out);
    };
    let Some(index) = arg.parse::<usize>().ok().and_then(|n| n.checked_sub(1)) else {
        return Outcome::failed("usage: lunchroom approve [<number from the list>]", 2);
    };
    let Some(request) = mail.requests().get(index).cloned() else {
        return Outcome::denied("no call with that number is waiting", 2);
    };
    // A2.2: what the user confirms is this text; the approval covers nothing else.
    let shown = mail.approval_prompt(
        &request.session,
        &request.agent,
        &request.tool,
        &request.input,
        &request.cwd,
    );
    let question = format!(
        "Lunchroom: this call is outside {}. Approve this one call, for 10 minutes, once?\n{shown}\n",
        request.rule
    );
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&reason, 3);
    }
    // The waiting list or the messages holding the session may have changed while the user read
    // the prompt: the approval is given only if the same call would still be shown the same way.
    let approved = store.update(|m| m.approve_request(index, &request, &shown, env.now));
    match approved {
        // Card 4: "Granted. Codex can merge.", with the agent and the call of the real event.
        Ok(Ok(id)) => Outcome::ok(format!(
            "{}\n{id}\n",
            cards::granted(
                &request.agent,
                &cards::action_of(&request.tool, &request.input)
            )
        )),
        Ok(Err(_)) => Outcome::denied(
            "what you were shown changed while you confirmed (a message may have arrived, or the \
             list of waiting calls changed); nothing was approved. Run `lunchroom approve` again.",
            3,
        ),
        Err(e) => Outcome::failed(&crate::cli::unwritten(e), 1),
    }
}

/// The question `install` asks, and `lunchroom mode` without a mode shows (P1.6).
pub const MODE_QUESTION: &str = "\
How much should a message from one agent limit what the agent receiving it may do?
  1. Relaxed: agents act on each other's messages freely; Lunchroom still stops injection into
     other sessions, impersonating you, and leaking secrets, and changes to Lunchroom come to you.
  2. Balanced (recommended): agents act freely, but pushes, publishes, deletes, sending data out
     of this computer, credentials and changes to Lunchroom come to you.
  3. Strict: everything an agent would change after another agent's message waits for you.
Codex cannot show an approval prompt: what would come to you there is blocked instead and waits
for `lunchroom approve`.
";

/// The mode named by an answer to [`MODE_QUESTION`]: its number or its name; Balanced for none.
#[must_use]
pub fn mode_answer(answer: &str) -> Option<HoldMode> {
    match answer.trim() {
        "" | "2" => Some(HoldMode::Balanced),
        "1" => Some(HoldMode::Relaxed),
        "3" => Some(HoldMode::Strict),
        other => HoldMode::parse(other),
    }
}

/// `lunchroom mode [strict|balanced|relaxed]`: shows the hold mode, or the user sets it (P1.6).
#[must_use]
pub fn mode(args: &[String], env: &Env, sys: &mut dyn System) -> Outcome {
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    let Some(word) = args.first() else {
        return Outcome::ok(format!(
            "hold mode: {}\n\n{MODE_QUESTION}Set it with: lunchroom mode relaxed|balanced|strict\n",
            mail.hold_mode().word()
        ));
    };
    let Some(chosen) = HoldMode::parse(word) else {
        return Outcome::failed("usage: lunchroom mode [relaxed|balanced|strict]", 2);
    };
    let question = format!("Lunchroom: set the hold mode to {}?\n", chosen.word());
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&reason, 3);
    }
    match store.update(|m| m.set_hold_mode(chosen)) {
        Ok(()) => Outcome::ok(format!("hold mode: {}\n", chosen.word())),
        Err(e) => Outcome::failed(&crate::cli::unwritten(e), 1),
    }
}

/// `lunchroom repair`: when Lunchroom's store cannot be read, the user puts back the state from
/// before its last change; the unreadable file is kept beside it.
#[must_use]
pub fn repair(env: &Env, sys: &mut dyn System) -> Outcome {
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    if store.read().is_ok() {
        return Outcome::ok("Lunchroom's store reads; nothing to repair\n".to_owned());
    }
    // A1.3: the terminal is checked against the sessions and processes the previous state
    // records, the state this puts back; with none to put back, nothing is done.
    let previous = match store.read_previous() {
        Ok(m) => m,
        Err(e) => {
            return Outcome::failed(
                &format!("the store cannot be read and has no earlier state to put back: {e}"),
                1,
            );
        }
    };
    let question = "Lunchroom: the store cannot be read. Put back its state from before the last \
                    change? The unreadable file is kept beside it.\n";
    if let Err(reason) = confirm(&previous, sys, question) {
        return Outcome::denied(&reason, 3);
    }
    match store.restore_previous() {
        Ok(_) => Outcome::ok("the store's previous state is back\n".to_owned()),
        Err(e) => Outcome::failed(&format!("the store cannot be repaired: {e}"), 1),
    }
}

/// `lunchroom register <name> <harness>:<session id>`: the user names a session, which from then on
/// receives messages. A taken name is reported, and moved only on a second confirmation.
#[must_use]
pub fn register(args: &[String], env: &Env, sys: &mut dyn System) -> Outcome {
    // `<harness>:<session id>`, or the earlier forms `--codex-thread <id>` and
    // `--claude-session <id>`.
    let who = match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("--codex-thread"), Some(id)) if !id.is_empty() => {
            Some(Identity::new(Harness::Codex, id))
        }
        (Some("--claude-session"), Some(id)) if !id.is_empty() => {
            Some(Identity::new(Harness::ClaudeCode, id))
        }
        (Some(k), _) => Identity::parse(k),
        _ => None,
    };
    let (Some(name), Some(who)) = (args.first(), who) else {
        return Outcome::failed(
            "usage: lunchroom register <name> <harness>:<session id> \
             (or --codex-thread <id> or --claude-session <id>)",
            2,
        );
    };
    if !valid_name(name) {
        return Outcome::denied(
            "a name is 1 to 32 letters, digits, '.', '_' or '-' (no spaces)",
            2,
        );
    }
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    let question = format!("Lunchroom: name {who} \"{name}\", so it receives messages?\n");
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&reason, 3);
    }
    let first = store.update(|m| m.register(name, &who, Origin::User, None));
    let holder = match first {
        Ok(Ok(_)) => return Outcome::ok(format!("{name} is {who}\n")),
        Ok(Err(RegisterRefusal::Taken { holder })) => holder,
        Ok(Err(RegisterRefusal::FromGuardedSession)) => {
            return Outcome::denied("a guarded session cannot register", 3);
        }
        Ok(Err(RegisterRefusal::InvalidName)) => {
            return Outcome::denied("the name is not valid", 2);
        }
        Err(e) => return Outcome::failed(&crate::cli::unwritten(e), 1),
    };
    let question = format!(
        "Lunchroom: the name \"{name}\" is held by {holder}. Messages already QUEUED for it stay \
         with it. Move the name to {who}?\n"
    );
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&format!("the name stays with {holder}: {reason}"), 3);
    }
    match store.update(|m| m.register(name, &who, Origin::User, Some(&holder))) {
        Ok(Ok(_)) => Outcome::ok(format!("{name} is {who} (moved from {holder})\n")),
        Ok(Err(_)) => Outcome::denied("the name changed holder meanwhile; nothing was moved", 3),
        Err(e) => Outcome::failed(&crate::cli::unwritten(e), 1),
    }
}

/// `lunchroom unregister <name>`: the user takes a name away, so that session receives no more
/// messages. Messages already QUEUED for it stay QUEUED.
#[must_use]
pub fn unregister(args: &[String], env: &Env, sys: &mut dyn System) -> Outcome {
    let [name] = args else {
        return Outcome::failed("usage: lunchroom unregister <name>", 2);
    };
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    let Some(who) = mail.named(name) else {
        return Outcome::denied(&format!("no agent is named \"{name}\""), 2);
    };
    let question = format!(
        "Lunchroom: take the name \"{name}\" from {who}, so it receives no more messages? Messages \
         already QUEUED for it stay QUEUED.\n"
    );
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&reason, 3);
    }
    match store.update(|m| m.unregister(name)) {
        Ok(true) => Outcome::ok(format!("{name} is no longer named\n")),
        Ok(false) => Outcome::denied("the name was removed meanwhile; nothing was changed", 3),
        Err(e) => Outcome::failed(&crate::cli::unwritten(e), 1),
    }
}

/// `lunchroom rate <messages> <seconds>`: the user sets the rate limit (R1.7).
#[must_use]
pub fn rate(args: &[String], env: &Env, sys: &mut dyn System) -> Outcome {
    let number = |k: usize| args.get(k).and_then(|a| a.parse::<u64>().ok());
    let (Some(ceiling), Some(window)) = (number(0), number(1)) else {
        return Outcome::failed("usage: lunchroom rate <messages> <seconds>", 2);
    };
    let Ok(limits) = u32::try_from(ceiling)
        .map_err(|_| ())
        .and_then(|c| Limits::new(c, window).map_err(|_| ()))
    else {
        return Outcome::denied(
            "a rate limit must be at least 1 message in at least 1 second",
            2,
        );
    };
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    let question =
        format!("Lunchroom: set the rate limit to {ceiling} messages in {window} seconds?\n");
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&reason, 3);
    }
    match store.update(|m| m.set_limits(limits)) {
        Ok(()) => Outcome::ok(format!(
            "rate limit: {ceiling} messages in {window} seconds\n"
        )),
        Err(e) => Outcome::failed(&crate::cli::unwritten(e), 1),
    }
}

/// `lunchroom passphrase`: the user sets the passphrase every command of this file asks for (A1.3).
/// With one already set, the current one is asked for first.
#[must_use]
pub fn passphrase(env: &Env, sys: &mut dyn System) -> Outcome {
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    if let Err(reason) = check(&mail, sys) {
        return Outcome::denied(&reason, 3);
    }
    set_passphrase(sys)
}

/// Sets the user's passphrase, on a terminal already checked: the current passphrase when there is
/// one, then the new one twice; the verifier is made, put in place as root's by the system, and
/// read back to show that it is root's and holds the passphrase just typed. The report names each
/// step done, whether the setting succeeds or stops.
#[must_use]
pub fn set_passphrase(sys: &mut dyn System) -> Outcome {
    let shown = verifier_shown(sys);
    // Nobody types a passphrase twice for a system that cannot put the check in place.
    if let Some(why) = sys.verifier_blocker() {
        return Outcome::failed(&format!("the passphrase was not set: {why}"), 1);
    }
    match trusted_verifier(sys) {
        Ok(current) => {
            let Some(typed) = sys.ask_secret("Current passphrase: ") else {
                return Outcome::denied(NO_SECRET_READ, 3);
            };
            if !current.matches(&typed) {
                return Outcome::denied("the current passphrase was wrong; nothing was changed", 3);
            }
        }
        Err(reason) if reason == NO_VERIFIER => {}
        // A check that cannot be trusted has no passphrase to ask for.
        Err(reason) => return Outcome::denied(&reason, 3),
    }
    let Some(first) = sys.ask_secret(&format!(
        "New passphrase (at least {} characters): ",
        passphrase::MIN_LENGTH
    )) else {
        return Outcome::denied(NO_SECRET_READ, 3);
    };
    if first.chars().count() < passphrase::MIN_LENGTH {
        return Outcome::denied(
            &format!(
                "a passphrase has at least {} characters; nothing was changed",
                passphrase::MIN_LENGTH
            ),
            2,
        );
    }
    let Some(second) = sys.ask_secret("New passphrase again: ") else {
        return Outcome::denied(NO_SECRET_READ, 3);
    };
    if first != second {
        return Outcome::denied("the two entries differ; nothing was changed", 2);
    }
    let salt = match sys.salt() {
        Ok(salt) => salt,
        Err(e) => return Outcome::failed(&format!("the passphrase was not set: {e}"), 1),
    };
    let line = Verifier::new(&first, salt, ITERATIONS).line();
    let mut report = format!("made the passphrase check ({ITERATIONS} rounds of PBKDF2)\n");
    if let Err(e) = sys.install_verifier(&line) {
        return Outcome {
            stdout: report,
            stderr: format!("the passphrase was not set: {e}\n"),
            code: 1,
        };
    }
    let _ = writeln!(report, "put it at {shown}, owned by root");
    match trusted_verifier(sys) {
        Ok(back) if back.matches(&first) => {
            let _ = writeln!(
                report,
                "read it back: it is owned by root and holds the passphrase just typed"
            );
            let _ = writeln!(
                report,
                "the passphrase is set; `sudo rm {shown}` removes the check"
            );
            Outcome::ok(report)
        }
        read_back => {
            let why = match read_back {
                Ok(_) => "it does not hold the passphrase just typed".to_owned(),
                Err(reason) => reason,
            };
            Outcome {
                stdout: report,
                stderr: format!(
                    "the passphrase is not set: the check at {shown} was read back and {why}; \
                     `sudo rm {shown}` removes it\n"
                ),
                code: 1,
            }
        }
    }
}

/// Claude Code tools that only read; the slip as shipped holds every one of them (P1.1).
const READ_TOOLS: [&str; 5] = ["Read", "NotebookRead", "LS", "Grep", "Glob"];

/// `lunchroom slip` shows the permission slip every agent has (P1.1); `lunchroom slip add <agent>
/// <what>` is how the user would widen one, and Lunchroom DENIES every addition: the slip as shipped
/// already holds every read and the reply, and a call that changes a file, runs a command or is
/// PROTECTED is never inside a slip (P1.1, P1.4). Nothing is written.
#[must_use]
pub fn slip(args: &[String]) -> Outcome {
    match args.first().map(String::as_str) {
        None => Outcome::ok(format!("slip: {}\n", crate::cli::SLIP)),
        Some("add") => match args.get(2..).unwrap_or_default() {
            [tool] if READ_TOOLS.contains(&tool.as_str()) => Outcome::ok(format!(
                "slip: {tool} is in every slip already; nothing changed\n"
            )),
            [] => Outcome::failed("usage: lunchroom slip add <agent> <tool>", 2),
            _ => Outcome::denied(
                "a slip holds only calls that read and the reply; a call that changes a file, \
                 runs a command or is PROTECTED is never added",
                3,
            ),
        },
        Some(_) => Outcome::failed("usage: lunchroom slip [add <agent> <tool>]", 2),
    }
}

/// Harnesses whose adapter has passed its test of turning YOLO on and off (R2.2, H1.1): Claude
/// Code, by the binary test `yolo_turns_harness_yolo_on_until_its_end`.
const YOLO_TESTED: [Harness; 1] = [Harness::ClaudeCode];

/// Days since the Unix epoch of a civil date (proleptic Gregorian), after H. Hinnant's
/// `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The end time `till` names, after `now`: `HH:MM` (UTC, the next time that comes) or
/// `YYYY-MM-DDTHH:MM[:SS]Z`.
fn parse_till(till: &str, now: u64) -> Option<u64> {
    let num = |s: &str| s.parse::<i64>().ok();
    let clock = |s: &str| -> Option<i64> {
        let mut parts = s.split(':');
        let (h, m) = (num(parts.next()?)?, num(parts.next()?)?);
        let sec = parts.next().map_or(Some(0), num)?;
        ((0..24).contains(&h)
            && (0..60).contains(&m)
            && (0..60).contains(&sec)
            && parts.next().is_none())
        .then_some(h * 3600 + m * 60 + sec)
    };
    let end = if let Some((date, time)) = till.strip_suffix('Z').and_then(|t| t.split_once('T')) {
        let mut d = date.split('-');
        let (y, mo, da) = (num(d.next()?)?, num(d.next()?)?, num(d.next()?)?);
        // Years outside 1970 to 9999 are no end time, and keep the arithmetic below from
        // overflowing on a year typed as a huge number.
        if d.next().is_some() || !(1..=12).contains(&mo) || !(1970..=9999).contains(&y) {
            return None;
        }
        // A day the month has (`2026-02-31` is no date).
        let (ny, nm) = if mo == 12 { (y + 1, 1) } else { (y, mo + 1) };
        if !(1..=days_from_civil(ny, nm, 1) - days_from_civil(y, mo, 1)).contains(&da) {
            return None;
        }
        days_from_civil(y, mo, da) * 86_400 + clock(time)?
    } else {
        let at = clock(till)?;
        let today = i64::try_from(now / 86_400).ok()? * 86_400;
        let now = i64::try_from(now).ok()?;
        if today + at > now {
            today + at
        } else {
            today + 86_400 + at
        }
    };
    u64::try_from(end).ok().filter(|e| *e > now)
}

/// `lunchroom yolo <agents|all> till <time>`: the user turns on each named agent's harness YOLO
/// until that time (R2.2). It always has an end time, and refuses an agent whose harness adapter
/// has not passed its YOLO test.
#[must_use]
pub fn yolo(args: &[String], env: &Env, sys: &mut dyn System) -> Outcome {
    let (Some(targets), Some(till)) = (
        args.first(),
        (args.get(1).map(String::as_str) == Some("till"))
            .then(|| args.get(2))
            .flatten(),
    ) else {
        return Outcome::failed(
            "usage: lunchroom yolo <agents|all> till <time>; it always has an end time",
            2,
        );
    };
    let Some(end) = parse_till(till, env.now) else {
        return Outcome::denied(
            "the end time must be HH:MM (UTC) or YYYY-MM-DDTHH:MMZ, after now",
            2,
        );
    };
    let store = match store(env) {
        Ok(s) => s,
        Err(o) => return o,
    };
    let mail = match read(&store) {
        Ok(m) => m,
        Err(o) => return o,
    };
    let chosen: Vec<(String, Identity)> = if targets == "all" {
        mail.names()
            .map(|(n, w)| (n.to_owned(), w.clone()))
            .collect()
    } else {
        let mut chosen = Vec::new();
        for name in targets.split(',').filter(|n| !n.is_empty()) {
            let Some(who) = mail.named(name) else {
                return Outcome::denied(&format!("no agent is named {name}"), 2);
            };
            chosen.push((name.to_owned(), who.clone()));
        }
        chosen
    };
    if chosen.is_empty() {
        return Outcome::denied("no agent is named", 2);
    }
    let untested: Vec<&str> = chosen
        .iter()
        .filter(|(_, w)| !YOLO_TESTED.contains(&w.harness))
        .map(|(n, _)| n.as_str())
        .collect();
    if !untested.is_empty() {
        // `yolo all` and a list of names alike turn it on for every one named or for none, so the
        // refusal says which agents can be named.
        let tested: Vec<&str> = chosen
            .iter()
            .filter(|(_, w)| YOLO_TESTED.contains(&w.harness))
            .map(|(n, _)| n.as_str())
            .collect();
        let can = if tested.is_empty() {
            "no agent can have it turned on yet".to_owned()
        } else {
            format!(
                "to turn it on for the others, name them: lunchroom yolo {} till <time>",
                tested.join(",")
            )
        };
        return Outcome::denied(
            &format!(
                "the harness adapter of {} has not passed its test of starting and ending {}; \
                 {} turns it on for every agent named or for none; {can}",
                untested.join(", "),
                Word::Yolo.text(),
                if targets == "all" {
                    "`yolo all`"
                } else {
                    "`yolo`"
                },
            ),
            3,
        );
    }
    let names: Vec<&str> = chosen.iter().map(|(n, _)| n.as_str()).collect();
    let question = format!(
        "Lunchroom: turn {} on for {} until {} UTC ({})?\n",
        Word::Yolo.text(),
        names.join(", "),
        hhmm(end),
        crate::delivery::utc(end)
    );
    if let Err(reason) = confirm(&mail, sys, &question) {
        return Outcome::denied(&reason, 3);
    }
    match store.update(|m| {
        for (_, who) in &chosen {
            m.set_yolo(who, end);
        }
    }) {
        Ok(()) => Outcome::ok(format!("{}\n", cards::yolo_until(end))),
        Err(e) => Outcome::failed(&crate::cli::unwritten(e), 1),
    }
}

/// `HH:MM` of a time, in UTC.
fn hhmm(secs: u64) -> String {
    let day = secs % 86_400;
    format!("{:02}:{:02}", day / 3600, day % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use lunchroom_core::approvals::Request;
    use lunchroom_core::vocab::Verdict;

    use super::*;
    use crate::terminal::fake;

    /// The user, in a terminal of their own, whose `answer` stands for the passphrase typed: a yes
    /// is the right one, anything else a wrong one; records each question and prompt shown.
    struct UserAt {
        answer: &'static str,
        asked: Vec<String>,
    }

    impl System for UserAt {
        fn ancestors(&self) -> Vec<(Option<String>, String)> {
            vec![(Some("100:5".to_owned()), "bash".to_owned())]
        }
        fn own_tty(&self) -> u64 {
            34816
        }
        fn tty_of(&self, _key: &str) -> Option<u64> {
            None
        }
        fn ask(&mut self, question: &str) -> Option<String> {
            self.asked.push(question.to_owned());
            Some(self.answer.to_owned())
        }
        fn uid(&self) -> Option<u32> {
            Some(1000)
        }
        fn verifier(&self) -> Result<String, String> {
            Ok(fake::verifier())
        }
        // The user's answer in these tests stands for the passphrase: a yes is the right one, and
        // anything else a wrong one.
        fn ask_secret(&mut self, prompt: &str) -> Option<String> {
            self.asked.push(prompt.to_owned());
            Some(fake::typed(self.answer))
        }
        fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String> {
            Ok([3; passphrase::SALT_BYTES])
        }
        fn install_verifier(&mut self, _line: &str) -> Result<(), String> {
            Ok(())
        }
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// A scratch Lunchroom folder under the build folder, removed afterwards.
    struct Scratch(Env);

    impl Scratch {
        fn new() -> Self {
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/user-tests")
                .join(format!("{}-{n}", std::process::id()));
            Self(Env {
                home: root.join("home"),
                lunchroom_home: root.join("lunchroom"),
                codex_home: root.join("home/.codex"),
                hermes_home: root.join("home/.hermes"),
                claude_pid: None,
                attended: None,
                entrypoint: None,
                claude_session: None,
                codex_thread: None,
                hermes_session: None,
                lunchroom_session: None,
                now: 1000,
            })
        }

        fn store(&self) -> Option<Store<Mail>> {
            Store::open(&self.0.store_dir()).ok()
        }
    }

    // P1.6: the user sets the hold mode in their own terminal with the passphrase; with no mode named
    // the command shows the mode and the question; an answer to the install question names a mode
    // by number or name, and none leaves Balanced.
    #[test]
    fn the_user_sets_the_hold_mode() {
        let s = Scratch::new();
        let store = s.store();
        assert!(store.is_some());
        let Some(store) = store else { return };
        let mut user = UserAt {
            answer: "yes",
            asked: Vec::new(),
        };
        let shown = mode(&[], &s.0, &mut user);
        assert!(
            shown.stdout.starts_with("hold mode: Balanced\n"),
            "{}",
            shown.stdout
        );
        assert!(shown.stdout.contains("2. Balanced (recommended)"));
        let set = mode(&["relaxed".to_owned()], &s.0, &mut user);
        assert_eq!(set.code, 0, "{}", set.stderr);
        assert_eq!(
            store.read().ok().map(|m| m.hold_mode()),
            Some(HoldMode::Relaxed)
        );
        let mut no = UserAt {
            answer: "no",
            asked: Vec::new(),
        };
        assert_eq!(mode(&["strict".to_owned()], &s.0, &mut no).code, 3);
        assert_eq!(
            store.read().ok().map(|m| m.hold_mode()),
            Some(HoldMode::Relaxed)
        );
        assert_eq!(mode(&["loose".to_owned()], &s.0, &mut user).code, 2);
        assert_eq!(mode_answer(""), Some(HoldMode::Balanced));
        assert_eq!(mode_answer("1"), Some(HoldMode::Relaxed));
        assert_eq!(mode_answer(" 3 "), Some(HoldMode::Strict));
        assert_eq!(mode_answer("strict"), Some(HoldMode::Strict));
        assert_eq!(mode_answer("yes"), None);
    }

    // `lunchroom repair` puts back the previous state only for the user in a terminal outside every
    // session the previous state records, and only when the store cannot be read.
    #[test]
    fn repair_puts_back_the_previous_state_for_the_user_only() {
        let s = Scratch::new();
        let store = s.store();
        assert!(store.is_some());
        let Some(store) = store else { return };
        let who = Identity::new(Harness::ClaudeCode, "c1");
        let mut user = UserAt {
            answer: "yes",
            asked: Vec::new(),
        };
        assert!(store.update(|m| m.observe(&who)).is_ok());
        assert!(
            store
                .update(|m| m.observe_process("100:5", Path::new("/w"), &who))
                .is_ok()
        );
        assert!(
            store
                .update(|m| m.observe(&Identity::new(Harness::Codex, "x1")))
                .is_ok()
        );
        assert_eq!(repair(&s.0, &mut user).code, 0);
        assert_eq!(user.asked, Vec::<String>::new());
        let state = s.0.store_dir().join("state.json");
        assert!(std::fs::write(&state, "{ broken").is_ok());
        // The terminal runs under a process the previous state records as a guarded session.
        let out = repair(&s.0, &mut user);
        assert_eq!(out.code, 3, "{}", out.stderr);
        assert!(store.read().is_err());
        // Without that record, the user's yes puts the previous state back.
        let fresh = Scratch::new();
        let other = fresh.store();
        assert!(other.is_some());
        let Some(other) = other else { return };
        assert!(other.update(|m| m.observe(&who)).is_ok());
        assert!(
            other
                .update(|m| m.observe(&Identity::new(Harness::Codex, "x1")))
                .is_ok()
        );
        let state = fresh.0.store_dir().join("state.json");
        assert!(std::fs::write(&state, "{ broken").is_ok());
        let out = repair(&fresh.0, &mut user);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert!(other.read().is_ok());
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Some(root) = self.0.lunchroom_home.parent() {
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    fn waiting(s: &Scratch) -> Identity {
        let me = Identity::new(Harness::ClaudeCode, "s1");
        let request = Request {
            session: me.clone(),
            agent: "Claude".to_owned(),
            tool: "Bash".to_owned(),
            input: json!({"command": "git push"}),
            cwd: "/work/a".to_owned(),
            rule: "PROTECTED (push or publish)".to_owned(),
            at: 1000,
        };
        assert!(
            s.store()
                .and_then(|st| st.update(|m| m.request(request)).ok())
                .is_some()
        );
        me
    }

    // §8::2: the list `lunchroom approve` prints shows the agent, session and tool with
    // control characters written out, never raw, so one waiting call stays one line.
    #[test]
    fn approve_list_shows_agent_session_and_tool_escaped() {
        let s = Scratch::new();
        let request = Request {
            session: Identity::new(Harness::ClaudeCode, "s\u{1b}[2K1"),
            agent: "Cl\naude\u{1b}[1A".to_owned(),
            tool: "Ba\rsh\u{85}".to_owned(),
            input: json!({"command": "git push"}),
            cwd: "/work/a".to_owned(),
            rule: "PROTECTED (push or publish)".to_owned(),
            at: 1000,
        };
        assert!(
            s.store()
                .and_then(|st| st.update(|m| m.request(request)).ok())
                .is_some()
        );
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let out = approve(&[], &s.0, &mut user);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert_eq!(out.stdout.lines().count(), 1, "{:?}", out.stdout);
        assert!(out.stdout.ends_with('\n'));
        let body = out.stdout.trim_end_matches('\n');
        assert!(
            !body.chars().any(char::is_control),
            "a raw control character: {body:?}"
        );
        for part in ["Cl\\naude\\u{001b}[1A", "Ba\\rsh\\u{0085}", "\\u{001b}[2K"] {
            assert!(body.contains(part), "{part}: {body:?}");
        }
        assert_eq!(user.asked, Vec::<String>::new());
    }

    // §7::7, §7::12, §7::13: in a terminal of the user's own, `lunchroom approve 1` asks a
    // question that starts "Lunchroom:", names the rule and shows the call; on yes the exact call is
    // approved once.
    #[test]
    fn approve_in_users_terminal_approves_that_call() {
        let s = Scratch::new();
        let me = waiting(&s);
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let out = approve(&["1".to_owned()], &s.0, &mut user);
        assert_eq!(out.code, 0, "{}", out.stderr);
        // Card 4's line, with the agent and call of this event.
        assert!(
            out.stdout.starts_with("Granted. Claude can push.\n"),
            "{}",
            out.stdout
        );
        let question = user.asked.first().cloned().unwrap_or_default();
        assert!(
            question.starts_with("Lunchroom: this call is outside PROTECTED (push or publish)."),
            "{question}"
        );
        assert!(
            question.contains("The call's input:\n{\"command\":\"git push\"}"),
            "{question}"
        );
        let verdicts: Vec<Verdict> = (0..2)
            .filter_map(|_| {
                s.store().and_then(|st| {
                    st.update(|m| {
                        m.use_approval(
                            &me,
                            "Bash",
                            &json!({"command": "git push"}),
                            "/work/a",
                            1001,
                        )
                    })
                    .ok()
                })
            })
            .collect();
        assert_eq!(verdicts, [Verdict::Granted, Verdict::Denied]);
        // A2.1/A2.2: the folder is shown, and the approval covers only that folder.
        assert!(question.contains("Runs in: /work/a\n"), "{question}");
        let elsewhere = s.store().and_then(|st| {
            st.update(|m| {
                m.approve(
                    &me,
                    "Bash",
                    &json!({"command": "git push"}),
                    "/work/a",
                    1002,
                );
                m.use_approval(
                    &me,
                    "Bash",
                    &json!({"command": "git push"}),
                    "/work/b",
                    1003,
                )
            })
            .ok()
        });
        assert_eq!(elsewhere, Some(Verdict::Denied));
    }

    /// The user of [`UserAt`], while whose passphrase is being typed another agent's message
    /// arrives and holds the session.
    struct Interrupted {
        user: UserAt,
        env: Env,
        who: Identity,
    }

    impl System for Interrupted {
        fn ancestors(&self) -> Vec<(Option<String>, String)> {
            self.user.ancestors()
        }
        fn own_tty(&self) -> u64 {
            self.user.own_tty()
        }
        fn tty_of(&self, key: &str) -> Option<u64> {
            self.user.tty_of(key)
        }
        fn ask(&mut self, question: &str) -> Option<String> {
            self.user.ask(question)
        }
        fn uid(&self) -> Option<u32> {
            self.user.uid()
        }
        fn verifier(&self) -> Result<String, String> {
            self.user.verifier()
        }
        fn ask_secret(&mut self, prompt: &str) -> Option<String> {
            if let Ok(store) = Store::<Mail>::open(&self.env.store_dir()) {
                let _ = store.update(|m| m.hold_unrecorded(&self.who, "codex", "late-1"));
            }
            self.user.ask_secret(prompt)
        }
        fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String> {
            self.user.salt()
        }
        fn install_verifier(&mut self, line: &str) -> Result<(), String> {
            self.user.install_verifier(line)
        }
    }

    // §8::1, §8::2 — the user read a prompt that showed no holding message; a message
    // that holds the session before the answer is applied was never shown, so nothing is approved
    // (not even for the same call), the request stays waiting, and the user is told to run
    // approve again, which then shows the new message and approves it.
    #[test]
    fn message_arriving_while_user_confirms_is_not_covered() {
        let s = Scratch::new();
        let me = waiting(&s);
        let mut racing = Interrupted {
            user: UserAt {
                answer: "yes\n",
                asked: Vec::new(),
            },
            env: s.0.clone(),
            who: me.clone(),
        };
        let out = approve(&["1".to_owned()], &s.0, &mut racing);
        assert_eq!(out.code, 3, "{}", out.stdout);
        assert!(
            out.stderr.contains("nothing was approved"),
            "{}",
            out.stderr
        );
        let call = json!({"command": "git push"});
        let state = s.store().and_then(|st| {
            st.update(|m| {
                (
                    m.requests().len(),
                    // Neither the held set at confirmation time (none) nor the current one is covered.
                    m.use_approval(&me, "Bash", &call, "/work/a", 1001),
                )
            })
            .ok()
        });
        assert_eq!(state, Some((1, Verdict::Denied)));
        // Run again: the prompt now names the message, and the approval covers it.
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        assert_eq!(approve(&["1".to_owned()], &s.0, &mut user).code, 0);
        let question = user.asked.first().cloned().unwrap_or_default();
        assert!(question.contains("codex (codex:late-1)"), "{question}");
        let granted = s.store().and_then(|st| {
            st.update(|m| m.use_approval(&me, "Bash", &call, "/work/a", 1001))
                .ok()
        });
        assert_eq!(granted, Some(Verdict::Granted));
    }

    // §7::12: any answer but yes approves nothing.
    #[test]
    fn approve_without_yes_approves_nothing() {
        let s = Scratch::new();
        let me = waiting(&s);
        let mut user = UserAt {
            answer: "y\n",
            asked: Vec::new(),
        };
        assert_eq!(approve(&["1".to_owned()], &s.0, &mut user).code, 3);
        let verdict = s.store().and_then(|st| {
            st.update(|m| {
                m.use_approval(
                    &me,
                    "Bash",
                    &json!({"command": "git push"}),
                    "/work/a",
                    1001,
                )
            })
            .ok()
        });
        assert_eq!(verdict, Some(Verdict::Denied));
    }

    // §9::8 and §2::11: a taken name moves only on the second yes; the rate limit is set on yes.
    #[test]
    fn register_takes_the_earlier_forms_too() {
        let s = Scratch::new();
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let args = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        assert_eq!(
            register(
                &args(&["Builder", "--codex-thread", "t-9"]),
                &s.0,
                &mut user
            )
            .code,
            0
        );
        assert_eq!(
            register(
                &args(&["Planner", "--claude-session", "s-9"]),
                &s.0,
                &mut user
            )
            .code,
            0
        );
        assert_eq!(
            register(&args(&["Nobody", "--codex-thread"]), &s.0, &mut user).code,
            2
        );
        let named = s
            .store()
            .and_then(|st| st.read().ok())
            .map(|m| (m.named("Builder").cloned(), m.named("Planner").cloned()));
        assert_eq!(
            named,
            Some((
                Identity::parse("codex:t-9"),
                Identity::parse("claude-code:s-9")
            ))
        );
    }

    #[test]
    fn register_and_rate_on_the_users_yes() {
        let s = Scratch::new();
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let args = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        assert_eq!(
            register(&args(&["codex", "codex:x1"]), &s.0, &mut user).code,
            0
        );
        assert_eq!(
            register(&args(&["codex", "codex:x2"]), &s.0, &mut user).code,
            0
        );
        assert_eq!(user.asked.len(), 3);
        assert!(
            user.asked[2].contains("is held by codex:x1"),
            "{}",
            user.asked[2]
        );
        let named = s
            .store()
            .and_then(|st| st.read().ok())
            .and_then(|m| m.named("codex").cloned());
        assert_eq!(named, Identity::parse("codex:x2"));
        assert_eq!(rate(&args(&["0", "60"]), &s.0, &mut user).code, 2);
        assert_eq!(rate(&args(&["5", "60"]), &s.0, &mut user).code, 0);
        let limits = s.store().and_then(|st| st.read().ok()).map(|m| m.limits());
        assert_eq!(limits, Limits::new(5, 60).ok());
    }

    /// A terminal under a harness process: an agent's command, which `confirm` refuses.
    struct FromAgent;

    impl System for FromAgent {
        fn ancestors(&self) -> Vec<(Option<String>, String)> {
            vec![(None, "claude".to_owned())]
        }
        fn own_tty(&self) -> u64 {
            34816
        }
        fn tty_of(&self, _key: &str) -> Option<u64> {
            None
        }
        fn ask(&mut self, _question: &str) -> Option<String> {
            Some("yes\n".to_owned())
        }
        fn uid(&self) -> Option<u32> {
            Some(1000)
        }
        fn verifier(&self) -> Result<String, String> {
            Ok(fake::verifier())
        }
        fn ask_secret(&mut self, _prompt: &str) -> Option<String> {
            Some(fake::PASSPHRASE.to_owned())
        }
        fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String> {
            Ok([3; passphrase::SALT_BYTES])
        }
        fn install_verifier(&mut self, _line: &str) -> Result<(), String> {
            Ok(())
        }
    }

    // `lunchroom unregister` takes the name away on the user's yes; it changes nothing without the
    // yes, from an agent, for an unknown name or with the wrong arguments.
    #[test]
    fn unregister_on_the_users_yes_only() {
        let s = Scratch::new();
        named(&s, "codex", "codex:x1");
        let args = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        let holds_name = || {
            s.store()
                .and_then(|st| st.read().ok())
                .is_some_and(|m| m.named("codex").is_some())
        };
        let mut no = UserAt {
            answer: "y\n",
            asked: Vec::new(),
        };
        assert_eq!(unregister(&args(&["codex"]), &s.0, &mut no).code, 3);
        assert_eq!(unregister(&args(&["codex"]), &s.0, &mut FromAgent).code, 3);
        assert_eq!(unregister(&args(&["nobody"]), &s.0, &mut no).code, 2);
        assert_eq!(unregister(&args(&[]), &s.0, &mut no).code, 2);
        assert!(holds_name());
        let mut yes = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let out = unregister(&args(&["codex"]), &s.0, &mut yes);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert!(!holds_name());
        assert_eq!(unregister(&args(&["codex"]), &s.0, &mut yes).code, 2);
    }

    // R2.2 end times: HH:MM is the next such time in UTC; a dated time must be after now.
    #[test]
    fn till_times() {
        let noon = 12 * 3600;
        assert_eq!(parse_till("14:00", noon), Some(14 * 3600));
        assert_eq!(parse_till("11:00", noon), Some(86_400 + 11 * 3600));
        assert_eq!(parse_till("12:00", noon), Some(86_400 + noon));
        assert_eq!(parse_till("2026-10-26T14:00Z", noon), Some(1_793_023_200));
        assert_eq!(
            parse_till("2026-10-26T14:00:30Z", noon),
            Some(1_793_023_230)
        );
        assert_eq!(parse_till("1970-01-01T11:00Z", noon), None);
        assert!(parse_till("2028-02-29T00:00Z", noon).is_some());
        assert!(parse_till("2026-12-31T00:00Z", noon).is_some());
        assert!(parse_till("9999-12-31T23:59Z", noon).is_some());
        for bad in [
            "",
            "14",
            "24:00",
            "14:60",
            "2026-13-01T00:00Z",
            "2026-02-29T00:00Z",
            "2026-04-31T00:00Z",
            "2026-10-00T00:00Z",
            "2026-10-26T14:00",
            "soon",
            // Years that would overflow the day count, or that no clock reaches.
            "9223372036854775807-12-01T00:00Z",
            "-9223372036854775808-01-01T00:00Z",
            "99999999999999999-01-01T00:00Z",
            "10000-01-01T00:00Z",
            "0000-01-01T00:00Z",
            "1969-12-31T23:59Z",
        ] {
            assert_eq!(parse_till(bad, noon), None, "{bad}");
        }
    }

    fn named(s: &Scratch, name: &str, who: &str) {
        let who = Identity::parse(who).unwrap_or_else(|| Identity::new(Harness::ClaudeCode, "x"));
        assert!(
            s.store()
                .and_then(|st| st
                    .update(|m| m.register(name, &who, Origin::User, None))
                    .ok())
                .is_some()
        );
    }

    // §3::1, §3::4 (command part): on the user's yes, `lunchroom yolo` covers each named
    // agent until the end time and prints card 5's line; it covers until then and not after.
    #[test]
    fn yolo_on_the_users_yes_until_its_end() {
        let s = Scratch::new();
        named(&s, "deepseek", "claude-code:d1");
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let args = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        let out = yolo(&args(&["deepseek", "till", "14:00"]), &s.0, &mut user);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert_eq!(out.stdout, "YOLO authorized until 14:00 UTC.\n");
        let d1 = Identity::new(Harness::ClaudeCode, "d1");
        let mail = s.store().and_then(|st| st.read().ok());
        assert_eq!(
            mail.as_ref().and_then(|m| m.yolo_until(&d1, 1000)),
            Some(14 * 3600)
        );
        assert_eq!(
            mail.as_ref().and_then(|m| m.yolo_until(&d1, 14 * 3600)),
            None
        );
    }

    // §3::2, §3::3: no end time is refused; an agent whose harness adapter has not passed
    // its YOLO test is refused; a name that does not exist is refused; nothing is asked or set.
    #[test]
    fn yolo_refusals() {
        let s = Scratch::new();
        named(&s, "deepseek", "claude-code:d1");
        named(&s, "codex", "codex:x1");
        named(&s, "claw", "openclaw:agent:main:a");
        named(&s, "hermes", "hermes:h1");
        let args = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        for (a, code) in [
            (args(&["deepseek"]), 2),
            (args(&["deepseek", "till"]), 2),
            (args(&["deepseek", "for", "14:00"]), 2),
            (args(&["codex", "till", "14:00"]), 3),
            (args(&["claw", "till", "14:00"]), 3),
            (args(&["hermes", "till", "14:00"]), 3),
            (args(&["all", "till", "14:00"]), 3),
            (args(&["nobody", "till", "14:00"]), 2),
        ] {
            let mut user = UserAt {
                answer: "yes\n",
                asked: Vec::new(),
            };
            assert_eq!(yolo(&a, &s.0, &mut user).code, code, "{a:?}");
            assert!(user.asked.is_empty(), "{a:?}");
        }
        let d1 = Identity::new(Harness::ClaudeCode, "d1");
        let set = s
            .store()
            .and_then(|st| st.read().ok())
            .and_then(|m| m.yolo_until(&d1, 1000));
        assert_eq!(set, None);
    }

    // §3::2: `yolo all` is all or nothing; its refusal says so, names the agents whose
    // harness has passed, and the command that turns it on for them.
    #[test]
    fn yolo_all_refusal_says_which_agents_can_be_named() {
        let s = Scratch::new();
        named(&s, "deepseek", "claude-code:d1");
        named(&s, "codex", "codex:x1");
        let mut user = UserAt {
            answer: "yes\n",
            asked: Vec::new(),
        };
        let a = ["all", "till", "14:00"].map(str::to_owned);
        let out = yolo(&a, &s.0, &mut user);
        assert_eq!(out.code, 3, "{}", out.stderr);
        for part in [
            "adapter of codex has not passed",
            "`yolo all` turns it on for every agent named or for none",
            "lunchroom yolo deepseek till <time>",
        ] {
            assert!(out.stderr.contains(part), "{part}: {}", out.stderr);
        }
        assert_eq!(user.asked, Vec::<String>::new());
    }

    /// A user setting a passphrase: types each secret in turn, and the system puts a verifier in
    /// place as root's (`after` is what reading it back then gives, when that is not the verifier
    /// just put in place).
    struct Setting {
        ancestors: Vec<(Option<String>, String)>,
        verifier: Result<String, String>,
        typed: Vec<&'static str>,
        prompts: Vec<String>,
        installed: Option<String>,
        install: Result<(), String>,
        after: Option<Result<String, String>>,
    }

    impl Setting {
        fn new(verifier: Result<String, String>, typed: &[&'static str]) -> Self {
            Self {
                ancestors: vec![(Some("100:5".to_owned()), "bash".to_owned())],
                verifier,
                typed: typed.to_vec(),
                prompts: Vec::new(),
                installed: None,
                install: Ok(()),
                after: None,
            }
        }

        /// A user with no passphrase yet.
        fn first(typed: &[&'static str]) -> Self {
            Self::new(Err(NO_VERIFIER.to_owned()), typed)
        }

        /// A user whose passphrase is [`fake::PASSPHRASE`].
        fn later(typed: &[&'static str]) -> Self {
            Self::new(Ok(fake::verifier()), typed)
        }
    }

    impl System for Setting {
        fn ancestors(&self) -> Vec<(Option<String>, String)> {
            self.ancestors.clone()
        }
        fn own_tty(&self) -> u64 {
            34816
        }
        fn tty_of(&self, _key: &str) -> Option<u64> {
            None
        }
        fn ask(&mut self, _question: &str) -> Option<String> {
            None
        }
        fn uid(&self) -> Option<u32> {
            Some(1000)
        }
        fn verifier(&self) -> Result<String, String> {
            self.verifier.clone()
        }
        fn ask_secret(&mut self, prompt: &str) -> Option<String> {
            self.prompts.push(prompt.to_owned());
            (!self.typed.is_empty()).then(|| self.typed.remove(0).to_owned())
        }
        fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String> {
            Ok([4; passphrase::SALT_BYTES])
        }
        fn install_verifier(&mut self, line: &str) -> Result<(), String> {
            self.install.clone()?;
            self.installed = Some(line.to_owned());
            self.verifier = self.after.take().unwrap_or_else(|| Ok(line.to_owned()));
            Ok(())
        }
    }

    const NEW: &str = "a new passphrase 7";

    // A1.3: with no passphrase set, `lunchroom passphrase` asks for the new one twice (and no
    // current one), makes the verifier from it, has the system put it in place as root's, reads it
    // back, and tells each step; the passphrase then confirms.
    #[test]
    fn the_first_passphrase_is_asked_twice_and_set() {
        let s = Scratch::new();
        let mut sys = Setting::first(&[NEW, NEW]);
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
        assert_eq!(
            sys.prompts,
            [
                "New passphrase (at least 12 characters): ",
                "New passphrase again: "
            ]
        );
        let line = sys.installed.clone().unwrap_or_default();
        let made = Verifier::parse(&line, ITERATIONS);
        assert_eq!(made.as_ref().map(|v| v.matches(NEW)), Ok(true), "{line}");
        assert_eq!(made.map(|v| v.matches(fake::PASSPHRASE)), Ok(false));
        for step in [
            "made the passphrase check",
            "put it at /etc/lunchroom/1000.verifier, owned by root",
            "read it back: it is owned by root and holds the passphrase just typed",
            "`sudo rm /etc/lunchroom/1000.verifier` removes the check",
        ] {
            assert!(out.stdout.contains(step), "{step}: {}", out.stdout);
        }
    }

    // A1.3: a passphrase of fewer than 12 characters, counted as characters and not bytes, is
    // denied before it is asked again and before anything is put in place; 12 is enough.
    #[test]
    fn a_passphrase_under_twelve_characters_is_refused() {
        let s = Scratch::new();
        for short in ["", "a", "elevenchars", "ééééééééééé"] {
            let mut sys = Setting::first(&[short, short]);
            let out = passphrase(&s.0, &mut sys);
            assert_eq!(out.code, 2, "{short:?}: {}", out.stderr);
            assert!(
                out.stderr.contains("at least 12 characters"),
                "{}",
                out.stderr
            );
            assert_eq!(sys.installed, None, "{short:?}");
            assert_eq!(sys.prompts.len(), 1, "{short:?}");
        }
        let mut sys = Setting::first(&["twelve chars", "twelve chars"]);
        assert_eq!(passphrase(&s.0, &mut sys).code, 0);
        assert!(sys.installed.is_some());
    }

    // A1.3: two entries that differ set nothing.
    #[test]
    fn two_entries_that_differ_are_refused() {
        let s = Scratch::new();
        for second in [
            "a new passphrase 8",
            "A new passphrase 7",
            "a new passphrase 7 ",
            "",
        ] {
            let mut sys = Setting::first(&[NEW, second]);
            let out = passphrase(&s.0, &mut sys);
            assert_eq!(out.code, 2, "{second:?}: {}", out.stderr);
            assert!(
                out.stderr.contains("the two entries differ"),
                "{}",
                out.stderr
            );
            assert_eq!(sys.installed, None, "{second:?}");
        }
    }

    // A1.3: with a passphrase already set, the current one is asked for first; a wrong one asks for
    // nothing more and changes nothing, the right one lets the new one replace it.
    #[test]
    fn the_current_passphrase_is_required_when_one_is_set() {
        let s = Scratch::new();
        for wrong in ["", "yes", "wrong passphrase", "Correct horse battery"] {
            let mut sys = Setting::later(&[wrong, NEW, NEW]);
            let out = passphrase(&s.0, &mut sys);
            assert_eq!(out.code, 3, "{wrong:?}: {}", out.stderr);
            assert!(
                out.stderr.contains("the current passphrase was wrong"),
                "{}",
                out.stderr
            );
            assert_eq!(sys.prompts, ["Current passphrase: "], "{wrong:?}");
            assert_eq!(sys.installed, None, "{wrong:?}");
        }
        let mut none = Setting::later(&[]);
        assert_eq!(passphrase(&s.0, &mut none).code, 3);
        assert_eq!(none.installed, None);
        let mut sys = Setting::later(&[fake::PASSPHRASE, NEW, NEW]);
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
        assert_eq!(sys.prompts.len(), 3);
        assert_eq!(sys.prompts[0], "Current passphrase: ");
        let line = sys.installed.clone().unwrap_or_default();
        assert_eq!(
            Verifier::parse(&line, ITERATIONS).map(|v| v.matches(NEW)),
            Ok(true)
        );
    }

    // A1.3: a check the system cannot trust is not replaced by asking for a passphrase: the user is
    // told to remove it.
    #[test]
    fn a_check_that_cannot_be_trusted_is_not_replaced_unasked() {
        let s = Scratch::new();
        let mut sys = Setting::new(
            Err(
                "the passphrase check at /etc/lunchroom/1000.verifier cannot be trusted (x); \
                 `sudo rm /etc/lunchroom/1000.verifier` removes it"
                    .to_owned(),
            ),
            &[NEW, NEW],
        );
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 3, "{}", out.stderr);
        assert!(out.stderr.contains("sudo rm"), "{}", out.stderr);
        assert_eq!(sys.prompts, Vec::<String>::new());
        assert_eq!(sys.installed, None);
    }

    // A1.3: the same checks as every other command only the user may run come first: a guarded
    // session in the parent chain gets no question and sets nothing.
    #[test]
    fn an_agent_cannot_set_the_passphrase() {
        let s = Scratch::new();
        let mut sys = Setting::first(&[NEW, NEW]);
        sys.ancestors = vec![(None, "claude".to_owned())];
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 3, "{}", out.stderr);
        assert!(out.stderr.starts_with("DENIED"), "{}", out.stderr);
        assert_eq!(sys.prompts, Vec::<String>::new());
        assert_eq!(sys.installed, None);
    }

    // A1.3: a system that cannot put the verifier in place (no sudo, a wrong sudo password) sets
    // nothing and says so, with the steps done; a verifier that reads back as not root's, or as
    // another passphrase, is reported as not set.
    #[test]
    fn a_verifier_that_is_not_put_in_place_is_reported_not_set() {
        let s = Scratch::new();
        let mut sys = Setting::first(&[NEW, NEW]);
        sys.install = Err(
            "installing /etc/lunchroom/1000.verifier did not succeed (exit status: 1)".to_owned(),
        );
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 1, "{}", out.stdout);
        assert!(
            out.stderr.contains("the passphrase was not set"),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains("did not succeed"), "{}", out.stderr);
        assert!(
            out.stdout.contains("made the passphrase check"),
            "{}",
            out.stdout
        );
        assert!(!out.stdout.contains("put it at"), "{}", out.stdout);
        // Read back as not root's alone.
        let mut sys = Setting::first(&[NEW, NEW]);
        sys.after = Some(Err(
            "the passphrase check at /etc/lunchroom/1000.verifier cannot be trusted (it is not a \
             regular file owned by root and writable by no one else)"
                .to_owned(),
        ));
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 1);
        assert!(
            out.stderr.contains("the passphrase is not set"),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains("cannot be trusted"), "{}", out.stderr);
        // Read back as a verifier for another passphrase (a file swapped while the user typed the
        // password for sudo).
        let mut sys = Setting::first(&[NEW, NEW]);
        sys.after = Some(Ok(fake::verifier()));
        let out = passphrase(&s.0, &mut sys);
        assert_eq!(out.code, 1);
        assert!(
            out.stderr
                .contains("does not hold the passphrase just typed"),
            "{}",
            out.stderr
        );
    }
}
