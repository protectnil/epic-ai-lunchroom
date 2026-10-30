//! The `lunchroom` command and the Claude Code guard hook.
//!
//! `lunchroom guard pretool|prompt|posttool` is the guard and `lunchroom listen [--once]` the
//! delivery hook (both read Claude Code's hook input on standard input); `lunchroom send` and
//! `lunchroom status` are the commands an agent may run. What the guard cannot decide (its own
//! error, a store it cannot use, a panic, or no answer within `GUARD_DEADLINE`) never locks the
//! user out (H1.5): a call goes to the user, or is DENIED alone where nobody can answer.

// The guard reads harness processes and sessions from `/proc`.
#[cfg(not(target_os = "linux"))]
compile_error!("Lunchroom runs on Linux: the guard reads harness processes from /proc.");

mod claude;
mod cli;
mod codex;
mod delivery;
mod evidence;
mod home;
mod install;
mod openclaw;
mod process;
mod terminal;
mod user;

use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use std::time::Duration;

/// How long one `lunchroom listen` waits for a message: under the hook's timeout of a day.
const LISTEN_MAX: Duration = Duration::from_hours(23);

fn write(out: Option<&str>, err: Option<&str>) {
    if let Some(text) = out {
        let _ = writeln!(std::io::stdout(), "{text}");
    }
    if let Some(text) = err {
        let _ = writeln!(std::io::stderr(), "{text}");
    }
}

/// H1.5: the guard answers within this time, under the hook's own timeout (15 seconds).
const GUARD_DEADLINE: Duration = Duration::from_secs(10);
/// How long a guard past its deadline waits for an answer already settled in the store.
const SETTLE: Duration = Duration::from_secs(1);

fn run_hook(
    mode: &str,
    text: &str,
    env: Result<home::Env, String>,
) -> Result<claude::HookOut, String> {
    let env = env?;
    let input = claude::HookInput::parse(text)?;
    match mode {
        "pretool" => claude::pretool(&input, &env),
        "prompt" => claude::prompt(&input, &env),
        "posttool" => claude::posttool(&input, &env),
        "start" => Ok(claude::start(&input, &env)),
        "listen" => delivery::listen(&input, &env, LISTEN_MAX),
        "listen-once" => delivery::listen(&input, &env, Duration::ZERO),
        _ => Err("usage: lunchroom guard pretool|prompt|posttool|start".to_owned()),
    }
}

/// What the hook's worker thread reports: the input it read, then the answer.
enum Step {
    Input(String),
    Answer(Result<claude::HookOut, String>),
}

/// The hook input. Input that is not UTF-8 is the guard's own error, but its text, decoded with
/// replacement characters, still comes back so a prompt carrying another agent's text is held
/// (H1.5).
fn read_input() -> Result<String, (String, String)> {
    let mut bytes = Vec::new();
    if std::io::stdin().read_to_end(&mut bytes).is_err() {
        return Err((String::new(), "the hook input cannot be read".to_owned()));
    }
    String::from_utf8(bytes).map_err(|e| {
        (
            String::from_utf8_lossy(e.as_bytes()).into_owned(),
            "the hook input is not UTF-8 text".to_owned(),
        )
    })
}

fn guard(mode: Option<&str>, env: Result<home::Env, String>) -> ExitCode {
    let owned = mode.unwrap_or_default().to_owned();
    let mut text = String::new();
    let mut timed_out = false;
    let result = if owned.starts_with("listen") {
        // The listener waits for messages by design; it has no deadline and asks nobody.
        read_input()
            .map_err(|(_, reason)| reason)
            .and_then(|t| run_hook(&owned, &t, env))
    } else {
        // Reading the input and deciding run on their own thread, so a stalled input, a panic or
        // a stall still gets an answer by the deadline.
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new().spawn(move || {
            let answer = match read_input() {
                Ok(t) => {
                    let _ = tx.send(Step::Input(t.clone()));
                    run_hook(&owned, &t, env)
                }
                Err((t, reason)) => {
                    let _ = tx.send(Step::Input(t));
                    Err(reason)
                }
            };
            let _ = tx.send(Step::Answer(answer));
        });
        let deadline = std::time::Instant::now() + GUARD_DEADLINE;
        let mut result = Err("the guard could not start".to_owned());
        if worker.is_ok() {
            result = Err(format!(
                "no answer within {} seconds",
                GUARD_DEADLINE.as_secs()
            ));
            loop {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                match rx.recv_timeout(left) {
                    Ok(Step::Input(t)) => text = t,
                    Ok(Step::Answer(answer)) => {
                        result = answer;
                        break;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Past the deadline nothing more is written; an answer whose last write
                        // was already made arrives at once and is the one given.
                        lunchroom_core::store::stop_updates();
                        match rx.recv_timeout(SETTLE) {
                            Ok(Step::Answer(Ok(out))) => result = Ok(out),
                            Ok(Step::Input(t)) => {
                                text = t;
                                timed_out = true;
                            }
                            _ => timed_out = true,
                        }
                        break;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        result = Err("the guard stopped with an internal error".to_owned());
                        break;
                    }
                }
            }
        }
        result
    };
    let out = result.unwrap_or_else(|reason| {
        // A call is still judged by the rules that need no record, unless the guard ran out of
        // time (judging it again could take as long).
        let settled = (mode == Some("pretool") && !timed_out)
            .then(|| claude::failed_call(&text))
            .flatten();
        settled.unwrap_or_else(|| claude::failed(mode, &reason, &text, claude::process_channel()))
    });
    let (stdout, stderr, code) = out.render();
    write(stdout.as_deref(), stderr.as_deref());
    ExitCode::from(code)
}

const USAGE: &str = "\
usage: lunchroom <command>

Agents may run:
  send <name> [--reply-to <id>] <text>    message another agent (text `-` reads standard input)
  status                                  agents, their states and queued messages
  codex-threads [-n COUNT]                recent Codex threads, to name one with `register`
  help, version

Only you, typed in a session as the whole prompt:
  join [<name>]                           include this session: it receives messages as <name>
  leave                                   take this session out

Only you, in a terminal outside every agent session; each one that changes something asks for your
passphrase, which it checks against /etc/lunchroom/<uid>.verifier, a file only root can write:
  passphrase                              set your passphrase, or change it (asks for the current one)
  install [claude-code|codex|openclaw|hermes]   no harness named: offers each one found
  uninstall claude-code|codex|openclaw|hermes   remove Lunchroom's hooks; every other hook stays
  register <name> <harness>:<session id>  let a session receive messages as <name>
  unregister <name>                       stop a session receiving messages as <name>
  approve [<n>]                           list the calls waiting for you, or approve one
  yolo <name,...|all> till <HH:MM>        let agents act without asking until then (UTC);
                                          `all` is every agent or none: name those that can
  mode [relaxed|balanced|strict]          how much another agent's message limits an agent
  rate <messages> <seconds>               set the message rate limit
  slip                                    show what a HELD agent may still do
  repair                                  put back the last good store when it cannot be read

Exit codes: 0 done, 1 store unusable, 2 usage, 3 not permitted, 4 HALTED, 5 rate limit, 7 DENIED.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("guard") => return guard(args.get(1).map(String::as_str), home::Env::from_process()),
        Some("listen") => {
            let once = args.get(1).map(String::as_str) == Some("--once");
            let mode = if once { "listen-once" } else { "listen" };
            return guard(Some(mode), home::Env::from_process());
        }
        _ => {}
    }
    let env = match home::Env::from_process() {
        Ok(env) => env,
        Err(reason) => {
            write(None, Some(&format!("Lunchroom: {reason}")));
            return ExitCode::from(2);
        }
    };
    let outcome = match args.first().map(String::as_str) {
        Some("send") => cli::send(&args[1..], &env),
        Some("status") => cli::status(&env),
        Some("codex-threads") => cli::codex_threads(&args[1..], &env),
        Some("approve") => user::approve(&args[1..], &env, &mut terminal::OsSystem),
        Some("register") => user::register(&args[1..], &env, &mut terminal::OsSystem),
        Some("unregister") => user::unregister(&args[1..], &env, &mut terminal::OsSystem),
        Some("rate") => user::rate(&args[1..], &env, &mut terminal::OsSystem),
        Some("slip") => user::slip(&args[1..]),
        Some("yolo") => user::yolo(&args[1..], &env, &mut terminal::OsSystem),
        Some("install") => install::install(&args[1..], &env, &mut terminal::OsSystem),
        Some("uninstall") => install::uninstall(&args[1..], &env, &mut terminal::OsSystem),
        Some("repair") => user::repair(&env, &mut terminal::OsSystem),
        Some("passphrase") => user::passphrase(&env, &mut terminal::OsSystem),
        Some("mode") => user::mode(&args[1..], &env, &mut terminal::OsSystem),
        Some("help" | "--help" | "-h") => cli::Outcome::ok(USAGE.to_owned()),
        Some("version" | "--version") => cli::Outcome::ok(format!("{}\n", cli::VERSION)),
        _ => {
            write(None, Some(USAGE.trim_end()));
            return ExitCode::from(2);
        }
    };
    let _ = std::io::stdout().write_all(outcome.stdout.as_bytes());
    let _ = std::io::stderr().write_all(outcome.stderr.as_bytes());
    ExitCode::from(outcome.code)
}
