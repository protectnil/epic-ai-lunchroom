//! The user's confirmation (A1.3) through the real system: the `lunchroom` binary run with no
//! controlling terminal, and under a pseudo-terminal made by the `script` utility, with the
//! passphrase check in `/etc/lunchroom` (as root). The rules
//! themselves are tested against a fake system in `src/terminal.rs`; here `/proc` and `/dev/tty`
//! are the real ones.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use lunchroom_core::passphrase::ITERATIONS;
use lunchroom_core::policy::HoldMode;

use common::Run;

/// `program` detached from this test's process tree: `setsid --fork` makes it the leader of a
/// session of its own, with no controlling terminal, and the process that started it goes, so the
/// system gives it no ancestor but init. A guarded session that happens to be running these tests
/// (a Claude Code, say) is then not in its parent chain, and a refusal can only be for the reason
/// the test names. Its output is the whole of what the run leaves: the pipes close when it ends.
fn detached(sb: &common::Sandbox, program: &str, args: &[&str]) -> Command {
    let setsid = common::which("setsid");
    assert!(setsid.is_some(), "this test needs `setsid` on PATH");
    let setsid = setsid.unwrap_or_default();
    let mut cmd = sb.command(&setsid.display().to_string());
    // A run that waits for an answer that never comes is ended after a minute, not left to hang
    // the test run.
    let mut head = vec!["--fork".to_owned()];
    if let Some(timeout) = common::which("timeout") {
        head.extend([timeout.display().to_string(), "60".to_owned()]);
    }
    cmd.args(head).arg(program).args(args);
    cmd
}

/// `lunchroom mode strict` run under a pseudo-terminal made by `script`, with `answer` typed on it.
fn mode_in_a_terminal(sb: &common::Sandbox, answer: &str) -> Run {
    let script = common::which("script");
    assert!(script.is_some(), "this test needs `script` on PATH");
    let script = script.unwrap_or_default();
    let line = format!("'{}' mode strict", env!("CARGO_BIN_EXE_lunchroom"));
    let cmd = detached(
        sb,
        &script.display().to_string(),
        &["-qec", &line, "/dev/null"],
    );
    common::finish(cmd, answer)
}

fn hold_mode(sb: &common::Sandbox) -> Option<HoldMode> {
    sb.store()
        .and_then(|s| s.read().ok())
        .map(|m| m.hold_mode())
}

// §7::12 (A1.3) through the real system: a command only the user may run, started where
// the system gives it no controlling terminal, is refused for want of one, whatever is on its
// standard input: a `yes` piped to it is not the user's answer. The mode, the rate limit and the
// store stay as they were.
#[test]
fn a_user_command_with_no_controlling_terminal_is_refused() {
    let sb = common::Sandbox::new("terminal-tests");
    for args in [vec!["mode", "strict"], vec!["rate", "1000", "1"]] {
        let cmd = detached(&sb, env!("CARGO_BIN_EXE_lunchroom"), &args);
        let run = common::finish(cmd, "yes\n");
        assert!(run.stderr.contains("DENIED"), "{args:?}: {}", run.stderr);
        assert!(
            run.stderr.contains("no controlling terminal"),
            "{args:?}: {}",
            run.stderr
        );
        assert!(run.stdout.is_empty(), "{args:?}: {}", run.stdout);
        assert_eq!(hold_mode(&sb), Some(HoldMode::default()), "{args:?}");
    }
}

// §7::12 (A1.3) through the real system: run from a real terminal (a pseudo-terminal that
// `script` makes, as the controlling terminal of a session of its own) outside every guarded
// session, a command only the user may run changes nothing on a typed `yes`, which is all that a
// process of the user's own can type there: with no passphrase set it is denied with the command
// that sets one, and with one set (this account's verifier, when the host has one) `yes` is a
// wrong passphrase. (The passphrase itself is checked in `a_user_command_in_a_real_terminal_runs_
// only_on_the_passphrase`, which needs root.)
#[test]
fn a_user_command_in_a_real_terminal_does_not_run_on_yes() {
    let sb = common::Sandbox::new("terminal-tests");
    for answer in ["yes\n", "YES\n", "y\n", "\n"] {
        let run = mode_in_a_terminal(&sb, answer);
        assert!(run.stdout.contains("DENIED"), "{answer:?}: {}", run.stdout);
        assert!(
            run.stdout.contains("`lunchroom passphrase`")
                || run.stdout.contains("the passphrase was wrong")
                || run.stdout.contains("cannot be trusted"),
            "{answer:?}: {}",
            run.stdout
        );
        assert!(
            !run.stdout.contains("Type yes"),
            "{answer:?}: {}",
            run.stdout
        );
        assert_eq!(hold_mode(&sb), Some(HoldMode::default()), "{answer:?}");
    }
}

// §7::12 (A1.3) through the real system: a command only the user may run, typed in a
// pseudo-terminal that a recorded guarded session also holds, is refused for that and for nothing
// else. A stand-in Claude Code (a shell whose `CLAUDE_PID` is itself) shows the guard a prompt,
// so its process is recorded, and keeps running on the terminal. It is a sibling of the command,
// not an ancestor, so the parent-chain check passes; the terminal exists, so the missing-terminal
// check passes; the only A1.3 check left to refuse it is the one on the terminal of a guarded
// session, which comes before any passphrase is asked.
#[test]
fn a_user_command_in_a_guarded_sessions_terminal_is_refused() {
    let sb = common::Sandbox::new("terminal-tests");
    let prompt = serde_json::json!({
        "session_id": "s1", "cwd": sb.home().join("project"),
        "hook_event_name": "UserPromptSubmit", "prompt": "Start.", "prompt_id": "p1",
    });
    assert!(std::fs::write(sb.root.join("prompt.json"), prompt.to_string()).is_ok());
    let stand_in = "echo $$ > standin.pid\n\
         export CLAUDE_PID=$$ CLAUDE_CODE_SESSION_ATTENDED=1 CLAUDE_CODE_ENTRYPOINT=cli\n\
         \"$LR\" guard prompt < prompt.json > /dev/null 2>&1\n\
         : > recorded\n\
         sleep 30\n";
    assert!(std::fs::write(sb.root.join("standin.sh"), stand_in).is_ok());
    let program = env!("CARGO_BIN_EXE_lunchroom");
    let line = format!(
        "LR='{program}'; export LR; cd '{}'; bash standin.sh & i=0; \
         while [ ! -f recorded ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; \
         \"$LR\" mode strict; kill $(cat standin.pid)",
        sb.root.display()
    );
    let script = common::which("script");
    assert!(script.is_some(), "this test needs `script` on PATH");
    let script = script.unwrap_or_default();
    let cmd = detached(
        &sb,
        &script.display().to_string(),
        &["-qec", &line, "/dev/null"],
    );
    let run = common::finish(cmd, "\n");
    assert!(
        sb.root.join("recorded").exists(),
        "the stand-in's session was not recorded: {}",
        run.stdout
    );
    assert!(run.stdout.contains("DENIED"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("this command runs in the terminal of a guarded session"),
        "{}",
        run.stdout
    );
    assert!(
        !run.stdout.contains("under a guarded session")
            && !run.stdout.contains("no controlling terminal")
            && !run.stdout.contains("passphrase"),
        "{}",
        run.stdout
    );
    assert_eq!(hold_mode(&sb), Some(HoldMode::default()));
}

/// The real user id of this process.
fn uid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// A verifier file in `/etc/lunchroom`, made as root for this test; whatever was there before is
/// put back, and a folder the test made is removed, when it goes out of scope.
struct Verifier {
    file: PathBuf,
    earlier: Option<Vec<u8>>,
    made_folder: bool,
}

impl Verifier {
    /// Writes `line` as the verifier of the user running the test; `None` when it cannot.
    fn write(line: &str) -> Option<Self> {
        let folder = Path::new("/etc/lunchroom");
        let made_folder = !folder.exists();
        if made_folder {
            std::fs::create_dir(folder).ok()?;
        }
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o755)).ok()?;
        let file = folder.join(format!("{}.verifier", uid()?));
        let earlier = std::fs::read(&file).ok();
        let this = Self {
            file,
            earlier,
            made_folder,
        };
        this.set(line, 0o644)?;
        Some(this)
    }

    /// Replaces the file's text and mode.
    fn set(&self, line: &str, mode: u32) -> Option<()> {
        std::fs::write(&self.file, format!("{line}\n")).ok()?;
        std::fs::set_permissions(&self.file, std::fs::Permissions::from_mode(mode)).ok()
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        match &self.earlier {
            Some(bytes) => {
                let _ = std::fs::write(&self.file, bytes);
            }
            None => {
                let _ = std::fs::remove_file(&self.file);
            }
        }
        if self.made_folder {
            let _ = std::fs::remove_dir("/etc/lunchroom");
        }
    }
}

// §7::12 (A1.3) through the real system, as root. This writes `/etc/lunchroom`, so it is
// ignored in an ordinary run; CI runs it with sudo: `sudo -E cargo test --test terminal -- --ignored`.
// With a verifier root made for the user running the test, a command only the user may run, typed
// in a real terminal (a pseudo-terminal that `script` makes), carries out on the passphrase and
// only on it: a wrong passphrase, a `yes`, and a verifier that is not root's alone (another owner,
// or writable by its group) change nothing.
#[test]
#[ignore = "writes /etc/lunchroom: CI runs it as root, with sudo"]
fn a_user_command_in_a_real_terminal_runs_only_on_the_passphrase() {
    const PASSPHRASE: &str = "correct horse battery";
    assert_eq!(
        uid(),
        Some(0),
        "this test writes /etc/lunchroom: run it as root"
    );
    let line = lunchroom_core::passphrase::Verifier::new(PASSPHRASE, [9; 16], ITERATIONS).line();
    let written = Verifier::write(&line);
    assert!(
        written.is_some(),
        "the verifier could not be written under /etc/lunchroom"
    );
    let Some(verifier) = written else { return };
    // The passphrase runs the command.
    let sb = common::Sandbox::new("terminal-tests");
    let run = mode_in_a_terminal(&sb, &format!("{PASSPHRASE}\n"));
    assert!(!run.stdout.contains("DENIED"), "{}", run.stdout);
    assert_eq!(hold_mode(&sb), Some(HoldMode::Strict), "{}", run.stdout);
    // Anything else does not.
    for typed in [
        "wrong passphrase\n",
        "yes\n",
        "\n",
        "correct horse batter\n",
    ] {
        let sb = common::Sandbox::new("terminal-tests");
        let run = mode_in_a_terminal(&sb, typed);
        assert!(
            run.stdout
                .contains("the passphrase was wrong; nothing was changed"),
            "{typed:?}: {}",
            run.stdout
        );
        assert_eq!(hold_mode(&sb), Some(HoldMode::default()), "{typed:?}");
    }
    // A verifier that is not root's alone is no check: the right passphrase is not enough.
    let sb = common::Sandbox::new("terminal-tests");
    assert!(std::os::unix::fs::chown(&verifier.file, Some(65534), None).is_ok());
    let run = mode_in_a_terminal(&sb, &format!("{PASSPHRASE}\n"));
    assert!(run.stdout.contains("cannot be trusted"), "{}", run.stdout);
    assert_eq!(hold_mode(&sb), Some(HoldMode::default()), "{}", run.stdout);
    assert!(verifier.set(&line, 0o664).is_some());
    assert!(std::os::unix::fs::chown(&verifier.file, Some(0), None).is_ok());
    let run = mode_in_a_terminal(&sb, &format!("{PASSPHRASE}\n"));
    assert!(run.stdout.contains("cannot be trusted"), "{}", run.stdout);
    assert_eq!(hold_mode(&sb), Some(HoldMode::default()), "{}", run.stdout);
    // A link in its place is not followed.
    let target = sb.root.join("elsewhere.verifier");
    assert!(std::fs::write(&target, format!("{line}\n")).is_ok());
    assert!(std::fs::remove_file(&verifier.file).is_ok());
    assert!(std::os::unix::fs::symlink(&target, &verifier.file).is_ok());
    let run = mode_in_a_terminal(&sb, &format!("{PASSPHRASE}\n"));
    assert!(run.stdout.contains("cannot be trusted"), "{}", run.stdout);
    assert_eq!(hold_mode(&sb), Some(HoldMode::default()), "{}", run.stdout);
    let _ = std::fs::remove_file(&verifier.file);
}
