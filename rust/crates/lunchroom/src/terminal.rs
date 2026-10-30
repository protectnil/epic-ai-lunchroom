//! The user's confirmation, read from a terminal no guarded session owns (A1.3).
//!
//! Spec: §7 A1.3 (node `§7::12`): Lunchroom carries out `lunchroom approve`, `lunchroom yolo` and the
//! commands that change its configuration only after reading the user's confirmation from a
//! controlling terminal that no guarded harness process owns; a process with no controlling
//! terminal, inside a guarded harness's terminal, or with a guarded session in its parent chain is
//! denied. The confirmation is the user's passphrase, checked against a verifier that only root can
//! write (`/etc/lunchroom/<uid>.verifier`): a process the user's account runs, detached or not,
//! can open a pseudo-terminal of its own and type `yes`, but it cannot make a verifier that passes
//! or learn a passphrase it was not given. The checks run on a [`System`], so the rules are tested
//! with a fake one.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use lunchroom_core::mail::Mail;
use lunchroom_core::passphrase::{self, Verifier};

use crate::process;

/// The fewest PBKDF2 iterations a verifier may name, and the number a new one uses. Tests use one,
/// so a roll-call does not spend minutes in hashing; the product always uses the full number.
pub const ITERATIONS: u32 = if cfg!(test) {
    1
} else {
    passphrase::ITERATIONS
};

/// The folder the verifiers are in, owned by root.
const VERIFIER_DIR: &str = "/etc/lunchroom";

/// What [`System::verifier`] reports when the user has no verifier yet.
pub const NO_VERIFIER: &str = "no passphrase is set; run `lunchroom passphrase` in a terminal of \
                               your own to set one";

/// What the user is told when the passphrase could not be read: nothing is read unless the typed
/// characters can be hidden, so a missing `stty` ends here as well as a missing terminal.
pub const NO_SECRET_READ: &str = "this command has no controlling terminal to read the passphrase \
                                  from, or the typed characters cannot be hidden (it needs `stty`)";

/// The only folders a system program is looked for in, in this order. The user's `PATH` is never
/// searched: the program found runs with the user's terminal, and for `sudo` with their password.
const SYSTEM_FOLDERS: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// The first of `folders` that holds an executable regular file named `name`.
fn program_in(folders: &[&str], name: &str) -> Option<PathBuf> {
    folders.iter().map(|f| Path::new(f).join(name)).find(|p| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// `name` in the first of [`SYSTEM_FOLDERS`] that has it.
fn system_program(name: &str) -> Option<PathBuf> {
    program_in(&SYSTEM_FOLDERS, name)
}

/// What the user is told when the system has no `sudo`: the passphrase check is root's, and
/// `doas` and the like are not used.
fn no_sudo(target: &str) -> String {
    format!(
        "sudo was not found in {}, and `doas` is not supported, so Lunchroom cannot put the \
         passphrase check at {target}, which only root may write; install sudo (your account \
         needs the right to use it), then run `lunchroom passphrase`",
        SYSTEM_FOLDERS.join(", ")
    )
}

/// Where the verifier of user `uid` is.
#[must_use]
pub fn verifier_path(uid: u32) -> PathBuf {
    Path::new(VERIFIER_DIR).join(format!("{uid}.verifier"))
}

/// The path of the verifier as the user is told it, `<uid>` when the system does not give the
/// user id.
#[must_use]
pub fn verifier_shown(sys: &dyn System) -> String {
    sys.uid().map_or_else(
        || format!("{VERIFIER_DIR}/<uid>.verifier"),
        |uid| verifier_path(uid).display().to_string(),
    )
}

/// What the check needs from the system.
pub trait System {
    /// For each process above this one, nearest first: its key (`<pid>:<start time>`) and its
    /// program name.
    fn ancestors(&self) -> Vec<(Option<String>, String)>;
    /// This process's controlling terminal number; 0 when it has none.
    fn own_tty(&self) -> u64;
    /// The controlling terminal number of the harness process `key`, when that process still
    /// runs under that key.
    fn tty_of(&self, key: &str) -> Option<u64>;
    /// Writes `question` to the controlling terminal and reads one line from it; `None` when there
    /// is no controlling terminal to use.
    fn ask(&mut self, question: &str) -> Option<String>;
    /// The real user id of this process.
    fn uid(&self) -> Option<u32>;
    /// The text of the user's verifier, when it can be trusted: a regular file in a folder, both
    /// owned by root and writable by no one else. [`NO_VERIFIER`] when there is none; any other
    /// error says why the one there cannot be trusted.
    ///
    /// # Errors
    /// The reason there is no verifier to check against.
    fn verifier(&self) -> Result<String, String>;
    /// Writes `prompt` to the controlling terminal and reads one line from it with the typed
    /// characters not shown, without its newline; `None` when there is no controlling terminal
    /// to use.
    fn ask_secret(&mut self, prompt: &str) -> Option<String>;
    /// A salt of fresh random bytes for a new verifier.
    ///
    /// # Errors
    /// Why the system gave none.
    fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String>;
    /// Makes `line` the user's verifier, owned by root, which takes the user's own authority over
    /// the terminal (`sudo`); the folder is made too when it is not there.
    ///
    /// # Errors
    /// Why the verifier was not put in place.
    fn install_verifier(&mut self, line: &str) -> Result<(), String>;
    /// Why [`System::install_verifier`] cannot work on this system, found before the user is asked
    /// for a passphrase; `None` when nothing is known to stand in its way.
    fn verifier_blocker(&self) -> Option<String> {
        None
    }
}

/// Program names of the harnesses Lunchroom guards: a process under one of them is inside a
/// guarded session, whether or not a hook has recorded it yet.
const HARNESSES: [&str; 5] = ["claude", "codex", "opencode", "openclaw", "hermes"];

/// Checks that this command runs where the user's answer can be trusted: no guarded session in the
/// parent chain, a controlling terminal, and not the terminal of a guarded session (A1.3).
///
/// # Errors
/// The reason the command is denied.
pub fn check(mail: &Mail, sys: &dyn System) -> Result<(), String> {
    for (key, name) in sys.ancestors() {
        let recorded = key
            .as_deref()
            .is_some_and(|k| mail.process_session(k).is_some());
        if recorded || HARNESSES.contains(&name.as_str()) {
            return Err(format!(
                "this command runs under a guarded session ({name}); only the user, in a \
                 terminal outside every guarded session, can run it"
            ));
        }
    }
    let tty = sys.own_tty();
    if tty == 0 {
        return Err(
            "this command has no controlling terminal to read the user's answer from".to_owned(),
        );
    }
    if mail.harness_processes().any(|k| sys.tty_of(k) == Some(tty)) {
        return Err("this command runs in the terminal of a guarded session".to_owned());
    }
    Ok(())
}

/// Shows `question` and succeeds only when every A1.3 condition holds and the user types the
/// passphrase the verifier was made from. The passphrase is read with the typed characters not
/// shown.
///
/// # Errors
/// The reason the command is denied.
pub fn confirm(mail: &Mail, sys: &mut dyn System, question: &str) -> Result<(), String> {
    check(mail, sys)?;
    prove(sys, question)
}

/// As [`confirm`], except that a user who has no verifier yet confirms with `yes` this once: the
/// install that sets the first passphrase has nothing to check a passphrase against. A verifier
/// that is there but cannot be trusted is never passed over.
///
/// # Errors
/// The reason the command is denied.
pub fn confirm_or_begin(mail: &Mail, sys: &mut dyn System, question: &str) -> Result<(), String> {
    check(mail, sys)?;
    if sys.verifier().is_err_and(|reason| reason == NO_VERIFIER) {
        let answer = sys.ask(&format!("{question}No passphrase is set yet. Type yes: "));
        return match answer {
            Some(answer) if answer.trim().eq_ignore_ascii_case("yes") => Ok(()),
            Some(_) => Err("the answer was not yes; nothing was changed".to_owned()),
            None => Err(
                "this command has no controlling terminal to read the user's answer from"
                    .to_owned(),
            ),
        };
    }
    prove(sys, question)
}

/// The verifier the user's check is made against.
///
/// # Errors
/// The reason there is none that can be used.
pub fn trusted_verifier(sys: &dyn System) -> Result<Verifier, String> {
    let line = sys.verifier()?;
    Verifier::parse(&line, ITERATIONS).map_err(|why| {
        format!(
            "the passphrase check at {} cannot be used ({why}); remove it with `sudo rm {}` and \
             run `lunchroom passphrase` to set it again",
            verifier_shown(sys),
            verifier_shown(sys)
        )
    })
}

/// Shows `question`, asks for the passphrase and checks it.
fn prove(sys: &mut dyn System, question: &str) -> Result<(), String> {
    let verifier = trusted_verifier(sys)?;
    let Some(typed) = sys.ask_secret(&format!("{question}Passphrase: ")) else {
        return Err(NO_SECRET_READ.to_owned());
    };
    if verifier.matches(&typed) {
        Ok(())
    } else {
        Err("the passphrase was wrong; nothing was changed".to_owned())
    }
}

/// The real system: `/proc` and `/dev/tty`.
#[derive(Debug, Default)]
pub struct OsSystem;

impl System for OsSystem {
    fn ancestors(&self) -> Vec<(Option<String>, String)> {
        process::ancestors(std::process::id())
            .into_iter()
            .skip(1)
            .map(|pid| (process::key(pid), process::name(pid).unwrap_or_default()))
            .collect()
    }

    fn own_tty(&self) -> u64 {
        process::tty(std::process::id()).unwrap_or(0)
    }

    fn tty_of(&self, key: &str) -> Option<u64> {
        let pid: u32 = key.split(':').next()?.parse().ok()?;
        (process::key(pid).as_deref() == Some(key))
            .then(|| process::tty(pid))
            .flatten()
    }

    fn ask(&mut self, question: &str) -> Option<String> {
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        tty.write_all(question.as_bytes()).ok()?;
        tty.flush().ok()?;
        let mut line = String::new();
        BufReader::new(tty).read_line(&mut line).ok()?;
        Some(line)
    }

    fn uid(&self) -> Option<u32> {
        real_uid(&std::fs::read_to_string("/proc/self/status").ok()?)
    }

    fn verifier(&self) -> Result<String, String> {
        let uid = self
            .uid()
            .ok_or("the user id of this process cannot be read from /proc")?;
        let file = verifier_path(uid);
        let untrusted = |why: &str| {
            format!(
                "the passphrase check at {} cannot be trusted ({why}); `sudo rm {}` removes it, \
                 and `lunchroom passphrase` sets a new one",
                file.display(),
                file.display()
            )
        };
        // The folder, then the file as it is on disk: a link is never followed.
        match std::fs::symlink_metadata(VERIFIER_DIR) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(NO_VERIFIER.to_owned());
            }
            Err(e) => return Err(untrusted(&format!("{VERIFIER_DIR} cannot be read: {e}"))),
            Ok(m) if !folder_trusted(m.file_type(), m.uid(), m.mode()) => {
                return Err(untrusted(&format!(
                    "{VERIFIER_DIR} is not a folder owned by root and writable by no one else"
                )));
            }
            Ok(_) => {}
        }
        match std::fs::symlink_metadata(&file) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(NO_VERIFIER.to_owned());
            }
            Err(e) => return Err(untrusted(&format!("it cannot be read: {e}"))),
            Ok(m) if !regular_file(m.file_type()) => {
                return Err(untrusted("it is not a regular file"));
            }
            Ok(_) => {}
        }
        // The facts are read again from the open file, so a file swapped in between is judged as
        // it is.
        let mut opened = std::fs::File::open(&file)
            .map_err(|e| untrusted(&format!("it cannot be read: {e}")))?;
        let facts = opened
            .metadata()
            .map_err(|e| untrusted(&format!("it cannot be read: {e}")))?;
        if !file_trusted(facts.file_type(), facts.uid(), facts.mode()) {
            return Err(untrusted(
                "it is not a regular file owned by root and writable by no one else",
            ));
        }
        let mut text = String::new();
        (&mut opened)
            .take(4096)
            .read_to_string(&mut text)
            .map_err(|e| untrusted(&format!("it cannot be read: {e}")))?;
        Ok(text)
    }

    fn ask_secret(&mut self, prompt: &str) -> Option<String> {
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        tty.write_all(prompt.as_bytes()).ok()?;
        tty.flush().ok()?;
        // Nothing is read while the typed characters would show, and they show again whatever
        // happens.
        let line = read_hidden(
            |arg| stty(&tty, arg),
            || {
                let mut line = String::new();
                let read = BufReader::new(tty.try_clone().ok()?).read_line(&mut line);
                read.ok().filter(|n| *n > 0).map(|_| line)
            },
        );
        let _ = tty.write_all(b"\n");
        line.map(|mut line| {
            if line.ends_with('\n') {
                line.pop();
            }
            line
        })
    }

    fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String> {
        let mut salt = [0u8; passphrase::SALT_BYTES];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut salt))
            .map_err(|e| format!("random bytes cannot be read: {e}"))?;
        Ok(salt)
    }

    fn install_verifier(&mut self, line: &str) -> Result<(), String> {
        let uid = self
            .uid()
            .ok_or("the user id of this process cannot be read from /proc")?;
        let target = verifier_path(uid).display().to_string();
        let (sudo_program, install_program) = system_programs(&target)?;
        // `sudo` asks for the user's password on the terminal, and reads the verifier from a pipe:
        // there is no file of the user's own that another process of the account could swap while
        // the password is being typed.
        let sudo = |what: &str, args: &[&str], input: Option<&str>| -> Result<(), String> {
            let tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .map_err(|e| format!("the terminal cannot be opened: {e}"))?;
            let own = |tty: &std::fs::File| {
                tty.try_clone()
                    .map_err(|e| format!("the terminal cannot be used: {e}"))
            };
            let mut command = std::process::Command::new(&sudo_program);
            command
                .args(args)
                .stdin(match input {
                    Some(_) => Stdio::piped(),
                    None => Stdio::from(own(&tty)?),
                })
                .stdout(Stdio::from(own(&tty)?))
                .stderr(Stdio::from(tty));
            let mut child = command
                .spawn()
                .map_err(|e| format!("sudo cannot be started: {e}"))?;
            if let (Some(text), Some(mut pipe)) = (input, child.stdin.take()) {
                pipe.write_all(text.as_bytes())
                    .map_err(|e| format!("{what}: sudo did not take the passphrase check: {e}"))?;
            }
            let status = child
                .wait()
                .map_err(|e| format!("{what}: sudo cannot be waited for: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("{what} did not succeed ({status})"))
            }
        };
        let text = format!("{line}\n");
        let install_program = install_program.display().to_string();
        let [folder, file] = install_steps(&install_program, &target);
        sudo(&format!("making {VERIFIER_DIR}"), &folder, None)?;
        sudo(&format!("installing {target}"), &file, Some(text.as_str()))
    }

    fn verifier_blocker(&self) -> Option<String> {
        system_programs(&verifier_shown(self)).err()
    }
}

/// `sudo` and `install` as the system has them, or why the verifier cannot be put in place.
fn system_programs(target: &str) -> Result<(PathBuf, PathBuf), String> {
    let sudo = system_program("sudo").ok_or_else(|| no_sudo(target))?;
    let install = system_program("install").ok_or_else(|| {
        format!(
            "`install` was not found in {}, so Lunchroom cannot put the passphrase check at \
             {target}",
            SYSTEM_FOLDERS.join(", ")
        )
    })?;
    Ok((sudo, install))
}

/// The two commands `sudo` runs to put the verifier at `target` (A1.3): its folder, then the file,
/// each owned by root and writable by no group or other user; the folder can be entered and the
/// file read by every user, so each user's own Lunchroom can check a passphrase against it.
/// `install` is the program that does it, found in a system folder.
fn install_steps<'a>(install: &'a str, target: &'a str) -> [Vec<&'a str>; 2] {
    [
        vec![
            install,
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "755",
            VERIFIER_DIR,
        ],
        vec![
            install,
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "644",
            "/dev/stdin",
            target,
        ],
    ]
}

/// The real user id in the text of `/proc/<pid>/status`: the first number on its `Uid:` line.
fn real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Whether a file or folder is owned by root and has no write permission for its group or others.
fn root_only(owner: u32, mode: u32) -> bool {
    owner == 0 && mode & 0o022 == 0
}

/// Whether a folder, as it is on disk (a link is not followed), is root's alone.
fn folder_trusted(kind: std::fs::FileType, owner: u32, mode: u32) -> bool {
    kind.is_dir() && root_only(owner, mode)
}

/// Whether what is on disk is a regular file: a link, a folder or a device is not.
fn regular_file(kind: std::fs::FileType) -> bool {
    kind.is_file()
}

/// Whether a regular file is root's alone.
fn file_trusted(kind: std::fs::FileType, owner: u32, mode: u32) -> bool {
    regular_file(kind) && root_only(owner, mode)
}

/// Reads with the typed characters hidden: `stty` is asked for `-echo`, nothing is read unless
/// that succeeded, and `echo` is asked for again whatever the read gave.
fn read_hidden(
    mut stty: impl FnMut(&str) -> bool,
    read: impl FnOnce() -> Option<String>,
) -> Option<String> {
    let line = stty("-echo").then(read).flatten();
    let _ = stty("echo");
    line
}

/// Runs `stty <arg>` on `tty`; whether it succeeded. Without an `stty` in a system folder it did
/// not, so the passphrase is not read.
fn stty(tty: &std::fs::File, arg: &str) -> bool {
    let Some(program) = system_program("stty") else {
        return false;
    };
    tty.try_clone().is_ok_and(|own| {
        std::process::Command::new(program)
            .arg(arg)
            .stdin(Stdio::from(own))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

/// What the tests of this crate share about a user who has set a passphrase.
#[cfg(test)]
pub mod fake {
    use lunchroom_core::passphrase::Verifier;

    /// The passphrase the fake user set.
    pub const PASSPHRASE: &str = "correct horse battery";

    /// The user's verifier, as the system would give it.
    pub fn verifier() -> String {
        Verifier::new(PASSPHRASE, [7; 16], super::ITERATIONS).line()
    }

    /// What the fake user types for a test that gives `answer`: the passphrase for a yes, and a
    /// passphrase that is not theirs for anything else.
    pub fn typed(answer: &str) -> String {
        if answer.trim().eq_ignore_ascii_case("yes") {
            PASSPHRASE.to_owned()
        } else {
            format!("not {PASSPHRASE}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunchroom_core::identity::{Harness, Identity};

    struct Fake {
        ancestors: Vec<(Option<String>, String)>,
        tty: u64,
        harness_ttys: Vec<(String, u64)>,
        answer: Option<String>,
        secret: Option<String>,
        verifier: Result<String, String>,
        /// Whether anything at all was asked of the user.
        asked: bool,
        /// Whether the passphrase was asked for.
        secret_asked: bool,
        prompts: Vec<String>,
    }

    impl System for Fake {
        fn ancestors(&self) -> Vec<(Option<String>, String)> {
            self.ancestors.clone()
        }
        fn own_tty(&self) -> u64 {
            self.tty
        }
        fn tty_of(&self, key: &str) -> Option<u64> {
            self.harness_ttys
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, t)| *t)
        }
        fn ask(&mut self, question: &str) -> Option<String> {
            self.asked = true;
            self.prompts.push(question.to_owned());
            self.answer.clone()
        }
        fn uid(&self) -> Option<u32> {
            Some(1000)
        }
        fn verifier(&self) -> Result<String, String> {
            self.verifier.clone()
        }
        fn ask_secret(&mut self, prompt: &str) -> Option<String> {
            self.asked = true;
            self.secret_asked = true;
            self.prompts.push(prompt.to_owned());
            self.secret.clone()
        }
        fn salt(&mut self) -> Result<[u8; passphrase::SALT_BYTES], String> {
            Ok([5; passphrase::SALT_BYTES])
        }
        fn install_verifier(&mut self, _line: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn user_shell() -> Fake {
        Fake {
            ancestors: vec![
                (Some("100:5".to_owned()), "bash".to_owned()),
                (Some("90:1".to_owned()), "sshd".to_owned()),
            ],
            tty: 34816,
            harness_ttys: vec![("200:7".to_owned(), 34817)],
            answer: Some("yes\n".to_owned()),
            secret: Some(fake::PASSPHRASE.to_owned()),
            verifier: Ok(fake::verifier()),
            asked: false,
            secret_asked: false,
            prompts: Vec::new(),
        }
    }

    fn mail_with_harness() -> Mail {
        let mut m = Mail::default();
        m.observe_process(
            "200:7",
            std::path::Path::new("/"),
            &Identity::new(Harness::ClaudeCode, "s1"),
        );
        m
    }

    // §7::12 — the user, in a terminal of their own, typing the passphrase: confirmed. The
    // question is shown with the prompt for the passphrase, and nothing else is asked.
    #[test]
    fn user_terminal_and_the_passphrase_confirms() {
        let mut sys = user_shell();
        assert_eq!(
            confirm(&mail_with_harness(), &mut sys, "Set the mode?\n"),
            Ok(())
        );
        assert!(sys.secret_asked);
        assert_eq!(sys.prompts, ["Set the mode?\nPassphrase: "]);
    }

    // §7::12 — anything but the passphrase changes nothing: not yes, not the passphrase in other
    // capitals or with a space, not part of it, not nothing. A yes is no confirmation.
    #[test]
    fn any_other_passphrase_is_refused() {
        for typed in [
            "",
            "yes",
            "YES",
            "no",
            "Correct horse battery",
            " correct horse battery",
            "correct horse battery ",
            "correct horse batter",
            "correct horse battery!",
        ] {
            let mut sys = user_shell();
            sys.secret = Some(typed.to_owned());
            assert_eq!(
                confirm(&mail_with_harness(), &mut sys, "q"),
                Err("the passphrase was wrong; nothing was changed".to_owned()),
                "{typed:?}"
            );
            assert!(sys.secret_asked, "{typed:?}");
        }
    }

    // §7::12 — a guarded session in the parent chain, recorded or known by its program name, is
    // denied before anything is asked, a passphrase least of all.
    #[test]
    fn guarded_session_in_parent_chain_is_refused() {
        for (key, name) in [
            ("200:7", "node"),
            ("300:9", "claude"),
            ("301:9", "codex"),
            ("302:9", "hermes"),
        ] {
            let mut sys = user_shell();
            sys.ancestors
                .insert(1, (Some(key.to_owned()), name.to_owned()));
            assert!(
                confirm(&mail_with_harness(), &mut sys, "q").is_err(),
                "{name}"
            );
            assert!(!sys.asked, "{name}");
            let mut sys = user_shell();
            sys.ancestors
                .insert(1, (Some(key.to_owned()), name.to_owned()));
            assert!(
                confirm_or_begin(&mail_with_harness(), &mut sys, "q").is_err(),
                "{name}"
            );
            assert!(!sys.asked, "{name}");
        }
    }

    // §7::12 — no controlling terminal, or the terminal of a guarded session, is denied before
    // anything is asked; a terminal that gives no passphrase is denied too.
    #[test]
    fn no_terminal_or_a_guarded_sessions_terminal_is_refused() {
        let mut sys = user_shell();
        sys.tty = 0;
        assert!(confirm(&mail_with_harness(), &mut sys, "q").is_err());
        assert!(!sys.asked);
        let mut sys = user_shell();
        sys.tty = 34817;
        assert!(confirm(&mail_with_harness(), &mut sys, "q").is_err());
        assert!(!sys.asked);
        let mut sys = user_shell();
        sys.secret = None;
        assert!(confirm(&mail_with_harness(), &mut sys, "q").is_err());
        assert!(sys.secret_asked);
    }

    // §7::12 — with no passphrase set, a command only the user may run is denied, with the
    // command that sets one, and neither the passphrase nor a yes is asked for.
    #[test]
    fn no_verifier_is_refused_with_the_command_that_sets_one() {
        let mut sys = user_shell();
        sys.verifier = Err(NO_VERIFIER.to_owned());
        let reason = confirm(&mail_with_harness(), &mut sys, "q")
            .err()
            .unwrap_or_default();
        assert!(reason.contains("`lunchroom passphrase`"), "{reason}");
        assert!(!sys.asked);
    }

    // §7::12 — a verifier the system reports as not root's alone (or one that cannot be read) is
    // denied as it is reported, and nothing is asked: a file the user's account could have written
    // proves nothing.
    #[test]
    fn a_verifier_not_owned_by_root_is_refused() {
        let reported = "the passphrase check at /etc/lunchroom/1000.verifier cannot be trusted \
                        (it is not a regular file owned by root and writable by no one else)";
        let mut sys = user_shell();
        sys.verifier = Err(reported.to_owned());
        assert_eq!(
            confirm(&mail_with_harness(), &mut sys, "q"),
            Err(reported.to_owned())
        );
        assert!(!sys.asked);
        let mut sys = user_shell();
        sys.verifier = Err(reported.to_owned());
        assert_eq!(
            confirm_or_begin(&mail_with_harness(), &mut sys, "q"),
            Err(reported.to_owned())
        );
        assert!(!sys.asked);
    }

    // §7::12 — a verifier line that is not the format (a different scheme, too few iterations, a
    // hash of the wrong length, two lines) is denied before the passphrase is asked.
    #[test]
    fn a_malformed_verifier_is_refused() {
        let good = fake::verifier();
        for line in [
            String::new(),
            "garbage".to_owned(),
            good.replace("pbkdf2-sha256", "pbkdf2-sha1"),
            good.replace("$1$", "$0$"),
            good[..good.len() - 2].to_owned(),
            format!("{good}\n{good}"),
            format!("{good}$x"),
        ] {
            let mut sys = user_shell();
            sys.verifier = Ok(line.clone());
            let reason = confirm(&mail_with_harness(), &mut sys, "q")
                .err()
                .unwrap_or_default();
            assert!(reason.contains("cannot be used"), "{line:?}: {reason}");
            assert!(
                reason.contains("`lunchroom passphrase`"),
                "{line:?}: {reason}"
            );
            assert!(!sys.asked, "{line:?}");
        }
    }

    // §7::12 — the install that sets the first passphrase confirms with yes, and only while there
    // is no verifier; with one, it asks for the passphrase and a yes is nothing; a verifier that
    // cannot be trusted is not passed over.
    #[test]
    fn only_the_first_install_confirms_with_yes() {
        let mail = mail_with_harness();
        let mut sys = user_shell();
        sys.verifier = Err(NO_VERIFIER.to_owned());
        assert_eq!(confirm_or_begin(&mail, &mut sys, "q\n"), Ok(()));
        assert!(!sys.secret_asked);
        assert_eq!(sys.prompts, ["q\nNo passphrase is set yet. Type yes: "]);
        for answer in ["no\n", "y\n", ""] {
            let mut sys = user_shell();
            sys.verifier = Err(NO_VERIFIER.to_owned());
            sys.answer = Some(answer.to_owned());
            assert!(
                confirm_or_begin(&mail, &mut sys, "q").is_err(),
                "{answer:?}"
            );
        }
        let mut sys = user_shell();
        sys.verifier = Err(NO_VERIFIER.to_owned());
        sys.answer = None;
        assert!(confirm_or_begin(&mail, &mut sys, "q").is_err());
        // With a verifier the passphrase is asked for, and the yes is never asked.
        let mut sys = user_shell();
        sys.secret = Some("yes".to_owned());
        assert!(confirm_or_begin(&mail, &mut sys, "q").is_err());
        assert!(sys.secret_asked);
        assert_eq!(sys.prompts, ["qPassphrase: "]);
        let mut sys = user_shell();
        assert_eq!(confirm_or_begin(&mail, &mut sys, "q"), Ok(()));
        // A verifier that cannot be trusted is no verifier to begin with.
        let mut sys = user_shell();
        sys.verifier = Err("the passphrase check cannot be trusted".to_owned());
        assert!(confirm_or_begin(&mail, &mut sys, "q").is_err());
        assert!(!sys.asked);
    }

    // §7::12 — root's alone: the owner is root and neither the group nor others may write.
    #[test]
    fn a_file_is_root_only_when_root_owns_it_and_no_one_else_writes() {
        for (owner, mode, expected) in [
            (0, 0o100_644, true),
            (0, 0o040_755, true),
            (0, 0o100_600, true),
            (0, 0o100_664, false),
            (0, 0o100_646, false),
            (0, 0o100_666, false),
            (0, 0o040_775, false),
            (0, 0o040_757, false),
            (1000, 0o100_644, false),
            (1000, 0o100_600, false),
            (1, 0o040_755, false),
        ] {
            assert_eq!(root_only(owner, mode), expected, "{owner} {mode:o}");
        }
    }

    // §7::19 — the passphrase is typed with echo off: `-echo` is set before anything is
    // read, `echo` is set again after the read, and also when the read gives nothing; when echo
    // cannot be turned off, nothing is read at all.
    #[test]
    fn the_passphrase_is_read_with_echo_off_and_echo_is_restored() {
        let run = |hide_ok: bool, typed: Option<&str>| {
            let log = std::cell::RefCell::new(Vec::<String>::new());
            let got = read_hidden(
                |arg| {
                    log.borrow_mut().push(format!("stty {arg}"));
                    hide_ok || arg != "-echo"
                },
                || {
                    log.borrow_mut().push("read".to_owned());
                    typed.map(str::to_owned)
                },
            );
            (got, log.into_inner())
        };
        let (got, log) = run(true, Some("correct horse battery"));
        assert_eq!(got.as_deref(), Some("correct horse battery"));
        assert_eq!(log, ["stty -echo", "read", "stty echo"]);
        // The read fails or ends: echo is restored all the same.
        let (got, log) = run(true, None);
        assert_eq!(got, None);
        assert_eq!(log, ["stty -echo", "read", "stty echo"]);
        // Echo cannot be turned off: the passphrase is never read, and echo is asked for again.
        let (got, log) = run(false, Some("correct horse battery"));
        assert_eq!(got, None);
        assert_eq!(log, ["stty -echo", "stty echo"]);
    }

    // §7::19, §7::24 — sudo, install and stty are looked for only in the fixed system
    // folders, in order, and only as executable regular files: an earlier folder wins, a folder
    // with no such file, a non-executable file or a folder is passed over, and nothing found is
    // `None` (never a search of the user's PATH).
    #[test]
    fn system_programs_are_found_only_in_the_fixed_folders_in_order() {
        let root = std::env::temp_dir().join(format!("lunchroom-programs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs = ["a", "b", "c"].map(|d| root.join(d));
        for d in &dirs {
            assert!(std::fs::create_dir_all(d).is_ok());
        }
        let put = |dir: &Path, name: &str, mode: u32| {
            let file = dir.join(name);
            assert!(std::fs::write(&file, "#!/bin/sh\n").is_ok());
            assert!(std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).is_ok());
        };
        put(&dirs[0], "plain", 0o644);
        assert!(std::fs::create_dir_all(dirs[0].join("folder")).is_ok());
        put(&dirs[1], "plain", 0o755);
        put(&dirs[1], "both", 0o755);
        put(&dirs[2], "both", 0o755);
        let names: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        let folders: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(program_in(&folders, "both"), Some(dirs[1].join("both")));
        assert_eq!(program_in(&folders, "plain"), Some(dirs[1].join("plain")));
        assert_eq!(program_in(&folders, "folder"), None);
        assert_eq!(program_in(&folders, "absent"), None);
        assert_eq!(program_in(&[], "both"), None);
        let _ = std::fs::remove_dir_all(&root);
        // The folders are the four system ones; the user's PATH is not among them.
        assert_eq!(SYSTEM_FOLDERS, ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]);
    }

    // §7::19 — a system with no sudo is told so, that doas is not supported and what to
    // do; the passphrase is not read when it cannot be hidden.
    #[test]
    fn a_system_with_no_sudo_is_told_what_to_do() {
        let text = no_sudo("/etc/lunchroom/1000.verifier");
        for part in [
            "sudo was not found in /usr/bin, /bin, /usr/sbin, /sbin",
            "`doas` is not supported",
            "/etc/lunchroom/1000.verifier",
            "install sudo",
            "`lunchroom passphrase`",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
        assert!(NO_SECRET_READ.contains("`stty`"));
    }

    // §7::24 and §7::20 — the verifier is put in place readable by every user (its
    // folder entered by every user), owned by root and writable by no group or other user.
    #[test]
    fn the_verifier_is_installed_readable_by_every_user_and_root_s_alone() {
        let [folder, file] = install_steps("/bin/install", "/etc/lunchroom/1000.verifier");
        assert_eq!((folder[0], file[0]), ("/bin/install", "/bin/install"));
        let mode = |step: &[&str]| {
            step.iter()
                .position(|a| *a == "-m")
                .and_then(|k| step.get(k + 1))
                .and_then(|m| u32::from_str_radix(m, 8).ok())
        };
        let owner = |step: &[&str]| step.windows(2).any(|w| w == ["-o", "root"]).then_some(0);
        assert_eq!(file.last(), Some(&"/etc/lunchroom/1000.verifier"));
        assert_eq!(folder.last(), Some(&VERIFIER_DIR));
        let modes = (mode(&file), mode(&folder));
        assert!(
            modes.0.is_some() && modes.1.is_some(),
            "{file:?} {folder:?}"
        );
        let (Some(file_mode), Some(folder_mode)) = modes else {
            return;
        };
        assert_eq!(file_mode & 0o444, 0o444, "{file_mode:o}");
        assert_eq!(folder_mode & 0o555, 0o555, "{folder_mode:o}");
        for (step, m) in [(&file, file_mode), (&folder, folder_mode)] {
            assert_eq!(owner(step), Some(0), "{step:?}");
            assert!(root_only(0, m), "{m:o}");
        }
    }

    // §7::20 — the verifier's folder and the verifier are each root's alone: owned by
    // root and writable by neither group nor others. Each failure refuses on its own; a link, a
    // folder or anything but a regular file is no verifier.
    #[test]
    fn the_verifier_and_its_folder_must_each_be_root_s_alone() {
        let scratch = std::env::temp_dir().join(format!("lunchroom-kinds-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap_or_default();
        let file = scratch.join("file");
        std::fs::write(&file, "x").unwrap_or_default();
        let link = scratch.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap_or_default();
        let kind = |p: &std::path::Path| std::fs::symlink_metadata(p).map(|m| m.file_type()).ok();
        let kinds = (kind(&scratch), kind(&file), kind(&link));
        assert!(
            kinds.0.is_some() && kinds.1.is_some() && kinds.2.is_some(),
            "{kinds:?}"
        );
        let (Some(dir_kind), Some(file_kind), Some(link_kind)) = kinds else {
            return;
        };
        // The positive cases.
        assert!(folder_trusted(dir_kind, 0, 0o040_755));
        assert!(file_trusted(file_kind, 0, 0o100_644));
        assert!(file_trusted(file_kind, 0, 0o100_600));
        // The folder: not owned by root; group-writable; other-writable; not a folder.
        assert!(!folder_trusted(dir_kind, 1000, 0o040_755));
        assert!(!folder_trusted(dir_kind, 0, 0o040_775));
        assert!(!folder_trusted(dir_kind, 0, 0o040_757));
        assert!(!folder_trusted(file_kind, 0, 0o040_755));
        assert!(!folder_trusted(link_kind, 0, 0o040_755));
        // The file: not owned by root; group-writable; other-writable.
        assert!(!file_trusted(file_kind, 1000, 0o100_644));
        assert!(!file_trusted(file_kind, 0, 0o100_664));
        assert!(!file_trusted(file_kind, 0, 0o100_646));
        // The file as a symbolic link (read as it is on disk, never followed), or a folder.
        assert!(!file_trusted(link_kind, 0, 0o100_644));
        assert!(!regular_file(link_kind));
        assert!(!file_trusted(dir_kind, 0, 0o100_644));
        std::fs::remove_dir_all(&scratch).unwrap_or_default();
    }

    // The real user id is the first number on the `Uid:` line of `/proc/<pid>/status` (the real
    // one, before the effective, saved and file-system ids), and the user's verifier is named by it.
    #[test]
    fn the_real_user_id_is_the_first_on_the_uid_line() {
        let status =
            "Name:\tlunchroom\nUmask:\t0022\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(real_uid(status), Some(1000));
        assert_eq!(real_uid("Uid:\t0\t1000\t1000\t1000\n"), Some(0));
        assert_eq!(real_uid("Gid:\t1000\n"), None);
        assert_eq!(real_uid("Uid:\n"), None);
        assert_eq!(real_uid("Uid:\tx\n"), None);
        assert_eq!(real_uid(""), None);
        assert_eq!(
            verifier_path(1000),
            std::path::PathBuf::from("/etc/lunchroom/1000.verifier")
        );
        // This process reports its own.
        assert!(OsSystem.uid().is_some());
        assert_eq!(
            OsSystem.uid(),
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| real_uid(&s))
        );
    }

    /// The real system's view of processes, with the terminal facts of a user's shell and the
    /// user's passphrase given.
    struct RealProcesses {
        tty: u64,
    }

    impl System for RealProcesses {
        fn ancestors(&self) -> Vec<(Option<String>, String)> {
            user_shell().ancestors
        }
        fn own_tty(&self) -> u64 {
            self.tty
        }
        fn tty_of(&self, key: &str) -> Option<u64> {
            OsSystem.tty_of(key)
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
            Ok([5; passphrase::SALT_BYTES])
        }
        fn install_verifier(&mut self, _line: &str) -> Result<(), String> {
            Ok(())
        }
    }

    // §7::12 (A1.3), `process.rs`: a process is named by its pid and its start time, so a pid the
    // system reuses never names an earlier process. A key with this process's pid and any other
    // start time (later, earlier, none, not a number) is not this process: its terminal is not
    // read, and a process recorded under it is not taken for one running now; a pid nothing runs
    // under is no process at all.
    #[test]
    fn a_reused_pid_is_not_the_recorded_process() {
        let me = std::process::id();
        let key = process::key(me).unwrap_or_default();
        let (pid, start) = key.split_once(':').unwrap_or_default();
        assert_eq!(pid, me.to_string());
        let start: u64 = start.parse().unwrap_or_default();
        assert_ne!(start, 0, "{key}");
        // The process's own key names it.
        assert_eq!(OsSystem.tty_of(&key), process::tty(me));
        for reused in [
            format!("{me}:{}", start + 1),
            format!("{me}:{}", start - 1),
            format!("{me}:0"),
            format!("{me}:"),
            format!("{me}:x"),
            me.to_string(),
            format!("{me}:{start}:{start}"),
            format!("{me}: {start}"),
        ] {
            assert_eq!(OsSystem.tty_of(&reused), None, "{reused}");
        }
        assert_eq!(OsSystem.tty_of(&format!("{}:{start}", u32::MAX)), None);
        // A recorded harness process whose pid is this process's but whose start time is not: its
        // terminal is none, so it does not share the user's terminal. Recorded under the right
        // key, and in the terminal the user answers from, it does.
        let own = process::tty(me).unwrap_or_default();
        let mut mail = Mail::default();
        let who = Identity::new(Harness::ClaudeCode, "s1");
        mail.observe_process(
            &format!("{me}:{}", start + 1),
            std::path::Path::new("/"),
            &who,
        );
        let shared = own.max(34816);
        assert_eq!(
            confirm(&mail, &mut RealProcesses { tty: shared }, "q"),
            Ok(())
        );
        if own != 0 {
            let mut mail = Mail::default();
            mail.observe_process(&key, std::path::Path::new("/"), &who);
            assert!(confirm(&mail, &mut RealProcesses { tty: own }, "q").is_err());
        }
    }

    // §7::12 (A1.3): a harness is recognised in the parent chain by the key a hook recorded for it,
    // pid and start time together. The same pid under another start time is a different process:
    // it is not the recorded session, however the ancestors are named.
    #[test]
    fn a_pid_recorded_with_another_start_time_is_not_a_guarded_ancestor() {
        let mail = mail_with_harness();
        for (key, refused) in [
            ("200:7", true),
            ("200:8", false),
            ("200:6", false),
            ("201:7", false),
        ] {
            let mut sys = user_shell();
            sys.ancestors
                .insert(1, (Some(key.to_owned()), "node".to_owned()));
            assert_eq!(confirm(&mail, &mut sys, "q").is_err(), refused, "{key}");
            assert_eq!(sys.asked, !refused, "{key}");
        }
        // A harness process under its recorded key in the user's terminal refuses; the same pid
        // reused (another start time) in that terminal is not a guarded session's terminal.
        let mut sys = user_shell();
        sys.tty = 34817;
        assert!(confirm(&mail, &mut sys, "q").is_err());
        let mut sys = user_shell();
        sys.tty = 34817;
        sys.harness_ttys = vec![("200:8".to_owned(), 34817)];
        assert_eq!(confirm(&mail, &mut sys, "q"), Ok(()));
    }
}
