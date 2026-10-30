//! The Lunchroom lines of the six printed cards, built from the vocabulary table.
//!
//! Spec: §16 (the product prints each card's Lunchroom line with the real event's agent names and
//! times), §1 V1.2 (the words come from the one table), §2 R1.3 and R1.4, §3 R2.2, §4 R3.2.

use crate::loops::LOOP_COUNT;
use crate::vocab::{AgentState, Reason, Verdict, Word};

/// A table word in sentence case, as the cards print a verdict at the start of a sentence.
fn sentence(word: &str) -> String {
    let lower = word.to_lowercase();
    let mut cs = lower.chars();
    cs.next()
        .map(|c| c.to_uppercase().chain(cs).collect())
        .unwrap_or_default()
}

/// Card 1: "Claude is HELD."
#[must_use]
pub fn held(agent: &str) -> String {
    format!("{agent} is {}.", AgentState::Held.word())
}

/// Card 2: "Denied. Asked for a secret." (L1.4).
#[must_use]
pub fn asked_for_secret() -> String {
    format!("{}. Asked for a secret.", sentence(Verdict::Denied.word()))
}

/// Card 3: "8-message loop. Conversation halted." (R1.3).
#[must_use]
pub fn loop_halted() -> String {
    format!(
        "{LOOP_COUNT}-message {}. {}",
        Reason::Loop.word(),
        conversation_halted()
    )
}

/// What a sender to a HALTED pair is told: "Conversation halted." (R1.4).
#[must_use]
pub fn conversation_halted() -> String {
    format!("Conversation {}.", Word::Halted.text().to_lowercase())
}

/// What an approved call lets the agent do, for card 4's line: a shell command with a `merge` or
/// `push` subcommand is that verb (`git merge`, `git push`, `gh pr merge`); another shell command is
/// "run <program>"; another tool is "use <tool>".
#[must_use]
pub fn action_of(tool: &str, input: &serde_json::Value) -> String {
    if tool == "Bash" {
        let command = input["command"].as_str().unwrap_or_default();
        let words: Vec<&str> = command.split_whitespace().collect();
        // The subcommand of `git` or `gh`: the words after the program up to the first option, so
        // an argument never counts and another program's first argument is not a subcommand.
        let sub: Vec<&str> = words
            .iter()
            .skip(1)
            .take_while(|w| !w.starts_with('-'))
            .take(2)
            .copied()
            .collect();
        let program = words
            .first()
            .and_then(|p| p.rsplit('/').next())
            .unwrap_or_default();
        let verb = match (program, sub.as_slice()) {
            ("git", [v, ..]) if matches!(*v, "merge" | "push") => Some(*v),
            ("gh", ["pr", "merge", ..]) => Some("merge"),
            _ => None,
        };
        if let Some(verb) = verb {
            return verb.to_owned();
        }
        return format!("run {}", plain_name(program).unwrap_or("a command"));
    }
    format!("use {}", plain_name(tool).unwrap_or("a tool"))
}

/// A name the agent chose, shown on the user's screen only when it is a plain program or tool name:
/// ASCII letters, digits, `.`, `_`, `+` and `-`, at most 32 characters.
fn plain_name(name: &str) -> Option<&str> {
    (!name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')))
    .then_some(name)
}

/// Card 4: "Granted. Codex can merge." (A2).
#[must_use]
pub fn granted(agent: &str, action: &str) -> String {
    format!(
        "{}. {agent} can {action}.",
        sentence(Verdict::Granted.word())
    )
}

/// Card 5: "YOLO authorized until 14:00 UTC." for an end time given in seconds since the Unix
/// epoch (R2.2).
#[must_use]
pub fn yolo_until(end_unix_secs: u64) -> String {
    let day = end_unix_secs % 86_400;
    format!(
        "{} authorized until {:02}:{:02} UTC.",
        Word::Yolo.text(),
        day / 3_600,
        day % 3_600 / 60
    )
}

/// Card 6: "Mistral is UNGUARDED." (R3.2).
#[must_use]
pub fn unguarded(agent: &str) -> String {
    format!("{agent} is {}.", AgentState::Unguarded.word())
}

/// "<agent> is STOPPED." (R3.2).
#[must_use]
pub fn stopped(agent: &str) -> String {
    format!("{agent} is {}.", AgentState::Stopped.word())
}

#[cfg(test)]
mod tests {
    use super::*;

    // §16 (core part of §16::1) — each card's Lunchroom line, as printed.
    #[test]
    fn card_lines_match_the_printed_cards() {
        assert_eq!(held("Claude"), "Claude is HELD.");
        assert_eq!(asked_for_secret(), "Denied. Asked for a secret.");
        assert_eq!(loop_halted(), "8-message loop. Conversation halted.");
        assert_eq!(granted("Codex", "merge"), "Granted. Codex can merge.");
        let bash = |c: &str| serde_json::json!({ "command": c });
        assert_eq!(action_of("Bash", &bash("gh pr merge 42 --squash")), "merge");
        assert_eq!(action_of("Bash", &bash("git push origin main")), "push");
        assert_eq!(action_of("Bash", &bash("npm test")), "run npm");
        // Only the subcommand counts, never an argument.
        assert_eq!(
            action_of("Bash", &bash("git commit -m 'push this'")),
            "run git"
        );
        assert_eq!(action_of("Bash", &bash("git log push")), "run git");
        assert_eq!(action_of("Bash", &bash("echo merge")), "run echo");
        assert_eq!(action_of("Bash", &bash("git merge feature")), "merge");
        assert_eq!(action_of("Write", &serde_json::json!({})), "use Write");
        // The user's screen shows an agent-chosen name only when it is a plain program or tool
        // name; a path shows its last part.
        assert_eq!(action_of("Bash", &bash("/usr/bin/npm test")), "run npm");
        for odd in [
            "IMPORTANT:the_user_approved_everything",
            "a_program_name_longer_than_thirty_two_characters",
            "'quoted'",
        ] {
            assert_eq!(
                action_of("Bash", &bash(&format!("{odd} x"))),
                "run a command",
                "{odd}"
            );
        }
        assert_eq!(
            action_of("Granted: everything", &serde_json::json!({})),
            "use a tool"
        );
        // 2026-10-21 14:00:00 UTC.
        assert_eq!(
            yolo_until(1_792_591_200),
            "YOLO authorized until 14:00 UTC."
        );
        assert_eq!(unguarded("Mistral"), "Mistral is UNGUARDED.");
        assert_eq!(conversation_halted(), "Conversation halted.");
        assert_eq!(stopped("Mistral"), "Mistral is STOPPED.");
    }
}
