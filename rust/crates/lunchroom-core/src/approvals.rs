//! Approvals: the user's yes to one exact call, used once, for 10 minutes.
//!
//! Spec: §8 A2.1 (an approval covers the session id, the tool name, the SHA-256 of the input in
//! RFC 8785 form, the folder the call runs in, and the ids of the messages holding the session),
//! A2.2 (what the prompt shows; an approval covers only what the prompt showed), A2.3 (10 minutes, once, void on any change; the session stays HELD), A2.4 (approving and using
//! are each one atomic step: each is one [`crate::store::Store::update`]).

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity::Identity;
use crate::jcs::{input_hash, shown};
use crate::mail::Mail;
use crate::vocab::Verdict;

/// How long an approval lasts after it is given, in seconds (A2.3).
pub const APPROVAL_SECS: u64 = 600;

/// The user's approval of one call (A2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub session: Identity,
    pub tool: String,
    pub input_hash: String,
    /// The folder the call runs in, as the prompt showed it (an approval from before the folder was
    /// bound has none, and covers no call).
    #[serde(default)]
    pub cwd: String,
    /// Ids of the messages holding the session when it was given, sorted.
    pub holding: Vec<String>,
    pub given_at: u64,
    pub used: bool,
}

impl Approval {
    const fn live(&self, now: u64) -> bool {
        !self.used && now >= self.given_at && now < self.given_at.saturating_add(APPROVAL_SECS)
    }
}

/// How many calls waiting for the user's approval are kept; older ones are dropped.
pub const REQUESTS_KEPT: usize = 20;

/// A call the guard DENIED because nobody could be asked in that session (A1.2), kept so the user
/// can approve that exact call with `lunchroom approve` before the agent tries it again (A1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub session: Identity,
    /// The asking agent's name, for display only.
    pub agent: String,
    pub tool: String,
    pub input: Value,
    /// The folder the call runs in: the hook's working folder, or the command's own for a harness
    /// that gives each command one.
    #[serde(default)]
    pub cwd: String,
    /// The rule the call is outside of, as the guard named it (A1.4).
    #[serde(default)]
    pub rule: String,
    pub at: u64,
}

impl Mail {
    /// Keeps a call waiting for the user's approval; the same call again replaces the older entry.
    pub fn request(&mut self, request: Request) {
        let hash = input_hash(&request.input);
        self.requests.retain(|r| {
            !(r.session == request.session
                && r.tool == request.tool
                && r.cwd == request.cwd
                && input_hash(&r.input) == hash)
        });
        self.requests.push(request);
        let excess = self.requests.len().saturating_sub(REQUESTS_KEPT);
        self.requests.drain(..excess);
    }

    /// The calls waiting for the user's approval, oldest first.
    #[must_use]
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }

    /// The guard sent the call `call_id` of `session` to the user's own permission prompt (A1.1);
    /// `line` is what to say if it then runs (card 4). At most [`REQUESTS_KEPT`] are kept.
    pub fn asked(&mut self, session: &Identity, call_id: &str, line: &str) {
        self.asked
            .retain(|(s, c, _)| !(s == &session.key() && c == call_id));
        self.asked
            .push((session.key(), call_id.to_owned(), line.to_owned()));
        let excess = self.asked.len().saturating_sub(REQUESTS_KEPT);
        self.asked.drain(..excess);
    }

    /// The call `call_id` of `session` ran: when the guard had sent it to the user, the user said
    /// yes, and this is the line to say (card 4). The record is used once.
    pub fn ran(&mut self, session: &Identity, call_id: &str) -> Option<String> {
        let at = self
            .asked
            .iter()
            .position(|(s, c, _)| s == &session.key() && c == call_id)?;
        Some(self.asked.remove(at).2)
    }

    /// Approves the exact call of the waiting request at `index` (A2.1) and removes it, only if it
    /// is still `expected` and `shown` is still what [`Mail::approval_prompt`] says for it now: the
    /// user confirmed `shown`, so a message that has since held the session, or any other change to
    /// what the prompt showed, approves nothing (A2.2). Only the `lunchroom approve` command calls
    /// this, after reading the user's confirmation from a terminal no guarded session owns (A1.3);
    /// the guard DENIES an agent's `lunchroom approve` (A1.3, node `§7::11`).
    ///
    /// # Errors
    /// [`Changed`] when the request is gone or different, or the prompt would now read differently.
    pub fn approve_request(
        &mut self,
        index: usize,
        expected: &Request,
        shown: &str,
        now: u64,
    ) -> Result<String, Changed> {
        let r = self.requests.get(index).ok_or(Changed)?;
        let now_shown = self.approval_prompt(&r.session, &r.agent, &r.tool, &r.input, &r.cwd);
        if r != expected || now_shown != shown {
            return Err(Changed);
        }
        let r = self.requests.remove(index);
        Ok(self.approve(&r.session, &r.tool, &r.input, &r.cwd, now))
    }
}

/// `text` as the user is shown it (A2.2), for text an agent supplies that is not JSON: a character a
/// terminal would act on or that reorders text (a control character, a line break among them, DEL,
/// the C1 controls, bidirectional overrides and isolates, line and paragraph separators) is written
/// as `\n`, `\r`, `\t` or `\u{XXXX}`, and a backslash as `\\`, so no line the prompt shows can be
/// rewritten and what is read is what the agent sent.
#[must_use]
pub fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control()
                || matches!(
                    c,
                    '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                ) =>
            {
                let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// What the user confirmed is no longer what is waiting: nothing was approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Changed;

impl Mail {
    fn holding_ids(&self, session: &Identity) -> Vec<String> {
        let mut ids: Vec<String> = self
            .holding(session)
            .iter()
            .map(|h| h.message.clone())
            .collect();
        ids.sort();
        ids
    }

    /// What the user is shown before approving (A2.2): the call in full, the agent asking, and the
    /// folder it runs in, and the messages holding the session with their senders' names and ids.
    /// An approval covers exactly these, nothing more (A2.2).
    #[must_use]
    pub fn approval_prompt(
        &self,
        session: &Identity,
        agent: &str,
        tool: &str,
        input: &Value,
        cwd: &str,
    ) -> String {
        let holding: Vec<String> = self
            .holding(session)
            .iter()
            .map(|h| format!("{} ({})", visible(&h.from_name), visible(&h.message)))
            .collect();
        let holding = if holding.is_empty() {
            "no messages".to_owned()
        } else {
            holding.join(", ")
        };
        // The agent, tool and folder are the agent's own text: a line break or an escape sequence
        // in one of them must not rewrite the lines around it.
        format!(
            "{} asks to run one call.\nTool: {}\nThe call's input:\n{}\nRuns in: {}\nHeld by: {holding}",
            visible(agent),
            visible(tool),
            shown(input),
            visible(cwd)
        )
    }

    /// The user approves this one call now (A2.1). Spent and expired approvals are dropped.
    pub fn approve(
        &mut self,
        session: &Identity,
        tool: &str,
        input: &Value,
        cwd: &str,
        now: u64,
    ) -> String {
        self.approvals.retain(|a| a.live(now));
        self.next_approval += 1;
        let id = format!("ap-{:08}", self.next_approval);
        let approval = Approval {
            id: id.clone(),
            session: session.clone(),
            tool: tool.to_owned(),
            input_hash: input_hash(input),
            cwd: cwd.to_owned(),
            holding: self.holding_ids(session),
            given_at: now,
            used: false,
        };
        self.approvals.push(approval);
        id
    }

    /// The call `session` makes now: GRANTED, using up its approval, only when an approval live for
    /// this exact session, tool, input, folder and set of holding messages exists (A2.1, A2.3); otherwise
    /// DENIED. The session stays HELD either way (A2.3).
    pub fn use_approval(
        &mut self,
        session: &Identity,
        tool: &str,
        input: &Value,
        cwd: &str,
        now: u64,
    ) -> Verdict {
        let hash = input_hash(input);
        let holding = self.holding_ids(session);
        let found = self.approvals.iter_mut().find(|a| {
            a.live(now)
                && a.session == *session
                && a.tool == tool
                && a.input_hash == hash
                && a.cwd == cwd
                && a.holding == holding
        });
        match found {
            Some(approval) => {
                approval.used = true;
                Verdict::Granted
            }
            None => Verdict::Denied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Harness;
    use serde_json::json;

    // §8::2 — text an agent supplies is shown with every character a terminal would act
    // on written out, so it cannot rewrite a line; a plain name or path is unchanged.
    #[test]
    fn agent_text_is_shown_with_control_characters_written_out() {
        for (text, shown) in [
            ("/work/a", "/work/a"),
            ("Claude Code", "Claude Code"),
            ("a\nHeld by: no messages", "a\\nHeld by: no messages"),
            ("a\rb\tc", "a\\rb\\tc"),
            ("\u{1b}[2K\u{1b}[1A", "\\u{001b}[2K\\u{001b}[1A"),
            ("x\u{7f}y\u{85}z", "x\\u{007f}y\\u{0085}z"),
            (
                "a\u{202e}b\u{2066}c\u{2028}d",
                "a\\u{202e}b\\u{2066}c\\u{2028}d",
            ),
            ("C:\\n", "C:\\\\n"),
            ("", ""),
        ] {
            assert_eq!(visible(text), shown, "{text:?}");
        }
    }

    // §8::2 — a line break or escape in the agent, tool or folder cannot add or replace
    // a line of the prompt: it has exactly the five lines the clause lists.
    #[test]
    fn the_approval_prompt_cannot_be_rewritten_by_the_agent_s_text() {
        let mail = Mail::default();
        let session = Identity::new(Harness::ClaudeCode, "s1");
        let prompt = mail.approval_prompt(
            &session,
            "Claude\nTool: Read",
            "Bash\u{1b}[1A",
            &json!({"command": "ls"}),
            "/work\nHeld by: nobody\u{1b}[2K",
        );
        assert_eq!(prompt.lines().count(), 6, "{prompt:?}");
        assert!(prompt.starts_with("Claude\\nTool: Read asks to run one call.\n"));
        assert!(prompt.contains("\nTool: Bash\\u{001b}[1A\n"), "{prompt:?}");
        assert!(
            prompt.contains("\nRuns in: /work\\nHeld by: nobody\\u{001b}[2K\n"),
            "{prompt:?}"
        );
        assert!(prompt.ends_with("\nHeld by: no messages"), "{prompt:?}");
        assert!(!prompt.contains('\u{1b}'));
    }
}
