//! HALTED: a pair of agents that repeats itself, or passes the rate limit, stops.
//!
//! Spec: §2 R1.1–R1.7. A message is a repeat when its text, ignoring case, whitespace, punctuation
//! and digits, equals a message the same sender sent to the same recipient since the user last
//! typed in either agent's session. Each sender's count of repeats in a row reaches 8: that message
//! is delivered and the pair is HALTED for reason `loop`. The message after the ceiling within the
//! window, counting the pair's messages in both directions, HALTS the pair for reason `rate limit`.
//! Only the user typing in either agent's session clears HALTED.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::vocab::Reason;

mod tables;

/// A sender's count that HALTS the pair (R1.3).
pub const LOOP_COUNT: u32 = 8;

/// The rate limit: at most `ceiling` messages between a pair, both directions counted, within
/// `window_secs`.
/// A stored value is read through [`Limits::new`], so a value below 1 is refused there too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawLimits")]
pub struct Limits {
    ceiling: u32,
    window_secs: u64,
}

/// [`Limits`] as stored, before [`Limits::new`] checks it.
#[derive(Deserialize)]
struct RawLimits {
    ceiling: u32,
    window_secs: u64,
}

impl TryFrom<RawLimits> for Limits {
    type Error = BelowOne;

    fn try_from(raw: RawLimits) -> Result<Self, BelowOne> {
        Self::new(raw.ceiling, raw.window_secs)
    }
}

impl std::fmt::Display for BelowOne {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rate limit must be at least 1 message in at least 1 second")
    }
}

impl Default for Limits {
    /// What Lunchroom ships: 20 messages in 600 seconds (R1.7).
    fn default() -> Self {
        Self {
            ceiling: 20,
            window_secs: 600,
        }
    }
}

/// A rate limit below 1 message or 1 second (R1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BelowOne;

impl Limits {
    /// A rate limit; a value below 1 message or 1 second is refused (R1.7).
    ///
    /// # Errors
    /// [`BelowOne`] when `ceiling` or `window_secs` is 0.
    pub const fn new(ceiling: u32, window_secs: u64) -> Result<Self, BelowOne> {
        if ceiling < 1 || window_secs < 1 {
            return Err(BelowOne);
        }
        Ok(Self {
            ceiling,
            window_secs,
        })
    }

    /// Messages allowed between a pair, both directions counted, within the window.
    #[must_use]
    pub const fn ceiling(self) -> u32 {
        self.ceiling
    }

    /// The window, in seconds.
    #[must_use]
    pub const fn window_secs(self) -> u64 {
        self.window_secs
    }
}

/// The text a repeat is judged on: without whitespace, punctuation (Unicode category P) or digits
/// (category Nd), in lower case (R1.1). Every other character, symbols included, counts.
#[must_use]
pub fn repeat_key(text: &str) -> String {
    text.chars()
        .filter(|&c| {
            !c.is_whitespace() && !within(&tables::PUNCTUATION, c) && !within(&tables::DIGITS, c)
        })
        .flat_map(char::to_lowercase)
        .collect()
}

/// `c` falls in one of `ranges`, which are sorted and do not overlap.
fn within(ranges: &[(char, char)], c: char) -> bool {
    ranges
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// What happens to one message between two agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Delivered.
    Deliver,
    /// Delivered, and the pair is now HALTED for reason `loop` (R1.3).
    DeliverAndHalt,
    /// DENIED: the pair is HALTED (`halted`, R1.4) or this message passed the rate limit
    /// (`rate limit`, R1.6, which HALTS the pair).
    Deny(Reason),
}

/// One sender's side of a pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Sender {
    /// Repeat keys of what this sender sent to the other since the user last typed (R1.1).
    sent: BTreeSet<String>,
    /// Repeat key of this sender's last message to the other since the user last typed.
    last: Option<String>,
    /// Times in a row this sender has sent the same message (R1.2).
    count: u32,
    /// The other agent sent this sender a message that was not a repeat since this sender's last
    /// message: the pair is not repeating itself, so this sender's next message starts at 1 (R1.2).
    answered_new: bool,
}

/// A pair of agents, in either direction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Pair {
    halted: Option<Halt>,
    /// When the pair's recent messages, in both directions, were accepted, for the rate limit.
    times: VecDeque<u64>,
    /// Keyed by sender identity.
    senders: BTreeMap<String, Sender>,
}

/// Why a pair is HALTED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Halt {
    Loop,
    RateLimit,
}

/// Every pair's state, and the rate limit the user set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversations {
    limits: Limits,
    /// Keyed by the two identities in sorted order. Stored as a list of `[key, pair]`, since a
    /// JSON object's keys are strings only.
    #[serde(with = "pairs_as_list")]
    pairs: BTreeMap<(String, String), Pair>,
}

mod pairs_as_list {
    use std::collections::BTreeMap;

    use serde::{Deserialize as _, Deserializer, Serializer};

    use super::Pair;

    type Pairs = BTreeMap<(String, String), Pair>;

    pub(super) fn serialize<S: Serializer>(pairs: &Pairs, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(pairs.iter())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Pairs, D::Error> {
        Ok(Vec::<((String, String), Pair)>::deserialize(d)?
            .into_iter()
            .collect())
    }
}

fn pair_key(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_owned(), b.to_owned())
    } else {
        (b.to_owned(), a.to_owned())
    }
}

impl Conversations {
    /// Conversations under another rate limit, for this module's tests. Nothing outside this
    /// module can change the limit: only the user may (R1.7), and the user's `lunchroom rate`
    /// command, which brings its own way in, is not written yet.
    #[cfg(test)]
    fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            pairs: BTreeMap::new(),
        }
    }

    /// The rate limit in force.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Sets the rate limit; reached only through [`crate::mail::Mail::set_limits`].
    pub(crate) const fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// The pair is HALTED, and why.
    #[must_use]
    pub fn halted(&self, a: &str, b: &str) -> Option<Reason> {
        self.pairs
            .get(&pair_key(a, b))
            .and_then(|p| p.halted)
            .map(|h| match h {
                Halt::Loop => Reason::Loop,
                Halt::RateLimit => Reason::RateLimit,
            })
    }

    /// Every HALTED pair, by its two identity keys in sorted order, and why (C1.1).
    #[must_use]
    pub fn halted_pairs(&self) -> Vec<(&str, &str, Reason)> {
        self.pairs
            .iter()
            .filter_map(|((a, b), p)| {
                p.halted.map(|h| {
                    let reason = match h {
                        Halt::Loop => Reason::Loop,
                        Halt::RateLimit => Reason::RateLimit,
                    };
                    (a.as_str(), b.as_str(), reason)
                })
            })
            .collect()
    }

    /// A sender's count of repeats in a row toward this recipient (R1.2).
    #[must_use]
    pub fn count(&self, from: &str, to: &str) -> u32 {
        self.pairs
            .get(&pair_key(from, to))
            .and_then(|p| p.senders.get(from))
            .map_or(0, |s| s.count)
    }

    /// Judges one message from `from` to `to` sent at `now` (seconds), and records it if it is
    /// delivered. `--reply-to` plays no part (R1.2).
    pub fn on_message(&mut self, from: &str, to: &str, text: &str, now: u64) -> Outcome {
        let limits = self.limits;
        let pair = self.pairs.entry(pair_key(from, to)).or_default();
        if pair.halted.is_some() {
            return Outcome::Deny(Reason::Halted);
        }
        // R1.6 counts the pair's messages in both directions. In the window: sent within the last
        // `window_secs` seconds, `now` included.
        while pair
            .times
            .front()
            .is_some_and(|t| t.saturating_add(limits.window_secs) <= now)
        {
            pair.times.pop_front();
        }
        if pair.times.len() >= limits.ceiling as usize {
            pair.halted = Some(Halt::RateLimit);
            return Outcome::Deny(Reason::RateLimit);
        }
        pair.times.push_back(now);
        let sender = pair.senders.entry(from.to_owned()).or_default();
        let key = repeat_key(text);
        let repeat = sender.sent.contains(&key);
        // In a row: the same as this sender's last message, with no new message from the other
        // agent since (R1.2).
        let same_again = sender.last.as_deref() == Some(key.as_str());
        sender.count = if same_again && !sender.answered_new {
            sender.count + 1
        } else {
            1
        };
        sender.answered_new = false;
        sender.sent.insert(key.clone());
        sender.last = Some(key);
        let count = sender.count;
        if !repeat {
            pair.senders.entry(to.to_owned()).or_default().answered_new = true;
        }
        if count >= LOOP_COUNT {
            pair.halted = Some(Halt::Loop);
            return Outcome::DeliverAndHalt;
        }
        Outcome::Deliver
    }

    /// The user typed in `agent`'s session: every pair with that agent is cleared of HALTED, its
    /// counts reset to zero and its earlier messages forgotten (R1.1, R1.5). The caller passes only
    /// a prompt the guard accepts as the user's.
    pub fn user_typed(&mut self, agent: &str) {
        self.pairs
            .retain(|(a, b), _| a.as_str() != agent && b.as_str() != agent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn under(ceiling: u32, window: u64) -> Conversations {
        Conversations::with_limits(Limits::new(ceiling, window).unwrap_or_default())
    }

    // §2::1 — case, spacing, punctuation and digits do not matter; a message from before
    // the user last typed does not count.
    #[test]
    fn repeat_ignores_case_whitespace_punctuation_digits() {
        assert_eq!(
            repeat_key("Run the TESTS, now! 42"),
            repeat_key("run  the tests now 7")
        );
        // Punctuation and digits beyond ASCII are ignored; symbols and other numbers are not.
        assert_eq!(repeat_key("「hi」—ok…"), repeat_key("hi ok"));
        assert_eq!(repeat_key("step ٣\u{a0}done"), repeat_key("step done"));
        assert_ne!(repeat_key("a🙂b"), repeat_key("ab"));
        assert_ne!(repeat_key("x½"), repeat_key("x"));
        assert_ne!(repeat_key("1 + 1"), repeat_key("1 1"));
        let mut c = under(100, 600);
        assert_eq!(
            c.on_message("a", "b", "Run the tests.", 0),
            Outcome::Deliver
        );
        assert_eq!(
            c.on_message("a", "b", "run THE tests 2!", 1),
            Outcome::Deliver
        );
        assert_eq!(c.count("a", "b"), 2);
        c.user_typed("b");
        c.on_message("a", "b", "Run the tests.", 2);
        assert_eq!(c.count("a", "b"), 1);
        // The same text to a different recipient, or from the other agent, is not a repeat.
        c.on_message("a", "c", "Run the tests.", 3);
        assert_eq!(c.count("a", "c"), 1);
        c.on_message("b", "a", "Run the tests.", 4);
        assert_eq!(c.count("b", "a"), 1);
    }

    // §2::2 — 60 messages that never repeat are all delivered (ceiling 100).
    #[test]
    fn non_repeat_messages_never_halt_pair() {
        let mut c = under(100, 600);
        let words = ["alpha", "beta", "gamma", "delta", "omega", "sigma"];
        for i in 0..60usize {
            let (from, to) = if i % 2 == 0 { ("a", "b") } else { ("b", "a") };
            let text = format!("{} {}", words[i % 6], words[(i / 6) % 6].repeat(i / 36 + 1));
            assert_eq!(c.on_message(from, to, &text, 0), Outcome::Deliver, "{i}");
        }
        assert_eq!(c.halted("a", "b"), None);
    }

    // §2::3 — three in a row counts 3; a new message in between starts again at 1.
    #[test]
    fn per_sender_repeat_count_resets_on_non_repeat() {
        let mut c = under(100, 600);
        for _ in 0..3 {
            c.on_message("a", "b", "same", 0);
        }
        assert_eq!(c.count("a", "b"), 3);
        c.on_message("a", "b", "something new", 0);
        assert_eq!(c.count("a", "b"), 1);
        // A, B, A: the third is a repeat (R1.1) but not the same message in a row.
        c.on_message("a", "b", "same", 0);
        assert_eq!(c.count("a", "b"), 1);
        c.on_message("a", "b", "something new", 0);
        assert_eq!(c.count("a", "b"), 1);
        c.on_message("b", "a", "reply", 0);
        assert_eq!(c.count("b", "a"), 1);
        assert_eq!(c.count("a", "b"), 1);
    }

    // §2::3 — a sender's same answer to messages that are not repeats is not a loop:
    // a helper that answers "Done." to twenty different tasks is never HALTED; once both sides
    // repeat, the count runs again.
    #[test]
    fn same_answer_to_new_messages_never_halts_pair() {
        let mut c = under(100, 600);
        for i in 0..20usize {
            let task = format!("task {}", "x".repeat(i + 1));
            assert_eq!(
                c.on_message("lead", "helper", &task, 0),
                Outcome::Deliver,
                "{i}"
            );
            assert_eq!(
                c.on_message("helper", "lead", "Done.", 0),
                Outcome::Deliver,
                "{i}"
            );
            assert_eq!(c.count("helper", "lead"), 1, "{i}");
        }
        assert_eq!(c.halted("lead", "helper"), None);
        // The lead now repeats its last task: from there both sides repeat and the count runs.
        let last = format!("task {}", "x".repeat(20));
        for n in 2..=7 {
            c.on_message("lead", "helper", &last, 0);
            c.on_message("helper", "lead", "Done.", 0);
            assert_eq!(c.count("helper", "lead"), n);
        }
    }

    // §2::4 — the count does not depend on `--reply-to`: the API takes no reply id, so
    // dropping it cannot reset the count.
    #[test]
    fn repeat_count_independent_of_reply_to() {
        let mut c = under(100, 600);
        c.on_message("a", "b", "same", 0);
        c.on_message("a", "b", "same", 0);
        assert_eq!(c.count("a", "b"), 2);
    }

    // §2::5 core part, card 3 — Claude's message 7 times and Codex's reply 8 times: all
    // 15 delivered, Codex's 8th HALTS the pair for reason `loop`.
    #[test]
    fn eighth_identical_message_halts_pair() {
        let mut c = Conversations::default();
        let mut delivered = 0;
        for i in 0..8 {
            if i < 7 {
                assert_eq!(
                    c.on_message("claude", "codex", "Please review the PR.", 0),
                    Outcome::Deliver
                );
                delivered += 1;
            }
            let reply = c.on_message("codex", "claude", "Reviewed. Please merge.", 0);
            assert_ne!(reply, Outcome::Deny(Reason::Halted));
            delivered += 1;
            if i == 7 {
                assert_eq!(reply, Outcome::DeliverAndHalt);
            } else {
                assert_eq!(reply, Outcome::Deliver);
            }
        }
        assert_eq!(delivered, 15);
        assert_eq!(c.halted("claude", "codex"), Some(Reason::Loop));
    }

    // §2::6 core part — after the halt, the next message either way is DENIED `halted`.
    #[test]
    fn halted_pair_denies_every_message_reason_halted() {
        let mut c = Conversations::default();
        for _ in 0..8 {
            c.on_message("a", "b", "loop", 0);
        }
        assert_eq!(
            c.on_message("a", "b", "new text", 0),
            Outcome::Deny(Reason::Halted)
        );
        assert_eq!(
            c.on_message("b", "a", "anything", 0),
            Outcome::Deny(Reason::Halted)
        );
        assert_eq!(c.on_message("a", "z", "other pair", 0), Outcome::Deliver);
    }

    // §2::7 core part — the user typing in either session clears HALTED and forgets the
    // earlier messages.
    #[test]
    fn only_user_typing_clears_halted_and_resets_count() {
        for typed_in in ["a", "b"] {
            let mut c = Conversations::default();
            for _ in 0..8 {
                c.on_message("a", "b", "loop", 0);
            }
            c.user_typed("x");
            assert_eq!(c.halted("a", "b"), Some(Reason::Loop));
            c.user_typed(typed_in);
            assert_eq!(c.halted("a", "b"), None);
            assert_eq!(c.on_message("a", "b", "loop", 0), Outcome::Deliver);
            assert_eq!(c.count("a", "b"), 1);
        }
    }

    // §2::8 core part — with the ceiling at 5, the 6th message in the window HALTS the
    // pair for reason `rate limit`; messages outside the window do not count; the user clears it.
    #[test]
    fn message_after_ceiling_halts_pair_rate_limit() {
        let mut c = under(5, 600);
        for (n, t) in (0..5u64).enumerate() {
            assert_eq!(
                c.on_message("a", "b", &format!("note {}", "x".repeat(n + 1)), t),
                Outcome::Deliver
            );
        }
        assert_eq!(
            c.on_message("a", "b", "sixth", 5),
            Outcome::Deny(Reason::RateLimit)
        );
        assert_eq!(c.halted("a", "b"), Some(Reason::RateLimit));
        assert_eq!(
            c.on_message("b", "a", "reply", 6),
            Outcome::Deny(Reason::Halted)
        );
        c.user_typed("b");
        assert_eq!(c.on_message("a", "b", "again", 7), Outcome::Deliver);

        // Both directions count: 3 one way and 2 the other fill a ceiling of 5, and the 6th
        // message of the pair, either way, HALTS it.
        for from_b in [false, true] {
            let mut p = under(5, 600);
            for n in 0..5usize {
                let (from, to) = if n < 3 { ("a", "b") } else { ("b", "a") };
                let text = format!("n {}", "z".repeat(n + 1));
                assert_eq!(p.on_message(from, to, &text, 0), Outcome::Deliver, "{n}");
            }
            let (from, to) = if from_b { ("b", "a") } else { ("a", "b") };
            assert_eq!(
                p.on_message(from, to, "sixth", 1),
                Outcome::Deny(Reason::RateLimit)
            );
            assert_eq!(p.halted("a", "b"), Some(Reason::RateLimit));
        }

        // The window's edge: with a 10-second window, a message sent at 0 still counts at 9 and
        // no longer counts at 10.
        for (now, want) in [
            (9, Outcome::Deny(Reason::RateLimit)),
            (10, Outcome::Deliver),
        ] {
            let mut d = under(5, 10);
            for (n, t) in (0..5u64).enumerate() {
                d.on_message("a", "b", &format!("m {}", "y".repeat(n + 1)), t);
            }
            assert_eq!(d.on_message("a", "b", "later", now), want, "{now}");
        }
    }

    // §2::9 — what ships: 20 messages in 600 seconds.
    #[test]
    fn default_ceiling_is_20_in_600_seconds() {
        let l = Conversations::default().limits();
        assert_eq!((l.ceiling(), l.window_secs()), (20, 600));
    }

    // §2::11 — a value below 1 message or 1 second is refused.
    #[test]
    fn ceiling_or_window_below_one_refused() {
        assert_eq!(Limits::new(0, 600), Err(BelowOne));
        assert_eq!(Limits::new(20, 0), Err(BelowOne));
        assert!(Limits::new(1, 1).is_ok());
        // A stored value is refused the same way when it is read back.
        assert!(serde_json::from_str::<Limits>(r#"{"ceiling":0,"window_secs":600}"#).is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"ceiling":20,"window_secs":0}"#).is_err());
        let stored = serde_json::to_string(&Conversations::default()).unwrap_or_default();
        let zeroed = stored.replace("\"ceiling\":20", "\"ceiling\":0");
        assert_ne!(stored, zeroed);
        assert!(serde_json::from_str::<Conversations>(&stored).is_ok());
        assert!(serde_json::from_str::<Conversations>(&zeroed).is_err());
        assert_eq!(
            serde_json::from_str::<Limits>(r#"{"ceiling":1,"window_secs":1}"#).ok(),
            Limits::new(1, 1).ok()
        );
    }

    // The state survives the store: counts, what each sender sent, the rate-limit window and a
    // HALTED pair read back as they were written, and judging goes on from there.
    #[test]
    fn conversations_round_trip_through_json() {
        let mut c = under(5, 600);
        for _ in 0..3 {
            c.on_message("claude-code:c1", "codex:x1", "same", 0);
        }
        c.on_message("codex:x1", "claude-code:c1", "reply", 1);
        let mut halted = under(1, 600);
        halted.on_message("a", "b", "one", 0);
        halted.on_message("a", "b", "two", 0);
        for state in [c, halted] {
            let text = serde_json::to_string(&state).unwrap_or_default();
            let back = serde_json::from_str::<Conversations>(&text).ok();
            assert_eq!(back.as_ref(), Some(&state), "{text}");
        }
        let text = serde_json::to_string(&under(5, 600)).unwrap_or_default();
        let mut back = serde_json::from_str::<Conversations>(&text).unwrap_or_default();
        back.on_message("a", "b", "x", 0);
        assert_eq!(back.count("a", "b"), 1);
    }
}
