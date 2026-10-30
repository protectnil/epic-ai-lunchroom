//! Who an agent is: its harness and the session id the guard saw in that session's hooks.
//!
//! Spec: §9 I1.1 (identity is the pair (harness, session id); a name is a display label only) and
//! I1.3 (messages record identities; inboxes are keyed by session id).

use std::fmt;

use serde::{Deserialize, Serialize};

/// The harness a session runs in (H1). The store writes each harness as its key's slug, so a
/// harness has one spelling everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Harness {
    ClaudeCode,
    Codex,
    #[serde(rename = "openclaw")]
    OpenClaw,
    Hermes,
}

impl Harness {
    const fn slug(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::OpenClaw => "openclaw",
            Self::Hermes => "hermes",
        }
    }

    const ALL: [Self; 4] = [Self::ClaudeCode, Self::Codex, Self::OpenClaw, Self::Hermes];
}

impl Identity {
    /// Reads an identity written as its key, `<harness>:<session id>` (`claude-code:abc`).
    #[must_use]
    pub fn parse(key: &str) -> Option<Self> {
        let (slug, session) = key.split_once(':')?;
        let harness = Harness::ALL.into_iter().find(|h| h.slug() == slug)?;
        (!session.is_empty()).then(|| Self::new(harness, session))
    }
}

/// An agent: one session of one harness, as the guard saw it in that session's hooks (I1.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Identity {
    pub harness: Harness,
    pub session: String,
}

impl Identity {
    /// The session `session` of `harness`.
    #[must_use]
    pub fn new(harness: Harness, session: &str) -> Self {
        Self {
            harness,
            session: session.to_owned(),
        }
    }

    /// The key that stores index this identity by, inboxes included: the harness, then the
    /// session id (I1.3). The harness part holds no `:`, so the key names one identity.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.harness.slug(), self.session)
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // I1.3: the store spells each harness as its key does (`openclaw`, not `open-claw`), and reads
    // back what it wrote.
    #[test]
    fn a_harness_is_stored_as_its_key_spells_it() {
        for harness in Harness::ALL {
            let stored = serde_json::to_value(harness).unwrap_or_default();
            assert_eq!(stored, harness.slug(), "{harness:?}");
            let read: Option<Harness> = serde_json::from_value(stored).ok();
            assert_eq!(read, Some(harness));
            let who = Identity::new(harness, "s");
            assert_eq!(Identity::parse(&who.key()), Some(who));
        }
    }
}
