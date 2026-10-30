//! What happens to one tool call: it goes ahead, it goes to the user, or it is DENIED.
//!
//! Spec: §6 P1.2–P1.4 (permission slip, PROTECTED), §3 R2.4 (YOLO), §7 A1.2 (no approval channel).
//! This module decides from an already-classified call; classifying a raw tool call is done elsewhere.

/// What kind of call this is, once classified against the agent's slip and the fixed rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallClass {
    /// Inside the agent's permission slip (P1.1: reads outside denied and protected paths).
    InSlip,
    /// Outside the slip and not PROTECTED: an ordinary edit or command.
    Ordinary,
    /// PROTECTED (P1.4): never inside a slip; a HELD agent makes it only with the user.
    Protected(ProtectedKind),
    /// Stopped by a DENIED rule or a fence, in every state (P1.2, F1, L1.1, A1.3).
    Denied(DenyReason),
}

/// Every PROTECTED kind a call raised, not only the one shown. A call can be several at once (a
/// guard-configuration write inside a command the guard cannot parse); what the policy requires
/// of it follows from all of them, whichever kind is the reason shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtectedKinds(u16);

impl ProtectedKinds {
    /// No kind.
    pub const NONE: Self = Self(0);

    /// These kinds and `kind`.
    #[must_use]
    pub const fn with(self, kind: ProtectedKind) -> Self {
        Self(self.0 | (1 << kind as u16))
    }

    /// `kind` is among them.
    #[must_use]
    pub const fn contains(self, kind: ProtectedKind) -> bool {
        self.0 & (1 << kind as u16) != 0
    }
}

/// A classified call: the one class shown for it, and every PROTECTED kind it raised. The class
/// alone is enough only when one kind was raised; the classifier returns this so that choosing a
/// reason to show can never drop a requirement (spec §6 P1.6: Relaxed keeps the guard's own
/// configuration PROTECTED whatever else the call is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    /// The class shown for the call, the most severe seen.
    pub class: CallClass,
    /// Every PROTECTED kind raised, including the one in `class`.
    pub kinds: ProtectedKinds,
}

impl Call {
    /// A call that is only `class`.
    #[must_use]
    pub const fn of(class: CallClass) -> Self {
        let kinds = match class {
            CallClass::Protected(kind) => ProtectedKinds::NONE.with(kind),
            _ => ProtectedKinds::NONE,
        };
        Self { class, kinds }
    }

    /// One class that [`decide`] treats as this call is treated by [`decide_call`]: a call that
    /// raised the guard's configuration is shown as it, so a caller holding only a class cannot
    /// lose it.
    #[must_use]
    pub const fn folded(self) -> CallClass {
        match self.class {
            CallClass::Protected(_) if self.kinds.contains(ProtectedKind::GuardConfig) => {
                CallClass::Protected(ProtectedKind::GuardConfig)
            }
            class => class,
        }
    }
}

/// Why a call is DENIED: the reason codes live in the one vocabulary table (spec §1 V1.2).
pub use crate::vocab::Reason as DenyReason;

/// Which PROTECTED kind a call is (spec §6 P1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedKind {
    /// Push or publish.
    PushOrPublish,
    /// Deleting a file.
    Delete,
    /// Sending data off the computer.
    Network,
    /// Reading or writing credentials (L1.1).
    Credential,
    /// Writing Lunchroom's program or the harness configuration that runs the guard (R3.1).
    GuardConfig,
    /// A command the guard cannot parse (F1.2).
    Unparsed,
    /// A tool the guard does not know, which may send data off the computer.
    UnknownTool,
    /// Text sent to another agent's session outside `lunchroom send` (Claude Code's `SendMessage`).
    OtherSession,
}

impl ProtectedKind {
    /// The vocabulary reason shown for this kind, where the spec names one (F1.2: `unparsed`).
    #[must_use]
    pub const fn reason(self) -> Option<DenyReason> {
        match self {
            Self::Unparsed => Some(DenyReason::Unparsed),
            _ => None,
        }
    }
}

/// Which YOLO, if any, the agent is under (spec §3 R2.1, R2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YoloSource {
    /// No YOLO.
    Off,
    /// Only the harness's own switch (Claude Code `bypassPermissions`, Codex `--yolo`, …). This
    /// alone never lets a HELD agent act without the user (R2.4).
    HarnessOnly,
    /// A `lunchroom yolo` the user set, which turns the harness's YOLO on until its end time.
    Lunchroom,
}

/// How much being HELD limits an agent, as the user chose it (P1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HoldMode {
    /// A HELD agent's calls outside its slip go to the user (P1.3, P1.4).
    Strict,
    /// A HELD agent's calls run, except PROTECTED ones, which go to the user.
    #[default]
    Balanced,
    /// A HELD agent's calls run as if it were not HELD (P1.2).
    Relaxed,
}

impl HoldMode {
    /// The mode named `word` (`strict`, `balanced`, `relaxed`).
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "balanced" => Some(Self::Balanced),
            "relaxed" => Some(Self::Relaxed),
            _ => None,
        }
    }

    /// The mode's name as Lunchroom shows it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Balanced => "Balanced",
            Self::Relaxed => "Relaxed",
        }
    }
}

/// The agent's situation when the call is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Situation {
    /// Another agent's text is in this agent's context.
    pub held: bool,
    /// Which YOLO covers the agent right now.
    pub yolo: YoloSource,
    /// This harness, in this mode, has a channel through which the user can approve a call (A1.1).
    pub approval_channel: bool,
    /// The hold mode the user chose (P1.6).
    pub mode: HoldMode,
}

/// The outcome for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The call runs; Lunchroom adds nothing (the harness's own rules still apply).
    Run,
    /// The call goes to the user through the harness's approval channel.
    AskUser,
    /// The call is DENIED.
    Deny(DenyReason),
}

/// Decides what happens to a call that is only `call`; one that raised several PROTECTED kinds is
/// decided by [`decide_call`].
#[must_use]
pub const fn decide(call: CallClass, s: Situation) -> Decision {
    decide_call(Call::of(call), s)
}

/// Decides what happens to a classified call.
#[must_use]
pub const fn decide_call(call: Call, s: Situation) -> Decision {
    let needs_user = match call.class {
        CallClass::Denied(reason) => return Decision::Deny(reason),
        // P1.2: an agent that is not HELD gets nothing from Lunchroom beyond DENIED rules and fences.
        _ if !s.held => return Decision::Run,
        // P1.6 Relaxed: a HELD agent gets the same, except writing the guard itself (R3.1). This
        // follows every kind the call raised, not only the one shown for it.
        _ if call.kinds.contains(ProtectedKind::GuardConfig) => true,
        _ if matches!(s.mode, HoldMode::Relaxed) => return Decision::Run,
        CallClass::InSlip => false,
        // Strict (P1.3, R2.4): under a lunchroom yolo the user set, ordinary calls run; under the
        // harness's own YOLO alone they still go to the user. Balanced: they run (P1.6).
        CallClass::Ordinary => {
            matches!(s.mode, HoldMode::Strict) && !matches!(s.yolo, YoloSource::Lunchroom)
        }
        // P1.4: in Strict and Balanced, PROTECTED calls go to the user, YOLO or not.
        CallClass::Protected(_) => true,
    };
    if !needs_user {
        Decision::Run
    } else if s.approval_channel {
        Decision::AskUser
    } else {
        // A1.2: a call that must go to the user, with no channel, is DENIED instead of asked.
        Decision::Deny(DenyReason::NoApprovalChannel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn sit(held: bool, yolo: YoloSource, approval_channel: bool) -> Situation {
        Situation {
            held,
            yolo,
            approval_channel,
            mode: HoldMode::Strict,
        }
    }

    use YoloSource::{HarnessOnly, Lunchroom, Off};

    // P1.6: the hold mode decides what a HELD agent's calls do; DENIED stays DENIED in every mode,
    // and a call for the user with nobody to ask is DENIED (A1.2).
    #[test]
    fn the_hold_mode_decides_what_a_held_agent_may_do() {
        let edit = CallClass::Ordinary;
        let push = CallClass::Protected(ProtectedKind::PushOrPublish);
        let fence = CallClass::Denied(DenyReason::Fence);
        let guard = CallClass::Protected(ProtectedKind::GuardConfig);
        let at = |mode, channel| Situation {
            held: true,
            yolo: Off,
            approval_channel: channel,
            mode,
        };
        for (mode, want_edit, want_push) in [
            (HoldMode::Strict, Decision::AskUser, Decision::AskUser),
            (HoldMode::Balanced, Decision::Run, Decision::AskUser),
            (HoldMode::Relaxed, Decision::Run, Decision::Run),
        ] {
            assert_eq!(decide(edit, at(mode, true)), want_edit, "{mode:?}");
            assert_eq!(decide(push, at(mode, true)), want_push, "{mode:?}");
            assert_eq!(decide(guard, at(mode, true)), Decision::AskUser, "{mode:?}");
            assert_eq!(
                decide(fence, at(mode, true)),
                Decision::Deny(DenyReason::Fence),
                "{mode:?}"
            );
        }
        // Codex has no approval channel: under Balanced its push is DENIED, kept for approve.
        assert_eq!(
            decide(push, at(HoldMode::Balanced, false)),
            Decision::Deny(DenyReason::NoApprovalChannel)
        );
        assert_eq!(HoldMode::default(), HoldMode::Balanced);
        assert_eq!(HoldMode::parse("STRICT"), Some(HoldMode::Strict));
        assert_eq!(HoldMode::parse("loose"), None);
    }

    // §6 P1.6 / R3.1 (review finding 1): the guard's configuration stays PROTECTED in every hold
    // mode, whatever other kind is the reason shown for the call. A call that raised it alongside
    // any other kind is decided as one that raised it alone, in every mode, with and without an
    // approval channel, under every YOLO.
    #[test]
    fn p1_6_guard_config_survives_every_other_kind_in_every_mode() {
        use ProtectedKind::{
            Credential, Delete, GuardConfig, Network, OtherSession, PushOrPublish, UnknownTool,
            Unparsed,
        };
        let others = [
            PushOrPublish,
            Delete,
            Network,
            Credential,
            Unparsed,
            UnknownTool,
            OtherSession,
        ];
        for mode in [HoldMode::Strict, HoldMode::Balanced, HoldMode::Relaxed] {
            for yolo in [Off, HarnessOnly, Lunchroom] {
                for channel in [false, true] {
                    let held = Situation {
                        held: true,
                        yolo,
                        approval_channel: channel,
                        mode,
                    };
                    let alone = decide(CallClass::Protected(GuardConfig), held);
                    assert_ne!(alone, Decision::Run, "{mode:?} {yolo:?} {channel}");
                    for shown in others {
                        // Shown as the other kind, in either order of discovery.
                        for kinds in [
                            ProtectedKinds::NONE.with(shown).with(GuardConfig),
                            ProtectedKinds::NONE.with(GuardConfig).with(shown),
                        ] {
                            let call = Call {
                                class: CallClass::Protected(shown),
                                kinds,
                            };
                            assert_eq!(
                                decide_call(call, held),
                                alone,
                                "{shown:?} {mode:?} {yolo:?} {channel}"
                            );
                            // The class a caller holding only a class decides on.
                            assert_eq!(
                                decide(call.folded(), held),
                                alone,
                                "{shown:?} {mode:?} {yolo:?} {channel}"
                            );
                        }
                        // Without the guard's configuration the mode still decides.
                        let plain = Call::of(CallClass::Protected(shown));
                        assert_eq!(plain.folded(), CallClass::Protected(shown));
                        if matches!(mode, HoldMode::Relaxed) {
                            assert_eq!(decide_call(plain, held), Decision::Run, "{shown:?}");
                        }
                    }
                    // DENIED stays DENIED, and a call not HELD runs, whatever it raised.
                    let denied = Call {
                        class: CallClass::Denied(DenyReason::Unparsed),
                        kinds: ProtectedKinds::NONE.with(GuardConfig),
                    };
                    assert_eq!(
                        decide_call(denied, held),
                        Decision::Deny(DenyReason::Unparsed)
                    );
                    let free = Situation {
                        held: false,
                        ..held
                    };
                    let mixed = Call {
                        class: CallClass::Protected(Unparsed),
                        kinds: ProtectedKinds::NONE.with(Unparsed).with(GuardConfig),
                    };
                    assert_eq!(decide_call(mixed, free), Decision::Run);
                }
            }
        }
        // A kind is remembered once raised, and only that kind.
        let k = ProtectedKinds::NONE.with(Delete);
        assert!(k.contains(Delete) && !k.contains(GuardConfig) && !k.contains(Unparsed));
        assert_eq!(ProtectedKinds::NONE.with(Delete).with(Delete), k);
    }

    // §6 P1.2: not HELD, Lunchroom adds nothing except DENIED rules and fences.
    #[test]
    fn p1_not_held_runs_everything_but_denied() {
        for yolo in [Off, HarnessOnly, Lunchroom] {
            let s = sit(false, yolo, true);
            for c in [
                CallClass::InSlip,
                CallClass::Ordinary,
                CallClass::Protected(ProtectedKind::Delete),
            ] {
                assert_eq!(decide(c, s), Decision::Run, "{c:?} {yolo:?}");
            }
            assert_eq!(
                decide(CallClass::Denied(DenyReason::Fence), s),
                Decision::Deny(DenyReason::Fence)
            );
        }
    }

    // §6 P1.3: HELD, a call inside the slip runs; one outside it goes to the user.
    #[test]
    fn p1_held_in_slip_runs_outside_asks() {
        let s = sit(true, Off, true);
        assert_eq!(decide(CallClass::InSlip, s), Decision::Run);
        assert_eq!(decide(CallClass::Ordinary, s), Decision::AskUser);
    }

    // §6 P1.4 and §3 R2.4: PROTECTED calls go to the user under every kind of YOLO.
    #[test]
    fn p1_protected_asks_even_under_lunchroom_yolo() {
        for yolo in [Off, HarnessOnly, Lunchroom] {
            assert_eq!(
                decide(
                    CallClass::Protected(ProtectedKind::Delete),
                    sit(true, yolo, true)
                ),
                Decision::AskUser,
                "{yolo:?}"
            );
        }
    }

    // §3 R2.4 / card 5: under a lunchroom yolo, a HELD agent's ordinary call runs without asking.
    #[test]
    fn r2_card5_held_ordinary_call_runs_under_lunchroom_yolo() {
        assert_eq!(
            decide(CallClass::Ordinary, sit(true, Lunchroom, true)),
            Decision::Run
        );
    }

    // §3 R2.4: an agent run in its harness's own skip-permissions mode, with
    // no lunchroom yolo, still sends a HELD call outside its slip to the user.
    #[test]
    fn r2_harness_yolo_alone_still_asks() {
        assert_eq!(
            decide(CallClass::Ordinary, sit(true, HarnessOnly, true)),
            Decision::AskUser
        );
    }

    // §7 A1.2: a call that must go to the user, with no channel, is DENIED; calls that do not go
    // to the user are not affected.
    #[test]
    fn a1_no_channel_denies_only_calls_that_go_to_the_user() {
        for yolo in [Off, HarnessOnly] {
            let s = sit(true, yolo, false);
            assert_eq!(
                decide(CallClass::Ordinary, s),
                Decision::Deny(DenyReason::NoApprovalChannel)
            );
            assert_eq!(
                decide(CallClass::Protected(ProtectedKind::Delete), s),
                Decision::Deny(DenyReason::NoApprovalChannel)
            );
            assert_eq!(decide(CallClass::InSlip, s), Decision::Run);
        }
        let s = sit(true, Lunchroom, false);
        assert_eq!(decide(CallClass::Ordinary, s), Decision::Run);
        assert_eq!(
            decide(CallClass::Protected(ProtectedKind::Delete), s),
            Decision::Deny(DenyReason::NoApprovalChannel)
        );
    }

    // DENIED rules apply in every situation, every kind of YOLO included (R2.5).
    #[test]
    fn r2_denied_rules_hold_under_yolo() {
        for held in [false, true] {
            for yolo in [Off, HarnessOnly, Lunchroom] {
                for channel in [false, true] {
                    assert_eq!(
                        decide(
                            CallClass::Denied(DenyReason::DeniedPath),
                            sit(held, yolo, channel)
                        ),
                        Decision::Deny(DenyReason::DeniedPath)
                    );
                }
            }
        }
    }
}
