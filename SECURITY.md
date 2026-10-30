# Security policy

Lunchroom is a guard: a way around it is a security defect, and we want to hear about it.

## Reporting a vulnerability

Report it privately, by either route:

- this repository's **Security → Report a vulnerability** form (GitHub private vulnerability
  reporting), or
- email to **support@epic-ai.io** with "Lunchroom security" in the subject.

Do not open a public issue for a vulnerability. We acknowledge a report within 2 business days.

Include the harness and its version, Lunchroom's version (`lunchroom version`), the hold mode
(`lunchroom status`), and the exact tool call or message that gets past the guard.

## Scope

In scope: anything that lets another agent's text act with more authority than the spec allows —
a call that runs when it should be DENIED or go to the user, a hold that is lost, a message
delivered to an agent that is not guarded, a reply that reaches an agent that does not hold the
sender, a secret that leaves in a reply, or a way for an agent to change Lunchroom or its settings.

Out of scope: the stated limits in the README ("Stated limits"), which Lunchroom documents as
what it does not prevent, such as a hostile program already running as the same user.

## Versions that receive fixes

Security fixes go to the latest 1.0.x release.

## Verifying a release

Every release publishes `SHA256SUMS` signed with Sigstore. `rust/README.md` ("Get it") gives the
`sha256sum` and `cosign verify-blob` commands (cosign 3 or newer).
