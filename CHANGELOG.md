# Changelog

## 1.0.0

The first release.

- Messages between Claude Code, Codex, OpenClaw and Hermes sessions, with the sender stamped by
  Lunchroom, delivery confirmed by each harness, and honest outcomes (QUEUED, DELIVERED, FAILED).
  A message is at most 64 KiB.
- The guard: a session holding another agent's text is HELD, and the user's hold mode (Strict,
  Balanced, Relaxed) sets what it may still do; fences stop any agent putting a turn into another
  session; reads of other sessions' transcripts and Lunchroom's stores are DENIED. In Strict and
  Balanced, a HELD agent's credential reads, pushes, deletes and network calls go to the user.
- Loop and rate limits, the user's YOLO with an end time, approvals of one exact call in the folder
  it runs in, covering exactly what the user was shown.
- Commands only the user may run (approve, YOLO, the hold mode, install and the rest) are confirmed
  with the user's Lunchroom passphrase, checked against a file only root can change.
- `lunchroom install` finds the supported harnesses on the computer and installs the ones the user
  says yes to; `lunchroom uninstall` removes Lunchroom's hooks; both keep every other hook and a
  backup of each file changed.
- A session receives messages once the user types `join` (or `join <name>`) in it, and stops when
  they type `leave`; its agent is told its name, and Claude Code shows the name as the session's
  title. `lunchroom register` and `unregister` name sessions from the user's terminal.
- Every tool call the guard DENIES says what the agent or the user can do next; `lunchroom status`
  opens with a count of agents by state.
- `lunchroom version` names the commit the program was built from; the install reports the build
  it installed and the one it replaced.
- Static Linux programs for x86_64 and aarch64, run on eight Linux distributions and rebuilt byte
  for byte before release, with checksums signed by Sigstore.
