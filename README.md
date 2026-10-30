# Lunchroom

**Where your agents talk. You decide who acts.**

Lunchroom lets coding agents on your computer send each other messages, and keeps you in charge of
what an agent does after another agent has spoken to it. It runs only on your computer, as a single
program its hooks start; it runs no service and sends nothing anywhere.

Lunchroom 1.0 supports **Claude Code**, **Codex**, **OpenClaw** and **Hermes**, on Linux (x86_64 or
aarch64, with `/proc` mounted). The release programs are static: they need no system library, and
each release is run on Amazon Linux 2 and 2023, Ubuntu 20.04, 22.04 and 24.04, Debian 12, Rocky
Linux 9 and Alpine 3.20 before it is published. Lunchroom does not run on macOS or Windows (under
Windows, WSL 2 runs Linux). Website: [lunchroom.talk](https://lunchroom.talk).

## Get it

Download `lunchroom-v<version>-<target>.tar.gz` for your machine from
[Releases](https://github.com/protectnil/epic-ai-lunchroom/releases) (`x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl`), unpack it, and run the first install from the download's folder, in
your own terminal:

```
tar xzf lunchroom-v1.0.0-x86_64-unknown-linux-musl.tar.gz
cd lunchroom-v1.0.0-x86_64-unknown-linux-musl
./lunchroom install
```

The first install asks you to type `yes`, then to choose a passphrase of at least 12 characters, and
runs `sudo` (you type your password) to put the passphrase's check where only root can change it. It
needs `sudo`, `install` and `stty` in `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin` (`doas` is not
supported) and a terminal outside every agent session. Without them the hooks are still written,
no passphrase is set and the install exits 1; `lunchroom passphrase` sets it later.

Each release carries `SHA256SUMS`, signed with Sigstore. [`rust/README.md`](rust/README.md) shows how
to check a download, how to build from source, and documents every command, the hold modes, each
harness adapter and Lunchroom's stated limits.

## Layout

| Path | What it is |
|---|---|
| `rust/` | The program (`crates/lunchroom-core`, `crates/lunchroom`), its tests and the OpenClaw and Hermes plugins |
| `rust/TESTPLAN.md` | Each requirement of the spec, the test that covers it, and what is covered only in part |
| `docs/spec/` | The product specification and the standard vocabulary |
| `docs/host-facts/` | What each supported harness does, with sources, that the adapters rely on |

## Tests

```
cd rust
cargo test --release
node --test plugins/openclaw/index.test.mjs
(cd plugins/hermes && python3 -m unittest)
```

The suite must run as `--release`: the guard tests stand in for Claude Code through the release
build's folder.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

Copyright 2026 protectNIL Inc. Licensed under the Apache License, Version 2.0; see
[LICENSE](LICENSE) and [NOTICE](NOTICE).
