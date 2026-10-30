# Contributing

Lunchroom is licensed under the Apache License 2.0. A contribution you submit is licensed under
the same terms (section 5 of the License).

## Build and test

```
cd rust
cargo build --release
cargo test --release
cargo clippy --release --all-targets -- -D warnings
node --test plugins/openclaw/index.test.mjs
(cd plugins/hermes && python3 -m unittest)
```

The suite runs as `--release`: the guard tests stand in for Claude Code through the release
build's folder. Lunchroom runs on Linux.

## Changes

- Behaviour is specified in `docs/spec/lunchroom-spec.md`; `rust/TESTPLAN.md` maps every
  requirement to the test that proves it. A change in behaviour changes the spec and its test
  in the same pull request.
- Tests use real inputs where they exist: recorded hook payloads in
  `rust/crates/lunchroom/tests/fixtures/`, the repository's own files, real commands.
- Every word Lunchroom prints for a state, verdict or reason comes from
  `rust/crates/lunchroom-core/src/vocab.rs`, which `docs/spec/standard-vocabulary.md` describes.
- No `unsafe`, no `unwrap` or `expect` outside tests (the workspace lints deny them).
- Report security problems privately (SECURITY.md), not in a pull request.
