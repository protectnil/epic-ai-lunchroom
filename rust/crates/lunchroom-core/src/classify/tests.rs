//! Tests for the classifier, on a throwaway home folder under the build's `target` folder.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{Guard, candidates, fence_args, starts_session};
use crate::fs::{BUDGET, OsFs};
use crate::paths::Layout;
use crate::policy::{
    Call, CallClass, Decision, DenyReason, HoldMode, ProtectedKind, Situation, YoloSource, decide,
    decide_call,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A home folder holding Lunchroom's stores and program, harness transcripts and settings,
/// credentials, a project (with links into the stores and credentials, and scripts) and a second
/// project holding a `.env`.
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    layout: Layout,
}

fn write(p: &Path, text: &str) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap_or_default();
    }
    std::fs::write(p, text).unwrap_or_default();
}

impl Fixture {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/classify-homes");
        std::fs::create_dir_all(&base).unwrap_or_default();
        let base = std::fs::canonicalize(&base).unwrap_or(base);
        let root = base.join(format!("{}-{n}", std::process::id()));
        let home = root.join("home");
        let files = [
            (".lunchroom/inbox/m1", "a message"),
            (".lunchroom/registry.json", "{}"),
            (".lunchroom/bin/lunchroom", "program"),
            (".claude/projects/p/t.jsonl", "{}"),
            (".claude/settings.json", "{}"),
            (".codex/sessions/s.jsonl", "{}"),
            (".ssh/id_rsa", "key"),
            ("project/src/main.rs", "fn main() {}"),
            ("secrets-project/.env", "K=V"),
            ("project/fence.sh", "#!/bin/sh\ncodex queue other hi\n"),
            (
                "project/env-fence.sh",
                "#!/usr/bin/env bash\nclaude --resume abc\n",
            ),
            (
                "project/plain.sh",
                "#!/bin/sh\nls\nif [ -f x ]; then echo $HOME; fi\n",
            ),
            ("project/approve.sh", "lunchroom approve 7\n"),
            ("bin/qq", "#!/bin/sh\nopenclaw agent --message hi\n"),
            (
                "project/send.py",
                "import subprocess\nsubprocess.run(['codex', 'queue', 'other', 'hi'])\n",
            ),
            ("project/notes.py", "# ask claude later\nprint('claude')\n"),
            (
                "project/loose.sh",
                "#!/bin/sh\necho \"restart claude $X\"\n",
            ),
            (
                "project/loose-fence.sh",
                "#!/bin/sh\ncodex queue other \"$MSG\"\n",
            ),
            (
                "project/run.py",
                "#!/usr/bin/env python3\nimport os\nos.system('claude --resume x')\n",
            ),
            ("tools/codex", "program"),
            (
                "project/oc.sh",
                "#!/bin/sh\nopencode attach http://h --continue\n",
            ),
            (
                "project/ocl.sh",
                "#!/bin/sh\nopenclaw cron edit j1 --message hi\nopenclaw acp\n",
            ),
            (
                "project/forge.sh",
                "export CODEX_THREAD_ID=x\nlunchroom send a hi\n",
            ),
            (
                "project/forge.py",
                "import os\nos.environ['CLAUDE_CODE_SESSION_ID'] = 'x'\n",
            ),
        ];
        for (rel, text) in files {
            write(&home.join(rel), text);
        }
        let links = [
            ("project/inbox-link", ".lunchroom/inbox/m1"),
            ("project/key-link", ".ssh/id_rsa"),
            ("project/store-dir-link", ".lunchroom/inbox"),
            ("bin/lrlink", ".lunchroom/bin/lunchroom"),
            ("bin/cx", "tools/codex"),
        ];
        for (link, target) in links {
            std::os::unix::fs::symlink(home.join(target), home.join(link)).unwrap_or_default();
        }
        Self {
            layout: Layout::for_home(&home),
            root,
            home,
        }
    }

    fn class(&self, held: bool, tool: &str, input: &Value) -> CallClass {
        let fs = OsFs::with_path(BUDGET, Some(self.home.join("bin").into_os_string()));
        let g = Guard {
            layout: &self.layout,
            fs: &fs,
            held,
        };
        g.classify(tool, input, &self.home.join("project"))
    }

    fn bash(&self, held: bool, cmd: &str) -> CallClass {
        self.class(held, "Bash", &json!({ "command": cmd }))
    }

    /// The classified call: the class shown and every PROTECTED kind raised.
    fn call(&self, held: bool, cmd: &str) -> Call {
        let fs = OsFs::with_path(BUDGET, Some(self.home.join("bin").into_os_string()));
        let g = Guard {
            layout: &self.layout,
            fs: &fs,
            held,
        };
        g.classify_call(
            "Bash",
            &json!({ "command": cmd }),
            &self.home.join("project"),
        )
    }

    fn path(&self, rel: &str) -> String {
        self.home.join(rel).to_string_lossy().into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap_or_default();
    }
}

// §6 P1.4 / §6::11 — a path attached to an option (`-o~/...`, `--file=/...`,
// `-I/...`) is extracted for the path rules: the option text is dropped, the path is kept.
#[test]
fn option_attached_paths_are_extracted() {
    assert!(candidates("-o~/.lunchroom/inbox/x").contains(&"~/.lunchroom/inbox/x"));
    assert!(
        candidates("--file=/home/u/.lunchroom/registry.json")
            .contains(&"/home/u/.lunchroom/registry.json")
    );
    assert!(candidates("-I/usr/include").contains(&"/usr/include"));
    assert!(!candidates("-o~/x").contains(&"-o~/x"));
}

const DENIED_PATH: CallClass = CallClass::Denied(DenyReason::DeniedPath);
const FENCE: CallClass = CallClass::Denied(DenyReason::Fence);
const DENIED_UNPARSED: CallClass = CallClass::Denied(DenyReason::Unparsed);
const CONFIG: CallClass = CallClass::Denied(DenyReason::Configuration);
const CREDENTIAL: CallClass = CallClass::Protected(ProtectedKind::Credential);
const GUARD_CONFIG: CallClass = CallClass::Protected(ProtectedKind::GuardConfig);
const UNPARSED: CallClass = CallClass::Protected(ProtectedKind::Unparsed);

const NOT_HELD: Situation = Situation {
    held: false,
    yolo: YoloSource::Off,
    approval_channel: true,
    mode: HoldMode::Strict,
};

const fn held_under(yolo: YoloSource) -> Situation {
    Situation {
        held: true,
        yolo,
        approval_channel: true,
        mode: HoldMode::Strict,
    }
}

// §6::1 — the slip that ships: a HELD agent reads any file except L1.1's paths.
#[test]
fn default_slip_reads_any_file_except_l1_1_paths() {
    let h = Fixture::new();
    let main_rs = h.path("project/src/main.rs");
    let src = h.path("project/src");
    for (tool, input) in [
        ("Read", json!({ "file_path": main_rs })),
        ("Grep", json!({ "pattern": "fn", "path": src })),
        ("Glob", json!({ "pattern": "src/**/*.rs" })),
        ("LS", json!({ "path": src })),
        ("ToolSearch", json!({ "query": "x" })),
    ] {
        let c = h.class(true, tool, &input);
        assert_eq!(c, CallClass::InSlip, "{tool}");
        assert_eq!(decide(c, held_under(YoloSource::Off)), Decision::Run);
        // Not HELD: the read runs (a folder search is not walked, so it is ordinary, not shown
        // to be inside the slip).
        assert_eq!(
            decide(h.class(false, tool, &input), NOT_HELD),
            Decision::Run,
            "{tool}"
        );
    }
    assert_eq!(
        h.class(
            false,
            "Read",
            &json!({ "file_path": h.path("project/src/main.rs") })
        ),
        CallClass::InSlip
    );
    // A read of a path L1.1 denies or protects is not run by the slip.
    for rel in [".lunchroom/inbox/m1", ".ssh/id_rsa"] {
        let c = h.class(true, "Read", &json!({ "file_path": h.path(rel) }));
        assert_ne!(
            decide(c, held_under(YoloSource::Off)),
            Decision::Run,
            "{rel}"
        );
    }
}

// §6::13 — a reply, a command that is exactly one `lunchroom send`, is inside every
// slip; the same send joined to any other command, or another program named `lunchroom`, is not.
#[test]
fn reply_is_inside_every_slip() {
    let h = Fixture::new();
    let program = h.path(".lunchroom/bin/lunchroom");
    write(&h.home.join("project/lunchroom"), "program");
    // Another program in Lunchroom's program folder is not Lunchroom's program.
    write(&h.home.join(".lunchroom/bin/helper"), "program");
    assert_eq!(
        h.bash(
            true,
            &format!("{} send codex hi", h.path(".lunchroom/bin/helper"))
        ),
        CallClass::Ordinary
    );
    // A folder whose name only begins with the program folder's name is not inside it.
    write(&h.home.join(".lunchroom/bin-other/lunchroom"), "program");
    let sibling = h.path(".lunchroom/bin-other/lunchroom");
    // `Path::starts_with` compares whole components, not text.
    assert!(!Path::new(&sibling).starts_with(&h.layout.program_dir));
    assert_ne!(
        h.bash(true, &format!("{sibling} send codex hi")),
        CallClass::InSlip
    );
    for cmd in [
        format!("{program} send codex hi"),
        format!("{program} send codex --reply-to 7 'Understood. Waiting for user.'"),
        // A link on `PATH` whose real path is Lunchroom's program.
        "lrlink send codex hi".to_owned(),
    ] {
        let c = h.bash(true, &cmd);
        assert_eq!(c, CallClass::InSlip, "{cmd}");
        assert_eq!(
            decide(c, held_under(YoloSource::Off)),
            Decision::Run,
            "{cmd}"
        );
        assert_eq!(h.bash(false, &cmd), CallClass::InSlip, "{cmd}");
    }
    for cmd in [
        format!("{program} send codex hi; ls"),
        format!("{program} send codex hi && ls"),
        format!("{program} send codex hi || ls"),
        format!("{program} send codex hi | cat"),
        format!("{program} send codex hi\nls"),
        format!("{program} send codex hi > out.txt"),
        format!("{program} send codex hi 2>&1"),
        format!("{program} send codex hi &"),
        format!("ls; {program} send codex hi"),
        format!("X=1 {program} send codex hi"),
        format!("{program} status"),
        format!("{program} --help send"),
        // Not Lunchroom's program: not on `PATH`, or another file of the same name.
        "lunchroom send codex hi".to_owned(),
        "./lunchroom send codex hi".to_owned(),
    ] {
        let c = h.bash(true, &cmd);
        assert_eq!(c, CallClass::Ordinary, "{cmd}");
        assert_eq!(
            decide(c, held_under(YoloSource::Off)),
            Decision::AskUser,
            "{cmd}"
        );
    }
    // A reply's words are still judged: a credential path goes to the user, a store is DENIED,
    // and text the guard cannot parse is not a reply.
    assert_eq!(
        h.bash(true, &format!("{program} send codex ~/.ssh/id_rsa")),
        CREDENTIAL
    );
    assert_eq!(
        h.bash(true, &format!("{program} send codex ~/.lunchroom/inbox/m1")),
        CONFIG
    );
    assert_ne!(
        h.bash(true, &format!("{program} send codex \"$(cat x)\"")),
        CallClass::InSlip
    );
}

// §11::1 (core part) — each denied path, by direct path, symlink, wildcard and
// parent-folder search, is DENIED to a HELD agent; an agent that is not HELD reads it.
#[test]
fn held_guard_denies_store_transcript_and_proc_reads() {
    let h = Fixture::new();
    let reads = [
        (
            "Read",
            json!({ "file_path": h.path(".lunchroom/inbox/m1") }),
        ),
        (
            "Read",
            json!({ "file_path": h.path(".lunchroom/registry.json") }),
        ),
        (
            "Read",
            json!({ "file_path": h.path(".claude/projects/p/t.jsonl") }),
        ),
        (
            "Read",
            json!({ "file_path": h.path(".codex/sessions/s.jsonl") }),
        ),
        ("Read", json!({ "file_path": "/proc/self/status" })),
        ("Read", json!({ "file_path": h.path("project/inbox-link") })),
        ("Read", json!({ "file_path": h.path(".lunch*/inbox/m?") })),
        ("Grep", json!({ "pattern": "x", "path": h.path(".claude") })),
        ("Grep", json!({ "pattern": "x", "path": h.path("") })),
        ("Grep", json!({ "pattern": "x", "path": "/" })),
        (
            "Glob",
            json!({ "pattern": "**/*.jsonl", "path": h.path("") }),
        ),
        ("LS", json!({ "path": h.path(".lunchroom/inbox") })),
    ];
    for (tool, input) in &reads {
        assert_eq!(h.class(true, tool, input), DENIED_PATH, "{tool} {input}");
        // Not HELD: never inside the slip, and it runs (L1.1 holds only while HELD).
        let c = h.class(false, tool, input);
        assert_ne!(c, CallClass::InSlip, "{tool} {input}");
        assert_eq!(decide(c, NOT_HELD), Decision::Run, "{tool} {input}");
    }
}

// §11::2 (core part) — each credential path, the same four ways, goes to the user,
// under a lunchroom yolo too.
#[test]
fn held_guard_sends_credential_path_reads_to_user() {
    let h = Fixture::new();
    let reads = [
        ("Read", json!({ "file_path": h.path(".ssh/id_rsa") })),
        (
            "Read",
            json!({ "file_path": h.path("secrets-project/.env") }),
        ),
        ("Read", json!({ "file_path": h.path("project/key-link") })),
        ("Read", json!({ "file_path": h.path(".ss?/id_*") })),
        (
            "Grep",
            json!({ "pattern": "K", "path": h.path("secrets-project") }),
        ),
        ("Grep", json!({ "pattern": "K", "path": h.path(".ssh") })),
        (
            "Glob",
            json!({ "pattern": "*", "path": h.path("secrets-project") }),
        ),
    ];
    for (tool, input) in &reads {
        let c = h.class(true, tool, input);
        assert_eq!(c, CREDENTIAL, "{tool} {input}");
        assert_eq!(
            decide(c, held_under(YoloSource::Lunchroom)),
            Decision::AskUser
        );
        // Not HELD: never inside the slip (PROTECTED, or a search not walked), and it runs (P1.2).
        let c = h.class(false, tool, input);
        assert_ne!(c, CallClass::InSlip, "{tool} {input}");
        assert_eq!(decide(c, NOT_HELD), Decision::Run, "{tool} {input}");
    }
}

// §11::1 — every denied path of L1.1, each by direct path, symlink, wildcard and
// parent-folder search, is DENIED to a HELD agent, under a lunchroom yolo too.
#[test]
fn every_denied_path_four_ways_is_denied() {
    let h = Fixture::new();
    for d in [".openclaw/agents", ".hermes/sessions"] {
        write(&h.home.join(d).join("s.json"), "{}");
    }
    let files = [
        h.home.join(".lunchroom/inbox/m1"),
        h.home.join(".claude/projects/p/t.jsonl"),
        h.home.join(".codex/sessions/s.jsonl"),
        h.home.join(".openclaw/agents/s.json"),
        h.home.join(".hermes/sessions/s.json"),
        PathBuf::from("/proc/self/status"),
    ];
    for (n, file) in files.iter().enumerate() {
        let link = h.home.join(format!("project/denied-link-{n}"));
        std::os::unix::fs::symlink(file, &link).unwrap_or_default();
        let name = file
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let wildcard = file.with_file_name(format!("{}?", &name[..name.len() - 1]));
        let parent = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let ways = [
            ("Read", json!({ "file_path": file })),
            ("Read", json!({ "file_path": link })),
            ("Read", json!({ "file_path": wildcard })),
            ("Grep", json!({ "pattern": "x", "path": parent })),
        ];
        for (tool, input) in &ways {
            let c = h.class(true, tool, input);
            assert_eq!(c, DENIED_PATH, "{tool} {input}");
            assert_eq!(
                decide(c, held_under(YoloSource::Lunchroom)),
                Decision::Deny(DenyReason::DeniedPath)
            );
        }
    }
}

// §11 L1.1 — a search from a folder holding a link to another folder reaches what is behind the
// link; a link loop ends.
#[test]
fn l1_search_follows_linked_folders() {
    let h = Fixture::new();
    for (dir, target) in [
        ("via-cred", "secrets-project"),
        ("via-store", ".lunchroom/inbox"),
    ] {
        std::fs::create_dir_all(h.home.join(dir)).unwrap_or_default();
        std::os::unix::fs::symlink(h.home.join(target), h.home.join(dir).join("l"))
            .unwrap_or_default();
    }
    let loop_dir = h.home.join("loop");
    std::fs::create_dir_all(&loop_dir).unwrap_or_default();
    std::os::unix::fs::symlink(&loop_dir, loop_dir.join("self")).unwrap_or_default();
    let grep = |rel: &str| {
        h.class(
            true,
            "Grep",
            &json!({ "pattern": "x", "path": h.path(rel) }),
        )
    };
    assert_eq!(grep("via-cred"), CREDENTIAL);
    assert_eq!(grep("via-store"), DENIED_PATH);
    assert_eq!(grep("loop"), CallClass::InSlip);
}

// §11::2 — every credential pattern of L1.1, each by direct path, symlink, wildcard and
// parent-folder search, is PROTECTED and goes to the user under a lunchroom yolo.
#[test]
fn every_credential_path_four_ways_reaches_user() {
    let h = Fixture::new();
    let creds = [
        "c1/.env",
        "c2/.env.local",
        "c3/cert.pem",
        "c4/server.key",
        "c5/id_rsa",
        "c6/id_rsa.pub",
        ".ssh/config",
        ".aws/credentials",
        ".config/gcloud/adc.json",
        "c7/.npmrc",
    ];
    for (n, rel) in creds.iter().enumerate() {
        let file = h.home.join(rel);
        write(&file, "x");
        let link = h.home.join(format!("project/cred-link-{n}"));
        std::os::unix::fs::symlink(&file, &link).unwrap_or_default();
        let name = file
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let wildcard = file.with_file_name(format!("{}?", &name[..name.len() - 1]));
        let parent = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let ways = [
            ("Read", json!({ "file_path": file })),
            ("Read", json!({ "file_path": link })),
            ("Read", json!({ "file_path": wildcard })),
            ("Grep", json!({ "pattern": "x", "path": parent })),
        ];
        for (tool, input) in &ways {
            let c = h.class(true, tool, input);
            assert_eq!(c, CREDENTIAL, "{rel}: {tool} {input}");
            assert_eq!(
                decide(c, held_under(YoloSource::Lunchroom)),
                Decision::AskUser,
                "{rel}"
            );
        }
    }
}

// §6 P1.1 and P1.4 (core part of §6::2 and §6::8) — a call that changes a file or runs a command,
// and a PROTECTED call, is never classified as inside the slip.
#[test]
fn slip_never_holds_writes_commands_or_protected_calls() {
    let h = Fixture::new();
    let calls = [
        (
            "Write",
            json!({ "file_path": h.path("project/new.rs"), "content": "x" }),
        ),
        (
            "Edit",
            json!({ "file_path": h.path("project/src/main.rs") }),
        ),
        (
            "MultiEdit",
            json!({ "file_path": h.path("project/src/main.rs") }),
        ),
        (
            "NotebookEdit",
            json!({ "notebook_path": h.path("project/n.ipynb") }),
        ),
        ("Bash", json!({ "command": "ls" })),
        ("Bash", json!({ "command": "cat src/main.rs" })),
        ("Bash", json!({ "command": "git push" })),
        ("WebFetch", json!({ "url": "https://example.com" })),
        ("TodoWrite", json!({ "todos": [] })),
        ("mcp__mail__send_message", json!({})),
    ];
    for held in [false, true] {
        for (tool, input) in &calls {
            assert_ne!(h.class(held, tool, input), CallClass::InSlip, "{tool}");
        }
    }
}

// §6 P1.4 — an agent's write to Lunchroom's stores is DENIED in every session, written directly
// or through a link; writing Lunchroom's program or the guard's configuration is PROTECTED.
#[test]
fn p1_writes_to_stores_denied_guard_config_protected() {
    let h = Fixture::new();
    for rel in [
        ".lunchroom/inbox/new",
        ".lunchroom/registry.json",
        "project/inbox-link",
        "project/store-dir-link/new",
    ] {
        let input = json!({ "file_path": h.path(rel), "content": "x" });
        for held in [false, true] {
            assert_eq!(h.class(held, "Write", &input), CONFIG, "{rel}");
        }
    }
    for (rel, held_class) in [
        (".claude/settings.json", GUARD_CONFIG),
        ("project/.claude/settings.local.json", GUARD_CONFIG),
        (".codex/config.toml", GUARD_CONFIG),
        (".lunchroom/bin/lunchroom", GUARD_CONFIG),
        ("secrets-project/.env", CREDENTIAL),
        ("project/src/new.rs", CallClass::Ordinary),
    ] {
        let input = json!({ "file_path": h.path(rel) });
        assert_eq!(h.class(true, "Edit", &input), held_class, "{rel}");
        assert_eq!(h.class(false, "Edit", &input), CallClass::Ordinary, "{rel}");
    }
}

// §12::1 (core part) — each injection channel is DENIED in every session: directly,
// behind wrappers, in an unparseable command, from a script file, from a pipe into a shell, and
// in code given to an interpreter.
#[test]
fn guard_denies_commands_that_inject_into_other_sessions() {
    let h = Fixture::new();
    let cmds = [
        "codex queue other hi",
        "codex resume",
        "codex exec resume --last",
        "claude --resume abc",
        "claude -c",
        "claude --continue -p hi",
        "claude -rp x",
        "opencode run --session s hi",
        "opencode run -c hi",
        "opencode run --continue hi",
        "opencode run --session=ses_1 hi",
        "opencode run -sses_1 hi",
        "opencode run -m p/m -s ses_1 hi",
        "opencode run --attach http://127.0.0.1:4096 -c hi",
        "opencode -s ses_1 --prompt hi",
        "opencode --continue --prompt hi",
        "opencode attach http://127.0.0.1:4096 --session ses_1",
        "openclaw agent --message hi",
        "openclaw sessions_send x",
        "openclaw gateway call agent --params x",
        "openclaw --profile work agent --message hi",
        "openclaw cron add --name n --message hi",
        "openclaw cron edit j1 --session-key agent:main:x",
        "openclaw acp --session agent:main:main",
        "sudo openclaw cron add --message hi",
        "curl -X POST http://127.0.0.1:8642/api/sessions/abc/chat -d hi",
        "sudo codex queue o hi",
        "sudo -u alice codex queue o hi",
        "env A=1 codex queue o hi",
        "timeout 5 codex queue o hi",
        "timeout -k 2 5 claude -c",
        "nohup codex queue o hi &",
        "sh -c 'codex queue o hi'",
        "bash -lc \"claude --resume x\"",
        "eval codex queue o hi",
        "env -S 'codex queue o hi'",
        // A program path that exists in the fixture home (not on any one machine).
        "~/tools/codex queue o hi",
        "c'od'ex queue o hi",
        "\\codex queue o hi",
        "cod?x queue o hi",
        "python3 -c \"import os; os.system('codex queue o hi')\"",
        "bash fence.sh",
        "sh ./fence.sh",
        "./fence.sh",
        "source fence.sh",
        ". ./env-fence.sh",
        "qq",
        // OpenCode's forms behind wrappers and from a script file.
        "sudo opencode run -s ses_1 hi",
        "env A=1 opencode -c --prompt hi",
        "timeout 5 opencode attach http://h --session ses_1",
        "sh -c 'opencode run --continue hi'",
        "bash oc.sh",
        "bash ocl.sh",
        "env A=1 openclaw acp --session agent:main:main",
        "sh -c 'openclaw cron edit j1 --message hi'",
    ];
    for cmd in cmds {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
        assert_eq!(h.bash(true, cmd), FENCE, "{cmd}");
    }
    // Text the guard cannot read: DENIED for the reason `unparsed` (F1.2, §12::5).
    for cmd in [
        "echo 'codex queue o hi' | bash",
        "codex queue o \"$(cat msg)\"",
        "X=$(date); claude -c",
        "cat <<EOF | sh\ncodex queue o hi\nEOF",
        "opencode run -s \"$(cat id)\" hi",
        "openclaw cron add --message \"$(cat m)\"",
        "openclaw acp --session $S",
    ] {
        assert_eq!(h.bash(false, cmd), DENIED_UNPARSED, "{cmd}");
        assert_eq!(h.bash(true, cmd), DENIED_UNPARSED, "{cmd}");
    }
    // A parseable `opencode run` into a new session is not DENIED by this rule, HELD or not.
    for held in [false, true] {
        assert!(
            !matches!(h.bash(held, "opencode run hi"), CallClass::Denied(_)),
            "{held}"
        );
    }
}

// §15 K1.8 with F1, I1.2 and A1.3 — a script or code a command runs is searched for a channel's
// name followed by its injecting word, an identity variable being set, or a Lunchroom command only
// the user may run; a name alone is not a match.
#[test]
fn f1_scripts_and_code_are_searched_for_channels() {
    let h = Fixture::new();
    for cmd in [
        "python3 send.py",
        "bash loose-fence.sh",
        "./run.py",
        "git -c core.pager='codex queue o hi' log",
        "cx queue o hi",
        "find . -name x -exec codex queue o {} \\;",
        "strace -f codex queue o hi",
        "strace -o log codex queue o hi",
        "python3 -c \"import subprocess; subprocess.run(['codex', '--model', 'm', '--x', 'y', 'queue', 'o'])\"",
        "python3 -c \"import subprocess\nsubprocess.run([\n  'claude',\n  '-p', 'x',\n  '--resume', 'abc',\n])\"",
        "node -e \"require('child_process').execSync('codex queue o hi')\"",
        "python3 -c \"import os; os.environ['CODEX_THREAD_ID']='x'\"",
    ] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
        assert_eq!(h.bash(true, cmd), FENCE, "{cmd}");
    }
    assert_eq!(
        h.bash(
            false,
            "python3 -c \"import subprocess; subprocess.run(['lunchroom', 'approve', '3'])\""
        ),
        CONFIG
    );
    for code in [
        "import subprocess; subprocess.run(['lunchroom', '--rate', '5'])",
        "import subprocess; subprocess.run(['lunchroom', '--json', 'approve', '3'])",
        "import subprocess; subprocess.run(['lunchroom', '--help', 'approve', '3'])",
        "import subprocess; subprocess.run(['lunchroom', 'listen', '--once'])",
    ] {
        assert_eq!(
            h.bash(false, &format!("python3 -c \"{code}\"")),
            CONFIG,
            "{code}"
        );
    }
    for cmd in [
        "python3 -c \"print('the lunchroom is open')\"",
        "python3 -c \"import subprocess; subprocess.run(['lunchroom', '--help'])\"",
        "python3 notes.py",
        "bash loose.sh",
    ] {
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
    }
}

// §9 I1.2 — no command sets, unsets or clears an identity variable, in every session.
#[test]
fn i1_identity_variables_cannot_be_changed() {
    let h = Fixture::new();
    for cmd in [
        "export CODEX_THREAD_ID=x",
        "CLAUDE_CODE_SESSION_ID=x lunchroom send a hi",
        "unset LUNCHROOM_HOME",
        "env -u CODEX_THREAD_ID ls",
        "env CODEX_THREAD_ID=x ls",
        "env -i LUNCHROOM_HOME=/tmp/x ls",
        "bash forge.sh",
        "python3 forge.py",
    ] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
        assert_eq!(h.bash(true, cmd), FENCE, "{cmd}");
    }
    // §9::3 — each variable set, unset and cleared, HELD and not.
    for var in [
        "CLAUDE_CODE_SESSION_ID",
        "CODEX_THREAD_ID",
        "LUNCHROOM_HOME",
    ] {
        for cmd in [
            format!("export {var}=x"),
            format!("{var}=x ls"),
            format!("{var}+=x ls"),
            format!("{var}+=x"),
            format!("export {var}+=x"),
            format!("unset {var}"),
            format!("env -u {var} ls"),
            format!("export {var}="),
            format!("read {var} < notes.txt"),
            format!("read -r {var}"),
            format!("printf -v {var} x"),
            format!("mapfile -t {var} < notes.txt"),
            format!("readarray {var}"),
            format!("getopts ab {var}"),
            format!("let {var}=1"),
            format!("declare -n r={var}"),
            format!("local {var}"),
        ] {
            assert_eq!(h.bash(false, &cmd), FENCE, "{cmd}");
            assert_eq!(h.bash(true, &cmd), FENCE, "{cmd}");
        }
        // From a script file that sets, unsets or clears it; and a script file or inline
        // code that only mentions it.
        let scripts = [
            ("set", format!("export {var}=x\n")),
            ("unset", format!("unset {var}\n")),
            ("clear", format!("export {var}=\n")),
            // Unparsed shell (`$NAME`), then parsed shell that only names it.
            ("read", format!("echo \"{var} is ${var}\"\n")),
            ("name", format!("echo {var}\n")),
            ("comment", format!("# uses {var}\nls\n")),
        ];
        for (kind, text) in &scripts {
            write(&h.home.join(format!("project/{kind}-{var}.sh")), text);
        }
        write(
            &h.home.join(format!("project/read-{var}.py")),
            &format!("import os\nprint(os.environ.get('{var}'))\n"),
        );
        let mut cmds: Vec<String> = scripts
            .iter()
            .map(|(kind, _)| format!("bash {kind}-{var}.sh"))
            .collect();
        cmds.push(format!("python3 read-{var}.py"));
        cmds.push(format!(
            "python3 -c \"import os; print(os.environ.get('{var}'))\""
        ));
        cmds.push(format!("node -e \"console.log(process.env.{var})\""));
        // Text handed to a shell is code the command runs.
        cmds.push(format!("bash -c 'echo {var}'"));
        cmds.push(format!("sh -c \"printf %s {var}\""));
        cmds.push(format!("eval echo {var}"));
        cmds.push(format!("source name-{var}.sh"));
        for cmd in cmds {
            assert_eq!(h.bash(false, &cmd), FENCE, "{cmd}");
            assert_eq!(h.bash(true, &cmd), FENCE, "{cmd}");
        }
        // §12::5: shell text it cannot parse that mentions one shows `unparsed`.
        for cmd in [
            format!("bash -c 'echo ${var}'"),
            format!("sh -c 'echo \"${{{var}:-none}}\"'"),
        ] {
            assert_eq!(h.bash(false, &cmd), DENIED_UNPARSED, "{cmd}");
            assert_eq!(h.bash(true, &cmd), DENIED_UNPARSED, "{cmd}");
        }
    }
}

// §9::3 — identity changes in inline code and through `env`; §12::5 reasons.
#[test]
fn i1_identity_changes_in_code_and_env_denied() {
    let h = Fixture::new();
    // In code: a dict update, a whole-environment clear; through `env`: unset and clear.
    for cmd in [
        "python3 -c \"import os; os.environ.update({'CODEX_THREAD_ID': 'x'})\"",
        "python3 -c \"import os; os.environ.clear()\"",
        "node -e \"process.env.LUNCHROOM_HOME = '/tmp/x'\"",
        "env -i lunchroom send a hi",
        "env --unset CODEX_THREAD_ID ls",
        "env --unset=CODEX_THREAD_ID ls",
        "env -uCODEX_THREAD_ID ls",
        "env -u CODEX_THREAD_ID ls",
        "env --ignore-environment ls",
    ] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
    }
    // Any mention in code counts, a read included (no list of ways to set a variable is complete).
    for cmd in [
        "python3 -c \"import os; os.environ.__setitem__('CODEX_THREAD_ID', 'x')\"",
        "python3 -c \"import os; sid = os.environ['CODEX_THREAD_ID']; print(sid)\"",
        "python3 -c \"import os; print(os.environ.get('CODEX_THREAD_ID'))\"",
    ] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
    }
    // §12::5: an unparseable command naming a Lunchroom user-only command shows `unparsed`.
    assert_eq!(
        h.bash(false, "lunchroom approve \"$(cat id)\""),
        DENIED_UNPARSED
    );
    assert_eq!(h.bash(false, "echo $CODEX_THREAD_ID"), DENIED_UNPARSED);
}

// §12::3 — an unparseable command naming a channel program as a whole word where a
// program runs is DENIED in every session; a word inside a path is not a match (F1.2, F1.3's
// heredoc test). A name in prose (an argument of `echo`, a heredoc written to a file) is not run:
// `echo $(true) codex` and `cat <<EOF\nclaude\nEOF` were DENIED before F1.2 read command positions.
#[test]
fn unparseable_command_naming_f1_program_denied_everywhere() {
    let h = Fixture::new();
    for cmd in [
        "x=`id` openclaw",
        "echo $(true) && codex",
        "cat <<EOF | sh\nclaude\nEOF",
    ] {
        assert_eq!(h.bash(false, cmd), DENIED_UNPARSED, "{cmd}");
        assert_eq!(h.bash(true, cmd), DENIED_UNPARSED, "{cmd}");
    }
    let heredoc = "python3 - <<'EOF'\nprint(open('/tmp/claude-1000/x').read())\nEOF";
    assert_eq!(h.bash(false, heredoc), CallClass::Ordinary);
    assert_eq!(h.bash(true, heredoc), UNPARSED);
}

// §12::4 (core part) and §12::5 — a HELD agent's unparseable command naming no channel
// is PROTECTED, under a lunchroom yolo too; the reason shown is `unparsed`, for it and for an
// unparseable command naming a channel, which is DENIED.
#[test]
fn unparseable_command_reason_is_unparsed_not_injection() {
    let h = Fixture::new();
    for cmd in [
        "echo $PATH",
        "ls `pwd`",
        "for f in a; do echo $f; done",
        "echo {a,b}",
    ] {
        assert_eq!(h.bash(true, cmd), UNPARSED, "{cmd}");
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
        assert_eq!(
            decide(h.bash(true, cmd), held_under(YoloSource::Lunchroom)),
            Decision::AskUser
        );
    }
    assert_eq!(ProtectedKind::Unparsed.reason(), Some(DenyReason::Unparsed));
    assert_eq!(DenyReason::Unparsed.word(), "unparsed");
    // While HELD, an unparseable command that also reads a credential path goes to the user
    // showing `unparsed`, whichever rule ran first.
    for cmd in ["echo $(true) ~/.ssh/id_rsa", "cat ~/.ssh/id_rsa $(true)"] {
        assert_eq!(h.bash(true, cmd), UNPARSED, "{cmd}");
    }
    // A parseable command DENIED under F1.2 for a script it cannot find shows `unparsed` too.
    assert_eq!(h.bash(false, "bash missing.sh"), DENIED_UNPARSED);
    assert_eq!(h.bash(true, "bash missing.sh"), DENIED_UNPARSED);
    assert_eq!(
        h.bash(true, "codex queue o \"$(cat msg)\""),
        DENIED_UNPARSED
    );
}

// Commands that only mention a channel's name are not fences.
#[test]
fn f1_mentions_are_not_fences() {
    let h = Fixture::new();
    for cmd in [
        "ls /tmp/claude-1000/x",
        "git commit -m 'codex queue docs'",
        "sed -i 's/claude/codex/' notes.md",
        "bash plain.sh",
        "which bash",
        "cargo test -p lunchroom",
        "grep -n claude notes.md",
        "echo codex queue hi",
        "echo CODEX_THREAD_ID=x",
        "echo http://127.0.0.1:8642/api/sessions/1/chat",
        "echo a=codex queue",
        // A new OpenCode session, not an existing one.
        "opencode run hi",
        "opencode session list",
        // OpenClaw commands that put no turn into a session.
        "openclaw cron list",
        "openclaw sessions tail --session-key agent:main:x",
    ] {
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
    }
    // §6::4 — a word a program known never to run its arguments is given adds nothing,
    // HELD or not (the command itself is still outside the slip).
    assert_eq!(h.bash(true, "echo codex queue hi"), CallClass::Ordinary);
    // §3::5 — a PROTECTED program named only as an argument it is never run as does not ask.
    assert_eq!(
        h.bash(true, "echo curl https://example.com"),
        CallClass::Ordinary
    );
    assert_eq!(
        h.bash(true, "mywrap curl https://example.com"),
        CallClass::Protected(ProtectedKind::Network)
    );
    // After a program the guard does not know, the words are judged as if it ran them.
    for cmd in ["mywrap codex queue hi", "mywrap CODEX_THREAD_ID=x ls"] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
        assert_eq!(h.bash(true, cmd), FENCE, "{cmd}");
    }
    assert_eq!(h.bash(false, "mywrap lunchroom approve 3"), CONFIG);
}

// §7 A1.3 — an agent's Lunchroom command that approves, sets YOLO, changes configuration or
// acts as the guard is DENIED in every session; its open commands are not.
#[test]
fn a1_agent_lunchroom_configuration_commands_denied() {
    let h = Fixture::new();
    let program = h.path(".lunchroom/bin/lunchroom");
    let denied = [
        "lunchroom approve 3".to_owned(),
        "lunchroom passphrase".to_owned(),
        format!("{program} passphrase"),
        "lunchroom --help passphrase".to_owned(),
        "mywrap lunchroom passphrase".to_owned(),
        format!("{program} yolo all till 14:00"),
        "sudo lunchroom register x --codex-thread y".to_owned(),
        "lunchroom guard prompt".to_owned(),
        "lunchroom listen --once".to_owned(),
        "sh -c 'lunchroom listen --once'".to_owned(),
        "sh -c 'lunchroom slip edit'".to_owned(),
        "lrlink approve 1".to_owned(),
        "lunchroom --rate 5".to_owned(),
        "lunchroom --help approve 3".to_owned(),
        "lunchroom help yolo all till 14:00".to_owned(),
        "lunchroom --version register x".to_owned(),
        "bash approve.sh".to_owned(),
    ];
    for cmd in &denied {
        assert_eq!(h.bash(false, cmd), CONFIG, "{cmd}");
        assert_eq!(h.bash(true, cmd), CONFIG, "{cmd}");
    }
    let open = [
        "lunchroom send codex hi".to_owned(),
        "lunchroom status".to_owned(),
        "lunchroom --help".to_owned(),
        "lunchroom help send".to_owned(),
        "lunchroom send codex approve the plan".to_owned(),
        "lunchroom".to_owned(),
        format!("{program} status"),
    ];
    for cmd in &open {
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
    }
    // `lunchroom send` writes the stores through Lunchroom itself: not DENIED by A1.3, HELD too.
    assert!(!matches!(
        h.bash(true, "lunchroom send codex hi"),
        CallClass::Denied(_)
    ));
}

// §7 A1.3 — a read-only tool given Lunchroom's program as a file to read does not run it: the
// words after such a tool are files, not commands, as after `cmp`.
#[test]
fn a1_read_only_tools_given_the_program_as_a_file_do_not_run_it() {
    let h = Fixture::new();
    let program = h.path(".lunchroom/bin/lunchroom");
    // Two downloaded copies, outside Lunchroom's own folder (the installed program is itself
    // protected, so reading it is judged by that rule, not this one).
    let copies = "dl-a/lunchroom dl-b/lunchroom";
    for tool in [
        "cmp",
        "diff",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "md5sum",
        "b2sum",
        "cksum",
        "file",
        "stat",
        "wc",
        "ls",
        "du",
        "readelf",
        "objdump",
        "nm",
        "strings",
        "xxd",
        "od",
        "hexdump",
        "head",
        "tail",
        "cat",
    ] {
        let cmd = format!("{tool} {copies}");
        assert_eq!(h.bash(false, &cmd), CallClass::Ordinary, "{cmd}");
        assert_eq!(h.bash(true, &cmd), CallClass::Ordinary, "{cmd}");
    }
    // Still run as Lunchroom: a program that may run its arguments, a command after a read-only
    // tool, and the program run by a path, a wrapper or a shell.
    let denied = [
        "lunchroom approve 3".to_owned(),
        format!("{program} approve 3"),
        format!("{program} yolo all till 14:00"),
        "env lunchroom mode strict".to_owned(),
        "xargs lunchroom approve 3".to_owned(),
        "sh -c \"lunchroom approve\"".to_owned(),
        format!("sha256sum {program} && lunchroom approve 3"),
        format!("sha256sum {program}; {program} yolo all till 14:00"),
        format!("sha256sum {program} | xargs lunchroom approve 3"),
        format!("mywrap sha256sum {program} lunchroom approve 3"),
    ];
    for cmd in &denied {
        assert_eq!(h.bash(false, cmd), CONFIG, "{cmd}");
        assert_eq!(h.bash(true, cmd), CONFIG, "{cmd}");
    }
}

// §6 P1.4 — a command naming Lunchroom's stores, or changing everything below a folder that
// holds them, is DENIED in every session; `cd` is followed.
#[test]
fn p1_commands_on_stores_denied() {
    let h = Fixture::new();
    for cmd in [
        "cat ~/.lunchroom/inbox/m1",
        "echo hi > ~/.lunchroom/registry.json",
        "rm -rf ~/.lunchroom",
        "rm -rf ~",
        "chmod -R 777 ~",
        "find ~ -name x -delete",
        "cd ~/.lunchroom && cat inbox/m1",
        "curl -o~/.lunchroom/inbox/x https://example.com",
        "cp evil ~/.lunchroom",
    ] {
        assert_eq!(h.bash(false, cmd), CONFIG, "{cmd}");
        // §6::11 — handled as a write to the stores: DENIED, never asked.
        for yolo in [
            YoloSource::Off,
            YoloSource::HarnessOnly,
            YoloSource::Lunchroom,
        ] {
            assert_eq!(
                decide(h.bash(true, cmd), held_under(yolo)),
                Decision::Deny(DenyReason::Configuration),
                "{cmd}"
            );
        }
    }
    assert_eq!(h.bash(false, "find ~ -name x"), CallClass::Ordinary);
}

// §6 P1.4 — each PROTECTED kind of command goes to a HELD agent's user, under a lunchroom yolo
// too; an agent that is not HELD runs it.
#[test]
fn p1_protected_commands_ask_under_yolo() {
    use ProtectedKind::{Credential, Delete, GuardConfig, Network, PushOrPublish};
    let h = Fixture::new();
    let program = h.path(".lunchroom/bin/lunchroom");
    // The Read tool only reads: reading the guard's configuration stays inside the slip, and
    // running Lunchroom's program is not naming it.
    let settings = json!({ "file_path": h.path(".claude/settings.json") });
    assert_eq!(h.class(true, "Read", &settings), CallClass::InSlip);
    // §6::12 — running the program to read its status runs under a lunchroom yolo.
    // Run directly or by a shell or interpreter it is run, not named; a user-only command run
    // that way is still DENIED (A1.3).
    for cmd in [
        format!("{program} status"),
        format!("python3 {program} status"),
        format!("bash {program} status"),
    ] {
        let status = h.bash(true, &cmd);
        assert_eq!(status, CallClass::Ordinary, "{cmd}");
        assert_eq!(
            decide(status, held_under(YoloSource::Lunchroom)),
            Decision::Run
        );
    }
    for cmd in [
        format!("python3 {program} approve 7"),
        format!("bash {program} approve 7"),
    ] {
        for held in [false, true] {
            assert_eq!(
                h.bash(held, &cmd),
                CallClass::Denied(DenyReason::Configuration),
                "{cmd}"
            );
        }
    }
    let cmds = [
        ("git push".to_owned(), PushOrPublish),
        ("git -C repo push origin main".to_owned(), PushOrPublish),
        ("npm publish".to_owned(), PushOrPublish),
        ("cargo publish".to_owned(), PushOrPublish),
        ("docker push img".to_owned(), PushOrPublish),
        ("rm f.txt".to_owned(), Delete),
        ("find src -name '*.tmp' -delete".to_owned(), Delete),
        ("git clean -fd".to_owned(), Delete),
        ("curl https://example.com".to_owned(), Network),
        ("scp a host:b".to_owned(), Network),
        ("git fetch".to_owned(), Network),
        ("dig x.example.com".to_owned(), Network),
        ("cat ../secrets-project/.env".to_owned(), Credential),
        ("printenv".to_owned(), Credential),
        ("env".to_owned(), Credential),
        ("export -p".to_owned(), Credential),
        ("cd ~/.ssh && cat id_rsa".to_owned(), Credential),
        ("echo x >> ~/.claude/settings.json".to_owned(), GuardConfig),
        // P1.4: a command naming the guard's configuration counts as writing it.
        ("cat ~/.claude/settings.json".to_owned(), GuardConfig),
        (format!("ls -l {program}"), GuardConfig),
        (format!("cp evil {program}"), GuardConfig),
    ];
    for (cmd, kind) in &cmds {
        let c = h.bash(true, cmd);
        assert_eq!(c, CallClass::Protected(*kind), "{cmd}");
        assert_eq!(
            decide(c, held_under(YoloSource::Lunchroom)),
            Decision::AskUser
        );
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
    }
}

// §3 R2.4, card 5 — a HELD agent's ordinary command runs under a lunchroom yolo and goes to the
// user under the harness's own YOLO alone.
#[test]
fn r2_card5_ordinary_command_runs_under_lunchroom_yolo_only() {
    let h = Fixture::new();
    for cmd in [
        "python3 migrate.py",
        "cargo test",
        "ls -la",
        "git status",
        "git commit -m 'msg'",
        "bash plain.sh",
    ] {
        let c = h.bash(true, cmd);
        assert_eq!(c, CallClass::Ordinary, "{cmd}");
        assert_eq!(decide(c, held_under(YoloSource::Lunchroom)), Decision::Run);
        assert_eq!(
            decide(c, held_under(YoloSource::HarnessOnly)),
            Decision::AskUser
        );
    }
}

// §11 L1.1 — a command that reads everything below a folder is judged like a search.
#[test]
fn l1_recursive_commands_are_searches() {
    let h = Fixture::new();
    for cmd in [
        "grep -r x ~",
        "ls -R ~",
        "find / -name x",
        "rg TODO ~/.claude",
    ] {
        assert_eq!(h.bash(true, cmd), DENIED_PATH, "{cmd}");
    }
    assert_eq!(h.bash(true, "rg TODO ../secrets-project"), CREDENTIAL);
    assert_eq!(h.bash(true, "rg TODO src"), CallClass::Ordinary);
    assert_eq!(h.bash(false, "grep -r x ~"), CallClass::Ordinary);
}

// §11 L1.1 — `grep -r` searches the working folder only when it is given no path; given files it
// reads those files, and given a folder it searches that folder.
#[test]
fn l1_recursive_grep_searches_only_the_paths_it_is_given() {
    let h = Fixture::new();
    for cmd in [
        "grep -rn -i -E 'fn main' src/main.rs",
        "grep -r -e main src/main.rs",
        "grep -r -A 3 main src/main.rs",
        "grep -rA 3 main src/main.rs",
        "grep -r --include '*.rs' main src/main.rs",
        "grep -rn main -- src/main.rs",
        "grep -rin --include '*.rs' main src",
        "egrep -R 'a|b' src/main.rs",
    ] {
        assert_eq!(h.bash(true, cmd), CallClass::Ordinary, "{cmd}");
    }
    // The working folder's walk reaches a link into Lunchroom's stores.
    for cmd in [
        "grep -r x",
        "grep -rn -i -E 'x'",
        "grep -r -e src",
        "grep -r -e x -e y",
        "grep -r -A 3 x",
        "grep -rA 3 x",
        "grep -r --include '*.rs' x",
        "grep -r x ~",
        "grep -r x src ~/.claude",
    ] {
        assert_eq!(h.bash(true, cmd), DENIED_PATH, "{cmd}");
    }
    // Lunchroom's own folder as an operand, or a wildcard that may expand to any name in the
    // folder (Lunchroom's program among them): still DENIED, by the rule for Lunchroom's files.
    for cmd in [
        "grep -r x ~/.lunchroom/inbox",
        "grep -r -e x ~/.lunchroom/inbox",
        "grep -r x src/main.rs ~/.lunchroom/inbox",
        "grep -r x *",
    ] {
        assert!(matches!(h.bash(true, cmd), CallClass::Denied(_)), "{cmd}");
    }
}

// Tools the guard does not know may send data off the computer: PROTECTED while HELD.
#[test]
fn p1_tools_by_kind() {
    let h = Fixture::new();
    let none = json!({});
    // §6::10 — a tool the guard does not know counts as sending data off the computer:
    // never inside the slip, and it goes to the user even under a lunchroom yolo.
    let unknown = h.class(true, "mcp__mail__send_message", &none);
    assert_eq!(unknown, CallClass::Protected(ProtectedKind::UnknownTool));
    assert_eq!(
        decide(unknown, held_under(YoloSource::Lunchroom)),
        Decision::AskUser
    );
    let no_channel = Situation {
        approval_channel: false,
        ..held_under(YoloSource::Lunchroom)
    };
    assert_eq!(
        decide(unknown, no_channel),
        Decision::Deny(DenyReason::NoApprovalChannel)
    );
    assert_eq!(
        h.class(true, "WebFetch", &none),
        CallClass::Protected(ProtectedKind::Network)
    );
    assert_eq!(
        h.class(true, "mcp__mail__send_message", &none),
        CallClass::Protected(ProtectedKind::UnknownTool)
    );
    assert_eq!(
        h.class(false, "mcp__mail__send_message", &none),
        CallClass::Ordinary
    );
    // §6::9 — an unknown tool given a path in Lunchroom's stores is DENIED, HELD or not.
    let write = json!({ "path": h.path(".lunchroom/registry.json"), "content": "{}" });
    let nested = json!({ "args": { "files": [h.path(".lunchroom/inbox/m1")] } });
    for input in [&write, &nested] {
        for held in [false, true] {
            assert_eq!(
                h.class(held, "mcp__filesystem__write_file", input),
                CONFIG,
                "{input}"
            );
        }
    }
    assert_eq!(h.class(true, "TodoWrite", &none), CallClass::Ordinary);
    assert_eq!(h.class(true, "Read", &none), UNPARSED);
    assert_eq!(h.class(true, "Bash", &none), UNPARSED);
}

// §12::6 — a shell script the guard cannot find or read, or any script larger than the
// 1 MiB it searches, is DENIED for the reason `unparsed`, HELD and not; data files and names an
// interpreter resolves its own way are left alone.
#[test]
fn f1_scripts_it_cannot_read_or_search_are_denied() {
    let h = Fixture::new();
    let big = "echo hi\n".repeat(140_000);
    for f in ["big.sh", "big.py", "big.awk", "big.csv"] {
        write(&h.home.join("project").join(f), &big);
    }
    write(
        &h.home.join("project/bigexec"),
        &format!("#!/bin/sh\n{big}"),
    );
    write(&h.home.join("project/tool.py"), "print('ok')\n");
    // The edge: exactly 1 MiB is searched; one byte more is not.
    let mib = 1024 * 1024;
    write(&h.home.join("project/edge.sh"), &"#".repeat(mib));
    write(&h.home.join("project/over.sh"), &"#".repeat(mib + 1));
    // A script the guard cannot read.
    let noread = h.home.join("project/noread.sh");
    write(&noread, "ls\n");
    std::fs::set_permissions(&noread, std::os::unix::fs::PermissionsExt::from_mode(0o000))
        .unwrap_or_default();
    assert_eq!(h.bash(false, "bash edge.sh"), CallClass::Ordinary);
    write(
        &h.home.join("project/prog.awk"),
        "BEGIN { system(\"codex queue o hi\") }\n",
    );
    for (cmd, want) in [
        ("bash missing.sh", DENIED_UNPARSED),
        ("bash over.sh", DENIED_UNPARSED),
        ("bash noread.sh", DENIED_UNPARSED),
        // A program run by a path that does not exist, directly or behind a wrapper.
        ("./missing.sh", DENIED_UNPARSED),
        ("sudo ./missing.sh", DENIED_UNPARSED),
        ("~/bin/missing", DENIED_UNPARSED),
        // A missing program that is not a script, as the command's own program and behind each
        // wrapper the clause names.
        ("~/no/such/tool", DENIED_UNPARSED),
        ("sudo ~/no/such/tool", DENIED_UNPARSED),
        ("timeout 5 ~/no/such/tool", DENIED_UNPARSED),
        // The same in text the guard cannot parse.
        ("./missing.sh $(date)", DENIED_UNPARSED),
        ("X=$(date); ./missing.sh", DENIED_UNPARSED),
        ("echo $(./missing.sh)", DENIED_UNPARSED),
        (
            "cat <<'EOF'\n/tmp/no/such\nEOF\n./missing.sh",
            DENIED_UNPARSED,
        ),
        // A shell an unknown wrapper is given, judged where channels are.
        ("mywrap bash missing.sh", DENIED_UNPARSED),
        ("mywrap -x bash big.sh", DENIED_UNPARSED),
        ("source missing.sh", DENIED_UNPARSED),
        ("bash big.sh", DENIED_UNPARSED),
        ("python3 big.py", DENIED_UNPARSED),
        ("python3 -X dev big.py", DENIED_UNPARSED),
        ("awk -f big.awk x", DENIED_UNPARSED),
        ("awk -fbig.awk x", DENIED_UNPARSED),
        ("./bigexec", DENIED_UNPARSED),
        // A bare name not in the working folder is found through `PATH`, as the shell does.
        ("bash qq", FENCE),
        ("awk -fprog.awk x", FENCE),
    ] {
        assert_eq!(h.bash(false, cmd), want, "{cmd}");
        assert_eq!(h.bash(true, cmd), want, "{cmd}");
    }
    for cmd in [
        "awk '{print}' big.csv",
        "sed -n 1p big.csv",
        "python3 tool.py big.csv",
        "python3 -c 'print(1)' big.csv",
        "node app",
        // Not a shell script and not over 1 MiB: left to the interpreter.
        "python3 missing.py",
        // A path given to a program the guard does not know to run it.
        "docker run -v ./data:/d img",
        "mywrap ./missing.sh",
    ] {
        assert!(!matches!(h.bash(false, cmd), CallClass::Denied(_)), "{cmd}");
    }
}

// K1.8 — `sed` and `awk` read their files as data: a file naming a channel or a user-only command
// is searched only when the script can run what it reads (`sed`'s `e`, `awk`'s `system` or a pipe),
// HELD and not.
#[test]
fn sed_and_awk_files_are_searched_only_when_the_script_runs_them() {
    let h = Fixture::new();
    write(&h.home.join("project/print.awk"), "{ print $1 }\n");
    write(&h.home.join("project/run.awk"), "{ system($0) }\n");
    write(&h.home.join("project/print.sed"), "1p\n");
    // Real files, not invented ones: Lunchroom's own source names its commands and the channels.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for file in [
        "lunchroom/src/main.rs",
        "lunchroom/src/install.rs",
        "lunchroom-core/src/classify.rs",
    ] {
        let path = crates.join(file).to_string_lossy().into_owned();
        for held in [false, true] {
            for cmd in [format!("sed -n 1,40p {path}"), format!("awk 'NR<9' {path}")] {
                assert!(!matches!(h.bash(held, &cmd), CallClass::Denied(_)), "{cmd}");
            }
        }
    }
    for held in [false, true] {
        for cmd in [
            "sed -n 1p fence.sh",
            "sed -n '1,5p' approve.sh",
            "sed -n -f print.sed fence.sh",
            "awk 1 fence.sh",
            "awk '{print $1}' approve.sh",
            "awk -f print.awk fence.sh",
            "gawk --file=print.awk approve.sh",
        ] {
            assert!(!matches!(h.bash(held, cmd), CallClass::Denied(_)), "{cmd}");
        }
        for (cmd, want) in [
            ("sed e fence.sh", FENCE),
            ("sed 's/^/x/e' fence.sh", FENCE),
            ("sed --expression=e fence.sh", FENCE),
            ("sed e approve.sh", CONFIG),
            ("awk '{system($0)}' fence.sh", FENCE),
            ("awk '{print | \"sh\"}' fence.sh", FENCE),
            ("awk -f run.awk fence.sh", FENCE),
            ("awk -frun.awk approve.sh", CONFIG),
            ("gawk -E run.awk fence.sh", FENCE),
            // A program file the guard cannot read: the data is searched.
            ("awk -f missing.awk fence.sh", FENCE),
        ] {
            assert_eq!(h.bash(held, cmd), want, "{cmd}");
        }
    }
}

// §12::1 — every channel, each directly, behind each wrapper (`sudo`, `env`, `timeout`,
// `sh -c`), in an unparseable command and from a script file, is DENIED, HELD and not.
#[test]
fn f1_every_channel_every_way_is_denied() {
    let h = Fixture::new();
    let channels = [
        "codex queue other hi",
        "codex resume",
        "claude --resume abc",
        "claude --continue",
        "opencode run --session s1 hi",
        "opencode run -s s1 hi",
        "opencode run --continue hi",
        "opencode run -c hi",
        "opencode --session s1 --prompt hi",
        "opencode -s s1 --prompt hi",
        "opencode --continue --prompt hi",
        "opencode -c --prompt hi",
        "opencode attach http://h --session s1",
        "opencode attach http://h -s s1",
        "opencode attach http://h --continue",
        "opencode attach http://h -c",
        "openclaw agent --message hi",
        "openclaw gateway call agent --params x",
        "openclaw sessions_send x",
        "openclaw acp",
        "openclaw cron add --message hi",
        "openclaw cron edit j1 --message hi",
        "curl -X POST http://127.0.0.1:8642/api/sessions/abc/chat -d hi",
    ];
    for (n, ch) in channels.iter().enumerate() {
        let script = format!("grid-{n}.sh");
        write(
            &h.home.join("project").join(&script),
            &format!("#!/bin/sh\n{ch}\n"),
        );
        let ways = [
            ((*ch).to_owned(), FENCE),
            (format!("sudo {ch}"), FENCE),
            (format!("env A=1 {ch}"), FENCE),
            (format!("timeout 5 {ch}"), FENCE),
            (format!("sh -c '{ch}'"), FENCE),
            (format!("bash {script}"), FENCE),
            (format!("{ch} \"$(cat m)\""), DENIED_UNPARSED),
        ];
        for (cmd, want) in &ways {
            assert_eq!(h.bash(false, cmd), *want, "{cmd}");
            assert_eq!(h.bash(true, cmd), *want, "{cmd}");
        }
    }
}

// §2 R1.7 — only the user changes the rate limit: an agent's command that changes it is DENIED,
// HELD or not, however it is run.
#[test]
fn r1_agent_rate_limit_change_denied() {
    let h = Fixture::new();
    let program = h.path(".lunchroom/bin/lunchroom");
    let denied = [
        "lunchroom rate 5 60".to_owned(),
        "lunchroom rate --ceiling 100".to_owned(),
        format!("{program} rate 1000 1"),
        "sudo lunchroom rate 5 60".to_owned(),
        "sh -c 'lunchroom rate 5 60'".to_owned(),
        format!("python3 {program} rate 5 60"),
    ];
    for cmd in &denied {
        assert_eq!(h.bash(false, cmd), CONFIG, "{cmd}");
        assert_eq!(h.bash(true, cmd), CONFIG, "{cmd}");
    }
    assert_eq!(
        h.bash(false, "lunchroom send codex rate 5"),
        CallClass::Ordinary
    );
}

// §12::1 — a channel given to a program that runs an option's value or a subcommand's
// words as a command (`git rebase -x`, `rg --pre`, `tar -I`, `sed`'s `e`), separated or attached,
// is DENIED; the same programs with ordinary text are not.
#[test]
fn a_channel_in_a_command_taking_option_is_denied() {
    let h = Fixture::new();
    let ch = "codex queue other hi";
    let cmds = [
        format!("git rebase -x '{ch}' HEAD~1"),
        format!("git rebase --exec '{ch}' HEAD~1"),
        format!("git bisect run {ch}"),
        format!("git submodule foreach '{ch}'"),
        format!("git difftool -x '{ch}'"),
        format!("git filter-branch --tree-filter '{ch}' HEAD"),
        format!("rg --pre '{ch}' x ."),
        format!("tar -I '{ch}' -cf a.tar b"),
        format!("tar --to-command '{ch}' -xf a.tar"),
        format!("tar -F '{ch}' -cf a.tar b"),
        format!("sort --compress-program '{ch}' f"),
        format!("man -P '{ch}' ls"),
        format!("sed 'e {ch}' f"),
        format!("sed -e 's/x/{ch}/e' f"),
        format!("less '+!{ch}' f"),
        format!("cargo --config 'target.x.runner=\"{ch}\"' run"),
    ];
    for cmd in &cmds {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
    }
    for cmd in [
        "git commit -m 'fix the queue'",
        "git log --oneline",
        "rg --pre-glob '*.gz' x .",
        "tar -cf a.tar b",
        "sed -e 's/a/b/' f",
        "sort -k2 f",
        // Searches and logs that name a channel or an identity variable as text run.
        "rg CODEX_THREAD_ID src",
        "rg 'codex queue' .",
        "git log --grep 'codex queue'",
        "sed -n 1p notes.md",
        // A file name is not sed's script.
        "sed -e 's/a/b/' codex-queue-notes.md",
        "git commit -m 'codex queue docs'",
    ] {
        assert_ne!(h.bash(false, cmd), FENCE, "{cmd}");
        assert!(!matches!(h.bash(false, cmd), CallClass::Denied(_)), "{cmd}");
    }
}

// §12::1 — a shell's options end at its first operand, as the shell reads them: a word
// after the script's name is the script's (`bash build.sh -clean` runs build.sh, not `-c lean`).
#[test]
fn a_word_after_the_script_is_not_a_shell_option() {
    let h = Fixture::new();
    write(&h.home.join("project/build.sh"), "codex queue other hi\n");
    for cmd in [
        "bash build.sh -clean",
        "sh build.sh -c x",
        "bash -x build.sh",
        "bash -- build.sh",
        "bash -ec 'codex queue other hi'",
        "bash -c -x 'codex queue other hi'",
        "bash --command '-x; codex queue other hi'",
    ] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
    }
}

/// A file of the repository, by its path from the repository's root.
fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel)
}

fn repo_file(rel: &str) -> String {
    let text = std::fs::read_to_string(repo_path(rel)).unwrap_or_default();
    assert!(!text.is_empty(), "{rel}");
    text
}

// F1.2 — the shape of a real call (2026-10-28): a quoted file name with spaces in a variable is
// not a program run by a path that does not exist.
#[test]
fn a_quoted_path_with_spaces_in_a_variable_is_not_a_missing_program() {
    let h = Fixture::new();
    let cmd = "F=\"/home/u/project/source/codes/Town, ST Code of Ordinances.txt\"; ls -la \"$F\"; head -5 \"$F\"; grep -n -iE \"height, building|building height|height of (a )?building|Sec\\. 78-333\" \"$F\" | head -30";
    assert_not_denied(&h, cmd);
    // A program by a quoted path that does not exist is still DENIED, after an assignment too.
    for cmd in ["X=\"a b\" \"./no such/tool\" $Y", "X='a b' ./missing.sh $Y"] {
        assert_eq!(h.bash(false, cmd), DENIED_UNPARSED, "{cmd}");
    }
}

/// The call is not DENIED, HELD or not.
fn assert_not_denied(h: &Fixture, cmd: &str) {
    for held in [false, true] {
        assert!(
            !matches!(h.bash(held, cmd), CallClass::Denied(_)),
            "{held} {cmd}"
        );
    }
}

// §12::3 — a channel's name in prose is not a command: a commit message, a pull request
// body or a heredoc written to a file, here the repository's own documents (they name `codex queue`
// and the user-only commands). The call runs, or goes to the user while HELD for being unparsed.
#[test]
fn prose_naming_a_channel_is_not_a_command() {
    let h = Fixture::new();
    for rel in [
        "rust/README.md",
        "rust/TESTPLAN.md",
        "docs/spec/lunchroom-spec.md",
    ] {
        let text = repo_file(rel);
        assert!(text.contains("codex queue"), "{rel}");
        for cmd in [
            format!("git commit -m \"$(cat <<'EOF'\n{text}\nEOF\n)\""),
            format!("gh pr create --title t --body \"$(cat <<'EOF'\n{text}\nEOF\n)\""),
            format!("cat > notes.md <<'EOF'\n{text}\nEOF"),
        ] {
            assert_eq!(h.bash(false, &cmd), CallClass::Ordinary, "{rel}");
            assert_eq!(h.bash(true, &cmd), UNPARSED, "{rel}");
        }
    }
    for cmd in [
        "git commit -m \"fix $(git rev-parse --short HEAD): codex resume\"",
        // An unquoted heredoc with nothing the shell expands.
        "cat > f.md <<EOF\nNote: codex resume and claude --resume are documented.\nEOF",
        "cat > f.md <<EOF\ncodex queue\nEOF",
        "echo $(true) codex queue",
    ] {
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
        assert_eq!(h.bash(true, cmd), UNPARSED, "{cmd}");
    }
    // Parsed commands whose arguments are prose.
    for cmd in [
        "gh pr create --title t --body 'fix codex resume and lunchroom approve'",
        "make MSG=\"codex queue\"",
        "git commit -m 'codex queue docs'",
    ] {
        assert_not_denied(&h, cmd);
    }
}

// §12::3 — a channel's name where text runs stays DENIED for the reason `unparsed`: in
// a command, in a substitution, in a heredoc the shell expands or feeds to a shell, and in a file
// the text writes and then runs.
#[test]
fn text_that_runs_a_channel_is_still_denied() {
    let h = Fixture::new();
    for cmd in [
        "cat <<EOF | sh\ncodex queue o hi\nEOF",
        "cat <<'EOF' | bash\nclaude --resume x\nEOF",
        "bash <<EOF\ncodex queue o hi\nEOF",
        "echo 'codex queue o hi' $(true) | sh",
        // A file written by a heredoc and then run, by a shell, an interpreter or its path.
        "cat > s.sh <<'EOF'\ncodex queue o hi\nEOF\nbash s.sh",
        "cat > s.sh <<'EOF'\ncodex queue o hi\nEOF\nsource s.sh",
        "cat > s.py <<'EOF'\nclaude --resume x\nEOF\npython3 s.py",
        "cat > s.sh <<'EOF'\nclaude --resume x\nEOF\nchmod +x s.sh && ./s.sh",
        // A substitution runs wherever it stands.
        "git commit -m \"$(codex queue o hi)\"",
        "git commit -m \"`claude --resume x`\"",
        "git commit -m \"$(cat <<EOF\n$(codex queue o hi)\nEOF\n)\"",
        "git commit -m \"$(cat <<EOF\n`codex queue o hi`\nEOF\n)\"",
        "echo \"$(date)\" | python3 -c 'import os; os.system(\"codex queue o hi\")'",
        "x=$(date); codex queue o hi",
        "for f in a b; do codex queue o $f; done",
        "mywrap codex queue o $(date)",
        "sudo -u alice codex queue o $(date)",
        "echo hi $(date) && lunchroom approve 3",
    ] {
        assert_eq!(h.bash(false, cmd), DENIED_UNPARSED, "{cmd}");
        assert_eq!(h.bash(true, cmd), DENIED_UNPARSED, "{cmd}");
    }
}

// §12::1 — an option's value is a command only for the programs and options that run
// it (`COMMAND_OPTIONS`); `-c` and `-o` mean something else to most programs, and `--opt=value`
// is data unless the option is one of those.
#[test]
fn an_option_value_is_a_command_only_for_a_program_that_runs_it() {
    let h = Fixture::new();
    let ch = "codex queue other hi";
    for cmd in [
        format!("git -c core.pager='{ch}' log"),
        format!("ssh -o ProxyCommand='{ch}' host"),
        format!("ssh -oProxyCommand='{ch}' host"),
        format!("scp -o ProxyCommand='{ch}' a b:c"),
        format!("sftp -oProxyCommand='{ch}' host"),
        format!("git rebase --exec='{ch}' HEAD~1"),
        format!("tar --use-compress-program='{ch}' -cf a.tar b"),
        format!("rg --pre='{ch}' x ."),
    ] {
        assert_eq!(h.bash(false, &cmd), FENCE, "{cmd}");
    }
    for cmd in [
        format!("grep -c '{ch}' notes.md"),
        format!("grep -o '{ch}' notes.md"),
        format!("grep --regexp='{ch}' notes.md"),
        format!("git commit --message='{ch}'"),
        format!("git log --grep='{ch}'"),
        format!("curl -o out.html 'https://example.com/?q={ch}'"),
        format!("wc -c '{ch}.txt'"),
        format!("printf '%s' --text='{ch}'"),
        "git commit -c HEAD".to_owned(),
    ] {
        assert_not_denied(&h, &cmd);
    }
}

// K1.8 — the files an interpreter is given are data to it: only the script it runs and its inline
// code are searched. The repository's README names `codex queue`, so searching it as code is DENIED.
#[test]
fn interpreter_data_files_are_not_searched() {
    let h = Fixture::new();
    let readme = repo_path("rust/README.md").to_string_lossy().into_owned();
    write(
        &h.home.join("project/tool.py"),
        "import sys\nprint(len(sys.argv))\n",
    );
    write(&h.home.join("project/tool.rb"), "puts ARGV.size\n");
    for cmd in [
        format!("python3 tool.py {readme}"),
        format!("python3 -u tool.py --input {readme}"),
        format!("python3 -c 'print(1)' {readme}"),
        format!("ruby tool.rb {readme}"),
        format!("perl -e 'print 1' {readme}"),
    ] {
        assert_not_denied(&h, &cmd);
    }
    // The script itself, and inline code, are still searched.
    let script = h.path("project/send.py");
    for cmd in [
        format!("python3 {script} {readme}"),
        "python3 -c \"import os; os.system('codex queue o hi')\" x".to_owned(),
        "node -e \"require('child_process').execSync('codex queue o hi')\" x".to_owned(),
    ] {
        assert_eq!(h.bash(false, &cmd), FENCE, "{cmd}");
    }
}

// K1.8 — `sed` and `awk` data files are searched only when the program really runs text: `sed`'s
// `e` command or `s` flag, `awk`'s `system(`, a pipe, `@load`. The README names `codex queue`.
#[test]
fn sed_and_awk_run_text_only_by_their_commands() {
    let h = Fixture::new();
    let readme = repo_path("rust/README.md").to_string_lossy().into_owned();
    for cmd in [
        format!("sed -n '/error/p' {readme}"),
        format!("sed -n '/error/,/end/p' {readme}"),
        format!("sed -n '/needle/{{p;d}}' {readme}"),
        format!("sed 's/one/two/g' {readme}"),
        format!("sed 's/one/two/gI' {readme}"),
        format!("sed -e 's/one/two/' -e p {readme}"),
        format!("sed -n -e '/seen/p' {readme}"),
        format!("sed 'y/abc/xyz/' {readme}"),
        format!("sed '1~2d;$!N' {readme}"),
        format!("sed -n 1,5p {readme}"),
        format!("sed 's/e/E/' {readme}"),
        format!("awk -F'|' '{{print $1}}' {readme}"),
        format!("awk -F '|' '{{print $2}}' {readme}"),
        format!("awk 'BEGIN {{ x = \"a|b system(x)\" }} {{ print x || 1 }}' {readme}"),
        format!("awk -v 's=system(' '{{ print s }}' {readme}"),
    ] {
        assert_not_denied(&h, &cmd);
    }
    // Each real way to run text is a script, so the file is searched like one.
    for cmd in [
        format!("sed e {readme}"),
        format!("sed 's/a/b/e' {readme}"),
        format!("sed 's/a/b/ge' {readme}"),
        format!("sed -n '/x/{{p;e}}' {readme}"),
        format!("sed '1!e' {readme}"),
        format!("sed --expression='s/x/y/ge' {readme}"),
        format!("sed -e p -e 'e' {readme}"),
        format!("awk '{{ system($0) }}' {readme}"),
        format!("awk '{{ system ( $0 ) }}' {readme}"),
        format!("awk '{{ print | \"sh\" }}' {readme}"),
        format!("awk 'BEGIN {{ cmd = \"sh\" }} {{ print | cmd }}' {readme}"),
        format!("awk '{{ print |& \"sh\" }}' {readme}"),
        format!("awk 'BEGIN {{ \"date\" | getline d }}' {readme}"),
        format!("gawk '@load \"x\"; 1' {readme}"),
    ] {
        for held in [false, true] {
            assert!(
                matches!(h.bash(held, &cmd), CallClass::Denied(_)),
                "{held} {cmd}"
            );
        }
    }
}

// §12::6 — a program run by a path that does not exist yet may be what an earlier build or
// install in the same call makes; nothing else makes it.
#[test]
fn a_build_makes_the_program_a_later_command_runs() {
    let h = Fixture::new();
    for cmd in [
        "cargo build --release && ./target/release/app",
        "cargo install --path . --root ./out && ./out/bin/app",
        "make && ./a.out",
        "cmake --build build && ./build/app",
        "gcc -o app main.c && ./app",
        "go build -o bin/x . && ./bin/x",
        "npm run build; ./dist/cli.js",
        "python3 -m venv .venv && .venv/bin/pip install x",
        "cd build && make && ./tool",
        "sudo cargo build && sudo ./target/debug/app",
        "cargo build && echo done && ./target/debug/app",
        // The same in text the guard cannot parse.
        "cargo build --release && ./target/release/app \"$(date)\"",
        "make && ./a.out $(date)",
        "python3 -m venv .venv && .venv/bin/pip install \"$X\"",
    ] {
        assert_not_denied(&h, cmd);
    }
    for cmd in [
        "./app",
        "./app && cargo build",
        "ls && ./missing.sh",
        // A script made by a redirection, a heredoc or a command that is no build.
        "echo x > s.sh && sh s.sh",
        "echo x > s.sh && ./s.sh",
        "echo $(date) > s.sh && ./s.sh",
        "printf 'make' && ./missing",
        "echo make && ./missing",
        "git status && ./missing",
        // A builder's program that neither builds nor installs.
        "cargo metadata && ./missing",
        "pip --version && ./missing",
        "go version && ./missing",
        "cmake --version && ./missing",
    ] {
        assert_eq!(h.bash(false, cmd), DENIED_UNPARSED, "{cmd}");
        assert_eq!(h.bash(true, cmd), DENIED_UNPARSED, "{cmd}");
    }
}

// §11 L1.1 — only a process's own folder in `/proc` holds another session's data.
#[test]
fn only_a_process_folder_of_proc_is_denied() {
    let h = Fixture::new();
    for p in [
        "/proc/loadavg",
        "/proc/meminfo",
        "/proc/cpuinfo",
        "/proc/uptime",
        "/proc/stat",
        "/proc/version",
    ] {
        assert_eq!(
            h.class(true, "Read", &json!({ "file_path": p })),
            CallClass::InSlip,
            "{p}"
        );
        assert_eq!(
            h.bash(true, &format!("cat {p}")),
            CallClass::Ordinary,
            "{p}"
        );
    }
    for p in [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/thread-self/fd/0",
        "/proc/1/maps",
        "/proc/12345/environ",
    ] {
        assert_eq!(
            h.class(true, "Read", &json!({ "file_path": p })),
            DENIED_PATH,
            "{p}"
        );
        assert_eq!(h.bash(true, &format!("cat {p}")), DENIED_PATH, "{p}");
    }
    // A search from `/proc` reaches the process folders.
    assert_eq!(
        h.class(true, "Grep", &json!({ "pattern": "x", "path": "/proc" })),
        DENIED_PATH
    );
}

// §11 L1.1 and §6 P1.4 — the pattern a searcher is given, what `echo` prints and a commit message
// are text, not paths; every other word is still judged, and a redirection's target too.
#[test]
fn a_pattern_or_message_is_text_not_a_path() {
    let h = Fixture::new();
    for cmd in [
        "grep -n /proc notes.md",
        "grep -n '/proc/self/environ' notes.md",
        "grep -e '.lunchroom/inbox' notes.md",
        "grep -n -e '.lunchroom/inbox' -e /proc notes.md",
        "grep --regexp=.lunchroom/inbox notes.md",
        "egrep -n '/proc|.lunchroom/inbox' notes.md",
        "rg '.lunchroom/inbox' src",
        "rg -e '.lunchroom/registry' src",
        "echo reading /proc/self/environ",
        "echo '.lunchroom/inbox/m1 is where messages land'",
        "printf '%s\\n' ~/.lunchroom/inbox",
        "git commit -m 'see /proc/self/environ and .lunchroom/inbox'",
        "git commit --message='.lunchroom/inbox'",
    ] {
        assert_not_denied(&h, cmd);
    }
    for (cmd, want) in [
        ("grep -n x ~/.lunchroom/inbox/m1", CONFIG),
        ("grep -e x ~/.lunchroom/inbox/m1", CONFIG),
        ("grep -f pats ~/.lunchroom/inbox/m1", CONFIG),
        ("grep --regexp=x ~/.lunchroom/inbox/m1", CONFIG),
        ("grep -nepattern ~/.lunchroom/inbox/m1", CONFIG),
        ("rg --files ~/.lunchroom/inbox", CONFIG),
        ("echo hi > ~/.lunchroom/registry.json", CONFIG),
        ("echo hi >> ~/.lunchroom/inbox/m1", CONFIG),
        ("git commit -m x ~/.lunchroom/inbox/m1", CONFIG),
        ("tee ~/.lunchroom/registry.json", CONFIG),
    ] {
        assert_eq!(h.bash(false, cmd), want, "{cmd}");
        assert_eq!(h.bash(true, cmd), want, "{cmd}");
    }
    assert_eq!(
        h.bash(true, "echo hi >> ~/.claude/settings.json"),
        GUARD_CONFIG
    );
}

// §12::7 (F1.2, with P1.4 and A1.3) — an executable text file with no `#!` line is run
// by the shell as a script, so it is searched as one, HELD or not, and one too large to search is
// DENIED; a file that is not executable, and a compiled program, are not.
#[test]
fn an_executable_file_with_no_first_line_is_judged_as_a_script() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Fixture::new();
    let made = |name: &str, text: &str, mode: u32| {
        let file = h.home.join("project").join(name);
        write(&file, text);
        let set = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode));
        assert!(set.is_ok(), "{set:?}");
    };
    made("fence", "codex queue --thread other --message hi\n", 0o755);
    made("user", "lunchroom approve 1\n", 0o755);
    made("spawn", "claude -p 'push it'\n", 0o755);
    made("plain", "echo hello\n", 0o755);
    made("data", "codex queue --thread other --message hi\n", 0o644);
    made("large", &"# nothing here\n".repeat(80_000), 0o755);
    for held in [true, false] {
        for cmd in ["./fence", "./user"] {
            assert!(matches!(h.bash(held, cmd), CallClass::Denied(_)), "{cmd}");
        }
        assert_eq!(h.bash(held, "./large"), DENIED_UNPARSED);
        assert_eq!(h.bash(held, "./plain"), CallClass::Ordinary);
        assert!(!matches!(h.bash(held, "./data"), CallClass::Denied(_)));
    }
    assert_eq!(
        h.bash(true, "./spawn"),
        CallClass::Protected(ProtectedKind::OtherSession)
    );
    assert_eq!(h.bash(false, "./spawn"), CallClass::Ordinary);
    // A compiled program is not read as text, whatever its bytes hold.
    let program = std::fs::read("/bin/true");
    assert!(program.is_ok(), "{program:?}");
    let mut bytes = program.unwrap_or_default();
    bytes.extend_from_slice(b"\ncodex queue --thread other --message hi\n");
    let real = h.home.join("project/real");
    assert!(std::fs::write(&real, bytes).is_ok());
    let set = std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755));
    assert!(set.is_ok(), "{set:?}");
    assert_eq!(h.bash(false, "./real"), CallClass::Ordinary);
}

// §6::30 — the runtimes the harnesses run under decide what runs the guard too.
#[test]
fn a_harness_runtime_is_guard_configuration_and_running_it_is_not_writing_it() {
    for path in [
        ".local/bin/node",
        ".nvm/versions/node/v24.0.0/bin/node",
        ".local/bin/python3",
        ".local/bin/python",
    ] {
        let cmd = format!("cp a ~/{path}");
        let h = Fixture::new();
        assert_eq!(h.bash(true, &cmd), GUARD_CONFIG, "{cmd}");
    }
    let h = Fixture::new();
    assert_ne!(h.bash(true, "node --version"), GUARD_CONFIG);
    // Running one by its path is not writing it.
    let runtime = h.home.join(".local/bin/python3");
    write(&runtime, "");
    assert!(std::fs::copy("/bin/true", &runtime).is_ok());
    assert_ne!(h.bash(true, "~/.local/bin/python3 --version"), GUARD_CONFIG);
    // A file of that name outside a `bin` folder is an ordinary file.
    for name in ["node", "python", "python3"] {
        assert_ne!(
            h.bash(true, &format!("cp a ~/project/{name}")),
            GUARD_CONFIG
        );
    }
}

// §6::15 (P1.4) — a command of `claude` or `codex` that takes no prompt starts nothing.
#[test]
fn harness_commands_that_take_no_prompt_start_no_session() {
    let h = Fixture::new();
    for cmd in [
        "claude config get theme",
        "claude migrate-installer",
        "codex migrate-rollouts",
        "codex migrate-nfs-db",
        "codex exec-server",
    ] {
        assert_ne!(
            h.bash(true, cmd),
            CallClass::Protected(ProtectedKind::OtherSession),
            "{cmd}"
        );
    }
}

// §11::13 (L1.1) — a search whose walk stops before it has seen every file counts as
// having reached a credential path: HELD, it goes to the user in the Strict and Balanced hold
// modes, YOLO or not, and is DENIED where nobody can answer (A1.2); a walk that finishes over the
// same ordinary files runs as any read does.
#[test]
fn a_search_whose_walk_stops_early_goes_to_the_user() {
    let h = Fixture::new();
    write(&h.home.join("tree/a/b.txt"), "x");
    let src = json!({ "pattern": "x", "path": h.path("tree") });
    let here = h.home.join("project");
    let spent = OsFs::with_path(Duration::ZERO, None);
    let stopped = Guard {
        layout: &h.layout,
        fs: &spent,
        held: true,
    }
    .classify("Grep", &src, &here);
    assert_eq!(stopped, CREDENTIAL);
    let whole = OsFs::with_path(BUDGET, None);
    let finished = Guard {
        layout: &h.layout,
        fs: &whole,
        held: true,
    }
    .classify("Grep", &src, &here);
    assert_ne!(finished, CREDENTIAL);
    for mode in [HoldMode::Strict, HoldMode::Balanced] {
        for yolo in [
            YoloSource::Off,
            YoloSource::HarnessOnly,
            YoloSource::Lunchroom,
        ] {
            let at = |approval_channel| Situation {
                held: true,
                yolo,
                approval_channel,
                mode,
            };
            assert_eq!(decide(stopped, at(true)), Decision::AskUser, "{mode:?}");
            assert_eq!(
                decide(stopped, at(false)),
                Decision::Deny(DenyReason::NoApprovalChannel),
                "{mode:?}"
            );
            assert_eq!(decide(finished, at(true)), Decision::Run, "{mode:?}");
        }
    }
}

// §11 L1.1 (review finding 7) — a search enters every folder below the one it is given, the
// folders of fetched or built files included, because `grep -R`, `find` and the like read them; a
// template of a credential file is not a credential; the credential rules otherwise stand.
#[test]
fn credential_search_enters_every_folder_and_skips_templates() {
    let h = Fixture::new();
    for rel in [
        "repo/src/main.rs",
        "repo/node_modules/dep/index.js",
        "repo/.env.example",
        "repo/config/.env.sample",
        "repo/certs/server.key.template",
        "repo/a.pem.dist",
    ] {
        write(&h.home.join(rel), "x");
    }
    let search = |rel: &str| {
        h.class(
            true,
            "Grep",
            &json!({ "pattern": "x", "path": h.path(rel) }),
        )
    };
    assert_eq!(search("repo"), CallClass::InSlip);
    assert_eq!(
        h.class(
            true,
            "Read",
            &json!({ "file_path": h.path("repo/.env.example") })
        ),
        CallClass::InSlip
    );
    // A credential in each folder a search used to skip is reached by a search from the project:
    // by the Grep and Glob tools and by commands that read everything below a folder.
    for (dir, secret) in [
        ("node_modules", "dep/.env"),
        ("target", "debug/server.key"),
        (".git", "hooks/id_rsa"),
        ("vendor", "x/.npmrc"),
        ("dist", "x.pem"),
        (".venv", "lib/.env"),
        ("__pycache__", "id_rsa"),
    ] {
        let project = format!("proj{dir}");
        write(&h.home.join(&project).join("src/main.rs"), "x");
        write(&h.home.join(&project).join(dir).join(secret), "x");
        assert_eq!(search(&project), CREDENTIAL, "{dir}");
        let glob = json!({ "pattern": "**/*.rs", "path": h.path(&project) });
        assert_eq!(h.class(true, "Glob", &glob), CREDENTIAL, "{dir}");
        for cmd in ["grep -R x", "grep -rn x", "rg x", "find", "du -a"] {
            let cmd = format!("{cmd} {}", h.path(&project));
            assert_eq!(h.bash(true, &cmd), CREDENTIAL, "{cmd}");
            assert_eq!(h.bash(false, &cmd), CallClass::Ordinary, "{cmd}");
        }
    }
    // A link named as one of those folders is entered too (pnpm links `node_modules`).
    write(&h.home.join("store/pkg/.env"), "K=V");
    write(&h.home.join("repo2/src/main.rs"), "x");
    std::os::unix::fs::symlink(h.home.join("store"), h.home.join("repo2/node_modules"))
        .unwrap_or_default();
    assert_eq!(search("repo2"), CREDENTIAL);
    // A walk that runs out of time reached anything: the search goes to the user.
    let spent = OsFs::with_path(Duration::ZERO, None);
    let g = Guard {
        layout: &h.layout,
        fs: &spent,
        held: true,
    };
    let src = json!({ "pattern": "x", "path": h.path("repo/src") });
    assert_eq!(
        g.classify("Grep", &src, &h.home.join("project")),
        CREDENTIAL
    );
    // The same names where they are credentials, and a credential among the rest.
    write(&h.home.join("repo/real/.env"), "K=V");
    assert_eq!(search("repo"), CREDENTIAL);
    assert_eq!(search("repo/real"), CREDENTIAL);
    assert_eq!(
        h.class(
            true,
            "Read",
            &json!({ "file_path": h.path("repo/real/.env.local") })
        ),
        CREDENTIAL
    );
}

// §6 P1.4 — a word naming `/dev/tcp/` or `/dev/udp/` is a network connection the shell opens, a
// redirection's target included: PROTECTED while HELD.
#[test]
fn dev_tcp_and_dev_udp_are_network() {
    let h = Fixture::new();
    for cmd in [
        "cat < /dev/tcp/example.com/80",
        "echo GET > /dev/tcp/example.com/80",
        "echo hi > /dev/udp/127.0.0.1/9",
        "cat /dev/tcp/example.com/80",
        "bash -c 'cat < /dev/tcp/example.com/80'",
        "sudo cat < /dev/udp/127.0.0.1/9",
    ] {
        assert_eq!(
            h.bash(true, cmd),
            CallClass::Protected(ProtectedKind::Network),
            "{cmd}"
        );
        assert_eq!(h.bash(false, cmd), CallClass::Ordinary, "{cmd}");
    }
    assert_eq!(h.bash(true, "cat /dev/null"), CallClass::Ordinary);
}

// §6 P1.6 / §11 R3.1 (review finding 1) — in the Relaxed hold mode only a write to Lunchroom's
// program or the guard's configuration still goes to the user. A command that does that and is
// also something else the guard shows a reason for (a construct it cannot read, a push, a delete,
// network, a credential) keeps the requirement, in whatever order the parts are met, in every
// hold mode, with and without an approval channel, under every YOLO.
#[test]
fn guard_config_requirement_survives_every_other_reason() {
    let h = Fixture::new();
    let settings = "~/.claude/settings.json";
    let mixed = [
        // A construct the guard cannot read, before and after the write.
        format!("echo $(date) > {settings}"),
        format!("echo $(true) >> {settings}"),
        format!("echo x > {settings} && echo $PATH"),
        // Each other kind, met before the write and after it.
        format!("git push && echo x > {settings}"),
        format!("echo x > {settings} && git push"),
        format!("rm ~/project/src/main.rs && echo x > {settings}"),
        format!("echo x > {settings} && rm ~/project/src/main.rs"),
        format!("curl http://example.com -o {settings}"),
        format!("cat ~/.ssh/id_rsa > {settings}"),
        format!("echo x > {settings} && cat ~/.ssh/id_rsa"),
        format!("cat ~/.ssh/id_rsa && echo x > {settings}"),
        // Another harness's configuration.
        "echo x > ~/.codex/config.toml && git push".to_owned(),
    ];
    let guard = |kind| CallClass::Protected(kind);
    for cmd in &mixed {
        let call = h.call(true, cmd);
        assert!(
            !matches!(call.class, CallClass::Denied(_)),
            "{cmd}: {:?}",
            call.class
        );
        assert!(call.kinds.contains(ProtectedKind::GuardConfig), "{cmd}");
        // The class folded for a caller that holds only a class keeps it as well.
        assert_eq!(h.bash(true, cmd), GUARD_CONFIG, "{cmd}");
        for mode in [HoldMode::Strict, HoldMode::Balanced, HoldMode::Relaxed] {
            for yolo in [
                YoloSource::Off,
                YoloSource::HarnessOnly,
                YoloSource::Lunchroom,
            ] {
                for approval_channel in [true, false] {
                    let at = Situation {
                        held: true,
                        yolo,
                        approval_channel,
                        mode,
                    };
                    let want = decide(guard(ProtectedKind::GuardConfig), at);
                    assert_ne!(want, Decision::Run);
                    assert_eq!(decide_call(call, at), want, "{cmd} {mode:?} {yolo:?}");
                    assert_eq!(decide(h.bash(true, cmd), at), want, "{cmd} {mode:?}");
                    // Not HELD: nothing is added.
                    let free = Situation { held: false, ..at };
                    assert_eq!(
                        decide_call(h.call(false, cmd), free),
                        Decision::Run,
                        "{cmd}"
                    );
                }
            }
        }
    }
    // The reason shown still follows F1.2 where it names one: `unparsed`.
    assert_eq!(h.call(true, &mixed[0]).class, UNPARSED);
    // F1.2: a quoted `$(` leaves an unbalanced quote in the piece that starts a program, so the
    // guard reads a "program" path that does not exist and the call is DENIED `unparsed`. That is
    // stronger than the GuardConfig requirement in every mode, so the requirement is not lost.
    let quoted = h.call(true, &format!("echo \"$(date)\" > {settings}"));
    assert_eq!(quoted.class, DENIED_UNPARSED);
    for mode in [HoldMode::Strict, HoldMode::Balanced, HoldMode::Relaxed] {
        for approval_channel in [true, false] {
            let at = Situation {
                held: true,
                yolo: YoloSource::Lunchroom,
                approval_channel,
                mode,
            };
            assert_eq!(
                decide_call(quoted, at),
                Decision::Deny(DenyReason::Unparsed)
            );
        }
    }
    // Without a write to the guard, Relaxed lets each of the other kinds run.
    let relaxed = Situation {
        held: true,
        yolo: YoloSource::Off,
        approval_channel: true,
        mode: HoldMode::Relaxed,
    };
    for cmd in [
        "echo \"$(date)\" > out.txt",
        "git push",
        "rm out.txt",
        "curl http://example.com",
        "cat ~/.ssh/id_rsa",
    ] {
        let call = h.call(true, cmd);
        assert!(!call.kinds.contains(ProtectedKind::GuardConfig), "{cmd}");
        assert_eq!(decide_call(call, relaxed), Decision::Run, "{cmd}");
    }
}

// §11 L1.1 "Paths are resolved (symlinks, wildcards) before checking" (review finding 2) — `..`
// leaves the folder a link led to, not the folder holding the link, so a path through a link and a
// parent part is judged as the file the operating system opens.
#[test]
#[allow(clippy::too_many_lines)] // one case per kind of link
fn parent_part_after_a_link_is_judged_as_the_file_opened() {
    let h = Fixture::new();
    write(&h.home.join(".claude/history.jsonl"), "{}");
    // The file the text names once the link is ignored is an ordinary one.
    write(&h.home.join("project/history.jsonl"), "decoy");
    // A folder inside the harness folder that is not itself a transcript store.
    write(&h.home.join(".claude/plain/f.txt"), "x");
    let link = |name: &str, target: &str| {
        std::os::unix::fs::symlink(target, h.home.join("project").join(name)).unwrap_or_default();
    };
    link("tlink", &h.path(".claude/projects"));
    link("rel", "../.claude/projects");
    link("plink", &h.path(".claude/plain"));
    link("chain", "tlink");
    link("chain2", "chain");
    link("self", "self");
    link("dang", &h.path(".claude/settings.local.json"));
    let read = |held: bool, p: &str| h.class(held, "Read", &json!({ "file_path": p }));
    let reads = [
        "tlink/../history.jsonl",
        "./tlink/../history.jsonl",
        "rel/../history.jsonl",
        "chain/../history.jsonl",
        "chain2/../history.jsonl",
        "plink/../history.jsonl",
        "tlink/p/../../history.jsonl",
        "tlink/../projects/p/t.jsonl",
        "tlink/../h*.jsonl",
    ];
    for rel in reads {
        assert_eq!(read(true, rel), DENIED_PATH, "{rel}");
        let abs = h.path(&format!("project/{rel}"));
        assert_eq!(read(true, &abs), DENIED_PATH, "{abs}");
        assert_eq!(h.bash(true, &format!("cat {rel}")), DENIED_PATH, "{rel}");
        assert_eq!(
            h.bash(true, &format!("head -n1 {abs}")),
            DENIED_PATH,
            "{abs}"
        );
        assert_eq!(
            h.bash(true, &format!("grep x {rel}")),
            DENIED_PATH,
            "grep {rel}"
        );
        // Not HELD: the read runs (L1.1 holds only while HELD).
        assert_eq!(decide(read(false, rel), NOT_HELD), Decision::Run, "{rel}");
    }
    // A search from the parent reached through the link reaches what is below it.
    assert_eq!(h.bash(true, "grep -r x tlink/.."), DENIED_PATH);
    assert_eq!(h.bash(true, "ls -R tlink/.."), DENIED_PATH);
    assert_eq!(
        h.class(
            true,
            "Grep",
            &json!({ "pattern": "x", "path": h.path("project/tlink/..") })
        ),
        DENIED_PATH
    );
    // A shell's own `cd` tracks the working folder as written, and the next relative path is
    // resolved from the folder the link leads to.
    assert_eq!(
        h.bash(true, "cd plink && cat ../history.jsonl"),
        DENIED_PATH
    );
    // Writes: the guard's configuration, reached through a link and a parent part, and through a
    // dangling link to a file that does not exist yet.
    for (tool, input) in [
        (
            "Write",
            json!({ "file_path": h.path("project/tlink/../settings.json") }),
        ),
        (
            "Edit",
            json!({ "file_path": h.path("project/rel/../settings.json") }),
        ),
        ("Write", json!({ "file_path": h.path("project/dang") })),
    ] {
        assert_eq!(h.class(true, tool, &input), GUARD_CONFIG, "{input}");
        assert_eq!(h.class(false, tool, &input), CallClass::Ordinary, "{input}");
    }
    assert_eq!(
        h.bash(true, "echo x > tlink/../settings.json"),
        GUARD_CONFIG
    );
    assert_eq!(h.bash(true, "echo x > dang"), GUARD_CONFIG);
    // Lunchroom's stores are DENIED in every session, however they are reached.
    link("ilink", &h.path(".lunchroom/inbox"));
    for held in [false, true] {
        assert_eq!(
            h.class(
                held,
                "Write",
                &json!({ "file_path": h.path("project/ilink/../registry.json") })
            ),
            CONFIG,
            "{held}"
        );
        assert_eq!(h.bash(held, "echo x > ilink/../registry.json"), CONFIG);
    }
    // Controls: the same shapes with no link in front are the ordinary files they name.
    for rel in [
        "history.jsonl",
        "src/../history.jsonl",
        "../project/history.jsonl",
        "src/main.rs",
    ] {
        assert_eq!(read(true, rel), CallClass::InSlip, "{rel}");
        assert_eq!(
            h.bash(true, &format!("cat {rel}")),
            CallClass::Ordinary,
            "{rel}"
        );
    }
}

// L1.1, fail closed — a path the guard cannot settle may be anywhere, so while HELD a read of it
// is DENIED and a shell word naming it is PROTECTED as everything it could be; an agent that is
// not HELD is unaffected (P1.2).
#[test]
fn a_path_that_cannot_be_resolved_is_not_assumed_harmless() {
    let h = Fixture::new();
    std::os::unix::fs::symlink("self", h.home.join("project/self")).unwrap_or_default();
    std::os::unix::fs::symlink(h.path(".claude/projects"), h.home.join("project/tlink"))
        .unwrap_or_default();
    let read = |held: bool, p: &str| h.class(held, "Read", &json!({ "file_path": p }));
    for rel in [
        // A link loop.
        "self/x",
        // A `..` after a part that does not exist: a command may make it a link first.
        "nodir/../history.jsonl",
        // A `..` after a wildcard: the folders it matched are not known.
        "tlink/*/../history.jsonl",
        "*/../history.jsonl",
    ] {
        assert_eq!(read(true, rel), DENIED_PATH, "{rel}");
        assert_eq!(decide(read(false, rel), NOT_HELD), Decision::Run, "{rel}");
        let word = h.call(true, &format!("cat {rel}"));
        assert!(
            word.kinds.contains(ProtectedKind::GuardConfig)
                && word.kinds.contains(ProtectedKind::Credential),
            "{rel}: {word:?}"
        );
        assert!(matches!(
            h.bash(true, &format!("cat {rel}")),
            CallClass::Protected(_) | CallClass::Denied(_)
        ));
        assert_eq!(h.bash(false, &format!("cat {rel}")), CallClass::Ordinary);
    }
    // The failing command the construct is made for: a link made in the same command.
    assert!(matches!(
        h.bash(
            true,
            "mkdir -p work && ln -s ~/.claude/plain work/l && cat work/l/../history.jsonl"
        ),
        CallClass::Protected(_) | CallClass::Denied(_)
    ));
    // A destination that does not exist is not a failure: the name stays where it was written.
    assert_eq!(
        h.class(
            true,
            "Write",
            &json!({ "file_path": h.path("project/new/dir/file.txt") })
        ),
        CallClass::Ordinary
    );
    assert_eq!(
        h.bash(true, "echo x > new/dir/file.txt"),
        CallClass::Ordinary
    );
}

/// The real file system, except that one path reports itself as one the guard has no permission
/// to look at (as a folder without the search permission does, whoever runs the test).
struct Blind {
    inner: OsFs,
    blind: PathBuf,
}

impl crate::fs::Fs for Blind {
    fn real(&self, p: &Path) -> PathBuf {
        self.inner.real(p)
    }
    fn node(&self, p: &Path) -> crate::fs::Node {
        if p == self.blind {
            crate::fs::Node::Unreadable
        } else {
            self.inner.node(p)
        }
    }
    fn is_dir(&self, p: &Path) -> bool {
        self.inner.is_dir(p)
    }
    fn exists(&self, p: &Path) -> bool {
        self.inner.exists(p)
    }
    fn expand(&self, pattern: &Path) -> crate::fs::Expansion {
        self.inner.expand(pattern)
    }
    fn walk(&self, dir: &Path, visit: &mut dyn FnMut(&Path) -> bool) -> crate::fs::WalkEnd {
        self.inner.walk(dir, visit)
    }
    fn script(&self, p: &Path) -> crate::fs::Script {
        self.inner.script(p)
    }
    fn runs_as_script(&self, p: &Path) -> bool {
        self.inner.runs_as_script(p)
    }
    fn which(&self, prog: &str) -> Option<PathBuf> {
        self.inner.which(prog)
    }
}

// §11::10 — a part of the path the guard has no permission to look at leaves the file
// the path opens unknown: for a HELD session a read tool of it is DENIED and a command naming it
// is PROTECTED as a credential and as the guard's configuration; a session that is not HELD is
// unaffected.
#[test]
fn a_path_through_a_part_the_guard_cannot_look_at_is_not_assumed_harmless() {
    let h = Fixture::new();
    write(&h.home.join("project/blind/x"), "data");
    let blind = Blind {
        inner: OsFs::with_path(BUDGET, Some(h.home.join("bin").into_os_string())),
        blind: h.home.join("project/blind"),
    };
    let classify = |held: bool, tool: &str, input: &Value| {
        Guard {
            layout: &h.layout,
            fs: &blind,
            held,
        }
        .classify(tool, input, &h.home.join("project"))
    };
    let call = |held: bool, cmd: &str| {
        Guard {
            layout: &h.layout,
            fs: &blind,
            held,
        }
        .classify_call("Bash", &json!({ "command": cmd }), &h.home.join("project"))
    };
    for target in ["blind/x", &h.path("project/blind/x")] {
        // A command from a HELD session.
        let word = call(true, &format!("cat {target}"));
        assert!(
            word.kinds.contains(ProtectedKind::GuardConfig)
                && word.kinds.contains(ProtectedKind::Credential),
            "{target}: {word:?}"
        );
        assert!(
            matches!(
                classify(true, "Bash", &json!({ "command": format!("cat {target}") })),
                CallClass::Protected(_) | CallClass::Denied(_)
            ),
            "{target}"
        );
        // A read tool of the same path from a HELD session.
        let input = json!({ "file_path": h.path("project/blind/x") });
        assert_eq!(classify(true, "Read", &input), DENIED_PATH, "{target}");
        // Not HELD: nothing changes.
        assert_eq!(
            classify(
                false,
                "Bash",
                &json!({ "command": format!("cat {target}") })
            ),
            CallClass::Ordinary,
            "{target}"
        );
        assert_eq!(
            decide(classify(false, "Read", &input), NOT_HELD),
            Decision::Run,
            "{target}"
        );
    }
    // Control: the folder the guard can look at, with the same names, is an ordinary file.
    write(&h.home.join("project/seen/x"), "data");
    assert_eq!(
        classify(
            true,
            "Read",
            &json!({ "file_path": h.path("project/seen/x") })
        ),
        CallClass::InSlip
    );
    assert_eq!(
        classify(true, "Bash", &json!({ "command": "cat seen/x" })),
        CallClass::Ordinary
    );
}

fn strict_balanced_relaxed(call: Call) -> [Decision; 3] {
    [HoldMode::Strict, HoldMode::Balanced, HoldMode::Relaxed].map(|mode| {
        decide_call(
            call,
            Situation {
                held: true,
                yolo: YoloSource::Off,
                approval_channel: true,
                mode,
            },
        )
    })
}

// §6::8 — a HELD agent that starts a new agent session of any harness (the child is
// guarded but not HELD, so it would run what its parent may not) makes a PROTECTED call: it goes
// to the user in Strict and Balanced, also under a `lunchroom yolo`, and runs in Relaxed like the
// other PROTECTED calls (§6::22). Every spelling the classifier reads a command through counts.
#[test]
fn p1_4_a_held_agent_starting_a_new_session_is_protected() {
    let h = Fixture::new();
    write(
        &h.home.join("project/newsess.sh"),
        "#!/bin/sh\nclaude -p 'do it'\n",
    );
    write(
        &h.home.join("project/newsess.py"),
        "import subprocess\nsubprocess.run(['codex', 'exec', '--yolo', 'x'])\n",
    );
    for cmd in [
        // Each harness's non-interactive and prompt forms.
        "claude -p hi",
        "claude --print hi",
        "claude --dangerously-skip-permissions -p 'task'",
        "claude --bg 'task'",
        "claude --background 'task'",
        "claude 'do the task'",
        "claude --model opus 'do the task'",
        "codex exec --yolo 'task'",
        "codex e 'task'",
        "codex review",
        "codex fork",
        "codex 'do the task'",
        "opencode run hi",
        "opencode pr 5",
        "opencode --prompt hi",
        "hermes chat -q hi",
        "hermes chat --query hi",
        "hermes chat --query=hi",
        "hermes chat --que hi",
        "hermes chat --query-file p.txt",
        "hermes chat -Qq hi",
        "hermes -z hi",
        "hermes --oneshot hi",
        "hermes --one hi",
        // Behind a path, a wrapper, an environment, a shell, a script or code.
        "env A=1 claude -p hi",
        "timeout 60 claude -p hi",
        "nohup codex exec hi",
        "mywrap hermes -z hi",
        "sh -c 'claude -p hi'",
        "bash -lc \"codex exec --yolo x\"",
        "eval 'hermes chat -q hi'",
        "cx exec hi",
        "bash newsess.sh",
        "python3 newsess.py",
        "python3 -c \"import subprocess; subprocess.run(['claude', '-p', 'x'])\"",
        "node -e \"require('child_process').execSync('opencode run hi')\"",
        "echo ok && claude -p hi",
    ] {
        let call = h.call(true, cmd);
        assert!(
            call.kinds.contains(ProtectedKind::OtherSession),
            "{cmd}: {call:?}"
        );
        assert!(!matches!(call.class, CallClass::Denied(_)), "{cmd}");
        assert_eq!(
            strict_balanced_relaxed(call),
            [Decision::AskUser, Decision::AskUser, Decision::Run],
            "{cmd}"
        );
        // Under a `lunchroom yolo` in Strict and Balanced it still goes to the user.
        for mode in [HoldMode::Strict, HoldMode::Balanced] {
            let at = Situation {
                held: true,
                yolo: YoloSource::Lunchroom,
                approval_channel: true,
                mode,
            };
            assert_eq!(decide_call(call, at), Decision::AskUser, "{cmd} {mode:?}");
        }
        // P1.2: an agent that is not HELD gets nothing from Lunchroom for it.
        let free = h.call(false, cmd);
        assert!(!free.kinds.contains(ProtectedKind::OtherSession), "{cmd}");
        assert_eq!(free.class, CallClass::Ordinary, "{cmd}");
    }
}

// §6::8 — what starts no session is not PROTECTED for it: a version or help request, a
// command that is not a prompt, an interactive launch, a name or a flag that is only text, and a
// script that only names a program. Resuming or continuing a session is the F1.1 fence, which
// ranks above.
#[test]
fn p1_4_commands_that_start_no_session_are_not_new_session() {
    let h = Fixture::new();
    for cmd in [
        "claude --version",
        "claude -v",
        "claude --help",
        "claude mcp list",
        "claude doctor",
        "claude update",
        "claude auth status",
        "claude agents",
        "codex --version",
        "codex login",
        "codex mcp list",
        "codex apply",
        "codex --help",
        "opencode --version",
        "opencode session list",
        "opencode models",
        "hermes --version",
        "hermes chat",
        "hermes sessions list",
        "hermes model",
        "hermes chat --reasoning high",
        "hermes chat --checkpoints",
        "hermes chat --no-restore-cwd",
        "hermes chat -m anthropic/claude",
        "echo claude -p hi",
        "git commit -m 'claude -p fix'",
        "grep -p claude notes.md",
        "which claude",
        "cargo test -p lunchroom",
        "python3 notes.py",
        "bash loose.sh",
    ] {
        let call = h.call(true, cmd);
        assert!(
            !call.kinds.contains(ProtectedKind::OtherSession),
            "{cmd}: {call:?}"
        );
    }
    // A session resumed or continued is the fence, DENIED whatever else the command starts.
    for cmd in [
        "claude -p hi --resume abc",
        "codex exec resume --last",
        "opencode run -s ses_1 hi",
        "hermes chat -q hi --resume abc",
        "hermes -z hi -r abc",
    ] {
        assert_eq!(h.bash(true, cmd), FENCE, "{cmd}");
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
    }
}

// §12::1 — `hermes` puts a turn into an existing session with `--resume`/`-r` or
// `--continue`/`-c` (hermes-agent 9976f48: `hermes_cli/main.py:1403-1470,1511-1560`,
// `hermes_cli/oneshot.py:437-465`), in every spelling `argparse` accepts: a prefix of the long
// option, an attached value, a cluster of short options. The options that merely resemble them are
// not.
#[test]
fn f1_1_hermes_resume_and_continue_are_fences() {
    let h = Fixture::new();
    for cmd in [
        "hermes chat -q hi --resume abc",
        "hermes chat -q hi -r abc",
        "hermes chat -q hi --resume=abc",
        "hermes chat -q hi --res abc",
        "hermes chat -q hi --resu abc",
        "hermes chat -q hi -rabc",
        "hermes chat -q hi -c",
        "hermes chat -q hi -c name",
        "hermes chat -q hi --continue",
        "hermes chat -q hi --continue=name",
        "hermes chat -q hi --cont name",
        "hermes chat -q hi --co",
        "hermes -z hi --resume latest",
        "hermes --resume latest",
        "hermes -c",
        "env X=1 hermes -z hi -c",
        "sh -c 'hermes -z hi -r abc'",
        "bash -lc \"hermes chat -q hi --continue\"",
        "python3 -c \"import subprocess; subprocess.run(['hermes', '-z', 'hi', '--resume', 'abc'])\"",
    ] {
        assert_eq!(h.bash(false, cmd), FENCE, "{cmd}");
        assert_eq!(h.bash(true, cmd), FENCE, "{cmd}");
    }
    for args in [
        &["chat", "--reasoning", "high", "-q", "x"][..],
        &["chat", "--run-budget", "5", "-q", "x"],
        &["chat", "--no-restore-cwd", "-q", "x"],
        &["chat", "--checkpoints", "-q", "x"],
        &["chat", "--create-if-missing", "-q", "x"],
        &["chat", "-m", "anthropic/claude", "-q", "x"],
        &["chat", "-Q", "-q", "x"],
        &["chat", "--re", "x"],
        &["chat", "--c", "x"],
        &["sessions", "list"],
        &["--version"],
    ] {
        assert!(!fence_args("hermes", args), "{args:?}");
    }
    assert!(starts_session("hermes", &["chat", "-Q", "-q", "x"], true));
    assert!(!starts_session("hermes", &["chat", "--quiet"], true));
}

// §6::12 with §11 R3.1 — a HELD agent's write to a harness's own program, or to a shell
// startup file that decides what its name runs, is a write to the guard's configuration: PROTECTED
// in every hold mode, Relaxed included. Running the program is not.
#[test]
fn r3_1_writing_a_harness_program_or_shell_startup_file_is_guard_configuration() {
    let h = Fixture::new();
    write(&h.home.join(".local/bin/claude"), "#!/bin/sh\n");
    write(&h.home.join(".bashrc"), "# rc\n");
    let protected = [
        ".local/bin/claude",
        ".local/bin/codex",
        ".local/bin/hermes",
        ".local/bin/openclaw",
        ".local/bin/opencode",
        ".local/share/claude/versions/9.9.9",
        ".npm-global/bin/codex",
        ".npm-global/bin/openclaw",
        ".npm-global/lib/node_modules/@openai/codex/bin/codex.js",
        ".npm-global/lib/node_modules/@anthropic-ai/claude-code/cli.js",
        ".npm-global/lib/node_modules/openclaw/dist/index.js",
        ".local/lib/node_modules/opencode-ai/bin/opencode.exe",
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshenv",
        ".zshrc",
        ".zprofile",
        ".config/fish/config.fish",
        ".config/fish/functions/claude.fish",
        ".config/fish/conf.d/path.fish",
    ];
    for rel in protected {
        let input = json!({ "file_path": h.path(rel) });
        assert_eq!(h.class(true, "Write", &input), GUARD_CONFIG, "{rel}");
        assert_eq!(
            h.class(false, "Write", &input),
            CallClass::Ordinary,
            "{rel}"
        );
        let p = h.path(rel);
        for cmd in [
            format!("cp evil {p}"),
            format!("echo x >> {p}"),
            format!("ln -sf evil {p}"),
            format!("mv evil {p}"),
        ] {
            let call = h.call(true, &cmd);
            assert!(call.kinds.contains(ProtectedKind::GuardConfig), "{cmd}");
            assert_eq!(
                strict_balanced_relaxed(call),
                [Decision::AskUser; 3],
                "{cmd}"
            );
        }
    }
    // Not the program, not a startup file: an ordinary write.
    for rel in [
        "project/src/main.rs",
        ".local/bin/other-tool",
        ".local/share/other/x",
        ".bashrc.bak",
        ".config/fishy/x",
        ".npm-global/lib/node_modules/left-pad/index.js",
        ".npm-global/bin/prettier",
    ] {
        let input = json!({ "file_path": h.path(rel) });
        assert_eq!(h.class(true, "Write", &input), CallClass::Ordinary, "{rel}");
    }
    // Running a harness's program by its path is not writing it; reading a startup file is a read.
    let run = h.call(true, &format!("{} --version", h.path(".local/bin/claude")));
    assert!(!run.kinds.contains(ProtectedKind::GuardConfig), "{run:?}");
    assert_eq!(
        h.class(true, "Read", &json!({ "file_path": h.path(".bashrc") })),
        CallClass::InSlip
    );
}
