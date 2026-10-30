//! Checks of the product as shipped: its published adapter statement and what its code can reach.

use std::path::{Path, PathBuf};

/// Every Rust source of the workspace, tests included.
fn sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("..")];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.file_name() != Some("target".as_ref()) {
                dirs.push(path);
            } else if path.extension() == Some("rs".as_ref()) {
                files.push(path);
            }
        }
    }
    files
}

/// The plugins' own test files (Python and JavaScript), whose tests the README also names.
fn plugin_tests() -> String {
    let plugins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    ["hermes/test_plugin.py", "openclaw/index.test.mjs"]
        .iter()
        .map(|f| std::fs::read_to_string(plugins.join(f)).unwrap_or_default())
        .collect()
}

fn readme() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
        .unwrap_or_default()
}

// §13::1 (Claude Code and Codex): each supported harness's published adapter
// statement covers each of the seven items of H1.1, and every test it names exists in the code;
// the Codex adapter's install item names the user's approval of the hooks in `/hooks`.
#[test]
fn claude_code_adapter_states_and_proves_seven_items() {
    adapter_states_and_proves_seven_items("## The Claude Code adapter");
}

#[test]
fn codex_adapter_states_and_proves_seven_items() {
    let rows = adapter_states_and_proves_seven_items("## The Codex adapter");
    assert!(rows[0].contains("/hooks"), "{}", rows[0]);
}

#[test]
fn openclaw_adapter_states_and_proves_seven_items() {
    let rows = adapter_states_and_proves_seven_items("## The OpenClaw adapter");
    assert!(rows[0].contains("your steps in OpenClaw"), "{}", rows[0]);
    assert!(rows[1].contains("conversation access"), "{}", rows[1]);
    let tests = plugin_tests();
    assert!(
        tests
            .contains("test(\"only a call the user approved is reported as approved after it runs"),
        "the plugin test the README names"
    );
}

#[test]
fn hermes_adapter_states_and_proves_seven_items() {
    let rows = adapter_states_and_proves_seven_items("## The Hermes adapter");
    assert!(
        rows[0].contains("hermes plugins enable lunchroom"),
        "{}",
        rows[0]
    );
}

/// The seven rows of one adapter's table, after checking each against the code.
fn adapter_states_and_proves_seven_items(title: &str) -> Vec<String> {
    let text = readme();
    let section = text
        .split(title)
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .unwrap_or_default();
    let rows: Vec<&str> = section
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| Item"))
        .collect();
    let items = [
        "Install and your confirmation",
        "Guard evidence",
        "Identity",
        "Delivery and confirmation",
        "Approval channel",
        "Injection channels",
        "YOLO",
    ];
    assert_eq!(rows.len(), items.len(), "{section}");
    let code: String = sources()
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap_or_default())
        .chain(std::iter::once(plugin_tests()))
        .collect();
    for (row, item) in rows.iter().zip(items) {
        let cells: Vec<&str> = row.split(" | ").collect();
        assert_eq!(cells.len(), 3, "{row}");
        assert_eq!(cells[0].trim_start_matches("| "), item, "{row}");
        assert!(cells[1].len() > 40, "{row}");
        let tests: Vec<&str> = cells[2].split('`').skip(1).step_by(2).collect();
        assert!(!tests.is_empty(), "{row}");
        for t in tests {
            // A Rust test function, or a Python one in a plugin's tests.
            assert!(
                code.contains(&format!("fn {t}(")) || code.contains(&format!("def {t}(")),
                "{item}: no test {t}"
            );
        }
    }
    rows.iter().map(|r| (*r).to_owned()).collect()
}

// Every test the test plan names exists: each name with two or more underscores in a row's test
// column (outside `code` spans) is a Rust test function or a plugin's Python test.
#[test]
fn every_test_the_test_plan_names_exists() {
    let plan =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../TESTPLAN.md"))
            .unwrap_or_default();
    let code: String = sources()
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap_or_default())
        .chain(std::iter::once(plugin_tests()))
        .collect();
    let mut checked = 0;
    // Every table row is a requirement except the header and its rule line.
    let rows = plan.lines().filter(|l| {
        l.starts_with("| ")
            && !l.starts_with("|---")
            && l.split(" | ").nth(3).is_some_and(|c| c != "test name")
    });
    for row in rows {
        let cell = row.split(" | ").nth(3).unwrap_or_default();
        let prose: String = cell.split('`').step_by(2).collect();
        for name in prose
            .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .filter(|w| w.matches('_').count() >= 2 && !w.starts_with('_'))
        {
            checked += 1;
            assert!(
                code.contains(&format!("fn {name}(")) || code.contains(&format!("def {name}(")),
                "{}: no test {name}",
                row.split(" | ").next().unwrap_or_default()
            );
        }
    }
    assert!(checked > 100, "{checked}");
}

// `lunchroom version` names this build: the version, and the commit it was built from.
#[test]
fn version_names_the_build() {
    let stdout = std::process::Command::new(env!("CARGO_BIN_EXE_lunchroom"))
        .arg("--version")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    assert_eq!(stdout, format!("{}\n", env!("LUNCHROOM_VERSION")));
    // A build from a source copy with no git history is stamped with the version alone; one made
    // in a checkout names its commit.
    let committed = env!("LUNCHROOM_COMMIT_STAMPED") == "yes";
    let named = format!("lunchroom {} (", env!("CARGO_PKG_VERSION"));
    assert_eq!(stdout.starts_with(&named), committed, "{stdout}");
    if !committed {
        assert_eq!(stdout, format!("lunchroom {}\n", env!("CARGO_PKG_VERSION")));
    }
}

// §5::2, §7::8 (inspection aid): the shipped code opens no network connection, listens
// on nothing, runs no service and sends or receives no chat message; its only dependencies are
// serde, serde_json and sha2.
#[test]
fn product_runs_locally_and_sends_no_chat_message() {
    let banned = [
        "std::net",
        "TcpListener",
        "TcpStream",
        "UdpSocket",
        "UnixListener",
        "UnixStream",
        "UnixDatagram",
        "os::unix::net",
        "reqwest",
        "hyper",
        "tokio",
        "ureq",
        "websocket",
    ];
    for file in sources() {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        let shipped = text.split("#[cfg(test)]").next().unwrap_or_default();
        for b in banned {
            assert!(!shipped.contains(b), "{} uses {b}", file.display());
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for manifest in [
        "Cargo.toml",
        "crates/lunchroom/Cargo.toml",
        "crates/lunchroom-core/Cargo.toml",
    ] {
        let text = std::fs::read_to_string(root.join(manifest)).unwrap_or_default();
        let mut in_deps = false;
        for line in text.lines() {
            if line.starts_with('[') {
                in_deps = line.contains("dependencies");
            } else if in_deps && line.contains('=') {
                let name = line.split(['=', '.']).next().unwrap_or_default().trim();
                assert!(
                    ["serde", "serde_json", "sha2", "lunchroom-core"].contains(&name),
                    "{manifest}: {name}"
                );
            }
        }
    }
}
