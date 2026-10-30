//! Stamps the program with the commit it was built from, so `lunchroom version` tells builds apart.
//! A build from a source copy with no git history is stamped with the version alone.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    // The workspace's tracked files, as the commit has them or not.
    let workspace = "../..";
    let commit = git(&["rev-parse", "--short=7", "HEAD"]);
    // Whether the stamp names a commit, so a test does not guess it from the stamp's text.
    let stamped = if commit.is_some() { "yes" } else { "no" };
    let stamp = match commit {
        Some(commit) => {
            let changed = git(&[
                "status",
                "--porcelain",
                "--untracked-files=no",
                "--",
                workspace,
            ])
            .is_none_or(|s| !s.is_empty());
            let modified = if changed { ", modified" } else { "" };
            format!("lunchroom {version} ({commit}{modified})")
        }
        None => format!("lunchroom {version}"),
    };
    println!("cargo:rustc-env=LUNCHROOM_VERSION={stamp}");
    println!("cargo:rustc-env=LUNCHROOM_COMMIT_STAMPED={stamped}");
    // Stamped again after a commit, a checkout or a change to the workspace's sources.
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
        if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={dir}/{head}");
        }
    }
    for path in ["crates", "Cargo.toml"] {
        println!("cargo:rerun-if-changed={workspace}/{path}");
    }
}
