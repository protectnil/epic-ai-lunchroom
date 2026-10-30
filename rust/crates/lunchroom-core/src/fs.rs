//! The file system as the guard sees it: real paths, wildcard matches, a bounded walk, script text.
//!
//! Spec §11 L1.1: "Paths are resolved (symlinks, wildcards) before checking." The guard runs before
//! every tool call, so wildcard matching and walking stop at a time budget; the caller treats a
//! stopped search as one that may have reached anything (fail safe). A walk enters every folder:
//! the command being judged may read any of them, so none is skipped as not the project's own.

use std::ffi::OsString;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

/// Time one classification may spend matching wildcards and walking folders.
pub const BUDGET: Duration = Duration::from_secs(2);

/// Largest script file the guard reads to check what it runs.
pub const SCRIPT_MAX: u64 = 1 << 20;

/// Deepest folder level a wildcard or walk descends to.
const MAX_DEPTH: usize = 64;

/// Folders of a project that hold fetched or built files, usually large: a walk enters them after
/// everything else, so a budget that runs out spends itself on them last. They are never skipped,
/// because a search such as `grep -R` reads them, and a walk that ends early is treated as having
/// reached a credential.
const LAST: [&str; 7] = [
    ".git",
    "node_modules",
    "target",
    "dist",
    "vendor",
    ".venv",
    "__pycache__",
];

/// Most symbolic links one path resolution follows (Linux's own limit is 40, `ELOOP` beyond it).
pub const MAX_LINKS: usize = 40;

/// The paths a wildcard matched.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Expansion {
    /// Every match found.
    pub matches: Vec<PathBuf>,
    /// The budget ran out before every match was found.
    pub capped: bool,
}

/// How a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    /// Every entry was visited.
    Done,
    /// The visitor asked to stop.
    Stopped,
    /// The budget ran out first.
    Capped,
}

/// What a single path is, looked at without following it (`lstat`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Nothing is there, or a part before it is not a folder.
    Missing,
    /// A file or folder.
    Plain,
    /// A symbolic link, with the text it holds.
    Link(PathBuf),
    /// It could not be looked at (no permission, I/O error): what it is stays unknown.
    Unreadable,
}

/// A path resolved the way the operating system opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The real path of the longest part that exists, with the rest after it as written.
    pub path: PathBuf,
    /// Every part was looked at. `false` after a link loop, a part that could not be looked at, or
    /// a `..` that follows a part that does not exist (a command may make that part a link before
    /// the path is used): the file the path opens is then unknown.
    pub complete: bool,
}

/// The parts of `p` that name something (`Normal` and `..`), last first, for use as a stack.
fn parts_reversed(p: &Path) -> Vec<OsString> {
    let mut v: Vec<OsString> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
        })
        .collect();
    v.reverse();
    v
}

/// A script file's text, as far as the guard can read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Script {
    /// The whole file.
    Text(String),
    /// Larger than [`SCRIPT_MAX`].
    TooLarge,
    /// Missing or unreadable (the harness cannot run it either).
    Unreadable,
}

/// File-system questions the classifier asks.
pub trait Fs {
    /// The real path: symlinks resolved, for the longest part of the path that exists. `p` must
    /// not hold `..` (a link before it changes which folder it leaves): use [`Fs::resolve`].
    fn real(&self, p: &Path) -> PathBuf;
    /// What `p` is, not following it if it is a link.
    fn node(&self, p: &Path) -> Node;
    /// Resolves the absolute path `p` as the operating system does when it opens it: part by part
    /// from the root, a link replaced by its target (relative to the folder holding the link), and
    /// `..` leaving the folder reached so far, which is already real. A part that does not exist
    /// (a file about to be written) and what follows it stay as written. A loop, a part that
    /// cannot be looked at and a `..` after a part that does not exist leave the result
    /// incomplete, for the caller to treat as reaching anything.
    fn resolve(&self, p: &Path) -> Resolved {
        let mut todo = parts_reversed(p);
        let mut out = PathBuf::from("/");
        let (mut exists, mut complete, mut links) = (true, true, 0usize);
        while let Some(part) = todo.pop() {
            if part == ".." {
                complete &= exists;
                out.pop();
                continue;
            }
            let next = out.join(&part);
            if !exists {
                out = next;
                continue;
            }
            match self.node(&next) {
                Node::Plain => out = next,
                Node::Missing => {
                    exists = false;
                    out = next;
                }
                Node::Unreadable => {
                    (exists, complete) = (false, false);
                    out = next;
                }
                Node::Link(target) => {
                    links += 1;
                    if links > MAX_LINKS {
                        (exists, complete) = (false, false);
                        out = next;
                    } else {
                        if target.is_absolute() {
                            out = PathBuf::from("/");
                        }
                        todo.extend(parts_reversed(&target));
                    }
                }
            }
        }
        Resolved {
            path: out,
            complete,
        }
    }
    /// `p` is a folder (following symlinks).
    fn is_dir(&self, p: &Path) -> bool;
    /// Something exists at `p` (following symlinks: a dangling link does not).
    fn exists(&self, p: &Path) -> bool;
    /// Every existing path an absolute wildcard pattern matches.
    fn expand(&self, pattern: &Path) -> Expansion;
    /// Visits every path below `dir`. A symlink is visited as written and as its real path, and a
    /// linked folder is walked at its real path; each folder is walked once, and every folder is
    /// entered (those named in [`LAST`] after the rest). The visitor returns `true` to stop.
    fn walk(&self, dir: &Path, visit: &mut dyn FnMut(&Path) -> bool) -> WalkEnd;
    /// The text of a script file, for checking what it runs.
    fn script(&self, p: &Path) -> Script;
    /// The system runs this file as a script: its first two bytes are `#!`, or it is an executable
    /// file that is not an ELF program, which a shell runs as a script of its own.
    fn runs_as_script(&self, p: &Path) -> bool;
    /// Where `PATH` finds a program, as a real path.
    fn which(&self, prog: &str) -> Option<PathBuf>;
}

/// The real file system, with one time budget shared by every question.
#[derive(Debug)]
pub struct OsFs {
    deadline: Instant,
    path_var: Option<OsString>,
}

impl OsFs {
    /// A view whose wildcard matching and walks stop after `budget`.
    #[must_use]
    pub fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            path_var: std::env::var_os("PATH"),
        }
    }

    /// As [`OsFs::new`], with an explicit `PATH`.
    #[must_use]
    pub fn with_path(budget: Duration, path_var: Option<OsString>) -> Self {
        Self {
            deadline: Instant::now() + budget,
            path_var,
        }
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

impl Fs for OsFs {
    fn real(&self, p: &Path) -> PathBuf {
        let mut base = p.to_path_buf();
        let mut rest: Vec<OsString> = Vec::new();
        loop {
            if let Ok(r) = std::fs::canonicalize(&base) {
                return rest.iter().rev().fold(r, |acc, part| acc.join(part));
            }
            match (base.file_name().map(ToOwned::to_owned), base.parent()) {
                (Some(name), Some(parent)) => {
                    rest.push(name);
                    base = parent.to_path_buf();
                }
                _ => return p.to_path_buf(),
            }
        }
    }

    fn node(&self, p: &Path) -> Node {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                std::fs::read_link(p).map_or(Node::Unreadable, Node::Link)
            }
            Ok(_) => Node::Plain,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
                Node::Missing
            }
            Err(_) => Node::Unreadable,
        }
    }

    fn is_dir(&self, p: &Path) -> bool {
        p.is_dir()
    }

    fn exists(&self, p: &Path) -> bool {
        p.exists()
    }

    fn expand(&self, pattern: &Path) -> Expansion {
        let parts: Vec<String> = pattern
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        let mut out = Expansion::default();
        let mut stack: Vec<(PathBuf, usize, usize)> = vec![(PathBuf::from("/"), 0, 0)];
        while let Some((dir, i, depth)) = stack.pop() {
            if self.expired() || depth > MAX_DEPTH {
                out.capped = true;
                break;
            }
            let Some(part) = parts.get(i) else {
                if std::fs::symlink_metadata(&dir).is_ok() {
                    out.matches.push(dir);
                }
                continue;
            };
            if !part.contains(['*', '?', '[']) {
                stack.push((dir.join(part), i + 1, depth));
                continue;
            }
            if part == "**" {
                stack.push((dir.clone(), i + 1, depth + 1));
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let path = e.path();
                if part == "**" {
                    if !name.starts_with('.') && path.is_dir() {
                        stack.push((path, i, depth + 1));
                    }
                } else if fnmatch(part, &name) {
                    stack.push((path, i + 1, depth + 1));
                }
            }
        }
        out
    }

    fn walk(&self, dir: &Path, visit: &mut dyn FnMut(&Path) -> bool) -> WalkEnd {
        let mut stack = vec![(dir.to_path_buf(), 0usize)];
        // Folders already walked, by real path, so a link loop is walked once.
        let mut seen = std::collections::HashSet::new();
        seen.insert(self.real(dir));
        while let Some((d, depth)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            // Folders found here: those in LAST go on the stack first, so they are walked last.
            let (mut first, mut last) = (Vec::new(), Vec::new());
            for e in entries.flatten() {
                if self.expired() || depth > MAX_DEPTH {
                    return WalkEnd::Capped;
                }
                let path = e.path();
                if visit(&path) {
                    return WalkEnd::Stopped;
                }
                let Ok(ft) = e.file_type() else { continue };
                let late = LAST.iter().any(|n| e.file_name() == *n);
                let queue = if late { &mut last } else { &mut first };
                if ft.is_symlink() {
                    let real = self.real(&path);
                    if visit(&real) {
                        return WalkEnd::Stopped;
                    }
                    // A linked folder is walked at its real path: a search that follows links
                    // reads what is there.
                    if real.is_dir() && seen.insert(real.clone()) {
                        queue.push((real, depth + 1));
                    }
                } else if ft.is_dir() && seen.insert(self.real(&path)) {
                    queue.push((path, depth + 1));
                }
            }
            stack.extend(last);
            stack.extend(first);
        }
        WalkEnd::Done
    }

    fn script(&self, p: &Path) -> Script {
        let Ok(meta) = std::fs::metadata(p) else {
            return Script::Unreadable;
        };
        if !meta.is_file() {
            return Script::Unreadable;
        }
        if meta.len() > SCRIPT_MAX {
            return Script::TooLarge;
        }
        match std::fs::read(p) {
            Ok(bytes) => Script::Text(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Script::Unreadable,
        }
    }

    fn runs_as_script(&self, p: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(meta) = std::fs::metadata(p) else {
            return false;
        };
        let executable = meta.is_file() && meta.permissions().mode() & 0o111 != 0;
        let mut head = [0u8; 4];
        // An executable file the guard cannot open is judged as one: `script` then refuses it.
        let Ok(mut file) = std::fs::File::open(p) else {
            return executable;
        };
        let read = file.read(&mut head).unwrap_or(0);
        head.starts_with(b"#!") && read >= 2 || executable && head != *b"\x7fELF"
    }

    fn which(&self, prog: &str) -> Option<PathBuf> {
        let path_var = self.path_var.as_ref()?;
        std::env::split_paths(path_var)
            .map(|d| d.join(prog))
            .find(|c| c.is_file())
            .map(|c| self.real(&c))
    }
}

/// Shell wildcard matching of one name: `*`, `?` and `[...]` (with `!` or `^` and ranges). A name
/// starting with `.` matches only a pattern starting with `.`.
#[must_use]
pub fn fnmatch(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    match_from(&p, &n)
}

fn match_from(p: &[char], n: &[char]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some('*') => (0..=n.len()).any(|k| match_from(&p[1..], &n[k..])),
        Some('?') => !n.is_empty() && match_from(&p[1..], &n[1..]),
        Some('[') => match class(p) {
            Some((len, set)) => n
                .first()
                .is_some_and(|c| set(*c) && match_from(&p[len..], &n[1..])),
            None => n.first() == Some(&'[') && match_from(&p[1..], &n[1..]),
        },
        Some(c) => n.first() == Some(c) && match_from(&p[1..], &n[1..]),
    }
}

/// A `[...]` class at the start of `p`: its length and its test, or `None` if unterminated.
fn class(p: &[char]) -> Option<(usize, impl Fn(char) -> bool)> {
    let mut i = 1;
    let negate = matches!(p.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let start = i;
    if p.get(i) == Some(&']') {
        i += 1;
    }
    while p.get(i).is_some_and(|c| *c != ']') {
        i += 1;
    }
    p.get(i)?;
    let body: Vec<char> = p[start..i].to_vec();
    let test = move |c: char| {
        let mut hit = false;
        let mut k = 0;
        while k < body.len() {
            if body.get(k + 1) == Some(&'-') && k + 2 < body.len() {
                hit |= body[k] <= c && c <= body[k + 2];
                k += 3;
            } else {
                hit |= body[k] == c;
                k += 1;
            }
        }
        hit != negate
    };
    Some((i + 1, test))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A file system held in a map, for resolution cases that need no real folders: a path not in
    /// the map is missing.
    #[derive(Default)]
    struct MapFs(HashMap<PathBuf, Node>);

    impl MapFs {
        fn with(plain: &[&str], links: &[(&str, &str)]) -> Self {
            let mut m = HashMap::new();
            for p in plain {
                m.insert(PathBuf::from(p), Node::Plain);
            }
            for (l, t) in links {
                m.insert(PathBuf::from(l), Node::Link(PathBuf::from(t)));
            }
            Self(m)
        }
    }

    impl Fs for MapFs {
        fn real(&self, p: &Path) -> PathBuf {
            p.to_path_buf()
        }
        fn node(&self, p: &Path) -> Node {
            self.0.get(p).cloned().unwrap_or(Node::Missing)
        }
        fn is_dir(&self, _: &Path) -> bool {
            false
        }
        fn exists(&self, _: &Path) -> bool {
            false
        }
        fn expand(&self, _: &Path) -> Expansion {
            Expansion::default()
        }
        fn walk(&self, _: &Path, _: &mut dyn FnMut(&Path) -> bool) -> WalkEnd {
            WalkEnd::Done
        }
        fn script(&self, _: &Path) -> Script {
            Script::Unreadable
        }
        fn runs_as_script(&self, _: &Path) -> bool {
            false
        }
        fn which(&self, _: &str) -> Option<PathBuf> {
            None
        }
    }

    fn resolved(fs: &MapFs, p: &str) -> (String, bool) {
        let r = fs.resolve(Path::new(p));
        (r.path.to_string_lossy().into_owned(), r.complete)
    }

    // §11 L1.1 "Paths are resolved (symlinks, wildcards) before checking": `..` leaves the folder
    // a link led to, not the folder holding the link (review finding 2).
    #[test]
    fn resolve_follows_a_link_before_a_parent_part() {
        let fs = MapFs::with(
            &[
                "/project",
                "/home",
                "/home/u",
                "/home/u/.claude",
                "/home/u/.claude/projects",
            ],
            &[("/project/link", "/home/u/.claude/projects")],
        );
        assert_eq!(
            resolved(&fs, "/project/link/../history.jsonl"),
            ("/home/u/.claude/history.jsonl".to_owned(), true)
        );
        // Without a link in front, `..` is the folder above.
        assert_eq!(
            resolved(&fs, "/project/../home/u"),
            ("/home/u".to_owned(), true)
        );
        // Beyond the root stays at the root, as `/..` does.
        assert_eq!(resolved(&fs, "/../x"), ("/x".to_owned(), true));
    }

    // L1.1: relative targets are read from the folder holding the link; a chain of links is
    // followed to its end; an absolute target restarts at the root.
    #[test]
    fn resolve_follows_relative_and_chained_links() {
        let fs = MapFs::with(
            &["/a", "/a/b", "/a/b/c", "/z", "/t", "/t/dir"],
            &[
                ("/a/rel", "b/c"),
                ("/a/up", "../z"),
                ("/a/l1", "l2"),
                ("/a/l2", "/t/dir"),
                ("/a/b/back", "../../z"),
            ],
        );
        assert_eq!(resolved(&fs, "/a/rel/x"), ("/a/b/c/x".to_owned(), true));
        assert_eq!(resolved(&fs, "/a/up/f"), ("/z/f".to_owned(), true));
        assert_eq!(resolved(&fs, "/a/l1/f"), ("/t/dir/f".to_owned(), true));
        // A link's target is read from the folder the link sits in.
        assert_eq!(resolved(&fs, "/a/b/back/f"), ("/z/f".to_owned(), true));
        // `..` after a relative link leaves the target's folder.
        assert_eq!(resolved(&fs, "/a/rel/../g"), ("/a/b/g".to_owned(), true));
    }

    // L1.1: a destination that does not exist yet keeps its name; a dangling link is followed to
    // the file a write would create.
    #[test]
    fn resolve_keeps_a_destination_that_does_not_exist() {
        let fs = MapFs::with(
            &["/w", "/home", "/home/u", "/home/u/.claude"],
            &[("/w/new", "/home/u/.claude/settings.json")],
        );
        assert_eq!(
            resolved(&fs, "/w/file.txt"),
            ("/w/file.txt".to_owned(), true)
        );
        assert_eq!(
            resolved(&fs, "/w/nodir/deeper/file.txt"),
            ("/w/nodir/deeper/file.txt".to_owned(), true)
        );
        assert_eq!(
            resolved(&fs, "/w/new"),
            ("/home/u/.claude/settings.json".to_owned(), true)
        );
        // `.` parts are dropped.
        assert_eq!(
            resolved(&fs, "/w/./file.txt"),
            ("/w/file.txt".to_owned(), true)
        );
    }

    // L1.1, fail closed: what cannot be resolved is reported incomplete, never guessed complete.
    #[test]
    fn resolve_reports_what_it_could_not_resolve() {
        let mut fs = MapFs::with(
            &["/a"],
            &[
                ("/a/loop", "/a/loop"),
                ("/a/ping", "pong"),
                ("/a/pong", "ping"),
            ],
        );
        assert!(!fs.resolve(Path::new("/a/loop")).complete);
        assert!(!fs.resolve(Path::new("/a/ping/x")).complete);
        // A `..` after a part that does not exist: a command may make it a link first.
        assert!(!fs.resolve(Path::new("/a/missing/../x")).complete);
        // A part that cannot be looked at.
        fs.0.insert(PathBuf::from("/a/locked"), Node::Unreadable);
        assert!(!fs.resolve(Path::new("/a/locked/x")).complete);
        // The limit is 40 links: a chain of 40 resolves, 41 does not.
        let links: Vec<(String, String)> = (0..41)
            .map(|i| (format!("/c/l{i}"), format!("l{}", i + 1)))
            .collect();
        let refs: Vec<(&str, &str)> = links
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let chain = MapFs::with(&["/c", "/c/l41"], &refs);
        assert!(chain.resolve(Path::new("/c/l1")).complete);
        assert!(!chain.resolve(Path::new("/c/l0")).complete);
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// A throwaway folder under the build's `target` folder, removed on drop.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fs-tests");
            std::fs::create_dir_all(&base).unwrap_or_default();
            let base = std::fs::canonicalize(&base).unwrap_or(base);
            let root = base.join(format!("{}-{n}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap_or_default();
            Self(root)
        }
        fn put(&self, rel: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap_or(&self.0)).unwrap_or_default();
            std::fs::write(p, "x").unwrap_or_default();
        }
        fn link(&self, name: &str, target: &str) {
            let p = self.0.join(name);
            std::fs::create_dir_all(p.parent().unwrap_or(&self.0)).unwrap_or_default();
            std::os::unix::fs::symlink(target, p).unwrap_or_default();
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap_or_default();
        }
    }

    // L1.1: the real file system is the oracle: for every path that exists, `resolve` reaches the
    // file the operating system opens (`canonicalize`), `..` after a link included.
    #[test]
    fn resolve_agrees_with_the_operating_system() {
        let t = Tmp::new();
        t.put("store/projects/t.jsonl");
        t.put("store/history.jsonl");
        t.put("proj/a.txt");
        t.link("proj/link", "../store/projects");
        t.link("proj/abs", &t.0.join("store").to_string_lossy());
        t.link("proj/chain", "link");
        t.link("proj/up", "..");
        let fs = OsFs::new(BUDGET);
        for rel in [
            "proj/link/../history.jsonl",
            "proj/link/t.jsonl",
            "proj/abs/../store/history.jsonl",
            "proj/chain/../history.jsonl",
            "proj/up/store/history.jsonl",
            "proj/up/proj/a.txt",
            "proj/./a.txt",
            "proj/link/../../proj/a.txt",
        ] {
            let p = t.0.join(rel);
            let want = std::fs::canonicalize(&p);
            assert!(want.is_ok(), "{rel}: {want:?}");
            let Ok(want) = want else { return };
            let got = fs.resolve(&p);
            assert_eq!(got.path, want, "{rel}");
            assert!(got.complete, "{rel}");
        }
        // The lexical form is another file, which is the defect resolve closes.
        assert_ne!(
            t.0.join("proj/history.jsonl"),
            fs.resolve(&t.0.join("proj/link/../history.jsonl")).path
        );
        // A destination that does not exist: the existing folder resolves, the name stays.
        assert_eq!(
            fs.resolve(&t.0.join("proj/link/../new.txt")).path,
            t.0.join("store/new.txt")
        );
        // A loop on the real file system.
        t.link("proj/self", "self");
        assert!(!fs.resolve(&t.0.join("proj/self/x")).complete);
        assert_eq!(fs.node(&t.0.join("proj/missing")), Node::Missing);
        assert_eq!(fs.node(&t.0.join("proj/a.txt/x")), Node::Missing);
        assert_eq!(fs.node(&t.0.join("proj/a.txt")), Node::Plain);
        assert_eq!(
            fs.node(&t.0.join("proj/link")),
            Node::Link(PathBuf::from("../store/projects"))
        );
    }

    // §11 L1.1 (review finding 7): a walk enters every folder, the ones that usually hold fetched
    // or built files included, because a recursive search reads them; those are walked last.
    #[test]
    fn walk_enters_every_folder_and_the_usual_bulk_ones_last() {
        let t = Tmp::new();
        t.put("src/main.rs");
        for dir in LAST {
            t.put(&format!("{dir}/deep/.env"));
        }
        t.link("pnpm/node_modules", "../store");
        t.put("store/pkg/id_rsa");
        let fs = OsFs::new(BUDGET);
        let mut seen: Vec<PathBuf> = Vec::new();
        let end = fs.walk(&t.0, &mut |p| {
            seen.push(p.to_path_buf());
            false
        });
        assert_eq!(end, WalkEnd::Done);
        for dir in LAST {
            assert!(seen.contains(&t.0.join(dir).join("deep/.env")), "{dir}");
        }
        assert!(seen.contains(&t.0.join("store/pkg/id_rsa")));
        let at = |p: &Path| seen.iter().position(|s| s == p);
        let main = at(&t.0.join("src/main.rs"));
        let bulk = at(&t.0.join("node_modules/deep/.env"));
        assert!(main.is_some() && bulk.is_some() && main < bulk);
    }

    // L1.1, fail closed: a walk whose budget ran out says so, so the caller does not read the
    // part it saw as the whole.
    #[test]
    fn walk_out_of_budget_is_capped() {
        let t = Tmp::new();
        t.put("a/b/c.txt");
        let fs = OsFs::new(Duration::ZERO);
        assert_eq!(fs.walk(&t.0, &mut |_| false), WalkEnd::Capped);
    }

    #[test]
    fn fnmatch_classes_and_dots() {
        assert!(fnmatch("*.pem", "a.pem"));
        assert!(fnmatch("cod?x", "codex"));
        assert!(fnmatch("c[a-z]dex", "codex"));
        assert!(!fnmatch("c[!o]dex", "codex"));
        assert!(fnmatch("c[^x]dex", "codex"));
        assert!(!fnmatch("*", ".env"));
        assert!(fnmatch(".e*", ".env"));
        assert!(fnmatch("a[b", "a[b"));
        assert!(fnmatch("[]]x", "]x"));
    }
}
