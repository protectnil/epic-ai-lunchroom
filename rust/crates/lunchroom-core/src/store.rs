//! A crash-safe store: one state file, replaced whole and atomically, one writer at a time.
//!
//! Spec: §10 D1 (no loss, no duplicates across a crash or restart) and §8 A2.4 (approving and using
//! an approval are each one atomic step). Every change is one [`Store::update`]: take the
//! exclusive lock, read the state, change it, write it to a temporary file, flush it to disk,
//! rename it over the state file and flush the folder; a change that leaves the state as it was
//! writes nothing. A crash at any point leaves either the old
//! state or the new one, never a mix, and two processes' changes never interleave. A state file
//! that cannot be read is an error, never an empty state, so nothing fails open.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::marker::PhantomData;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde::de::DeserializeOwned;

const STATE: &str = "state.json";
const TEMP: &str = "state.json.tmp";
/// The state as it was before the last change: a state that was read whole, so `repair` can
/// return to it when the state file cannot be read.
const PREVIOUS: &str = "state.json.prev";
const PREVIOUS_TEMP: &str = "state.json.prev.tmp";
const GUARD_FILE: &str = "state.flock";
/// How long a reader or writer waits for another to finish: past it, the store is reported busy,
/// so no command, the user's own included, waits on a process that never lets go.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

static STOPPED: AtomicBool = AtomicBool::new(false);

/// From now on, no update in this process changes the state (H1.5: a guard past its deadline
/// answers as one that could not decide, so nothing it is still doing may commit a different
/// outcome). An update already under way finishes.
pub fn stop_updates() {
    STOPPED.store(true, Ordering::SeqCst);
}

/// The longest pause between tries for a lock held by another.
const LOCK_RETRY_MAX: std::time::Duration = std::time::Duration::from_millis(20);

/// The pause after `pause`: twice as long, up to [`LOCK_RETRY_MAX`].
fn longer(pause: std::time::Duration) -> std::time::Duration {
    (pause * 2).min(LOCK_RETRY_MAX)
}

/// Takes the lock with `try_lock`, retrying until [`LOCK_WAIT`] has passed. The first retry comes
/// after 1 ms, so a lock held briefly costs little more than that wait, not a flat 20 ms.
fn wait_for(try_lock: impl Fn() -> Result<(), fs::TryLockError>) -> io::Result<()> {
    let start = std::time::Instant::now();
    let mut pause = std::time::Duration::from_millis(1);
    loop {
        match try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::Error(e)) => return Err(e),
            Err(fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(pause);
                pause = longer(pause);
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "another Lunchroom process has held the store for 10 seconds",
                ));
            }
        }
    }
}

/// What identifies one version of the state file: its change time (seconds, nanoseconds), size
/// and inode. Every write replaces the file, so a new state is a new stamp.
pub type Stamp = (i64, i64, u64, u64);

/// A state of type `T` kept in one folder.
#[derive(Debug)]
pub struct Store<T> {
    dir: PathBuf,
    kind: PhantomData<fn() -> T>,
}

/// Where a test stops an update, to stand for a crash (D1.2). Only tests stop one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Crash {
    /// Part way through writing the new state to the temporary file: half of it is there, none
    /// of it flushed.
    MidWrite,
    /// After the new state is written to the temporary file, before it replaces the state file.
    BeforeRename,
    /// After the state being replaced is kept as the previous one, before the new state replaces it.
    AfterPrevious,
    /// After the new state replaces the state file, before the folder is flushed.
    AfterRename,
    /// A repair, after the previous state is written to the temporary file, before the unreadable
    /// state file is kept or replaced.
    RepairAfterTemp,
    /// A repair, after the unreadable state file is kept beside, before it is replaced.
    RepairAfterKeep,
    /// A repair, after the previous state replaces the state file, before the folder is flushed.
    RepairAfterRename,
}

impl<T: Serialize + DeserializeOwned + Default> Store<T> {
    /// The store in `dir`, which is created, readable by its owner only, if it is missing.
    ///
    /// # Errors
    /// When the folder cannot be created.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            kind: PhantomData,
        })
    }

    /// The state as last written; the default state before the first write.
    ///
    /// # Errors
    /// When the state file cannot be read or does not parse.
    pub fn read(&self) -> io::Result<T> {
        let guard = self.guard()?;
        wait_for(|| guard.try_lock_shared())?;
        let state = self.load().map(|(state, _)| state);
        guard.unlock()?;
        state
    }

    /// The stamp of the state file as it is now, taken without a lock; all zeros when there is
    /// none. Equal stamps mean the same state, so a caller that found nothing to do may skip
    /// reading until the stamp changes.
    #[must_use]
    pub fn stamp(&self) -> Stamp {
        fs::metadata(self.dir.join(STATE)).map_or((0, 0, 0, 0), |m| {
            (m.mtime(), m.mtime_nsec(), m.size(), m.ino())
        })
    }

    /// Changes the state in one atomic step and returns what `change` returns.
    ///
    /// # Errors
    /// When the state cannot be read, or the new state cannot be written; the state on disk is then
    /// the one before the call.
    pub fn update<R>(&self, change: impl FnOnce(&mut T) -> R) -> io::Result<R> {
        self.update_inner(change, None)
    }

    /// [`Store::update`] that stops at `crash`, as a crash would.
    #[cfg(test)]
    pub(crate) fn update_crashing<R>(
        &self,
        change: impl FnOnce(&mut T) -> R,
        crash: Crash,
    ) -> io::Result<R> {
        self.update_inner(change, Some(crash))
    }

    fn update_inner<R>(
        &self,
        change: impl FnOnce(&mut T) -> R,
        crash: Option<Crash>,
    ) -> io::Result<R> {
        let guard = self.guard()?;
        wait_for(|| guard.try_lock())?;
        // Checked under the lock: an update that starts after `stop_updates` changes nothing.
        let result = if STOPPED.load(Ordering::SeqCst) {
            Err(io::Error::other(
                "the guard's time ran out; nothing more is written",
            ))
        } else {
            self.change_locked(change, crash)
        };
        guard.unlock()?;
        result
    }

    fn change_locked<R>(
        &self,
        change: impl FnOnce(&mut T) -> R,
        crash: Option<Crash>,
    ) -> io::Result<R> {
        let (mut state, text) = self.load()?;
        let result = change(&mut state);
        let bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
        // Nothing changed: the state on disk already is the new state.
        if bytes == text.as_bytes() {
            return Ok(result);
        }
        let temp = self.dir.join(TEMP);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        let half = bytes.len() / 2;
        file.write_all(&bytes[..half])?;
        if crash == Some(Crash::MidWrite) {
            return Err(io::Error::other(
                "stopped part way through the write, as a crash",
            ));
        }
        file.write_all(&bytes[half..])?;
        file.sync_all()?;
        drop(file);
        if crash == Some(Crash::BeforeRename) {
            return Err(io::Error::other("stopped before the rename, as a crash"));
        }
        // The state replaced is kept as the previous one (it was read whole above).
        if !text.is_empty() {
            let link = self.dir.join(PREVIOUS_TEMP);
            let _ = fs::remove_file(&link);
            fs::hard_link(self.dir.join(STATE), &link)?;
            fs::rename(&link, self.dir.join(PREVIOUS))?;
        }
        if crash == Some(Crash::AfterPrevious) {
            return Err(io::Error::other(
                "stopped after keeping the previous state, as a crash",
            ));
        }
        fs::rename(&temp, self.dir.join(STATE))?;
        if crash == Some(Crash::AfterRename) {
            return Err(io::Error::other("stopped after the rename, as a crash"));
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(result)
    }

    /// The state from before the last change.
    ///
    /// # Errors
    /// When there is none, or it does not parse.
    pub fn read_previous(&self) -> io::Result<T> {
        let text = fs::read_to_string(self.dir.join(PREVIOUS))?;
        serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// When the state file cannot be read, puts the previous state back and keeps the unreadable
    /// file beside it as `state.json.unreadable-<n>`. `Ok(false)` when the state file reads.
    ///
    /// The replacement is written and flushed first, the unreadable file is kept by a second link
    /// to it, and the state file is then replaced in one rename, so there is no moment without a
    /// state file: a crash at any step leaves the unreadable file in place (the repair runs
    /// again) or the previous state in its place.
    ///
    /// # Errors
    /// When there is no previous state that reads either, or the files cannot be moved.
    pub fn restore_previous(&self) -> io::Result<bool> {
        self.restore_inner(None)
    }

    /// [`Store::restore_previous`] that stops at `crash`, as a crash would.
    #[cfg(test)]
    pub(crate) fn restore_previous_crashing(&self, crash: Crash) -> io::Result<bool> {
        self.restore_inner(Some(crash))
    }

    fn restore_inner(&self, crash: Option<Crash>) -> io::Result<bool> {
        let guard = self.guard()?;
        wait_for(|| guard.try_lock())?;
        let result = self.repair_locked(crash);
        guard.unlock()?;
        result
    }

    fn repair_locked(&self, crash: Option<Crash>) -> io::Result<bool> {
        if self.load().is_ok() {
            return Ok(false);
        }
        let previous = fs::read_to_string(self.dir.join(PREVIOUS))?;
        serde_json::from_str::<T>(&previous)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let temp = self.dir.join(TEMP);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(previous.as_bytes())?;
        file.sync_all()?;
        drop(file);
        if crash == Some(Crash::RepairAfterTemp) {
            return Err(io::Error::other(
                "stopped after the temporary file, as a crash",
            ));
        }
        // The unreadable file is kept by a link, not a move, so the state file is absent for no
        // moment. A state file that is missing (lost, or an earlier repair that stopped) has
        // nothing to keep.
        match fs::symlink_metadata(self.dir.join(STATE)) {
            Ok(_) => {
                let mut n = 1;
                loop {
                    let kept = self.dir.join(format!("{STATE}.unreadable-{n}"));
                    match fs::hard_link(self.dir.join(STATE), &kept) {
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1,
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if crash == Some(Crash::RepairAfterKeep) {
            return Err(io::Error::other(
                "stopped after keeping the file, as a crash",
            ));
        }
        fs::rename(&temp, self.dir.join(STATE))?;
        if crash == Some(Crash::RepairAfterRename) {
            return Err(io::Error::other("stopped after the rename, as a crash"));
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(true)
    }

    /// The state and the text it was read from (empty before the first write).
    fn load(&self) -> io::Result<(T, String)> {
        let mut text = String::new();
        match File::open(self.dir.join(STATE)) {
            Ok(mut file) => {
                file.read_to_string(&mut text)?;
            }
            // A missing state file is a store never written to only when no previous state
            // exists: every write keeps one, and no step of a write or a repair removes the state
            // file, so a previous state beside a missing state file is a store whose state was
            // lost, an error to repair, never an empty store.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if self.dir.join(PREVIOUS).exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the state file is missing but a previous state exists",
                    ));
                }
                return Ok((T::default(), text));
            }
            Err(e) => return Err(e),
        }
        let state = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok((state, text))
    }

    /// The file whose exclusive lock admits one writer at a time. It is never replaced, so every
    /// process locks the same file.
    fn guard(&self) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.dir.join(GUARD_FILE))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    // An update that changes nothing leaves the state file as it is: no rewrite and no flush,
    // which every guard hook and every listener tick would otherwise pay.
    #[test]
    fn an_update_that_changes_nothing_writes_nothing() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit")
            .join(std::process::id().to_string());
        let store = Store::<BTreeMap<String, u32>>::open(&dir);
        assert!(store.is_ok());
        let Ok(store) = store else { return };
        let inode = || fs::metadata(dir.join(STATE)).ok().map(|m| m.ino());
        assert!(store.update(|m| m.insert("a".to_owned(), 1)).is_ok());
        let before = inode();
        assert!(before.is_some());
        assert_eq!(store.update(|m| m.get("a").copied()).ok(), Some(Some(1)));
        assert_eq!(inode(), before);
        assert!(store.update(|m| m.insert("a".to_owned(), 2)).is_ok());
        assert_ne!(inode(), before);
        assert_eq!(store.read().ok().and_then(|m| m.get("a").copied()), Some(2));
        let _ = fs::remove_dir_all(&dir);
    }

    // The stamp moves with every write and stays put for a read and for an update that changes
    // nothing: what lets a listener tick skip the store while nothing was written.
    #[test]
    fn the_stamp_moves_only_when_the_state_is_written() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit-stamp")
            .join(std::process::id().to_string());
        let store = Store::<BTreeMap<String, u32>>::open(&dir);
        assert!(store.is_ok());
        let Ok(store) = store else { return };
        assert_eq!(store.stamp(), (0, 0, 0, 0));
        assert!(store.update(|m| m.insert("a".to_owned(), 1)).is_ok());
        let written = store.stamp();
        assert_ne!(written, (0, 0, 0, 0));
        assert!(store.read().is_ok());
        assert!(store.update(|m| m.get("a").copied()).is_ok());
        assert_eq!(store.stamp(), written);
        assert!(store.update(|m| m.insert("a".to_owned(), 2)).is_ok());
        assert_ne!(store.stamp(), written);
        let _ = fs::remove_dir_all(&dir);
    }

    // The wait between tries starts at 1 ms, doubles, and stops at the cap.
    #[test]
    fn the_lock_wait_backs_off_to_its_cap() {
        let mut pause = std::time::Duration::from_millis(1);
        let mut seen = Vec::new();
        for _ in 0..7 {
            seen.push(pause.as_millis());
            pause = longer(pause);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 20, 20]);
        assert!(LOCK_RETRY_MAX < LOCK_WAIT);
    }

    // An unreadable state file is repaired from the state before the last change; the bad file is
    // kept beside it; a store that reads is left alone.
    #[test]
    fn an_unreadable_store_is_repaired_from_the_previous_state() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit-repair")
            .join(std::process::id().to_string());
        let store = Store::<BTreeMap<String, u32>>::open(&dir);
        assert!(store.is_ok());
        let Ok(store) = store else { return };
        assert!(store.update(|m| m.insert("a".to_owned(), 1)).is_ok());
        assert!(store.update(|m| m.insert("a".to_owned(), 2)).is_ok());
        assert_eq!(store.restore_previous().ok(), Some(false));
        assert!(fs::write(dir.join(STATE), "{ broken").is_ok());
        assert!(store.read().is_err());
        assert_eq!(store.restore_previous().ok(), Some(true));
        assert_eq!(store.read().ok().and_then(|m| m.get("a").copied()), Some(1));
        assert!(dir.join(format!("{STATE}.unreadable-1")).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A store in `case` that has held `a = 1` and then `a = 2`, its state file then broken.
    fn broken(case: &str) -> Option<(PathBuf, Store<BTreeMap<String, u32>>)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit-repair-crash")
            .join(std::process::id().to_string())
            .join(case);
        let store = Store::<BTreeMap<String, u32>>::open(&dir).ok()?;
        store.update(|m| m.insert("a".to_owned(), 1)).ok()?;
        store.update(|m| m.insert("a".to_owned(), 2)).ok()?;
        fs::write(dir.join(STATE), "{ broken").ok()?;
        Some((dir, store))
    }

    // §10::2 (D1.2): a repair stopped at any step never turns the store into an empty
    // one. The state file exists at every step (the unreadable file is kept by a link, the
    // replacement arrives in one rename); until the rename it is still the unreadable file, so the
    // store reads as an error, never as a new store; after it, it is the previous state. The
    // repair run again, as a restarted process runs it, ends with the previous state in place and
    // every unreadable copy kept.
    #[test]
    fn a_repair_stopped_at_any_step_never_leaves_an_empty_store() {
        let previous: BTreeMap<String, u32> = [("a".to_owned(), 1)].into();
        for (case, crash, readable) in [
            ("after-temp", Crash::RepairAfterTemp, false),
            ("after-keep", Crash::RepairAfterKeep, false),
            ("after-rename", Crash::RepairAfterRename, true),
        ] {
            let broken = broken(case);
            assert!(broken.is_some(), "{case}");
            let Some((dir, store)) = broken else { return };
            assert!(store.restore_previous_crashing(crash).is_err(), "{case}");
            assert!(dir.join(STATE).exists(), "{case}: state file present");
            assert_eq!(store.read().is_ok(), readable, "{case}: reads");
            if !readable {
                assert!(store.read().is_err(), "{case}: an error, not a new store");
            }
            assert!(store.restore_previous().is_ok(), "{case}: run again");
            assert_eq!(store.read().ok().as_ref(), Some(&previous), "{case}");
            assert!(dir.join(format!("{STATE}.unreadable-1")).exists(), "{case}");
            assert_eq!(
                fs::read_to_string(dir.join(format!("{STATE}.unreadable-1"))).ok(),
                Some("{ broken".to_owned()),
                "{case}: the unreadable file is kept as it was"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    // §10::2 (D1.2): a state file that is missing while the previous state exists is a
    // lost state, not a new store: it reads as an error (so nothing fails open on an empty state),
    // an update refuses to write over it, and the repair puts the previous state back with nothing
    // unreadable to keep. A store never written to still reads as the default.
    #[test]
    fn a_missing_state_file_beside_a_previous_state_is_repaired_not_read_as_new() {
        let fresh = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit-missing")
            .join(std::process::id().to_string());
        let store = Store::<BTreeMap<String, u32>>::open(&fresh);
        assert!(
            store
                .as_ref()
                .is_ok_and(|s| s.read().is_ok_and(|m| m.is_empty()))
        );
        let _ = fs::remove_dir_all(&fresh);
        let missing = broken("missing");
        assert!(missing.is_some());
        let Some((dir, store)) = missing else { return };
        assert!(fs::remove_file(dir.join(STATE)).is_ok());
        assert!(store.read().is_err());
        assert!(store.update(|m| m.insert("b".to_owned(), 3)).is_err());
        assert!(!dir.join(STATE).exists());
        assert_eq!(store.restore_previous().ok(), Some(true));
        assert_eq!(store.read().ok().and_then(|m| m.get("a").copied()), Some(1));
        assert!(!dir.join(format!("{STATE}.unreadable-1")).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A store in `case` that has held `a = 1` and then `a = 2`, stopped by `crash` while it
    /// added `b = 3`, and opened again as a restarted process opens it.
    fn after_crash(case: &str, crash: Crash) -> Option<(PathBuf, Store<BTreeMap<String, u32>>)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit-crash")
            .join(std::process::id().to_string())
            .join(case);
        let store = Store::<BTreeMap<String, u32>>::open(&dir).ok()?;
        store.update(|m| m.insert("a".to_owned(), 1)).ok()?;
        store.update(|m| m.insert("a".to_owned(), 2)).ok()?;
        let crashed = store.update_crashing(|m| m.insert("b".to_owned(), 3), crash);
        assert!(crashed.is_err(), "{case}");
        drop(store);
        Some((dir.clone(), Store::open(&dir).ok()?))
    }

    // §10::2 (D1.2): a crash at any point of an update leaves the state as it was or as
    // it would have been, never a mix. A crash before the new state replaces the state file (part
    // way through writing it, written, or with the previous state kept) leaves the old state, with
    // the half-written or whole temporary file ignored and replaced by the next update; a crash
    // after the replacement leaves the new state, and the old one as the previous state. The store
    // is never held by the crashed update, and the next update is whole.
    #[test]
    fn a_crash_at_any_point_of_an_update_leaves_the_old_state_or_the_new() {
        let map = |pairs: &[(&str, u32)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), *v))
                .collect::<BTreeMap<_, _>>()
        };
        let (older, old, new) = (
            map(&[("a", 1)]),
            map(&[("a", 2)]),
            map(&[("a", 2), ("b", 3)]),
        );
        for (case, crash, state, previous, temp_left) in [
            ("mid-write", Crash::MidWrite, &old, &older, true),
            ("before-rename", Crash::BeforeRename, &old, &older, true),
            ("after-previous", Crash::AfterPrevious, &old, &old, true),
            ("after-rename", Crash::AfterRename, &new, &old, false),
        ] {
            let crashed = after_crash(case, crash);
            assert!(crashed.is_some(), "{case}");
            let Some((dir, store)) = crashed else { return };
            assert_eq!(store.read().ok().as_ref(), Some(state), "{case}: state");
            assert_eq!(
                store.read_previous().ok().as_ref(),
                Some(previous),
                "{case}: previous"
            );
            assert_eq!(dir.join(TEMP).exists(), temp_left, "{case}: temporary file");
            // The restarted process updates at once (the lock was let go) and the result is whole:
            // the state it read, with its own change, and no trace of the leftover file.
            let next = store.update(|m| m.insert("c".to_owned(), 9));
            assert!(next.is_ok(), "{case}: {next:?}");
            let mut expected = state.clone();
            expected.insert("c".to_owned(), 9);
            assert_eq!(store.read().ok(), Some(expected), "{case}: next state");
            assert_eq!(
                store.read_previous().ok().as_ref(),
                Some(state),
                "{case}: next previous"
            );
            assert!(!dir.join(TEMP).exists(), "{case}: temporary file replaced");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    // A store another process holds is reported busy after LOCK_WAIT, never waited on forever.
    #[test]
    fn a_held_store_is_reported_busy() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/store-unit-busy")
            .join(std::process::id().to_string());
        let store = Store::<BTreeMap<String, u32>>::open(&dir);
        assert!(store.is_ok());
        let Ok(store) = store else { return };
        let holder = store.guard();
        assert!(holder.as_ref().is_ok_and(|h| h.try_lock().is_ok()));
        let start = std::time::Instant::now();
        let busy = store.update(|m| m.insert("a".to_owned(), 1));
        assert_eq!(busy.err().map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
        assert!(start.elapsed() >= LOCK_WAIT);
        drop(holder);
        assert!(store.update(|m| m.insert("a".to_owned(), 1)).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
