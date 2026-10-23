// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The epoch file.
//!
//! A copy is restorable only if its tag equals the epoch in this file.
//! Fences write even epochs. Replica tags are odd. An advance writes a tag
//! only if the file still contains the epoch that the primary wrote last.
//! The file is on the pool's system dataset. Only the controller that has
//! imported the pool can write it. The epoch never decreases. Each writer
//! holds an exclusive `flock` on `<file>.lock` while it reads and replaces
//! the file. smbd's fallback fence uses this code too.
//!
//! The file is a 24-byte XDR record (`EpochRecord`): a magic number, the
//! layout version, the epoch and the `f_fsid` of the file system of the
//! file. A file of another file system, for example a copy from another
//! pool, reads as a fence above its epoch: no copy is restorable with it,
//! and the next write continues above it. A file without the magic is an
//! error.
//!
//! A later layout version keeps the first 24 bytes and their meaning, and
//! can add bytes after them. A reader accepts any version from 1 and reads
//! the first 24 bytes. Writers write version 1, so an older writer drops
//! the added bytes: they must be optional.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use truenas_ros::sync_fs::{AtomicWriteOptions, atomic_write, fstatfs};

/// The first 4 bytes of the file: "SMBE".
pub const MAGIC: u32 = 0x534d_4245;

/// Layout version of the file.
pub const FORMAT_VERSION: u32 = 1;

/// The length of the version 1 record. Later versions start with it.
pub const RECORD_LEN: usize = 24;

/// The highest version that a read accepts. A version counts revisions of
/// the layout; a larger value means that the file is not an epoch file.
pub const MAX_FORMAT_VERSION: u32 = 256;

/// The highest epoch that a read accepts and a write writes. `next_tag` and
/// `next_fence` of an epoch from the file cannot overflow.
pub const MAX_EPOCH: u64 = 1 << 48;

/// Returns the smallest even epoch above `x`. Fences write even epochs.
pub fn next_fence(x: u64) -> Option<u64> {
    (x | 1).checked_add(1)
}

/// Returns the smallest odd tag above `x`. Replica tags are odd. A fence
/// never writes the tag of a replica.
pub fn next_tag(x: u64) -> u64 {
    (x + 1) | 1
}

/// The result of a fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bumped {
    /// The epoch in the file before the fence.
    pub previous: u64,
    /// The epoch that the fence wrote.
    pub epoch: u64,
}

/// The file's contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecord {
    /// `MAGIC`.
    pub magic: u32,
    /// `FORMAT_VERSION`.
    pub version: u32,
    /// The epoch.
    pub epoch: u64,
    /// `f_fsid` of the file system of the file.
    pub fsid: u64,
}

/// Returns `f_fsid` of the file system of `file`, as smbd's `tn_fsid()`.
/// ZFS keeps it in the dataset, so an import on the other controller
/// normally keeps it. ZFS changes it when it collides with a dataset that
/// is open in that kernel (`unique_insert()`). A remount of the same
/// dataset does not collide: `dsl_dataset_evict_sync()` releases it at
/// once. A changed fsid makes the file read as foreign: a fence.
fn fsid_of(file: &File) -> io::Result<u64> {
    let id = fstatfs(file)?.fsid();
    Ok((u64::from(id[1]) << 32) | u64::from(id[0]))
}

/// Why a read or a change of the epoch file failed.
#[derive(Debug)]
pub enum EpochError {
    /// An open, lock or read of a file failed.
    Io(io::Error),
    /// The replacement of the file failed.
    Write(truenas_ros::Error),
    /// The file does not contain a valid epoch record of this version.
    Format(String),
    /// The caller asked for an epoch above `MAX_EPOCH`. The file is not
    /// changed.
    Ceiling {
        /// The refused epoch.
        epoch: u64,
    },
    /// For `advance_to`, the file does not contain the expected epoch or
    /// the tag is not larger than the epoch in the file.
    Stale {
        /// The epoch in the file.
        current: u64,
    },
}

impl std::fmt::Display for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochError::Io(e) => write!(f, "epoch file: {e}"),
            EpochError::Write(e) => write!(f, "replacing the epoch file: {e}"),
            EpochError::Format(m) => write!(f, "epoch file: {m}"),
            EpochError::Ceiling { epoch } => {
                write!(f, "epoch {epoch} is above {MAX_EPOCH}")
            }
            EpochError::Stale { current } => {
                write!(f, "epoch file already at {current}")
            }
        }
    }
}

impl std::error::Error for EpochError {}

impl From<io::Error> for EpochError {
    fn from(e: io::Error) -> Self {
        EpochError::Io(e)
    }
}

/// The epoch file and its lock file.
#[derive(Debug)]
pub struct EpochFile {
    path: PathBuf,
    lock_path: PathBuf,
}

impl EpochFile {
    /// The epoch file at `path`. The file does not have to exist.
    pub fn new(path: &Path) -> EpochFile {
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        EpochFile {
            path: path.to_owned(),
            lock_path: PathBuf::from(lock_path),
        }
    }

    /// Returns the current epoch, or 0 if the file does not exist. A file of
    /// another file system reads as the smallest fence above its epoch.
    ///
    /// # Errors
    ///
    /// The read fails, or the file does not contain a valid epoch record.
    pub fn read(&self) -> Result<u64, EpochError> {
        Ok(self.read_opt()?.map_or(0, |(epoch, _)| epoch))
    }

    /// As `read`. Also returns true if the file is of another file system.
    ///
    /// # Errors
    ///
    /// As `read`.
    pub fn read_foreign(&self) -> Result<(u64, bool), EpochError> {
        Ok(self.read_opt()?.unwrap_or((0, false)))
    }

    /// The epoch and whether the file is foreign, or `None` if the file
    /// does not exist. One open decides both: every caller agrees about a
    /// symlink, a FIFO and a file removed during the call.
    fn read_opt(&self) -> Result<Option<(u64, bool)>, EpochError> {
        // Not through a symlink, and no wait for the writer of a FIFO.
        let mut file = match File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !file.metadata()?.is_file() {
            return Err(EpochError::Format("not a regular file".to_owned()));
        }
        let mut bytes = Vec::with_capacity(64);
        file.by_ref().take(4096).read_to_end(&mut bytes)?;
        let Some(prefix) = bytes.get(..RECORD_LEN) else {
            return Err(EpochError::Format(format!(
                "{} bytes, not {RECORD_LEN}",
                bytes.len()
            )));
        };
        let record: EpochRecord = truenas_xdr::from_bytes(prefix)
            .map_err(|e| EpochError::Format(e.to_string()))?;
        if record.magic != MAGIC {
            return Err(EpochError::Format("not an epoch file".to_owned()));
        }
        if !(FORMAT_VERSION..=MAX_FORMAT_VERSION).contains(&record.version)
            || record.epoch > MAX_EPOCH
        {
            return Err(EpochError::Format(format!(
                "version {} or epoch {} is out of range",
                record.version, record.epoch
            )));
        }
        if record.fsid != fsid_of(&file)? {
            // A copy from another file system. Its epoch can be of another
            // pool: no copy is restorable with it.
            let fence = next_fence(record.epoch).ok_or_else(|| {
                EpochError::Format("epoch overflow".to_owned())
            })?;
            return Ok(Some((fence, true)));
        }
        Ok(Some((record.epoch, false)))
    }

    /// Fences every copy. Sets the epoch to the smallest even value above
    /// `floor` and above its current value. Returns the epoch before and
    /// the new epoch. Replica tags are odd, so no copy has the new epoch as
    /// its tag.
    ///
    /// # Errors
    ///
    /// A lock, read or replacement of the file failed. The caller must then
    /// not send any `Protection::Unprotected` reply.
    pub fn bump(&self, floor: u64) -> Result<Bumped, EpochError> {
        let _lock = self.lock()?;
        let previous = self.read()?;
        let epoch = next_fence(previous.max(floor))
            .ok_or_else(|| EpochError::Format("epoch overflow".to_owned()))?;
        self.write(epoch)?;
        Ok(Bumped { previous, epoch })
    }

    /// Sets the epoch to `tag`, the tag of a copy that the standby completed.
    /// That copy becomes restorable. `from` is the epoch that the caller
    /// wrote last.
    ///
    /// # Errors
    ///
    /// `Stale` if the file does not contain `from` or `tag` is not larger. A
    /// fence happened during the resync. The resync must start again with a
    /// new tag.
    pub fn advance_to(&self, tag: u64, from: u64) -> Result<(), EpochError> {
        let _lock = self.lock()?;
        let current = self.read()?;
        if current != from || tag <= current {
            return Err(EpochError::Stale { current });
        }
        self.write(tag)
    }

    /// The fence of smbd when it cannot reach the daemon. Writes the
    /// smallest even epoch above the epoch in the file and returns it. Does
    /// nothing if the file does not exist: no copy is restorable, for
    /// example on a system that is not HA. Does nothing if the file
    /// contains `fenced_to`, the epoch of the last fence of the caller: the
    /// daemon did not write an epoch after that fence.
    ///
    /// # Errors
    ///
    /// A lock, read or replacement of the file failed, or the file does not
    /// contain a valid epoch record.
    pub fn fence(&self, fenced_to: u64) -> Result<Option<u64>, EpochError> {
        // First without the lock: while the daemon is down, every smbd
        // process fences on each promise. A write replaces the whole file,
        // so a read sees the old or the new epoch.
        let Some((current, _)) = self.read_opt()? else {
            return Ok(None);
        };
        if fenced_to != 0 && current == fenced_to {
            return Ok(None);
        }
        let _lock = self.lock()?;
        // Again under the lock. A file removed meanwhile stays removed: a
        // fence from 0 would lower the epoch.
        let Some((current, _)) = self.read_opt()? else {
            return Ok(None);
        };
        if fenced_to != 0 && current == fenced_to {
            return Ok(None);
        }
        let epoch = next_fence(current)
            .ok_or_else(|| EpochError::Format("epoch overflow".to_owned()))?;
        self.write(epoch)?;
        Ok(Some(epoch))
    }

    /// Takes the lock file. Not through a symlink, and no wait for the
    /// writer of a FIFO: a FIFO would block every bump and fence. The lock
    /// itself still waits.
    fn lock(&self) -> Result<File, EpochError> {
        let file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.lock_path)?;
        file.lock()?;
        Ok(file)
    }

    /// Replaces the file. The fsid in the record is that of the new file.
    ///
    /// # Errors
    ///
    /// `Ceiling` for an epoch that a read would refuse, or the replacement
    /// failed.
    fn write(&self, epoch: u64) -> Result<(), EpochError> {
        use std::io::Write as _;

        if epoch > MAX_EPOCH {
            return Err(EpochError::Ceiling { epoch });
        }
        let opts = AtomicWriteOptions {
            mode: 0o600,
            ..AtomicWriteOptions::default()
        };
        atomic_write(&self.path, opts, |f| {
            let bytes = truenas_xdr::to_bytes(&EpochRecord {
                magic: MAGIC,
                version: FORMAT_VERSION,
                epoch,
                fsid: fsid_of(f)?,
            })
            .map_err(|e| io::Error::other(e.to_string()))?;
            f.write_all(&bytes)
        })
        .map_err(EpochError::Write)
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::single_match_else
)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_epoch_zero_and_bumps_count_up() {
        let dir = truenas_ros::tempdir().unwrap();
        let ef = EpochFile::new(&dir.path().join("smbhad.epoch"));
        assert_eq!(ef.read().unwrap(), 0);
        assert_eq!(
            ef.bump(0).unwrap(),
            Bumped {
                previous: 0,
                epoch: 2
            }
        );
        assert_eq!(ef.bump(0).unwrap().epoch, 4);
        assert_eq!(
            ef.bump(11).unwrap(),
            Bumped {
                previous: 4,
                epoch: 12
            }
        );
        assert_eq!(ef.read().unwrap(), 12);
    }

    #[test]
    fn advance_to_needs_the_last_epoch_and_never_moves_backwards() {
        let dir = truenas_ros::tempdir().unwrap();
        let ef = EpochFile::new(&dir.path().join("smbhad.epoch"));
        ef.bump(4).unwrap();
        assert!(matches!(
            ef.advance_to(5, 6),
            Err(EpochError::Stale { current: 6 })
        ));
        assert!(matches!(
            ef.advance_to(7, 4),
            Err(EpochError::Stale { current: 6 })
        ));
        ef.advance_to(7, 6).unwrap();
        assert_eq!(ef.read().unwrap(), 7);
    }

    fn dir_fsid(dir: &Path) -> u64 {
        fsid_of(&File::open(dir).unwrap()).unwrap()
    }

    fn record(version: u32, epoch: u64, fsid: u64) -> Vec<u8> {
        truenas_xdr::to_bytes(&EpochRecord {
            magic: MAGIC,
            version,
            epoch,
            fsid,
        })
        .unwrap()
    }

    #[test]
    fn the_file_is_the_24_byte_layout() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        EpochFile::new(&path).bump(0x0102).unwrap();
        let mut want = vec![b'S', b'M', b'B', b'E', 0, 0, 0, 1];
        want.extend_from_slice(&0x0104u64.to_be_bytes());
        want.extend_from_slice(&dir_fsid(dir.path()).to_be_bytes());
        assert_eq!(std::fs::read(&path).unwrap(), want);
    }

    #[test]
    fn a_file_of_another_file_system_reads_as_a_fence() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let other = dir_fsid(dir.path()) ^ 1;
        std::fs::write(&path, record(FORMAT_VERSION, 7, other)).unwrap();
        let ef = EpochFile::new(&path);
        assert_eq!(ef.read().unwrap(), 8, "no tag matches it");
        assert_eq!(ef.read_foreign().unwrap(), (8, true));
        assert!(matches!(
            ef.advance_to(9, 7),
            Err(EpochError::Stale { current: 8 })
        ));
        assert_eq!(ef.fence(0).unwrap(), Some(10));
        assert_eq!(ef.read().unwrap(), 10, "written for this file system");
        assert_eq!(ef.read_foreign().unwrap(), (10, false));
    }

    #[test]
    fn a_fence_takes_existence_and_epoch_from_one_read() {
        let d = truenas_ros::tempdir().unwrap();
        let path = d.path().join("smbhad.epoch");
        let ef = EpochFile::new(&path);
        assert_eq!(ef.fence(0).unwrap(), None, "no file");
        assert!(!path.exists());
        ef.bump(0).unwrap();
        assert_eq!(ef.fence(0).unwrap(), Some(4));
        // A dangling symlink is not a missing file.
        let link = d.path().join("dangling.epoch");
        std::os::unix::fs::symlink(d.path().join("absent"), &link).unwrap();
        assert!(EpochFile::new(&link).fence(0).is_err());
    }

    #[test]
    fn a_file_removed_during_a_fence_stays_removed() {
        let run = |remove: bool| {
            let d = truenas_ros::tempdir().unwrap();
            let path = d.path().join("smbhad.epoch");
            EpochFile::new(&path).bump(98).unwrap();
            // The lock makes the fence wait after its first read.
            let held = EpochFile::new(&path).lock().unwrap();
            let p = path.clone();
            let t = std::thread::spawn(move || EpochFile::new(&p).fence(0));
            std::thread::sleep(std::time::Duration::from_millis(200));
            if remove {
                std::fs::remove_file(&path).unwrap();
            }
            drop(held);
            (t.join().unwrap().unwrap(), path.exists())
        };
        assert_eq!(run(false), (Some(102), true));
        assert_eq!(run(true), (None, false), "a fence from 0 lowers the epoch");
    }

    #[test]
    fn no_write_goes_above_the_ceiling() {
        let d = truenas_ros::tempdir().unwrap();
        let ef = EpochFile::new(&d.path().join("smbhad.epoch"));
        ef.bump(0).unwrap();
        assert!(matches!(
            ef.bump(MAX_EPOCH + 1),
            Err(EpochError::Ceiling { .. })
        ));
        assert!(matches!(
            ef.advance_to(u64::MAX, 2),
            Err(EpochError::Ceiling { .. })
        ));
        assert_eq!(ef.read().unwrap(), 2, "the file is intact");
        assert_eq!(ef.bump(MAX_EPOCH - 2).unwrap().epoch, MAX_EPOCH);
        assert_eq!(ef.read().unwrap(), MAX_EPOCH);
    }

    #[test]
    fn a_fifo_or_a_symlink_at_the_lock_path_is_refused() {
        let d = truenas_ros::tempdir().unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(d.path().join("fifo.epoch.lock"))
            .status()
            .unwrap();
        assert!(made.success());
        let ef = EpochFile::new(&d.path().join("fifo.epoch"));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(ef.bump(0).is_err());
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(got.expect("the bump waited on the FIFO"), "a FIFO lock");
        std::fs::write(d.path().join("target"), b"").unwrap();
        std::os::unix::fs::symlink(
            d.path().join("target"),
            d.path().join("link.epoch.lock"),
        )
        .unwrap();
        let path = d.path().join("link.epoch");
        assert!(EpochFile::new(&path).bump(0).is_err(), "a symlinked lock");
        assert!(!path.exists());
    }

    #[test]
    fn concurrent_bumps_never_hand_out_the_same_epoch() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let ef = EpochFile::new(&path);
                    (0..25)
                        .map(|_| ef.bump(0).unwrap().epoch)
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        let mut all: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all.sort_unstable();
        assert_eq!(all, (1..=200).map(|i| i * 2).collect::<Vec<u64>>());
        assert_eq!(EpochFile::new(&path).read().unwrap(), 400);
    }

    #[test]
    fn the_fence_of_smbd_needs_the_file_and_skips_its_own_epoch() {
        let dir = truenas_ros::tempdir().unwrap();
        let file = EpochFile::new(&dir.path().join("smbhad.epoch"));
        // No file: nothing to fence, and no file is made.
        assert_eq!(file.fence(0).unwrap(), None);
        assert!(!dir.path().join("smbhad.epoch").exists());
        file.write(5).unwrap();
        assert_eq!(file.fence(0).unwrap(), Some(6));
        assert_eq!(file.fence(6).unwrap(), None);
        assert_eq!(file.read().unwrap(), 6);
        // The daemon advanced: the next fence writes again.
        file.write(7).unwrap();
        assert_eq!(file.fence(6).unwrap(), Some(8));
    }

    #[test]
    fn a_fence_to_the_current_epoch_does_not_wait_for_the_lock() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let file = EpochFile::new(&path);
        file.write(6).unwrap();
        let held = file.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(EpochFile::new(&path).fence(6).unwrap());
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5));
        drop(held);
        assert_eq!(got.expect("the fence waited for the lock"), None);
    }

    #[test]
    fn fences_are_even_and_tags_are_odd() {
        for x in 0..64u64 {
            let f = next_fence(x).unwrap();
            let t = next_tag(x);
            assert!(f > x && f.is_multiple_of(2) && f - x <= 2, "fence {x}");
            assert!(t > x && !t.is_multiple_of(2) && t - x <= 2, "tag {x}");
        }
        assert_eq!(next_fence(u64::MAX), None);
    }

    #[test]
    fn a_later_version_with_more_bytes_is_read_from_its_prefix() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let mut bytes = record(2, 0x0105, dir_fsid(dir.path()));
        bytes.extend_from_slice(&[0xcd; 12]);
        std::fs::write(&path, &bytes).unwrap();
        let ef = EpochFile::new(&path);
        assert_eq!(ef.read().unwrap(), 0x0105);
        // A version 1 writer replaces it with the 24-byte layout.
        assert_eq!(ef.bump(0).unwrap().epoch, 0x0106);
        assert_eq!(std::fs::read(&path).unwrap().len(), RECORD_LEN);
    }

    #[test]
    fn version_zero_and_short_files_are_refused() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let ef = EpochFile::new(&path);
        let fsid = dir_fsid(dir.path());
        std::fs::write(&path, record(0, 6, fsid)).unwrap();
        assert!(ef.read().is_err(), "version 0");
        let bytes = record(FORMAT_VERSION, 6, fsid);
        std::fs::write(&path, &bytes[..RECORD_LEN - 1]).unwrap();
        assert!(ef.read().is_err(), "23 bytes");
    }

    #[test]
    fn a_damaged_file_is_an_error_not_epoch_zero() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        std::fs::write(&path, b"junk").unwrap();
        let ef = EpochFile::new(&path);
        assert!(ef.read().is_err());
        assert!(ef.bump(0).is_err(), "never fence from a guess");
        let mut bytes = record(FORMAT_VERSION, 6, dir_fsid(dir.path()));
        bytes[0] = b's';
        std::fs::write(&path, &bytes).unwrap();
        assert!(ef.read().is_err(), "no magic");
        assert!(ef.bump(0).is_err(), "no magic, no fence");
    }

    #[test]
    fn a_symlink_a_fifo_and_values_out_of_range_are_errors() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let ef = EpochFile::new(&path);
        let target = dir.path().join("target");
        EpochFile::new(&target).bump(5).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ef.read().is_err(), "a symlink to a valid file");
        std::fs::remove_file(&path).unwrap();

        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let fifo = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(EpochFile::new(&fifo).read().is_err());
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(got.expect("the read waited on the FIFO"), "a FIFO");
        std::fs::remove_file(&path).unwrap();

        let fsid = dir_fsid(dir.path());
        let over = record(MAX_FORMAT_VERSION + 1, 6, fsid);
        std::fs::write(&path, over).unwrap();
        assert!(ef.read().is_err(), "version out of range");
        let over = record(FORMAT_VERSION, MAX_EPOCH + 1, fsid);
        std::fs::write(&path, over).unwrap();
        assert!(ef.read().is_err(), "epoch out of range");
        std::fs::write(&path, b"root:x:0:0:root:/root:/bin/sh\n").unwrap();
        assert!(ef.read().is_err(), "the start of /etc/passwd");
        std::fs::write(&path, record(FORMAT_VERSION, MAX_EPOCH, fsid)).unwrap();
        assert_eq!(ef.read().unwrap(), MAX_EPOCH);
    }
}
