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
//! the file. smbd's fallback fence must use the same lock and the same
//! 12-byte XDR layout (`EpochRecord`).
//!
//! A later layout version keeps the first 12 bytes and their meaning, and
//! can add bytes after them. A reader accepts any version from 1 and reads
//! the first 12 bytes. Writers write version 1, so an older writer drops
//! the added bytes: they must be optional.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use truenas_ros::sync_fs::{AtomicWriteOptions, atomic_replace};

/// Layout version of the file.
pub const FORMAT_VERSION: u32 = 1;

/// The length of the version 1 record. Later versions start with it.
pub const RECORD_LEN: usize = 12;

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
    /// `FORMAT_VERSION`.
    pub version: u32,
    /// The epoch.
    pub epoch: u64,
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

    /// Returns the current epoch, or 0 if the file does not exist.
    ///
    /// # Errors
    ///
    /// The read fails, or the file does not contain a valid epoch record.
    pub fn read(&self) -> Result<u64, EpochError> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
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
        if record.version < FORMAT_VERSION {
            return Err(EpochError::Format(format!(
                "version {} is below {FORMAT_VERSION}",
                record.version
            )));
        }
        Ok(record.epoch)
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
        if let Err(e) = std::fs::metadata(&self.path)
            && e.kind() == io::ErrorKind::NotFound
        {
            return Ok(None);
        }
        let _lock = self.lock()?;
        let current = self.read()?;
        if fenced_to != 0 && current == fenced_to {
            return Ok(None);
        }
        let epoch = next_fence(current)
            .ok_or_else(|| EpochError::Format("epoch overflow".to_owned()))?;
        self.write(epoch)?;
        Ok(Some(epoch))
    }

    fn lock(&self) -> Result<File, EpochError> {
        let file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)?;
        file.lock()?;
        Ok(file)
    }

    fn write(&self, epoch: u64) -> Result<(), EpochError> {
        let bytes = truenas_xdr::to_bytes(&EpochRecord {
            version: FORMAT_VERSION,
            epoch,
        })
        .map_err(|e| EpochError::Format(e.to_string()))?;
        let opts = AtomicWriteOptions {
            mode: 0o600,
            ..AtomicWriteOptions::default()
        };
        atomic_replace(&self.path, &bytes, opts).map_err(EpochError::Write)
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

    #[test]
    fn the_file_is_the_12_byte_layout_smbd_reads() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        EpochFile::new(&path).bump(0x0102).unwrap();
        let want = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x01, 0x04];
        assert_eq!(std::fs::read(&path).unwrap(), want);
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
        let mut bytes = vec![0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0x01, 0x05];
        bytes.extend_from_slice(&[0xcd; 12]);
        std::fs::write(&path, &bytes).unwrap();
        let ef = EpochFile::new(&path);
        assert_eq!(ef.read().unwrap(), 0x0105);
        // A version 1 writer replaces it with the 12-byte layout.
        assert_eq!(ef.bump(0).unwrap().epoch, 0x0106);
        assert_eq!(std::fs::read(&path).unwrap().len(), RECORD_LEN);
    }

    #[test]
    fn version_zero_and_short_files_are_refused() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        let ef = EpochFile::new(&path);
        let mut bytes = vec![0u8; 12];
        std::fs::write(&path, &bytes).unwrap();
        assert!(ef.read().is_err(), "version 0");
        bytes[3] = 1;
        std::fs::write(&path, &bytes[..RECORD_LEN - 1]).unwrap();
        assert!(ef.read().is_err(), "11 bytes");
    }

    #[test]
    fn a_damaged_file_is_an_error_not_epoch_zero() {
        let dir = truenas_ros::tempdir().unwrap();
        let path = dir.path().join("smbhad.epoch");
        std::fs::write(&path, b"junk").unwrap();
        let ef = EpochFile::new(&path);
        assert!(ef.read().is_err());
        assert!(ef.bump(0).is_err(), "never fence from a guess");
    }
}
