// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon. It runs one role at a time. A signal or a role change
//! stops the role. Each role gets the copy that the previous role returned.

use crate::auth::LinkKey;
use crate::config::{Config, RoleSetting};
use crate::ids;
use crate::proto::local::Origin;
use crate::role::{self, Role};
use crate::serve::{self, Identity};
use crate::standby::{self, Standby};
use crate::store::{Header, Store};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use truenas_ros::log::{Level, Logger};
use truenas_ros::net::server::ShutdownHandle;
use truenas_ros::signal::{self, SigSet, Signal};

/// The copy that a role returns. The daemon gives it to the next role.
#[derive(Debug)]
pub enum Copy {
    /// No copy.
    Empty,
    /// The copy of a primary.
    Own {
        /// The records.
        store: Store,
        /// The generation and the writer.
        header: Header,
        /// The origin that a rehydration reports. A replica that became the
        /// copy of a primary keeps `Origin::Replica` until `Primary::done`.
        origin: Origin,
        /// The last epoch of the primary. The next primary serves the copy
        /// only if the epoch file still has this epoch.
        epoch: u64,
    },
    /// The replica of a standby. A new primary serves the replica only if
    /// its tag equals the epoch in the epoch file.
    Replica {
        /// The records.
        store: Store,
        /// The generation, the tag and the writer.
        header: Header,
    },
}

/// The reason to stop the current role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// SIGTERM or SIGINT. The daemon stops.
    Stop,
    /// SIGHUP. The daemon reads the configuration again. The role can change.
    Reload,
    /// With `auto`, the detected role is not the current role.
    Role,
    /// The primary dropped its copy. The role starts again.
    Restart,
    /// The primary served smbd without the link because the link port was
    /// not free. The port is free now. The role starts again with the link
    /// and keeps the copy.
    Link,
}

#[derive(Debug, Default)]
struct Inner {
    reason: Option<Reason>,
    shutdown: Option<ShutdownHandle>,
}

/// A request to stop the current role. The signal thread and the role
/// watcher raise it. The current role checks it.
#[derive(Debug, Default)]
pub struct Interrupt {
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl Interrupt {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Asks the current role to stop.
    pub fn raise(&self, reason: Reason) {
        let mut g = self.lock();
        g.reason = Some(match (g.reason, reason) {
            (Some(Reason::Stop), _) | (_, Reason::Stop) => Reason::Stop,
            (Some(Reason::Reload), _) | (_, Reason::Reload) => Reason::Reload,
            (Some(Reason::Role), _) | (_, Reason::Role) => Reason::Role,
            (Some(Reason::Restart), _) | (_, Reason::Restart) => {
                Reason::Restart
            }
            _ => Reason::Link,
        });
        if let Some(h) = &g.shutdown {
            h.shutdown();
        }
        self.cv.notify_all();
    }

    /// Returns true if a reason to stop is set.
    pub fn pending(&self) -> bool {
        self.lock().reason.is_some()
    }

    /// Returns the reason to stop and clears it.
    pub fn take(&self) -> Option<Reason> {
        self.lock().reason.take()
    }

    /// Waits up to `d` for a reason to stop. Returns true if a reason is set.
    pub fn wait(&self, d: Duration) -> bool {
        let g = self.lock();
        if g.reason.is_some() {
            return true;
        }
        let (g, _) = self
            .cv
            .wait_timeout(g, d)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.reason.is_some()
    }

    /// Registers the shutdown handle of the current server. `raise` stops
    /// the server. If a reason is already set, the server stops at once.
    pub fn register(&self, h: ShutdownHandle) {
        let mut g = self.lock();
        if g.reason.is_some() {
            h.shutdown();
        }
        g.shutdown = Some(h);
    }

    /// Removes the registered shutdown handle.
    pub fn unregister(&self) {
        self.lock().shutdown = None;
    }
}

/// The values that `role_watcher` reads. `run` sets them before each role
/// starts.
#[derive(Debug)]
struct Watched {
    setting: RoleSetting,
    local_address: Option<Ipv4Addr>,
    sysdataset: PathBuf,
    running: Role,
}

/// The stack size of each thread that the daemon starts: 2 MiB, the Rust
/// default. It is set, so the environment (`RUST_MIN_STACK`) cannot change
/// it.
pub const THREAD_STACK: usize = 2 << 20;

/// The most bytes of the secret file. The pwenc secret has 32.
const MAX_SECRET: usize = 4096;

/// Reads the secret file. Not through a symlink, no wait for the writer of
/// a FIFO, a regular file of at most `MAX_SECRET` bytes.
fn read_secret(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut secret = Vec::new();
    file.by_ref()
        .take(MAX_SECRET as u64 + 1)
        .read_to_end(&mut secret)?;
    if secret.len() > MAX_SECRET {
        return Err(std::io::Error::other(format!(
            "more than {MAX_SECRET} bytes"
        )));
    }
    Ok(secret)
}

fn read_key(cfg: &Config, log: &Logger) -> Option<LinkKey> {
    match read_secret(&cfg.secret_file) {
        Ok(secret) if !secret.is_empty() => match LinkKey::derive(&secret) {
            Ok(key) => Some(key),
            Err(e) => {
                truenas_ros::log!(
                    log,
                    Level::Warning,
                    "deriving the link key: {e}"
                );
                None
            }
        },
        Ok(_) => {
            truenas_ros::log!(
                log,
                Level::Warning,
                "{}: empty",
                cfg.secret_file.display()
            );
            None
        }
        Err(e) => {
            truenas_ros::log!(
                log,
                Level::Warning,
                "{}: {e}",
                cfg.secret_file.display()
            );
            None
        }
    }
}

/// Runs the daemon until SIGTERM or SIGINT.
///
/// # Errors
///
/// - The daemon cannot block the signals.
/// - The daemon cannot read the configuration.
/// - The daemon cannot read the boot id.
/// - A thread does not start.
#[allow(clippy::too_many_lines)]
pub fn run(config_path: &Path, log: &Logger) -> Result<(), String> {
    let blocked =
        signal::block(SigSet::of([Signal::Hup, Signal::Int, Signal::Term]))
            .map_err(|e| format!("blocking signals: {e}"))?;
    let mut cfg = Config::load(config_path).map_err(|e| e.to_string())?;
    let boot =
        ids::boot_id(&cfg.boot_id_file).map_err(|e| format!("boot id: {e}"))?;
    truenas_ros::log!(
        log,
        Level::Notice,
        "starting on boot {}",
        ids::hex(&boot)
    );
    let interrupt = Arc::new(Interrupt::default());
    {
        let interrupt = Arc::clone(&interrupt);
        thread::Builder::new()
            .name("smbhad-signals".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                while let Ok(d) = blocked.wait() {
                    match d.signal {
                        Signal::Hup => interrupt.raise(Reason::Reload),
                        _ => interrupt.raise(Reason::Stop),
                    }
                }
            })
            .map_err(|e| format!("signal thread: {e}"))?;
    }
    let watched = Arc::new(Mutex::new(Watched {
        setting: cfg.role,
        local_address: cfg.local_address,
        sysdataset: cfg.sysdataset_path.clone(),
        running: Role::Idle,
    }));
    {
        let interrupt = Arc::clone(&interrupt);
        let watched = Arc::clone(&watched);
        thread::Builder::new()
            .name("smbhad-role".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || role_watcher(&interrupt, &watched))
            .map_err(|e| format!("role thread: {e}"))?;
    }

    let mut copy = Copy::Empty;
    loop {
        let role = role::current(&cfg);
        {
            let mut w = watched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            w.setting = cfg.role;
            w.local_address = cfg.local_address;
            w.sysdataset.clone_from(&cfg.sysdataset_path);
            w.running = role;
        }
        let node = match (role, cfg.node) {
            (Role::Idle, _) => None,
            (_, Some(node)) => Some(node),
            (_, None) => {
                truenas_ros::log!(
                    log,
                    Level::Warning,
                    "role {role:?} needs `node` in the configuration"
                );
                None
            }
        };
        let role = if node.is_some() { role } else { Role::Idle };
        truenas_ros::log!(log, Level::Notice, "role {role:?}");
        let key = read_key(&cfg, log);
        copy = match (role, node) {
            (Role::Primary, Some(node)) => serve::run(
                &cfg,
                copy,
                &Identity { node, boot },
                key,
                &interrupt,
                log,
            ),
            (Role::Standby, Some(node)) => {
                if let Some(key) = key {
                    let (store, header) = match copy {
                        Copy::Replica { store, header } => (store, header),
                        _ => (Store::default(), Header::empty(node, boot)),
                    };
                    let sb = Standby::new(
                        key,
                        node,
                        boot,
                        ids::random_fill,
                        store,
                        header,
                        log.clone(),
                    );
                    let (store, header) = standby::run(&cfg, sb, &interrupt);
                    Copy::Replica { store, header }
                } else {
                    crate::notify::ready(log);
                    while !interrupt.wait(Duration::from_secs(3600)) {}
                    copy
                }
            }
            _ => {
                crate::notify::ready(log);
                while !interrupt.wait(Duration::from_secs(3600)) {}
                copy
            }
        };
        match interrupt.take() {
            Some(Reason::Stop) => break,
            Some(Reason::Reload) => match Config::load(config_path) {
                Ok(c) => cfg = c,
                Err(e) => truenas_ros::log!(
                    log,
                    Level::Warning,
                    "keeping the old configuration: {e}"
                ),
            },
            Some(Reason::Role | Reason::Restart | Reason::Link) | None => {}
        }
    }
    truenas_ros::log!(log, Level::Notice, "stopped");
    Ok(())
}

/// The number of role readings in a row, one a second, that must differ
/// from the running role before the role changes.
const ROLE_READINGS: u32 = 3;

fn role_watcher(interrupt: &Interrupt, watched: &Mutex<Watched>) {
    let mut differ = 0;
    loop {
        thread::sleep(Duration::from_secs(1));
        let (setting, local, path, running) = {
            let w = watched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (w.setting, w.local_address, w.sysdataset.clone(), w.running)
        };
        if setting == RoleSetting::Auto && role::auto(local, &path) != running {
            differ += 1;
        } else {
            differ = 0;
        }
        if differ >= ROLE_READINGS {
            differ = 0;
            interrupt.raise(Reason::Role);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_file_is_a_regular_file_of_bounded_size() {
        let d = truenas_ros::tempdir().unwrap();
        let secret = d.path().join("secret");
        std::fs::write(&secret, [7u8; 32]).unwrap();
        assert_eq!(read_secret(&secret).unwrap(), vec![7u8; 32]);
        std::fs::write(&secret, vec![7u8; MAX_SECRET + 1]).unwrap();
        assert!(read_secret(&secret).is_err(), "too large");
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(read_secret(&link).is_err(), "a symlink");
        let fifo = d.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_secret(&fifo).is_err());
        });
        let got = rx.recv_timeout(Duration::from_secs(5));
        assert!(got.expect("the read waited on the FIFO"), "a FIFO");
    }
}
