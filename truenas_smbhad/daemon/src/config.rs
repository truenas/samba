// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Settings from `/etc/truenas_smbhad.conf`, section `[smbhad]`.
//!
//! Every key has a default. If the file does not exist, the daemon uses the
//! defaults. The daemon detects the role with the rule of the ctdb HA
//! reclock helper. It detects the addresses with the rule of middleware.
//! Keys in the file override the detection. On SIGHUP, the daemon reads the
//! file again.

use crate::proto::Node;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use truenas_ros::configfile::ConfigFile;

/// Path of the configuration file. Middleware writes this file.
pub const DEFAULT_PATH: &str = "/etc/truenas_smbhad.conf";

/// The section that holds every key.
pub const SECTION: &str = "smbhad";

/// Values of the `role` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleSetting {
    /// `auto`: the daemon detects the role from the mount source of the
    /// system dataset.
    Auto,
    /// `primary`: the daemon always runs the primary role.
    Primary,
    /// `standby`: the daemon always runs the standby role.
    Standby,
    /// `none`: the daemon does nothing.
    None,
}

impl FromStr for RoleSetting {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(RoleSetting::Auto),
            "primary" => Ok(RoleSetting::Primary),
            "standby" => Ok(RoleSetting::Standby),
            "none" => Ok(RoleSetting::None),
            other => Err(format!(
                "role {other:?} is not auto, primary, standby or none"
            )),
        }
    }
}

/// The settings of the daemon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `role`: the role to run.
    pub role: RoleSetting,
    /// `sysdataset_path`: mount point of the system dataset. With `auto`,
    /// its mount source sets the role.
    pub sysdataset_path: PathBuf,
    /// `local_address`: the address of this controller on the internal link.
    /// If unset, the daemon detects it from the HA heartbeat addresses.
    pub local_address: Option<Ipv4Addr>,
    /// `peer_address`: the address of the other controller on the internal
    /// link.
    pub peer_address: Option<Ipv4Addr>,
    /// `port`: TCP port on the internal link.
    pub port: u16,
    /// `socket_dir`: directory of `smbd.sock`, mode 0700.
    pub socket_dir: PathBuf,
    /// `epoch_file`: path of the epoch file on the system dataset.
    pub epoch_file: PathBuf,
    /// `secret_file`: file with the pwenc secret. The daemon derives the link
    /// key from it.
    pub secret_file: PathBuf,
    /// `node`: this controller, `A` or `B`, as `failover.node` of the
    /// middleware reports it. Without it, the daemon stays idle.
    pub node: Option<Node>,
    /// `boot_id_file`: file with the kernel boot id.
    pub boot_id_file: PathBuf,
    /// `allowed_uid`: the only uid that the primary accepts on `smbd.sock`.
    pub allowed_uid: u32,
    /// `heartbeat_ms`: after this time, the primary answers a held poll with
    /// a heartbeat.
    pub heartbeat: Duration,
    /// `link_timeout_ms`: after this time without a message from the other
    /// controller, the daemon closes the connection.
    pub link_timeout: Duration,
    /// `max_lag_bytes`: maximum size of the operations that the standby has
    /// not acknowledged. Above it, the primary disconnects the standby.
    pub max_lag_bytes: usize,
    /// `snapshot_chunk_bytes`: maximum size of a snapshot chunk, a batch or
    /// a rehydration page.
    pub snapshot_chunk_bytes: usize,
    /// `pool_size`: maximum number of concurrent connections to the primary.
    pub pool_size: u32,
    /// `backlog`: `listen(2)` backlog of `smbd.sock` and of the TCP socket.
    pub backlog: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            role: RoleSetting::Auto,
            sysdataset_path: PathBuf::from("/var/db/system"),
            local_address: None,
            peer_address: None,
            port: 4390,
            socket_dir: PathBuf::from("/run/truenas_smbhad"),
            epoch_file: PathBuf::from("/var/db/system/samba4/smbhad.epoch"),
            secret_file: PathBuf::from("/data/pwenc_secret"),
            node: None,
            boot_id_file: PathBuf::from("/proc/sys/kernel/random/boot_id"),
            allowed_uid: 0,
            heartbeat: Duration::from_millis(100),
            link_timeout: Duration::from_millis(500),
            max_lag_bytes: 256 << 20,
            snapshot_chunk_bytes: 4 << 20,
            pool_size: 65536,
            backlog: 4096,
        }
    }
}

/// A configuration that the daemon cannot use.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads `path`. If the file does not exist, returns the defaults.
    ///
    /// # Errors
    ///
    /// The file exists but is not readable or not INI, or a value is invalid.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let mut cf = ConfigFile::new();
        match cf.read_path(path) {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => return Ok(Config::default()),
            Err(e) => {
                return Err(ConfigError(format!("{}: {e}", path.display())));
            }
        }
        Config::from_file(&cf)
            .map_err(|e| ConfigError(format!("{}: {}", path.display(), e.0)))
    }

    /// Parses `text` as `load` parses a file.
    ///
    /// # Errors
    ///
    /// The text is not INI, or a value is invalid.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let mut cf = ConfigFile::new();
        cf.read_str(text).map_err(|e| ConfigError(e.to_string()))?;
        Config::from_file(&cf)
    }

    fn from_file(cf: &ConfigFile) -> Result<Config, ConfigError> {
        let d = Config::default();
        let ms = |key| -> Result<Option<Duration>, ConfigError> {
            Ok(opt::<u64>(cf, key)?.map(Duration::from_millis))
        };
        let c = Config {
            role: opt(cf, "role")?.unwrap_or(d.role),
            sysdataset_path: opt(cf, "sysdataset_path")?
                .unwrap_or(d.sysdataset_path),
            local_address: opt(cf, "local_address")?.or(d.local_address),
            peer_address: opt(cf, "peer_address")?.or(d.peer_address),
            port: opt(cf, "port")?.unwrap_or(d.port),
            socket_dir: opt(cf, "socket_dir")?.unwrap_or(d.socket_dir),
            epoch_file: opt(cf, "epoch_file")?.unwrap_or(d.epoch_file),
            secret_file: opt(cf, "secret_file")?.unwrap_or(d.secret_file),
            node: opt(cf, "node")?.or(d.node),
            boot_id_file: opt(cf, "boot_id_file")?.unwrap_or(d.boot_id_file),
            allowed_uid: opt(cf, "allowed_uid")?.unwrap_or(d.allowed_uid),
            heartbeat: ms("heartbeat_ms")?.unwrap_or(d.heartbeat),
            link_timeout: ms("link_timeout_ms")?.unwrap_or(d.link_timeout),
            max_lag_bytes: opt(cf, "max_lag_bytes")?.unwrap_or(d.max_lag_bytes),
            snapshot_chunk_bytes: opt(cf, "snapshot_chunk_bytes")?
                .unwrap_or(d.snapshot_chunk_bytes),
            pool_size: opt(cf, "pool_size")?.unwrap_or(d.pool_size),
            backlog: opt(cf, "backlog")?.unwrap_or(d.backlog),
        };
        c.check()?;
        Ok(c)
    }

    fn check(&self) -> Result<(), ConfigError> {
        if self.heartbeat.is_zero() || self.link_timeout <= self.heartbeat {
            return Err(ConfigError(
                "link_timeout_ms must be above heartbeat_ms, both nonzero"
                    .to_owned(),
            ));
        }
        if self.snapshot_chunk_bytes < crate::proto::MAX_RECORD_BYTES + 1024
            || self.snapshot_chunk_bytes > crate::proto::MAX_FRAME / 2
        {
            return Err(ConfigError(format!(
                "snapshot_chunk_bytes must hold a record and stay under {}",
                crate::proto::MAX_FRAME / 2
            )));
        }
        Ok(())
    }

    /// Returns the path of the socket that smbd connects to.
    pub fn smbd_socket(&self) -> PathBuf {
        self.socket_dir.join("smbd.sock")
    }
}

/// Returns the value of `key`, or `None` if the file does not set it.
fn opt<T: FromStr>(
    cf: &ConfigFile,
    key: &str,
) -> Result<Option<T>, ConfigError> {
    let Some(v) = cf
        .get(SECTION, key)
        .map_err(|e| ConfigError(format!("{key}: {e}")))?
    else {
        return Ok(None);
    };
    v.trim()
        .parse()
        .map(Some)
        .map_err(|_| ConfigError(format!("{key}: {v:?} is not valid")))
}

fn is_not_found(e: &truenas_ros::Error) -> bool {
    matches!(e, truenas_ros::Error::Errno(truenas_ros::Errno::ENOENT))
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
    fn a_missing_file_is_the_defaults() {
        let dir = truenas_ros::tempdir().unwrap();
        let c = Config::load(&dir.path().join("absent.conf")).unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.node, None, "no node: the daemon stays idle");
    }

    #[test]
    fn overrides_are_read_from_the_smbhad_section() {
        let c = Config::parse(
            "[smbhad]\nrole = standby\nlocal_address = 127.0.0.2\n\
             peer_address = 127.0.0.1\nport = 7000\nheartbeat_ms = 20\n\
             link_timeout_ms = 200\nsocket_dir = /tmp/x\nnode = B\n",
        )
        .unwrap();
        assert_eq!(c.role, RoleSetting::Standby);
        assert_eq!(c.node, Some(Node::B));
        assert_eq!(c.local_address, Some(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(c.peer_address, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(c.port, 7000);
        assert_eq!(c.heartbeat, Duration::from_millis(20));
        assert_eq!(c.smbd_socket(), PathBuf::from("/tmp/x/smbd.sock"));
    }

    #[test]
    fn bad_values_are_refused() {
        assert!(Config::parse("[smbhad]\nrole = leader\n").is_err());
        assert!(Config::parse("[smbhad]\nnode = MANUAL\n").is_err());
        assert!(Config::parse("[smbhad]\nport = 99999\n").is_err());
        assert!(
            Config::parse(
                "[smbhad]\nheartbeat_ms = 500\nlink_timeout_ms = 100\n"
            )
            .is_err()
        );
    }
}
