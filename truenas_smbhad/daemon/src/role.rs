// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The role to run and the addresses on the internal link.
//!
//! The role follows the rule of the ctdb HA reclock helper of middleware
//! (`ctdb_ha_reclock.py`). If the system dataset is on a data pool, this
//! controller is the active controller. If not, it is the standby
//! controller. With `auto`, the daemon checks the role once a second.
//!
//! The addresses follow `failover.local_ip` and `failover.remote_ip` of
//! middleware. Node A has 169.254.10.1 and node B has 169.254.10.2. The
//! local address is the HA heartbeat address that this controller can bind.
//! The peer address is the other one. Keys in the configuration file
//! override the role and the addresses.

use crate::config::{Config, RoleSetting};
use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;

/// Names of the boot pool (`BOOT_POOL_NAME_VALID` in middleware).
pub const BOOT_POOLS: [&str; 2] = ["boot-pool", "freenas-boot"];

/// The HA heartbeat addresses of node A and node B.
pub const HA_ADDRESSES: [Ipv4Addr; 2] = [
    Ipv4Addr::new(169, 254, 10, 1),
    Ipv4Addr::new(169, 254, 10, 2),
];

/// A role to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The active controller.
    Primary,
    /// The standby controller.
    Standby,
    /// The daemon does nothing.
    Idle,
}

/// Returns the role that the configuration sets. Detects it for `auto`. A
/// controller without an HA heartbeat address and without `local_address` is
/// not HA. Its role is `Idle`.
pub fn current(cfg: &Config) -> Role {
    match cfg.role {
        RoleSetting::Primary => Role::Primary,
        RoleSetting::Standby => Role::Standby,
        RoleSetting::None => Role::Idle,
        RoleSetting::Auto => auto(cfg.local_address, &cfg.sysdataset_path),
    }
}

/// Returns the role for `auto`. A controller without an HA heartbeat
/// address and without `local_address` is not HA: `Idle`. Otherwise the
/// system dataset decides.
pub fn auto(local_address: Option<Ipv4Addr>, sysdataset: &Path) -> Role {
    let ha = local_address.is_some()
        || HA_ADDRESSES
            .iter()
            .any(|ip| UdpSocket::bind((*ip, 0)).is_ok());
    if ha { detect(sysdataset) } else { Role::Idle }
}

/// Detects the role from the mount source of `sysdataset`.
pub fn detect(sysdataset: &Path) -> Role {
    match truenas_ros::mount::statmount_path(sysdataset) {
        Ok(sm) => match sm.sb_source.as_deref() {
            Some(source) => role_of_source(source),
            None => Role::Standby,
        },
        Err(_) => Role::Standby,
    }
}

/// Returns `Role::Primary` if `source` (`pool/dataset`) is on a data pool.
/// Returns `Role::Standby` if not.
pub fn role_of_source(source: &str) -> Role {
    let pool = source.split('/').next().unwrap_or_default();
    if pool.is_empty() || BOOT_POOLS.contains(&pool) {
        Role::Standby
    } else {
        Role::Primary
    }
}

/// Returns the local address and the peer address on the internal link.
///
/// # Errors
///
/// The configuration has no `local_address`, and this controller holds no
/// HA heartbeat address or both of them. Or `local_address` is not an HA
/// heartbeat address and the configuration has no `peer_address`.
pub fn addresses(cfg: &Config) -> Result<(Ipv4Addr, Ipv4Addr), String> {
    let local_ha = || {
        let mine: Vec<Ipv4Addr> = HA_ADDRESSES
            .iter()
            .copied()
            .filter(|ip| UdpSocket::bind((*ip, 0)).is_ok())
            .collect();
        match mine.as_slice() {
            [ip] => Ok(*ip),
            [] => Err("no HA heartbeat address on this controller".to_owned()),
            _ => {
                Err("both HA heartbeat addresses on this controller".to_owned())
            }
        }
    };
    let local = match cfg.local_address {
        Some(ip) => ip,
        None => local_ha()?,
    };
    let peer = match (cfg.peer_address, HA_ADDRESSES) {
        (Some(ip), _) => ip,
        (None, [a, b]) if local == a => b,
        (None, [a, b]) if local == b => a,
        (None, _) => {
            return Err(format!(
                "{local} is not an HA heartbeat address; set peer_address"
            ));
        }
    };
    Ok((local, peer))
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
    fn the_system_dataset_on_a_data_pool_is_the_active_controller() {
        assert_eq!(role_of_source("tank/.system"), Role::Primary);
        assert_eq!(role_of_source("boot-pool/.system"), Role::Standby);
        assert_eq!(role_of_source("freenas-boot/.system"), Role::Standby);
        assert_eq!(role_of_source(""), Role::Standby);
    }

    #[test]
    fn auto_without_an_ha_address_is_idle() {
        let lab = Config {
            local_address: Some(Ipv4Addr::LOCALHOST),
            sysdataset_path: "/nonexistent/system".into(),
            ..Config::default()
        };
        assert_eq!(current(&lab), Role::Standby, "no system dataset");
        if !HA_ADDRESSES
            .iter()
            .any(|ip| UdpSocket::bind((*ip, 0)).is_ok())
        {
            assert_eq!(current(&Config::default()), Role::Idle);
        }
    }

    #[test]
    fn configured_roles_and_addresses_win() {
        let cfg = Config {
            role: RoleSetting::Standby,
            local_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
            peer_address: Some(Ipv4Addr::new(10, 0, 0, 2)),
            ..Config::default()
        };
        assert_eq!(current(&cfg), Role::Standby);
        assert_eq!(
            addresses(&cfg).unwrap(),
            (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        );
        let a = Config {
            local_address: Some(HA_ADDRESSES[0]),
            ..Config::default()
        };
        assert_eq!(addresses(&a).unwrap(), (HA_ADDRESSES[0], HA_ADDRESSES[1]));
        let b = Config {
            local_address: Some(HA_ADDRESSES[1]),
            ..Config::default()
        };
        assert_eq!(addresses(&b).unwrap(), (HA_ADDRESSES[1], HA_ADDRESSES[0]));
        let other = Config {
            local_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..Config::default()
        };
        assert!(addresses(&other).is_err(), "no peer for a non-HA address");
    }
}
