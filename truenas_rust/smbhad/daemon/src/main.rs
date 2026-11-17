// truenas_smbhad: durable SMB handle state for TrueNAS HA.
//
// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The entry point of the daemon. The logic is in the library crate.
//!
//! `truenas_smbhad [--config PATH] mark-synced [--timeout-ms MS]` does not
//! start a daemon. It asks the running daemon to mark the copy as synced,
//! see `truenas_smbhad::control`, and prints the result. It exits with 0
//! only if the standby has the mark.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use truenas_ros::log::journal::Journal;
use truenas_ros::log::{Level, Logger};
use truenas_smbhad::proto::Protection;
use truenas_smbhad::{config, control, daemon};

fn main() -> ExitCode {
    // The journal under systemd, stderr otherwise. The daemon logs each
    // state change of the link and of protection once, nothing per request.
    let log =
        Logger::new(Arc::new(Journal::open("truenas_smbhad", Level::Notice)));
    let mut args = std::env::args().skip(1);
    let mut config_path = PathBuf::from(config::DEFAULT_PATH);
    let mut mark = false;
    let mut timeout = Duration::from_secs(5);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let Some(path) = args.next() else {
                    truenas_ros::log!(
                        log,
                        Level::Error,
                        "--config needs a path"
                    );
                    return ExitCode::from(2);
                };
                config_path = PathBuf::from(path);
            }
            "--version" => {
                println!("truenas_smbhad {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "mark-synced" => mark = true,
            "--timeout-ms" => {
                let Some(ms) = args.next().and_then(|v| v.parse().ok()) else {
                    eprintln!("--timeout-ms needs a number of milliseconds");
                    return ExitCode::from(2);
                };
                timeout = Duration::from_millis(ms);
            }
            other => {
                truenas_ros::log!(
                    log,
                    Level::Error,
                    "unknown argument {other}"
                );
                return ExitCode::from(2);
            }
        }
    }
    if mark {
        return mark_synced(&config_path, timeout);
    }
    match daemon::run(&config_path, &log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            truenas_ros::log!(log, Level::Error, "{e}");
            ExitCode::from(1)
        }
    }
}

fn mark_synced(config_path: &Path, timeout: Duration) -> ExitCode {
    let cfg = match config::Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mark-synced: {e}");
            return ExitCode::from(1);
        }
    };
    match control::mark_synced(&cfg.smbd_socket(), timeout) {
        Ok(s) if s.protection == Protection::Protected => {
            println!("marked: the standby has the mark (epoch {})", s.epoch);
            ExitCode::SUCCESS
        }
        Ok(s) => {
            println!(
                "not marked: the copy is {:?} (epoch {})",
                s.protection, s.epoch
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("mark-synced: {e}");
            ExitCode::from(1)
        }
    }
}
