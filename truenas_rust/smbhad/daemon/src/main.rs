// truenas_smbhad: durable SMB handle state for TrueNAS HA.
//
// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The entry point of the daemon. The logic is in the library crate.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use truenas_ros::log::journal::Journal;
use truenas_ros::log::{Level, Logger};
use truenas_smbhad::{config, daemon};

fn main() -> ExitCode {
    // The journal under systemd, stderr otherwise. The daemon logs each
    // state change of the link and of protection once, nothing per request.
    let log =
        Logger::new(Arc::new(Journal::open("truenas_smbhad", Level::Notice)));
    let mut args = std::env::args().skip(1);
    let mut config_path = PathBuf::from(config::DEFAULT_PATH);
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
    match daemon::run(&config_path, &log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            truenas_ros::log!(log, Level::Error, "{e}");
            ExitCode::from(1)
        }
    }
}
