// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! Readiness for systemd (`Type=notify`). The daemon sends `READY=1` once,
//! when its first role runs. A primary is ready when `smbd.sock` listens.
//! Only the socket of systemd or an abstract socket gets the message.

use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::atomic::{AtomicBool, Ordering};
use truenas_ros::log::{Level, Logger};

/// The socket of systemd for `Type=notify` services
const SYSTEMD_NOTIFY: &[u8] = b"/run/systemd/notify";

static READY: AtomicBool = AtomicBool::new(false);

/// Tells systemd that the daemon runs. Only the first call sends.
pub fn ready(log: &Logger) {
    if READY.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };
    let path = path.as_encoded_bytes();
    let sent = match path.strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)
            .and_then(|addr| sock.send_to_addr(b"READY=1", &addr)),
        None if path == SYSTEMD_NOTIFY => {
            sock.send_to(b"READY=1", OsStr::from_bytes(path))
        }
        None => {
            truenas_ros::log!(
                log,
                Level::Warning,
                "NOTIFY_SOCKET is not the socket of systemd: not notifying"
            );
            return;
        }
    };
    if let Err(e) = sent {
        truenas_ros::log!(log, Level::Warning, "notifying systemd: {e}");
    }
}
