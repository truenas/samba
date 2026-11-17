// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! `truenas_smbhad mark-synced`, the control client. Middleware runs it
//! before a planned failover, see `local::Request::MarkSynced`.

use crate::proto::local::{Client, Hello, Reply, Request, Synced};
use crate::proto::{MAX_FRAME, Owner, VERSION, encode};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Sends `MarkSynced` to the daemon on `socket` and returns its reply. Each
/// read and write waits at most `timeout`.
///
/// # Errors
///
/// The daemon is not reachable, refused the request, did not reply in
/// time, or broke the protocol.
pub fn mark_synced(socket: &Path, timeout: Duration) -> Result<Synced, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| e.to_string())?;
    let hello = Request::Hello(Hello {
        version: VERSION,
        role: Client::Control,
        owner: Owner {
            pid: std::process::id(),
            unique_id: 0,
        },
    });
    match call(&mut stream, &hello)? {
        Reply::HelloOk(_) => {}
        other => return Err(unexpected(&other)),
    }
    match call(&mut stream, &Request::MarkSynced)? {
        Reply::Synced(s) => Ok(s),
        other => Err(unexpected(&other)),
    }
}

fn unexpected(reply: &Reply) -> String {
    match reply {
        Reply::Error(f) => format!("the daemon refused: {}", f.message),
        _ => format!("the daemon sent {reply:?}"),
    }
}

fn call(stream: &mut UnixStream, req: &Request) -> Result<Reply, String> {
    let frame = encode(req).ok_or("a request without an encoding")?;
    stream.write_all(&frame).map_err(|e| e.to_string())?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(format!("a reply of {len} bytes"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).map_err(|e| e.to_string())?;
    truenas_xdr::from_bytes(&body).map_err(|e| e.to_string())
}
