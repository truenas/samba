// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The connection of an smbd process to the local daemon, on the unix
//! socket of the daemon. A message is the length of its body (4 bytes,
//! big-endian), then the body. smbd sends a `Request`, the daemon replies
//! with a `Reply`. The daemon does not reply to a submit with
//! `SyncLevel::None` or to a forget. Each call blocks. A read or a write of
//! a call that takes longer than the timeout fails.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use truenas_smbhad_proto::local::{
    Client as Role, Hello, HelloOk, Rehydrate, RehydratePage, Reply, Request,
    Submit, Synced,
};
use truenas_smbhad_proto::{MAX_FRAME, Op, Owner, Record, SyncLevel, VERSION};

/// Why a call failed. After an error, the connection is not usable.
#[derive(Debug)]
pub enum Error {
    /// The connect, a read or a write failed, or it took longer than the
    /// timeout.
    Io(io::Error),
    /// The daemon closed the connection.
    Closed,
    /// The daemon sent a message that is not a reply to the request.
    Protocol(String),
    /// The daemon refused the request: an errno value and the error text.
    Refused(i32, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Closed => write!(f, "the daemon closed the connection"),
            Error::Protocol(m) => write!(f, "{m}"),
            Error::Refused(_, m) => write!(f, "the daemon refused: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::Closed
        } else {
            Error::Io(e)
        }
    }
}

/// The operations of one or more submits.
#[derive(Debug, Default)]
pub struct Batch {
    ops: Vec<Op>,
    bytes: usize,
}

impl Batch {
    /// Adds a put of `record`. Returns the encoded size of the operation.
    pub fn put(&mut self, record: Record) -> usize {
        self.push(Op::Put(record))
    }

    /// Adds a delete of the record of `id`. Returns the encoded size of
    /// the operation.
    pub fn del(&mut self, id: u64) -> usize {
        self.push(Op::Del(id))
    }

    fn push(&mut self, op: Op) -> usize {
        let n = truenas_xdr::serialized_size(&op).unwrap_or(0);
        self.bytes += n;
        self.ops.push(op);
        n
    }

    /// The encoded size of the operations.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// The number of operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True if the batch has no operation.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub(crate) fn take(&mut self) -> Vec<Op> {
        self.bytes = 0;
        std::mem::take(&mut self.ops)
    }
}

/// A connection after a successful hello.
#[derive(Debug)]
pub struct Connection {
    stream: UnixStream,
    hello: HelloOk,
}

impl Connection {
    /// Connects to the daemon at `path` and sends the hello of `owner`.
    ///
    /// # Errors
    ///
    /// The connect or the hello failed.
    pub fn connect(
        path: &Path,
        role: Role,
        owner: Owner,
        timeout: Duration,
    ) -> Result<Connection, Error> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let req = Request::Hello(Hello {
            version: VERSION,
            role,
            owner,
        });
        match call(&mut stream, &req)? {
            Reply::HelloOk(hello) => Ok(Connection { stream, hello }),
            other => Err(unexpected("hello", &other)),
        }
    }

    /// The reply to the hello.
    pub fn hello(&self) -> &HelloOk {
        &self.hello
    }

    /// Sends the operations of `batch` and empties it. With
    /// `SyncLevel::None`, the daemon does not reply. Else the call waits
    /// for the reply.
    ///
    /// # Errors
    ///
    /// The send or the reply failed.
    pub fn submit(
        &mut self,
        batch: &mut Batch,
        sync: SyncLevel,
    ) -> Result<Option<Synced>, Error> {
        let req = Request::Submit(Submit {
            sync,
            ops: batch.take(),
        });
        if sync == SyncLevel::None {
            send(&mut self.stream, &req)?;
            return Ok(None);
        }
        match call(&mut self.stream, &req)? {
            Reply::Synced(s) => Ok(Some(s)),
            other => Err(unexpected("submit", &other)),
        }
    }

    /// Reports that the processes of `owner` exited uncleanly. The daemon
    /// does not reply.
    ///
    /// # Errors
    ///
    /// The send failed.
    pub fn forget(&mut self, owner: Owner) -> Result<(), Error> {
        send(&mut self.stream, &Request::ForgetOwner(owner))
    }

    /// Reads the page of the copy at `cursor`.
    ///
    /// # Errors
    ///
    /// The request or the reply failed.
    pub fn rehydrate(
        &mut self,
        cursor: u64,
        max_bytes: u32,
    ) -> Result<RehydratePage, Error> {
        let req = Request::Rehydrate(Rehydrate { cursor, max_bytes });
        match call(&mut self.stream, &req)? {
            Reply::RehydratePage(p) => Ok(p),
            other => Err(unexpected("rehydrate", &other)),
        }
    }

    /// Ends the rehydration. Returns the new generation.
    ///
    /// # Errors
    ///
    /// The request or the reply failed.
    pub fn done(&mut self) -> Result<u64, Error> {
        match call(&mut self.stream, &Request::Done)? {
            Reply::DoneOk(generation) => Ok(generation),
            other => Err(unexpected("done", &other)),
        }
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

fn unexpected(what: &str, reply: &Reply) -> Error {
    match reply {
        Reply::Error(f) => Error::Refused(f.code, f.message.clone()),
        _ => Error::Protocol(format!("the daemon sent {reply:?} to {what}")),
    }
}

fn send(stream: &mut UnixStream, req: &Request) -> Result<(), Error> {
    let frame = truenas_smbhad_proto::encode(req).ok_or_else(|| {
        Error::Protocol("a request without an encoding".to_owned())
    })?;
    stream.write_all(&frame)?;
    Ok(())
}

fn call(stream: &mut UnixStream, req: &Request) -> Result<Reply, Error> {
    send(stream, req)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(Error::Protocol(format!("a reply of {len} bytes")));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    truenas_xdr::from_bytes(&body).map_err(|e| Error::Protocol(e.to_string()))
}
