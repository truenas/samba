// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The C interface. cbindgen makes `include/truenas_smbhad_client.h` from
//! this module. The header uses `struct GUID`, `struct dom_sid` and `struct
//! smb2_lease_key` of Samba. A C file includes the Samba headers first.
//!
//! The functions do not keep pointers from their arguments after they
//! return. A failed call returns an errno value or NULL, and sets the text
//! that `smbhad_last_error()` returns.

#![allow(unsafe_code)]

use crate::conn::{Batch, Connection, Error};
use crate::{cookie, record};
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;
use truenas_smbhad_proto::epoch::EpochFile;
use truenas_smbhad_proto::local::{Client as Role, Origin, RehydratePage};
use truenas_smbhad_proto::{MAX_RECORD_BYTES, Node, Owner, Record, SyncLevel};
use truenas_xdr::{Bounded, FixedOpaque, VarOpaque, VarOpaqueRef};

/// The kinds of smbd process: `role` of `smbhad_connect()`.
pub const TN_WORKER: u32 = 1;
/// The parent: rehydrate and done.
pub const TN_PARENT: u32 = 2;
/// cleanupd: forget.
pub const TN_CLEANUPD: u32 = 3;

/// No reply to the submit.
pub const TN_SYNC_NONE: u32 = 0;
/// The reply comes after the daemon applied the operations.
pub const TN_SYNC_LOCAL: u32 = 1;
/// The reply comes after the standby has the operations or the daemon
/// fenced the copy of the standby.
pub const TN_SYNC_REMOTE: u32 = 2;

/// No copy to restore.
pub const TN_ORIGIN_NONE: u32 = 0;
/// smbd on this controller wrote the copy.
pub const TN_ORIGIN_OWN: u32 = 1;
/// The other controller sent the copy.
pub const TN_ORIGIN_REPLICA: u32 = 2;

/// Node A of the HA pair.
pub const TN_NODE_A: u32 = 1;
/// Node B of the HA pair.
pub const TN_NODE_B: u32 = 2;

/// `smbhad_batch_put()` added the put.
pub const TN_PUT_OK: c_int = 0;
/// The record is larger than the daemon accepts. `smbhad_batch_put()` added
/// a delete instead: the standby does not restore the handle.
pub const TN_PUT_DELETED: c_int = 1;
/// The record has a value without an encoding. The batch did not change.
pub const TN_PUT_FAILED: c_int = 2;

/// `struct GUID` of Samba
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Guid {
    time_low: u32,
    time_mid: u16,
    time_hi_and_version: u16,
    clock_seq: [u8; 2],
    node: [u8; 6],
}

/// `struct dom_sid` of Samba
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DomSid {
    sid_rev_num: u8,
    num_auths: i8,
    id_auth: [u8; 6],
    sub_auths: [u32; 15],
}

/// `struct smb2_lease_key` of Samba
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LeaseKey {
    data: [u64; 2],
}

/// The record of a durable handle, see `record::RecordV1`.
#[repr(C)]
#[derive(Debug)]
pub struct DurableRecord {
    /// `TRUENAS_DURABLE_*`
    pub flags: u32,
    /// NTTIME
    pub updated: u64,
    /// The change cookie of the file as the client knows it
    pub change_cookie: u64,
    /// The path of the share
    pub servicepath: *const c_char,
    /// The path of the file in the share
    pub base_name: *const c_char,
    /// statfs `f_fsid` of the file
    pub fsid: u64,
    /// The inode of the file
    pub inode: u64,
    /// The generation of the inode
    pub extid: u64,
    /// The hash of the name
    pub name_hash: u32,
    /// The persistent id of the open
    pub persistent_id: u64,
    /// The volatile id of the open
    pub volatile_id: u64,
    /// The owner of the open
    pub owner: DomSid,
    /// NTTIME
    pub open_time: u64,
    /// The create GUID
    pub create_guid: Guid,
    /// The client GUID
    pub client_guid: Guid,
    /// The app instance id
    pub app_instance_id: Guid,
    /// The create action
    pub create_action: u32,
    /// NTTIME
    pub disconnect_time: u64,
    /// The durable timeout
    pub durable_timeout_msec: u32,
    /// The channel sequence
    pub channel_sequence: u16,
    /// The channel generation
    pub channel_generation: u64,
    /// The lock sequence array
    pub lock_sequence_array: [u8; 64],
    /// The values of the share mode entry
    pub op_type: u32,
    /// The lease key
    pub lease_key: LeaseKey,
    /// The access mask
    pub access_mask: u32,
    /// The share access
    pub share_access: u32,
    /// NTTIME
    pub share_time: u64,
    /// The uid
    pub uid: u32,
    /// The flags of the share mode entry
    pub share_flags: u32,
    /// The state of the lease
    pub lease_state: u32,
    /// The version of the lease
    pub lease_version: u16,
    /// The epoch of the lease
    pub lease_epoch: u16,
    /// The values of the `vfs_default` durable cookie
    pub initial_allocation_size: u64,
    /// See `initial_allocation_size`
    pub position_information: u64,
    /// See `initial_allocation_size`
    pub write_time_forced: bool,
    /// The number of locks
    pub num_locks: u32,
    /// The locks
    pub locks: *const record::Lock,
}

/// The reply to the hello.
#[repr(C)]
#[derive(Debug)]
pub struct Hello {
    /// A new value each time the daemon starts
    pub instance: u64,
    /// smbd fences through this file
    pub epoch_file: *const c_char,
    /// This controller: `TN_NODE_A` or `TN_NODE_B`
    pub node: u32,
}

/// A record in a page of the copy.
#[repr(C)]
#[derive(Debug)]
pub struct Put {
    /// The share
    pub share: *const c_char,
    /// The encoded record, see `smbhad_record_decode()`
    pub body: *const u8,
    /// The length of `body`
    pub body_len: usize,
}

/// A page of the copy.
#[repr(C)]
#[derive(Debug)]
pub struct Page {
    /// `TN_ORIGIN_*`
    pub origin: u32,
    /// The node that wrote the copy: `TN_NODE_A` or `TN_NODE_B`
    pub writer_node: u32,
    /// The cursor of the next page
    pub next_cursor: u64,
    /// This is the last page
    pub last: bool,
    /// The number of records
    pub num_records: usize,
    /// The records, in id order
    pub records: *const Put,
}

/// The durable cookie of `vfs_zfs_core`. The share and the inner cookie are
/// not NUL-terminated.
#[repr(C)]
#[derive(Debug)]
pub struct Cookie {
    /// `TRUENAS_ZFS_DURABLE_*`
    pub flags: u32,
    /// The change cookie of the file
    pub change_cookie: u64,
    /// The share
    pub share: *const u8,
    /// The length of `share`
    pub share_len: usize,
    /// The `vfs_default` cookie
    pub inner: *const u8,
    /// The length of `inner`
    pub inner_len: usize,
}

/// A connection to the daemon.
#[derive(Debug)]
pub struct Conn {
    link: Connection,
    hello: Hello,
    _epoch_file: CString,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(text: &str) {
    let text = CString::new(text.replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = text);
}

/// The errno value of `e`. Sets the error text.
fn errno(e: &Error) -> c_int {
    set_error(&e.to_string());
    match e {
        Error::Io(e) => match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                libc::ETIMEDOUT
            }
            _ => e.raw_os_error().unwrap_or(libc::EIO),
        },
        Error::Closed => libc::ECONNRESET,
        Error::Refused(code, _) if *code > 0 => *code,
        Error::Protocol(_) | Error::Refused(..) => libc::EPROTO,
    }
}

/// Runs `f`. A panic in `f` returns `fallback`: no unwind crosses into C.
fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(
        |_| {
            set_error("truenas_smbhad_client: internal error");
            fallback
        },
    )
}

fn role_of(role: u32) -> Option<Role> {
    match role {
        TN_WORKER => Some(Role::Worker),
        TN_PARENT => Some(Role::Parent),
        TN_CLEANUPD => Some(Role::Cleanupd),
        _ => None,
    }
}

fn node_value(n: Node) -> u32 {
    match n {
        Node::A => TN_NODE_A,
        Node::B => TN_NODE_B,
    }
}

/// The GUID in RFC 4122 byte order
fn guid_bytes(g: &Guid) -> FixedOpaque<16> {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&g.time_low.to_be_bytes());
    b[4..6].copy_from_slice(&g.time_mid.to_be_bytes());
    b[6..8].copy_from_slice(&g.time_hi_and_version.to_be_bytes());
    b[8..10].copy_from_slice(&g.clock_seq);
    b[10..16].copy_from_slice(&g.node);
    FixedOpaque(b)
}

fn guid_of(b: &FixedOpaque<16>) -> Guid {
    let b = &b.0;
    Guid {
        time_low: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        time_mid: u16::from_be_bytes([b[4], b[5]]),
        time_hi_and_version: u16::from_be_bytes([b[6], b[7]]),
        clock_seq: [b[8], b[9]],
        node: [b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

fn sid_of(s: &DomSid) -> Option<record::Sid> {
    let n = usize::try_from(s.num_auths).ok().filter(|n| *n <= 15)?;
    let authority =
        s.id_auth.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
    Some(record::Sid {
        revision: s.sid_rev_num,
        authority,
        sub_auths: Bounded(s.sub_auths[..n].to_vec()),
    })
}

fn dom_sid_of(s: &record::Sid) -> DomSid {
    let mut d = DomSid {
        sid_rev_num: s.revision,
        // At most 15: `Bounded` refuses more.
        num_auths: i8::try_from(s.sub_auths.0.len()).unwrap_or(0),
        ..DomSid::default()
    };
    d.id_auth.copy_from_slice(&s.authority.to_be_bytes()[2..]);
    d.sub_auths[..s.sub_auths.0.len()].copy_from_slice(&s.sub_auths.0);
    d
}

/// The bytes of a C string, or `None` for NULL.
///
/// # Safety
///
/// `p` is NULL or a NUL-terminated string.
unsafe fn bytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller guarantees a NUL-terminated string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// `r` in the XDR form.
///
/// # Safety
///
/// The pointers of `r` are valid, see `smbhad_batch_put()`.
unsafe fn record_of(r: &DurableRecord) -> Option<record::RecordV1> {
    // SAFETY: the caller guarantees valid strings.
    let (servicepath, base_name) =
        unsafe { (bytes(r.servicepath)?, bytes(r.base_name)?) };
    let locks = if r.num_locks == 0 {
        &[][..]
    } else if r.locks.is_null() {
        return None;
    } else {
        // SAFETY: the caller guarantees `num_locks` locks at `locks`.
        unsafe { std::slice::from_raw_parts(r.locks, r.num_locks as usize) }
    };
    Some(record::RecordV1 {
        flags: r.flags,
        updated: r.updated,
        change_cookie: r.change_cookie,
        servicepath: VarOpaque(servicepath.to_vec()),
        base_name: VarOpaque(base_name.to_vec()),
        fsid: r.fsid,
        inode: r.inode,
        extid: r.extid,
        name_hash: r.name_hash,
        persistent_id: r.persistent_id,
        volatile_id: r.volatile_id,
        owner: sid_of(&r.owner)?,
        open_time: r.open_time,
        create_guid: guid_bytes(&r.create_guid),
        client_guid: guid_bytes(&r.client_guid),
        app_instance_id: guid_bytes(&r.app_instance_id),
        // Samba 4.24 has no app instance version.
        app_instance_vhigh: 0,
        app_instance_vlow: 0,
        create_action: r.create_action,
        disconnect_time: r.disconnect_time,
        durable_timeout_msec: r.durable_timeout_msec,
        channel_sequence: r.channel_sequence,
        channel_generation: r.channel_generation,
        lock_sequence_array: FixedOpaque(r.lock_sequence_array),
        op_type: r.op_type,
        lease_key: r.lease_key.data,
        access_mask: r.access_mask,
        share_access: r.share_access,
        share_time: r.share_time,
        uid: r.uid,
        share_flags: r.share_flags,
        lease_state: r.lease_state,
        lease_version: r.lease_version,
        lease_epoch: r.lease_epoch,
        initial_allocation_size: r.initial_allocation_size,
        position_information: r.position_information,
        write_time_forced: r.write_time_forced,
        locks: locks.to_vec(),
        exts: Vec::new(),
    })
}

/// A decoded record and the data that its pointers point to. `c` is the
/// first field: a pointer to `c` is a pointer to the `OwnedRecord`.
#[repr(C)]
struct OwnedRecord {
    c: DurableRecord,
    servicepath: CString,
    base_name: CString,
    locks: Vec<record::Lock>,
}

fn owned_record(r: &record::RecordV1) -> Option<Box<OwnedRecord>> {
    let servicepath = CString::new(r.servicepath.0.clone()).ok()?;
    let base_name = CString::new(r.base_name.0.clone()).ok()?;
    let locks = r.locks.clone();
    let c = DurableRecord {
        flags: r.flags,
        updated: r.updated,
        change_cookie: r.change_cookie,
        servicepath: servicepath.as_ptr(),
        base_name: base_name.as_ptr(),
        fsid: r.fsid,
        inode: r.inode,
        extid: r.extid,
        name_hash: r.name_hash,
        persistent_id: r.persistent_id,
        volatile_id: r.volatile_id,
        owner: dom_sid_of(&r.owner),
        open_time: r.open_time,
        create_guid: guid_of(&r.create_guid),
        client_guid: guid_of(&r.client_guid),
        app_instance_id: guid_of(&r.app_instance_id),
        create_action: r.create_action,
        disconnect_time: r.disconnect_time,
        durable_timeout_msec: r.durable_timeout_msec,
        channel_sequence: r.channel_sequence,
        channel_generation: r.channel_generation,
        lock_sequence_array: r.lock_sequence_array.0,
        op_type: r.op_type,
        lease_key: LeaseKey { data: r.lease_key },
        access_mask: r.access_mask,
        share_access: r.share_access,
        share_time: r.share_time,
        uid: r.uid,
        share_flags: r.share_flags,
        lease_state: r.lease_state,
        lease_version: r.lease_version,
        lease_epoch: r.lease_epoch,
        initial_allocation_size: r.initial_allocation_size,
        position_information: r.position_information,
        write_time_forced: r.write_time_forced,
        num_locks: u32::try_from(locks.len()).ok()?,
        locks: locks.as_ptr(),
    };
    Some(Box::new(OwnedRecord {
        c,
        servicepath,
        base_name,
        locks,
    }))
}

/// Connects to the daemon at `path` as root and sends the hello of the
/// process `pid` with `unique_id`. A read or write that takes longer than
/// `timeout_ms` fails, also in later calls.
///
/// # Safety
///
/// `path` is a NUL-terminated string. `out` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_connect(
    path: *const c_char,
    role: u32,
    pid: u32,
    unique_id: u64,
    timeout_ms: u32,
    out: *mut *mut Conn,
) -> c_int {
    guard(libc::EIO, || {
        // SAFETY: the caller guarantees a NUL-terminated string.
        let Some(path) = (unsafe { bytes(path) }) else {
            return libc::EINVAL;
        };
        let (Some(role), false) = (role_of(role), out.is_null()) else {
            return libc::EINVAL;
        };
        let path = Path::new(std::ffi::OsStr::from_bytes(path));
        let owner = Owner { pid, unique_id };
        let timeout = Duration::from_millis(u64::from(timeout_ms.max(1)));
        let conn = match Connection::connect(path, role, owner, timeout) {
            Ok(c) => c,
            Err(e) => return errno(&e),
        };
        let h = conn.hello();
        let epoch_file =
            CString::new(h.epoch_file.replace('\0', "")).unwrap_or_default();
        let hello = Hello {
            instance: h.instance,
            epoch_file: epoch_file.as_ptr(),
            node: node_value(h.node),
        };
        let c = Box::new(Conn {
            link: conn,
            hello,
            _epoch_file: epoch_file,
        });
        // SAFETY: the caller guarantees that `out` is valid for a write.
        unsafe { *out = Box::into_raw(c) };
        0
    })
}

/// The reply to the hello. It lives as long as `c`.
///
/// # Safety
///
/// `c` is a connection of `smbhad_connect()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_conn_hello(c: *const Conn) -> *const Hello {
    // SAFETY: the caller guarantees a valid connection.
    unsafe { &raw const (*c).hello }
}

/// The socket of `c`. The daemon sends nothing unasked: a readable socket
/// between two calls is closed.
///
/// # Safety
///
/// `c` is a connection of `smbhad_connect()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_conn_fd(c: *const Conn) -> c_int {
    // SAFETY: the caller guarantees a valid connection.
    unsafe { (*c).link.as_raw_fd() }
}

/// Closes the socket of `c` and frees `c`. A child process frees the
/// connection of its parent: the connection of the parent stays open.
///
/// # Safety
///
/// `c` is NULL or a connection of `smbhad_connect()`. `c` is not used
/// after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_conn_free(c: *mut Conn) {
    if !c.is_null() {
        // SAFETY: the caller guarantees a connection of
        // `smbhad_connect()`, which made it with `Box::into_raw()`.
        drop(unsafe { Box::from_raw(c) });
    }
}

/// The text of the last error of this thread.
#[unsafe(no_mangle)]
pub extern "C" fn smbhad_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// A new empty batch.
#[unsafe(no_mangle)]
pub extern "C" fn smbhad_batch_new() -> *mut Batch {
    Box::into_raw(Box::default())
}

/// Frees `b`.
///
/// # Safety
///
/// `b` is NULL or a batch of `smbhad_batch_new()`, not used after the
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_batch_free(b: *mut Batch) {
    if !b.is_null() {
        // SAFETY: `smbhad_batch_new()` made `b` with `Box::into_raw()`.
        drop(unsafe { Box::from_raw(b) });
    }
}

/// Adds the put of `r` to `b`. `pid` and `unique_id` are the process that
/// holds the handle: 0 and 0 for a disconnected handle. Returns `TN_PUT_OK`,
/// `TN_PUT_DELETED` or `TN_PUT_FAILED`.
///
/// # Safety
///
/// `b` is a batch, `share` a NUL-terminated string, and `r` a record whose
/// strings are NUL-terminated and whose `locks` has `num_locks` locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_batch_put(
    b: *mut Batch,
    share: *const c_char,
    pid: u32,
    unique_id: u64,
    r: *const DurableRecord,
) -> c_int {
    guard(TN_PUT_FAILED, || {
        // SAFETY: the caller guarantees valid pointers.
        let (b, share, r) = unsafe { (&mut *b, bytes(share), &*r) };
        // SAFETY: the caller guarantees the pointers of `r`.
        let Some(rec) = (unsafe { record_of(r) }) else {
            set_error("the record has a value out of range");
            return TN_PUT_FAILED;
        };
        let (Ok(body), Some(Ok(share))) =
            (record::encode(&rec), share.map(std::str::from_utf8))
        else {
            set_error("the record has no encoding");
            return TN_PUT_FAILED;
        };
        if body.len() > MAX_RECORD_BYTES {
            b.del(r.persistent_id);
            return TN_PUT_DELETED;
        }
        b.put(Record {
            id: r.persistent_id,
            share: share.to_owned(),
            owner: Owner { pid, unique_id },
            flags: r.flags,
            body: VarOpaque(body),
        });
        TN_PUT_OK
    })
}

/// Adds a delete of the record of `id` to `b`.
///
/// # Safety
///
/// `b` is a batch of `smbhad_batch_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_batch_del(b: *mut Batch, id: u64) {
    // SAFETY: the caller guarantees a valid batch.
    unsafe { (*b).del(id) };
}

/// The encoded size of the operations of `b`.
///
/// # Safety
///
/// `b` is a batch of `smbhad_batch_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_batch_bytes(b: *const Batch) -> usize {
    // SAFETY: the caller guarantees a valid batch.
    unsafe { (*b).bytes() }
}

/// The number of operations of `b`.
///
/// # Safety
///
/// `b` is a batch of `smbhad_batch_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_batch_len(b: *const Batch) -> usize {
    // SAFETY: the caller guarantees a valid batch.
    unsafe { (*b).len() }
}

/// Sends the operations of `b` and empties `b`. `sync` is `TN_SYNC_*`.
/// With `TN_SYNC_NONE`, the daemon does not reply. Else the call waits for
/// the reply.
///
/// # Safety
///
/// `c` is a connection and `b` a batch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_submit(
    c: *mut Conn,
    b: *mut Batch,
    sync: u32,
) -> c_int {
    guard(libc::EIO, || {
        let sync = match sync {
            TN_SYNC_NONE => SyncLevel::None,
            TN_SYNC_LOCAL => SyncLevel::Local,
            TN_SYNC_REMOTE => SyncLevel::Remote,
            _ => return libc::EINVAL,
        };
        // SAFETY: the caller guarantees valid pointers.
        let (c, b) = unsafe { (&mut *c, &mut *b) };
        match c.link.submit(b, sync) {
            Ok(_) => 0,
            Err(e) => errno(&e),
        }
    })
}

/// Reports that the process `pid` exited uncleanly. The daemon keeps the
/// handles of a live process with this pid.
///
/// # Safety
///
/// `c` is a connection of `smbhad_connect()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_forget(c: *mut Conn, pid: u32) -> c_int {
    guard(libc::EIO, || {
        // SAFETY: the caller guarantees a valid connection.
        let c = unsafe { &mut *c };
        match c.link.forget(Owner { pid, unique_id: 0 }) {
            Ok(()) => 0,
            Err(e) => errno(&e),
        }
    })
}

/// A page and the data that its pointers point to.
#[repr(C)]
struct OwnedPage {
    c: Page,
    puts: Vec<Put>,
    shares: Vec<CString>,
    page: RehydratePage,
}

/// Reads the page of the copy at `cursor`, 0 for the first page. Free the
/// page with `smbhad_page_free()`.
///
/// # Safety
///
/// `c` is a connection, `out` valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_rehydrate(
    c: *mut Conn,
    cursor: u64,
    max_bytes: u32,
    out: *mut *mut Page,
) -> c_int {
    guard(libc::EIO, || {
        // SAFETY: the caller guarantees a valid connection.
        let c = unsafe { &mut *c };
        let page = match c.link.rehydrate(cursor, max_bytes) {
            Ok(p) => p,
            Err(e) => return errno(&e),
        };
        let Ok(shares) = page
            .records
            .iter()
            .map(|r| CString::new(r.share.clone()))
            .collect::<Result<Vec<CString>, _>>()
        else {
            set_error("a share name with a NUL byte");
            return libc::EPROTO;
        };
        let puts: Vec<Put> = page
            .records
            .iter()
            .zip(&shares)
            .map(|(r, s)| Put {
                share: s.as_ptr(),
                body: r.body.0.as_ptr(),
                body_len: r.body.0.len(),
            })
            .collect();
        let p = Box::new(OwnedPage {
            c: Page {
                origin: match page.origin {
                    Origin::None => TN_ORIGIN_NONE,
                    Origin::Own => TN_ORIGIN_OWN,
                    Origin::Replica => TN_ORIGIN_REPLICA,
                },
                writer_node: node_value(page.writer_node),
                next_cursor: page.next_cursor,
                last: page.last,
                num_records: puts.len(),
                records: puts.as_ptr(),
            },
            puts,
            shares,
            page,
        });
        // SAFETY: the caller guarantees that `out` is valid for a write.
        unsafe { *out = Box::into_raw(p).cast::<Page>() };
        0
    })
}

/// Frees a page of `smbhad_rehydrate()`.
///
/// # Safety
///
/// `p` is NULL or a page of `smbhad_rehydrate()`, not used after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_page_free(p: *mut Page) {
    if !p.is_null() {
        // SAFETY: `smbhad_rehydrate()` made `p` from a `Box<OwnedPage>`;
        // `c` is its first field.
        drop(unsafe { Box::from_raw(p.cast::<OwnedPage>()) });
    }
}

/// Ends the rehydration.
///
/// # Safety
///
/// `c` is a connection of `smbhad_connect()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_done(c: *mut Conn) -> c_int {
    guard(libc::EIO, || {
        // SAFETY: the caller guarantees a valid connection.
        let c = unsafe { &mut *c };
        match c.link.done() {
            Ok(_) => 0,
            Err(e) => errno(&e),
        }
    })
}

/// Decodes a record. NULL if `buf` is not a record that this version can
/// restore. Free the record with `smbhad_record_free()`.
///
/// # Safety
///
/// `buf` has `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_record_decode(
    buf: *const u8,
    len: usize,
) -> *mut DurableRecord {
    guard(std::ptr::null_mut(), || {
        if buf.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller guarantees `len` bytes at `buf`.
        let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
        let Some(r) = record::decode(bytes).as_ref().and_then(owned_record)
        else {
            set_error("not a record that this version can restore");
            return std::ptr::null_mut();
        };
        Box::into_raw(r).cast::<DurableRecord>()
    })
}

/// Frees a record of `smbhad_record_decode()`.
///
/// # Safety
///
/// `r` is NULL or a record of `smbhad_record_decode()`, not used after the
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_record_free(r: *mut DurableRecord) {
    if !r.is_null() {
        // SAFETY: `smbhad_record_decode()` made `r` from a
        // `Box<OwnedRecord>`; `c` is its first field.
        drop(unsafe { Box::from_raw(r.cast::<OwnedRecord>()) });
    }
}

/// Encodes `c` into `buf` if `len` is large enough. Returns the length of
/// the encoded cookie, or 0 if `c` has no encoding.
///
/// # Safety
///
/// The pointers of `c` have their lengths. `buf` is NULL or has `len`
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_cookie_encode(
    c: *const Cookie,
    buf: *mut u8,
    len: usize,
) -> usize {
    guard(0, || {
        // SAFETY: the caller guarantees a valid cookie.
        let c = unsafe { &*c };
        let (Some(share), Some(inner)) = (
            // SAFETY: the caller guarantees the lengths of the pointers.
            unsafe { slice(c.share, c.share_len) },
            // SAFETY: as above.
            unsafe { slice(c.inner, c.inner_len) },
        ) else {
            return 0;
        };
        let Ok(bytes) = cookie::encode(&cookie::CookieV1 {
            flags: c.flags,
            change_cookie: c.change_cookie,
            share: VarOpaqueRef(share),
            inner: VarOpaqueRef(inner),
        }) else {
            return 0;
        };
        if !buf.is_null() && len >= bytes.len() {
            // SAFETY: the caller guarantees `len` bytes at `buf`.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
            }
        }
        bytes.len()
    })
}

/// Decodes the cookie in `buf` into `out`. The share and the inner cookie
/// of `out` point into `buf`. False if `buf` is not a cookie of
/// `vfs_zfs_core` of this version.
///
/// # Safety
///
/// `buf` has `len` bytes. `out` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_cookie_decode(
    buf: *const u8,
    len: usize,
    out: *mut Cookie,
) -> bool {
    guard(false, || {
        // SAFETY: the caller guarantees `len` bytes at `buf`.
        let Some(bytes) = (unsafe { slice(buf, len) }) else {
            return false;
        };
        let Some(c) = cookie::decode(bytes) else {
            return false;
        };
        // SAFETY: the caller guarantees that `out` is valid for a write.
        unsafe {
            *out = Cookie {
                flags: c.flags,
                change_cookie: c.change_cookie,
                share: c.share.0.as_ptr(),
                share_len: c.share.0.len(),
                inner: c.inner.0.as_ptr(),
                inner_len: c.inner.0.len(),
            };
        }
        true
    })
}

/// `len` bytes at `p`. An empty slice for a NULL `p` of length 0.
///
/// # Safety
///
/// `p` has `len` bytes.
unsafe fn slice<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return (len == 0).then_some(&[][..]);
    }
    // SAFETY: the caller guarantees `len` bytes at `p`.
    Some(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The fence of smbd when it cannot reach the daemon, see
/// `EpochFile::fence()`. `fenced_to` is the epoch of the last fence of the
/// process, or 0. Writes the epoch that the fence wrote, or 0, to `next`.
///
/// # Safety
///
/// `path` is a NUL-terminated string. `next` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smbhad_epoch_fence(
    path: *const c_char,
    fenced_to: u64,
    next: *mut u64,
) -> c_int {
    guard(libc::EIO, || {
        // SAFETY: the caller guarantees a NUL-terminated string.
        let Some(path) = (unsafe { bytes(path) }) else {
            return libc::EINVAL;
        };
        let file = EpochFile::new(Path::new(std::ffi::OsStr::from_bytes(path)));
        match file.fence(fenced_to) {
            Ok(epoch) => {
                // SAFETY: the caller guarantees that `next` is valid.
                unsafe { *next = epoch.unwrap_or(0) };
                0
            }
            Err(e) => {
                set_error(&e.to_string());
                libc::EIO
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::{PINNED, sample, unhex};

    /// The C form of `sample()`, as smbd fills it
    fn c_sample(
        servicepath: &CStr,
        base_name: &CStr,
        locks: &[record::Lock],
    ) -> DurableRecord {
        let r = owned_record(&sample()).unwrap();
        DurableRecord {
            servicepath: servicepath.as_ptr(),
            base_name: base_name.as_ptr(),
            locks: locks.as_ptr(),
            ..r.c
        }
    }

    #[test]
    fn a_put_of_the_c_record_has_the_bytes_of_the_record() {
        let locks = [record::Lock {
            start: 4096,
            size: 512,
            lock_type: 1,
            lock_flav: 0,
        }];
        let r = c_sample(c"/mnt/tank/share", c"dir/file.txt", &locks);
        let b = smbhad_batch_new();
        // SAFETY: valid pointers.
        let put = unsafe {
            smbhad_batch_put(b, c"data".as_ptr(), 1, 2, &raw const r)
        };
        assert_eq!(put, TN_PUT_OK);
        // SAFETY: `b` is a batch.
        let mut batch = unsafe { Box::from_raw(b) };
        let ops = batch.take();
        let truenas_smbhad_proto::Op::Put(rec) = &ops[0] else {
            panic!("{ops:?}");
        };
        assert_eq!(
            (rec.id, rec.flags),
            (0x31, record::TRUENAS_DURABLE_DISCONNECTED)
        );
        // Samba 4.24 has no app instance version: the C record has none.
        let want = record::RecordV1 {
            app_instance_vhigh: 0,
            app_instance_vlow: 0,
            ..sample()
        };
        assert_eq!(rec.body.0, record::encode(&want).unwrap());
    }

    #[test]
    fn a_decoded_record_has_the_values_of_the_c_record() {
        let pinned = unhex(PINNED);
        // SAFETY: `pinned` has its length.
        let r = unsafe { smbhad_record_decode(pinned.as_ptr(), pinned.len()) };
        assert!(!r.is_null());
        // SAFETY: a record of `smbhad_record_decode()`.
        let c = unsafe { &*r };
        // SAFETY: NUL-terminated strings of the record.
        unsafe {
            assert_eq!(CStr::from_ptr(c.base_name), c"dir/file.txt");
        }
        assert_eq!(c.owner.num_auths, 5);
        assert_eq!(c.owner.id_auth, [0, 0, 0, 0, 0, 5]);
        assert_eq!(c.owner.sub_auths[4], 1000);
        assert_eq!(c.create_guid.time_low, 0x0123_4567);
        assert_eq!(c.create_guid.time_mid, 0x89ab);
        assert_eq!(c.create_guid.node, [0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(c.num_locks, 1);
        // SAFETY: the record has one lock.
        assert_eq!(unsafe { (*c.locks).start }, 4096);
        // SAFETY: a record of `smbhad_record_decode()`.
        unsafe { smbhad_record_free(r) };
        // SAFETY: a short buffer.
        assert!(unsafe { smbhad_record_decode(pinned.as_ptr(), 8) }.is_null());
    }

    #[test]
    fn the_layout_is_the_layout_of_the_c_header() {
        // gcc's values for include/truenas_smbhad_client.h on x86_64
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        assert_eq!(std::mem::size_of::<DomSid>(), 68);
        assert_eq!(std::mem::size_of::<DurableRecord>(), 400);
        assert_eq!(std::mem::offset_of!(DurableRecord, owner), 88);
        assert_eq!(
            std::mem::offset_of!(DurableRecord, lock_sequence_array),
            248
        );
        assert_eq!(std::mem::offset_of!(DurableRecord, locks), 392);
    }

    #[test]
    fn a_large_record_becomes_a_delete() {
        let locks: Vec<record::Lock> = (0..3000)
            .map(|i| record::Lock {
                start: i,
                size: 1,
                lock_type: 1,
                lock_flav: 0,
            })
            .collect();
        let mut r = c_sample(c"/s", c"f", &locks);
        r.num_locks = 3000;
        let b = smbhad_batch_new();
        // SAFETY: valid pointers.
        let put = unsafe {
            smbhad_batch_put(b, c"data".as_ptr(), 1, 2, &raw const r)
        };
        assert_eq!(put, TN_PUT_DELETED);
        // SAFETY: `b` is a batch.
        unsafe {
            assert_eq!(smbhad_batch_len(b), 1);
            smbhad_batch_free(b);
        }
    }

    #[test]
    fn a_cookie_decodes_into_views_of_its_bytes() {
        let c = Cookie {
            flags: crate::cookie::TRUENAS_ZFS_DURABLE_DIRTY,
            change_cookie: 7,
            share: b"share".as_ptr(),
            share_len: 5,
            inner: b"VFS".as_ptr(),
            inner_len: 3,
        };
        // SAFETY: valid pointers.
        let n = unsafe {
            smbhad_cookie_encode(&raw const c, std::ptr::null_mut(), 0)
        };
        let mut buf = vec![0u8; n];
        // SAFETY: `buf` has `n` bytes.
        assert_eq!(
            unsafe { smbhad_cookie_encode(&raw const c, buf.as_mut_ptr(), n) },
            n
        );
        let mut back = Cookie {
            flags: 0,
            change_cookie: 0,
            share: std::ptr::null(),
            share_len: 0,
            inner: std::ptr::null(),
            inner_len: 0,
        };
        // SAFETY: valid pointers.
        assert!(unsafe {
            smbhad_cookie_decode(buf.as_ptr(), n, &raw mut back)
        });
        assert_eq!((back.flags, back.change_cookie), (c.flags, 7));
        // SAFETY: `back` points into `buf`.
        let share = unsafe { slice(back.share, back.share_len) };
        assert_eq!(share, Some(&b"share"[..]));
    }
}
