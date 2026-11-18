// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fields of SMB2 messages that this crate reads or sets.

use truenas_smbros::NBT_HDR_SIZE;

pub(crate) const SMB2_HDR_MAGIC: [u8; 4] = [0xfe, b'S', b'M', b'B'];
pub(crate) const SMB2_HDR_SIZE: usize = 64;
pub(crate) const SMB2_HDR_LENGTH: usize = 4;
pub(crate) const SMB2_HDR_STATUS: usize = 8;
pub(crate) const SMB2_HDR_OPCODE: usize = 12;
pub(crate) const SMB2_HDR_CREDIT: usize = 14;
pub(crate) const SMB2_HDR_FLAGS: usize = 16;
pub(crate) const SMB2_HDR_NEXT_COMMAND: usize = 20;
pub(crate) const SMB2_HDR_MESSAGE_ID: usize = 24;
/// The `AsyncId` of an async header. It takes the place of the process and
/// tree IDs.
pub(crate) const SMB2_HDR_ASYNC_ID: usize = 32;
pub(crate) const SMB2_HDR_SESSION_ID: usize = 40;
pub(crate) const SMB2_HDR_SIGNATURE: usize = 48;
pub(crate) const SMB2_HDR_FLAG_ASYNC: u32 = 0x02;
pub(crate) const SMB2_HDR_FLAG_CHAINED: u32 = 0x04;
pub(crate) const SMB2_HDR_FLAG_SIGNED: u32 = 0x08;
pub(crate) const SMB2_OP_NEGPROT: u16 = 0x00;
pub(crate) const SMB2_OP_SESSSETUP: u16 = 0x01;
pub(crate) const SMB2_OP_FLUSH: u16 = 0x07;
pub(crate) const SMB2_OP_READ: u16 = 0x08;
pub(crate) const SMB2_OP_WRITE: u16 = 0x09;
pub(crate) const SMB2_OP_CANCEL: u16 = 0x0c;
/// The offset of `DataLength` in a READ reply from the start of the SMB2
/// header. `Count` in a WRITE reply has the same offset.
pub(crate) const SMB2_RW_COUNT: usize = SMB2_HDR_SIZE + 4;

/// The SMB2 TRANSFORM header before an encrypted message.
pub(crate) const SMB2_TF_MAGIC: [u8; 4] = [0xfd, b'S', b'M', b'B'];
pub(crate) const SMB2_TF_SIZE: usize = 52;
pub(crate) const SMB2_TF_NONCE: usize = 20;
pub(crate) const SMB2_TF_MSG_SIZE: usize = 36;
pub(crate) const SMB2_TF_SESSION_ID: usize = 44;

pub(crate) const NT_STATUS_PENDING: u32 = 0x0000_0103;
pub(crate) const NT_STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub(crate) const NT_STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub(crate) const NT_STATUS_DISK_FULL: u32 = 0xC000_007F;
pub(crate) const NT_STATUS_FILE_CLOSED: u32 = 0xC000_0128;

pub(crate) fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

pub(crate) fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub(crate) fn le64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// Set the NBT length of the PDU in `buf` from the size of `buf`.
pub(crate) fn set_nbt_len(buf: &mut [u8]) {
    let len = (buf.len() - NBT_HDR_SIZE).to_be_bytes();
    buf[1..NBT_HDR_SIZE].copy_from_slice(&len[len.len() - 3..]);
}
