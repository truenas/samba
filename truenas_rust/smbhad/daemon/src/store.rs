// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The copy: durable handle records, sorted by persistent id. Rehydration
//! and snapshots read the copy in pages by id.

use crate::proto::{BootId, Node, Op, Owner, Record};
use std::collections::BTreeMap;

/// Metadata of the copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The primary increments it when a rehydration ends.
    pub generation: u64,
    /// On the standby, the epoch of the last complete snapshot. It is 0
    /// while a snapshot arrives. A copy with tag 0 is not restorable.
    pub tag: u64,
    /// The node whose smbd wrote the records.
    pub writer_node: Node,
    /// The boot of that node.
    pub writer_boot: BootId,
}

impl Header {
    /// Returns a header with generation 0, tag 0 and the given writer.
    pub fn empty(writer_node: Node, writer_boot: BootId) -> Header {
        Header {
            generation: 0,
            tag: 0,
            writer_node,
            writer_boot,
        }
    }
}

/// The records.
#[derive(Debug, Default)]
pub struct Store {
    records: BTreeMap<u64, Record>,
    bytes: usize,
}

/// Returns the size that `r` counts against the byte limits of the daemon.
pub fn charge(r: &Record) -> usize {
    // 40 is an estimate of the fixed fields and the XDR padding.
    40 + r.share.len() + r.body.0.len()
}

impl Store {
    /// Applies `op` to the records.
    pub fn apply(&mut self, op: Op) {
        match op {
            Op::Put(record) => {
                self.bytes += charge(&record);
                if let Some(old) = self.records.insert(record.id, record) {
                    self.bytes -= charge(&old);
                }
            }
            Op::Del(id) => {
                if let Some(old) = self.records.remove(&id) {
                    self.bytes -= charge(&old);
                }
            }
        }
    }

    /// Removes every record that `owner` holds, except the records of the
    /// processes in `keep`. `owner` is a process that exited. Disconnected
    /// handles have no owner. Their records stay. Returns the removed ids in
    /// id order.
    pub fn forget_owner(&mut self, owner: Owner, keep: &[Owner]) -> Vec<u64> {
        let gone = self.owned_by(owner, keep);
        for id in &gone {
            self.apply(Op::Del(*id));
        }
        gone
    }

    /// Returns the ids of the records that `owner` holds, in id order,
    /// except the records of the processes in `keep`. See `Owner::matches`.
    pub fn owned_by(&self, owner: Owner, keep: &[Owner]) -> Vec<u64> {
        self.records
            .iter()
            .filter(|(_, r)| owner.matches(r.owner) && !keep.contains(&r.owner))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Removes every record.
    pub fn clear(&mut self) {
        self.records.clear();
        self.bytes = 0;
    }

    /// Returns the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true if there are no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the sum of `charge` over all records.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns a page of records with an id at or above `cursor`, in id
    /// order. If records remain, the page holds at least one. It holds more
    /// only while its charge stays within `max_bytes`. Also returns the
    /// cursor of the next page and whether this is the last page.
    pub fn page(
        &self,
        cursor: u64,
        max_bytes: usize,
    ) -> (Vec<Record>, u64, bool) {
        let mut out = Vec::new();
        let mut used = 0;
        let mut next = cursor;
        for (&id, r) in self.records.range(cursor..) {
            if !out.is_empty() && used + charge(r) > max_bytes {
                return (out, next, false);
            }
            used += charge(r);
            out.push(r.clone());
            match id.checked_add(1) {
                Some(n) => next = n,
                None => return (out, id, true),
            }
        }
        (out, next, true)
    }
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
    use crate::proto::tests::record;

    #[test]
    fn put_replace_delete_keep_the_byte_count() {
        let mut s = Store::default();
        s.apply(Op::Put(record(1, 10, b"aaaa")));
        s.apply(Op::Put(record(2, 10, b"bb")));
        assert_eq!(
            s.bytes(),
            charge(&record(1, 10, b"aaaa")) + charge(&record(2, 10, b"bb"))
        );
        s.apply(Op::Put(record(1, 11, b"a")));
        s.apply(Op::Del(2));
        s.apply(Op::Del(3));
        assert_eq!(s.len(), 1);
        assert_eq!(s.bytes(), charge(&record(1, 11, b"a")));
    }

    #[test]
    fn forget_owner_keeps_other_processes_and_disconnected_handles() {
        let mut s = Store::default();
        s.apply(Op::Put(record(1, 10, b"x")));
        s.apply(Op::Put(record(2, 20, b"x")));
        s.apply(Op::Put(record(3, 0, b"x")));
        let mut gone = record(4, 10, b"x");
        gone.owner.unique_id = 8;
        s.apply(Op::Put(gone));
        let ten = Owner {
            pid: 10,
            unique_id: 7,
        };
        assert_eq!(s.forget_owner(ten, &[]), vec![1]);
        assert!(s.forget_owner(Owner::DISCONNECTED, &[]).is_empty());
        assert_eq!(s.len(), 3);
        assert_eq!(s.bytes(), 3 * charge(&record(2, 20, b"x")));
    }

    #[test]
    fn pages_cover_every_record_once_in_id_order() {
        let mut s = Store::default();
        for id in [5u64, 1, 9, 3, u64::MAX] {
            s.apply(Op::Put(record(id, 1, &[0; 100])));
        }
        let one = charge(&record(1, 1, &[0; 100]));
        let mut cursor = 0;
        let mut seen = Vec::new();
        loop {
            let (records, next, last) = s.page(cursor, 2 * one);
            assert!(!records.is_empty() && records.len() <= 2);
            seen.extend(records.iter().map(|r| r.id));
            if last {
                break;
            }
            cursor = next;
        }
        assert_eq!(seen, vec![1, 3, 5, 9, u64::MAX]);
        let (records, _, last) = s.page(0, 0);
        assert_eq!((records.len(), last), (1, false));
    }

    #[test]
    fn a_unique_id_of_zero_matches_any_process_with_the_pid() {
        let mut s = Store::default();
        s.apply(Op::Put(record(1, 10, b"x")));
        let mut other = record(2, 10, b"x");
        other.owner.unique_id = 99;
        s.apply(Op::Put(other));
        s.apply(Op::Put(record(3, 11, b"x")));
        assert_eq!(
            s.forget_owner(
                Owner {
                    pid: 10,
                    unique_id: 0
                },
                &[]
            ),
            vec![1, 2]
        );
        assert_eq!(s.len(), 1);
    }
}
