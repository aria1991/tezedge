// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

//! This sub module provides different implementations of the `repository` used to store objects.

use std::convert::{TryFrom, TryInto};
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::ObjectHash;

pub mod hashes;
pub mod in_memory;
pub mod index_map;
pub mod persistent;
pub mod readonly_ipc;

pub const INMEM: &str = "inmem";

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HashId(NonZeroU64); // NonZeroU64 so that `Option<HashId>` is 8 bytes

#[derive(Debug)]
pub struct HashIdError;

impl TryInto<usize> for HashId {
    type Error = HashIdError;

    fn try_into(self) -> Result<usize, Self::Error> {
        Ok(self.0.get().checked_sub(1).ok_or(HashIdError)? as usize)
    }
}

impl TryFrom<usize> for HashId {
    type Error = HashIdError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into().map_err(|_| HashIdError)?;

        value
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(HashId)
            .ok_or(HashIdError)
    }
}

/// `HashId` is a `NonZeroU64` (8 bytes), but in the working tree and repo,
/// they are 6 bytes. So the shift must be 47, or we will get overflow if
/// shift is more than 47.
/// See `DirEntryInner::object_hash_id`, `PointerToInodeInner::hash_id`, and
/// `serialize::serialize_hash_id`.
const SHIFT: usize = 48 - 1;
/// Bit set when the HashId hasn't been commited
const IN_WORKING_TREE: u64 = 1 << SHIFT;

impl HashId {
    pub fn new(value: u64) -> Option<Self> {
        Some(HashId(NonZeroU64::new(value)?))
    }

    pub fn as_u64(&self) -> u64 {
        self.0.get()
    }

    pub fn set_in_working_tree(&mut self) -> Result<(), HashIdError> {
        let hash_id = self.0.get();

        self.0 = NonZeroU64::new(hash_id | IN_WORKING_TREE).ok_or(HashIdError)?;

        Ok(())
    }

    pub fn get_in_working_tree(self) -> Result<Option<HashId>, HashIdError> {
        let hash_id = self.0.get();
        if hash_id & IN_WORKING_TREE != 0 {
            Ok(Some(HashId(
                NonZeroU64::new(hash_id & !IN_WORKING_TREE).ok_or(HashIdError)?,
            )))
        } else {
            Ok(None)
        }
    }
}

pub struct VacantObjectHash<'a> {
    entry: Option<&'a mut ObjectHash>,
    hash_id: HashId,
}

impl<'a> VacantObjectHash<'a> {
    pub fn new(entry: &'a mut ObjectHash, hash_id: HashId) -> Self {
        Self {
            entry: Some(entry),
            hash_id,
        }
    }

    pub(crate) fn write_with<F>(self, fun: F) -> HashId
    where
        F: FnOnce(&mut ObjectHash),
    {
        if let Some(entry) = self.entry {
            fun(entry);
        };
        self.hash_id
    }

    pub(crate) fn set_readonly_runner(mut self) -> Result<Self, HashIdError> {
        self.hash_id.set_in_working_tree()?;
        Ok(self)
    }
}
