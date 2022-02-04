// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::net::SocketAddr;

use crypto::hash::BlockHash;
use redux_rs::EnablingCondition;
use tezos_messages::{
    base::signature_public_key::SignaturePublicKey, p2p::encoding::block_header::BlockHeader,
};

use crate::State;

use super::{CurrentHeadPrecheckError, CurrentHeadState};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeadReceivedAction {
    pub address: SocketAddr,
    pub block_hash: BlockHash,
    pub block_header: BlockHeader,
}

/// Enables [CurrentHeadReceivedAction] when its level is the next to the one of last applied block
/// and its block hash hasn't seen yet.
impl EnablingCondition<State> for CurrentHeadReceivedAction {
    fn is_enabled(&self, state: &State) -> bool {
        !state.config.disable_block_precheck
            && state
                .current_head_candidate_level()
                .map_or(true, |l| l == self.block_header.level())
            && !state
                .current_heads
                .candidates
                .contains_key(&self.block_hash)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeadPrecheckAction {
    pub block_hash: BlockHash,
}

impl EnablingCondition<State> for CurrentHeadPrecheckAction {
    fn is_enabled(&self, state: &State) -> bool {
        !state.config.disable_block_precheck
            && state
                .current_head_level()
                .map_or(false, |applied_head_level| {
                    if let Some(CurrentHeadState::Received { block_header }) =
                        state.current_heads.candidates.get(&self.block_hash)
                    {
                        block_header.level() == applied_head_level + 1
                    } else {
                        false
                    }
                })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeadPrecheckSuccessAction {
    pub block_hash: BlockHash,
    pub baker: SignaturePublicKey,
    pub priority: u16,
}

impl EnablingCondition<State> for CurrentHeadPrecheckSuccessAction {
    fn is_enabled(&self, _state: &State) -> bool {
        true
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeadPrecheckRejectedAction {
    pub block_hash: BlockHash,
}

impl EnablingCondition<State> for CurrentHeadPrecheckRejectedAction {
    fn is_enabled(&self, _state: &State) -> bool {
        true
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeadErrorAction {
    pub block_hash: BlockHash,
    pub error: CurrentHeadPrecheckError,
}

impl EnablingCondition<State> for CurrentHeadErrorAction {
    fn is_enabled(&self, _state: &State) -> bool {
        true
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeadPrecacheBakingRightsAction {}

impl EnablingCondition<State> for CurrentHeadPrecacheBakingRightsAction {
    fn is_enabled(&self, state: &State) -> bool {
        !state.config.disable_block_precheck && state.current_head.get().is_some()
    }
}
