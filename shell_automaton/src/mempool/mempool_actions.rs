// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crypto::hash::{ChainId, BlockHash, OperationHash, BlockMetadataHash, OperationMetadataListListHash};
use tezos_messages::p2p::encoding::{
    block_header::BlockHeader, mempool::Mempool, operation::Operation,
};

use crate::service::rpc_service::RpcId;

use crate::{action::EnablingCondition, state::State};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolRecvDoneAction {
    pub address: SocketAddr,
    pub message: Mempool,
    pub level: i32,
}

impl EnablingCondition<State> for MempoolRecvDoneAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolGetOperationsAction {
    pub address: SocketAddr,
}

impl EnablingCondition<State> for MempoolGetOperationsAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolGetOperationsPendingAction {
    pub address: SocketAddr,
}

impl EnablingCondition<State> for MempoolGetOperationsPendingAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolOperationRecvDoneAction {
    pub address: SocketAddr,
    pub operation: Operation,
}

impl EnablingCondition<State> for MempoolOperationRecvDoneAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolOperationInjectAction {
    pub operation: Operation,
    pub operation_hash: OperationHash,
    pub rpc_id: RpcId,
}

impl EnablingCondition<State> for MempoolOperationInjectAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolValidateStartAction {
    pub operation: Operation,
}

impl EnablingCondition<State> for MempoolValidateStartAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolValidateWaitPrevalidatorAction {
    pub operation: Operation,
}

impl EnablingCondition<State> for MempoolValidateWaitPrevalidatorAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolCleanupWaitPrevalidatorAction {}

impl EnablingCondition<State> for MempoolCleanupWaitPrevalidatorAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolRegisterOperationsStreamAction {
    pub rpc_id: RpcId,
    pub applied: bool,
    pub refused: bool,
    pub branch_delayed: bool,
    pub branch_refused: bool,
}

impl EnablingCondition<State> for MempoolRegisterOperationsStreamAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolUnregisterOperationsStreamsAction {}

impl EnablingCondition<State> for MempoolUnregisterOperationsStreamsAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolSendAction {
    pub address: SocketAddr,
}

impl EnablingCondition<State> for MempoolSendAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolAskCurrentHeadAction {}

impl EnablingCondition<State> for MempoolAskCurrentHeadAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolBroadcastAction {}

impl EnablingCondition<State> for MempoolBroadcastAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolRpcRespondAction {}

impl EnablingCondition<State> for MempoolRpcRespondAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolBroadcastDoneAction {
    pub address: SocketAddr,
    pub known_valid: Vec<OperationHash>,
    pub pending: Vec<OperationHash>,
}

impl EnablingCondition<State> for MempoolBroadcastDoneAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolRemoveAppliedOperationsAction {
    pub operation_hashes: Vec<OperationHash>,
}

impl EnablingCondition<State> for MempoolRemoveAppliedOperationsAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MempoolFlushAction {}

impl EnablingCondition<State> for MempoolFlushAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

/// NOTE: this action is not specific to mempool, may be handled elsewhere
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BranchChangedAction {}

impl EnablingCondition<State> for BranchChangedAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}

/// NOTE: this action is not specific to mempool, may be handled elsewhere
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockAppliedAction {
    pub chain_id: ChainId,
    pub block: BlockHeader,
    pub hash: BlockHash,
    pub block_metadata_hash: Option<BlockMetadataHash>,
    pub ops_metadata_hash: Option<OperationMetadataListListHash>,
    pub is_bootstrapped: bool,
}

impl EnablingCondition<State> for BlockAppliedAction {
    fn is_enabled(&self, state: &State) -> bool {
        // TODO(vlad):
        let _ = state;
        true
    }
}
