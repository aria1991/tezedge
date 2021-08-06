// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT
#![forbid(unsafe_code)]

//! This crate handles low level p2p communication.

use std::sync::Arc;

use crypto::hash::CryptoboxPublicKeyHash;
pub use tezedge_state::PeerAddress;
use tezos_identity::Identity;

#[derive(Debug, Clone)]
pub struct PeerId {
    pub address: PeerAddress,
    pub public_key_hash: CryptoboxPublicKeyHash,
}

/// Local peer info
pub struct LocalPeerInfo {
    /// port where remote node can establish new connection
    listener_port: u16,
    /// Our node identity
    identity: Arc<Identity>,
    /// version of shell/network protocol which we are compatible with
    version: Arc<ShellCompatibilityVersion>,
    /// Target number for proof-of-work
    pow_target: f64,
}

impl LocalPeerInfo {
    pub fn new(
        listener_port: u16,
        identity: Arc<Identity>,
        version: Arc<ShellCompatibilityVersion>,
        pow_target: f64,
    ) -> Self {
        LocalPeerInfo {
            listener_port,
            identity,
            version,
            pow_target,
        }
    }

    pub fn listener_port(&self) -> u16 {
        self.listener_port
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.identity.clone()
    }

    pub fn version(&self) -> Arc<ShellCompatibilityVersion> {
        self.version.clone()
    }

    pub fn pow_target(&self) -> f64 {
        self.pow_target
    }
}

pub use tezedge_state::ShellCompatibilityVersion;
