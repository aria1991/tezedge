// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use networking::network_channel::PeerMessageReceived;
use storage::BlockHeaderWithHash;
use tezos_messages::p2p::binary_message::BinaryRead;
use tezos_messages::p2p::encoding::peer::{PeerMessage, PeerMessageResponse};
use tezos_messages::p2p::encoding::prelude::AdvertiseMessage;

use crate::bootstrap::{
    BootstrapPeerBlockHeaderReceivedAction, BootstrapPeerBlockOperationsReceivedAction,
    BootstrapPeerCurrentBranchReceivedAction,
};
use crate::peer::binary_message::read::PeerBinaryMessageReadInitAction;
use crate::peer::message::read::PeerMessageReadErrorAction;
use crate::peer::message::write::PeerMessageWriteInitAction;
use crate::peers::add::multi::PeersAddMultiAction;
use crate::peers::graylist::PeersGraylistAddressAction;
use crate::service::actors_service::{ActorsMessageTo, ActorsService};
use crate::service::{RandomnessService, Service};
use crate::{Action, ActionWithMeta, Store};

use super::{PeerMessageReadInitAction, PeerMessageReadSuccessAction};

pub fn peer_message_read_effects<S>(store: &mut Store<S>, action: &ActionWithMeta)
where
    S: Service,
{
    match &action.action {
        Action::PeerMessageReadInit(action) => {
            store.dispatch(PeerBinaryMessageReadInitAction {
                address: action.address,
            });
        }
        Action::PeerBinaryMessageReadReady(action) => {
            match store.state().peers.get(&action.address) {
                Some(peer) => match peer.status.as_handshaked() {
                    Some(_handshaked) => (),
                    None => return,
                },
                None => return,
            };

            match PeerMessageResponse::from_bytes(&action.message) {
                Ok(mut message) => {
                    // Set size hint to unencrypted encoded message size.
                    // Maybe we should set encrypted size instead? Since
                    // that's the actual size of data transmitted.
                    message.set_size_hint(action.message.len());

                    store.dispatch(PeerMessageReadSuccessAction {
                        address: action.address,
                        message: message.into(),
                    });
                }
                Err(err) => {
                    store.dispatch(PeerMessageReadErrorAction {
                        address: action.address,
                        error: err.into(),
                    });
                }
            }
        }
        Action::PeerMessageReadSuccess(action) => {
            store
                .service()
                .actors()
                .send(ActorsMessageTo::PeerMessageReceived(PeerMessageReceived {
                    peer_address: action.address,
                    message: action.message.clone(),
                }));

            match &action.message.message() {
                PeerMessage::Bootstrap => {
                    let potential_peers =
                        store.state.get().peers.potential_iter().collect::<Vec<_>>();
                    let advertise_peers = store
                        .service
                        .randomness()
                        .choose_potential_peers_for_advertise(&potential_peers);
                    store.dispatch(PeerMessageWriteInitAction {
                        address: action.address,
                        message: PeerMessageResponse::from(AdvertiseMessage::new(advertise_peers))
                            .into(),
                    });
                }
                PeerMessage::Advertise(msg) => {
                    store.dispatch(PeersAddMultiAction {
                        addresses: msg.id().iter().filter_map(|x| x.parse().ok()).collect(),
                    });
                }
                PeerMessage::CurrentBranch(msg) => {
                    if msg.chain_id() == &store.state().config.chain_id {
                        store.dispatch(BootstrapPeerCurrentBranchReceivedAction {
                            peer: action.address,
                            current_branch: msg.current_branch().clone(),
                        });
                    }
                }
                PeerMessage::BlockHeader(msg) => {
                    let state = store.state.get();
                    let block = match BlockHeaderWithHash::new(msg.block_header().clone()) {
                        Ok(v) => v,
                        Err(err) => {
                            slog::warn!(&state.log, "Failed to hash BlockHeader";
                                "peer" => format!("{}", action.address),
                                "peer_pkh" => format!("{:?}", state.peer_public_key_hash_b58check(action.address)),
                                "block_header" => format!("{:?}", msg.block_header()));
                            store.dispatch(PeersGraylistAddressAction {
                                address: action.address,
                            });
                            return;
                        }
                    };
                    if let Some(p) = state
                        .bootstrap
                        .peer_interval_by_level(action.address, block.header.level())
                    {
                        if !p.is_current_hash_eq(&block.hash) {
                            slog::warn!(&state.log, "BlockHeader hash didn't match requested hash";
                                "peer" => format!("{}", action.address),
                                "peer_pkh" => format!("{:?}", state.peer_public_key_hash_b58check(action.address)),
                                "block" => format!("{:?}", block),
                                "expected_hash" => format!("{:?}", p.current));
                            store.dispatch(PeersGraylistAddressAction {
                                address: action.address,
                            });
                            return;
                        }
                        store.dispatch(BootstrapPeerBlockHeaderReceivedAction {
                            peer: action.address,
                            block,
                        });
                    } else {
                        slog::warn!(&state.log, "Received unexpected BlockHeader from peer";
                            "peer" => format!("{}", action.address),
                            "peer_pkh" => format!("{:?}", state.peer_public_key_hash_b58check(action.address)),
                            "block_header" => format!("{:?}", msg.block_header()));
                        store.dispatch(PeersGraylistAddressAction {
                            address: action.address,
                        });
                    }
                }
                PeerMessage::OperationsForBlocks(msg) => {
                    store.dispatch(BootstrapPeerBlockOperationsReceivedAction {
                        peer: action.address,
                        message: msg.clone(),
                    });
                }
                _ => {}
            }

            // try to read next message.
            store.dispatch(PeerMessageReadInitAction {
                address: action.address,
            });
        }
        Action::PeerMessageReadError(action) => {
            store.dispatch(PeersGraylistAddressAction {
                address: action.address,
            });
        }
        _ => {}
    }
}
