// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use networking::network_channel::PeerMessageReceived;
use storage::BlockHeaderWithHash;
use tezos_messages::p2p::binary_message::BinaryRead;
use tezos_messages::p2p::encoding::peer::{PeerMessage, PeerMessageResponse};
use tezos_messages::p2p::encoding::prelude::AdvertiseMessage;

use crate::bootstrap::{
    BootstrapPeerBlockHeaderGetSuccessAction, BootstrapPeerBlockOperationsReceivedAction,
    BootstrapPeerCurrentBranchReceivedAction,
};
use crate::peer::binary_message::read::PeerBinaryMessageReadInitAction;
use crate::peer::message::read::PeerMessageReadErrorAction;
use crate::peer::message::write::PeerMessageWriteInitAction;
use crate::peer::remote_requests::block_header_get::PeerRemoteRequestsBlockHeaderGetEnqueueAction;
use crate::peer::remote_requests::block_operations_get::PeerRemoteRequestsBlockOperationsGetEnqueueAction;
use crate::peer::remote_requests::current_branch_get::PeerRemoteRequestsCurrentBranchGetInitAction;
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
                PeerMessage::GetCurrentBranch(msg) => {
                    if msg.chain_id != store.state().config.chain_id {
                        // TODO: log
                        return;
                    }
                    if !store.dispatch(PeerRemoteRequestsCurrentBranchGetInitAction {
                        address: action.address,
                    }) {
                        let state = store.state();
                        let current = state
                            .peers
                            .get_handshaked(&action.address)
                            .map(|p| &p.remote_requests.current_branch_get);
                        slog::debug!(&state.log, "Peer - Too many GetCurrentBranch requests!";
                                    "peer" => format!("{}", action.address),
                                    "current" => format!("{:?}", current));
                    }
                }
                PeerMessage::CurrentBranch(msg) => {
                    if msg.chain_id() == &store.state().config.chain_id {
                        store.dispatch(BootstrapPeerCurrentBranchReceivedAction {
                            peer: action.address,
                            current_branch: msg.current_branch().clone(),
                        });
                    }
                }
                PeerMessage::GetBlockHeaders(msg) => {
                    for block_hash in msg.get_block_headers() {
                        if !store.dispatch(PeerRemoteRequestsBlockHeaderGetEnqueueAction {
                            address: action.address,
                            block_hash: block_hash.clone(),
                        }) {
                            let state = store.state.get();
                            slog::debug!(&state.log, "Peer - Too many block header requests!";
                                "peer" => format!("{}", action.address),
                                "current_requested_block_headers_len" => msg.get_block_headers().len());
                            break;
                        }
                    }
                }
                PeerMessage::GetOperationsForBlocks(msg) => {
                    for key in msg.get_operations_for_blocks() {
                        if !store.dispatch(PeerRemoteRequestsBlockOperationsGetEnqueueAction {
                            address: action.address,
                            key: key.into(),
                        }) {
                            let state = store.state.get();
                            slog::debug!(&state.log, "Peer - Too many block operations requests!";
                                "peer" => format!("{}", action.address),
                                "current_requested_block_operations_len" => msg.get_operations_for_blocks().len());
                            break;
                        }
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
                                "block_header" => format!("{:?}", msg.block_header()),
                                "error" => format!("{:?}", err));
                            store.dispatch(PeersGraylistAddressAction {
                                address: action.address,
                            });
                            return;
                        }
                    };
                    if let Some((_, p)) = state
                        .bootstrap
                        .peer_interval(action.address, |p| p.current.is_pending())
                        .filter(|(_, p)| p.current.is_pending_block_hash_eq(&block.hash))
                    {
                        if !p.current.is_pending_block_level_eq(block.header.level()) {
                            slog::warn!(&state.log, "BlockHeader level didn't match expected level for requested block hash";
                                "peer" => format!("{}", action.address),
                                "peer_pkh" => format!("{:?}", state.peer_public_key_hash_b58check(action.address)),
                                "block" => format!("{:?}", block),
                                "expected_level" => format!("{:?}", p.current.block_level()));
                            store.dispatch(PeersGraylistAddressAction {
                                address: action.address,
                            });
                            return;
                        }
                        store.dispatch(BootstrapPeerBlockHeaderGetSuccessAction {
                            peer: action.address,
                            block,
                        });
                    } else {
                        slog::warn!(&state.log, "Received unexpected BlockHeader from peer";
                            "peer" => format!("{}", action.address),
                            "peer_pkh" => format!("{:?}", state.peer_public_key_hash_b58check(action.address)),
                            "block_header" => format!("{:?}", msg.block_header()),
                            "expected" => format!("{:?}", state.bootstrap.peer_interval(action.address, |p| p.current.is_pending())));
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
