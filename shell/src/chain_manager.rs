// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

//! Manages chain synchronisation process.
//! - tries to download most recent header from the other peers
//! - also supplies downloaded data to other peers
//!
//! Also responsible for:
//! -- managing attribute current head
//! -- start test chain (if needed)
//! -- validate blocks with protocol
//! -- ...

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{format_err, Error};
use itertools::{Itertools, MinMaxResult};
use slog::{debug, info, trace, warn, Logger};
use tezedge_actor_system::actors::*;

use crypto::hash::{
    BlockHash, BlockMetadataHash, ChainId, CryptoboxPublicKeyHash, OperationMetadataListListHash,
};
use crypto::seeded_step::Seed;
use networking::network_channel::{NetworkChannelMsg, NetworkChannelRef, NetworkChannelTopic};
use networking::PeerId;
use shell_integration::{
    dispatch_oneshot_result, InjectBlock, InjectBlockError, InjectBlockOneshotResultCallback,
    OneshotResultCallback, ThreadWatcher,
};
use storage::PersistentStorage;
use storage::{
    BlockHeaderWithHash, BlockMetaStorage, BlockMetaStorageReader, BlockStorage,
    BlockStorageReader, OperationKey, OperationsStorage, OperationsStorageReader, StorageError,
    StorageInitInfo,
};
use tezos_identity::Identity;
use tezos_messages::p2p::binary_message::MessageHash;
use tezos_messages::p2p::encoding::block_header::display_fitness;
use tezos_messages::p2p::encoding::limits::HISTORY_MAX_SIZE;
use tezos_messages::p2p::encoding::prelude::*;
use tezos_messages::Head;
use tezos_protocol_ipc_client::{ProtocolRunnerApi, ProtocolRunnerConnection};

use crate::chain_feeder::ChainFeederRef;
use crate::peer_branch_bootstrapper::{CleanPeerData, UpdateBranchBootstraping};
use crate::shell_automaton_manager::{ShellAutomatonMsg, ShellAutomatonSender};
use crate::shell_channel::{
    AllBlockOperationsReceived, BlockReceived, ShellChannelMsg, ShellChannelRef, ShellChannelTopic,
};
use crate::state::chain_state::{BlockAcceptanceResult, BlockchainState};
use crate::state::data_requester::tell_peer;
use crate::state::head_state::{
    has_any_higher_than, HeadResult, HeadState, RemoteBestKnownCurrentHead,
};
use crate::state::peer_state::PeerState;
use crate::state::synchronization_state::{
    PeerBranchSynchronizationDone, SynchronizationBootstrapState,
};
use crate::state::StateError;
use crate::subscription::*;
use shell_integration::notifications::NewCurrentHeadNotification;

/// How often to ask all connected peers for current head
const ASK_CURRENT_HEAD_INTERVAL: Duration = Duration::from_secs(90);
/// Initial delay to ask the peers for current head
const ASK_CURRENT_HEAD_INITIAL_DELAY: Duration = Duration::from_secs(15);
/// After this time we will disconnect peer if his current head level stays the same
const CURRENT_HEAD_LEVEL_UPDATE_TIMEOUT: Duration = Duration::from_secs(60 * 2);
/// We accept current_head not older that this timeout
const CURRENT_HEAD_LAST_RECEIVED_ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);

/// After this time peer will be disconnected if it fails to respond to our request
const SILENT_PEER_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum timeout duration in sandbox mode (do not disconnect peers in sandbox mode)
const SILENT_PEER_TIMEOUT_SANDBOX: Duration = Duration::from_secs(31_536_000);

/// How often to print stats in logs
const LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Message commands [`ChainManager`] to disconnect stalled peers.
#[derive(Clone, Debug)]
pub struct DisconnectStalledPeers {
    silent_peer_timeout: Duration,
}

/// Message commands [`ChainManager`] to ask all connected peers for their current head.
#[derive(Clone, Debug)]
pub struct AskPeersAboutCurrentHead {
    /// Optional, if Some timeout, we check it from the current_head_response_last, if timeout exceeded, we can request once more
    /// If None, we request immediatelly
    pub last_received_timeout: Option<Duration>,
}

/// Message commands [`ChainCurrentHeadManager`] to process applied block.
/// Chain_feeder propagates if block successfully validated and applied
/// This is not the same as NewCurrentHead, not every applied block is set as NewCurrentHead (reorg - several headers on same level, duplicate header ...)
#[derive(Clone, Debug)]
pub struct ProcessValidatedBlock {
    pub block: Arc<BlockHeaderWithHash>,
    chain_id: Arc<ChainId>,
    block_metadata_hash: Option<BlockMetadataHash>,
    ops_metadata_hash: Option<OperationMetadataListListHash>,
    result_roundtrip_timer: Arc<Instant>,
}

impl ProcessValidatedBlock {
    pub fn new(
        block: Arc<BlockHeaderWithHash>,
        chain_id: Arc<ChainId>,
        block_metadata_hash: Option<BlockMetadataHash>,
        ops_metadata_hash: Option<OperationMetadataListListHash>,
        result_roundtrip_timer: Instant,
    ) -> Self {
        Self {
            block,
            chain_id,
            block_metadata_hash,
            ops_metadata_hash,
            result_roundtrip_timer: Arc::new(result_roundtrip_timer),
        }
    }
}

#[derive(Clone, Debug)]
pub struct InjectBlockRequest {
    pub request: InjectBlock,
    pub result_callback: Option<InjectBlockOneshotResultCallback>,
}

/// Message commands [`ChainManager`] to log its internal stats.
#[derive(Clone, Debug)]
pub struct LogStats;

/// Holds various stats with info about internal synchronization.
struct Stats {
    /// Count of received blocks
    unseen_block_count: usize,
    /// Count of received blocks with all operations
    unseen_block_operations_count: usize,
    /// Last time when previously not seen block was received
    unseen_block_last: Instant,
    /// Last time when previously unseen operations were received
    unseen_block_operations_last: Instant,

    /// Count of received messages from the last log
    actor_received_messages_count: usize,
}

impl Stats {
    fn get_and_clear_unseen_block_headers_count(&mut self) -> usize {
        std::mem::replace(&mut self.unseen_block_count, 0)
    }
    fn get_and_clear_unseen_block_operations_count(&mut self) -> usize {
        std::mem::replace(&mut self.unseen_block_operations_count, 0)
    }
    fn get_and_clear_actor_received_messages_count(&mut self) -> usize {
        std::mem::replace(&mut self.actor_received_messages_count, 0)
    }
}

/// Purpose of this actor is to perform chain synchronization.
#[actor(
    DisconnectStalledPeers,
    AskPeersAboutCurrentHead,
    LogStats,
    NetworkChannelMsg,
    ShellChannelMsg,
    PeerBranchSynchronizationDone,
    ProcessValidatedBlock,
    InjectBlockRequest,
    SubscribedResponse
)]
pub struct ChainManager {
    /// All events generated by the network layer will end up in this channel
    network_channel: NetworkChannelRef,
    shell_automaton: ShellAutomatonSender,

    /// All events from shell will be published to this channel
    shell_channel: ShellChannelRef,
    /// p2p reader
    p2p_reader_sender: Arc<Mutex<P2pReaderSender>>,

    /// Block storage
    block_storage: Box<dyn BlockStorageReader>,
    /// Block meta storage
    block_meta_storage: Box<dyn BlockMetaStorageReader>,
    /// Holds state of the blockchain
    chain_state: BlockchainState,

    /// Holds the state of all peers
    peers: HashMap<SocketAddr, PeerState>,
    /// Current head information
    current_head_state: HeadState,
    /// Holds "best" known remote head
    remote_current_head_state: RemoteBestKnownCurrentHead,
    /// Internal stats
    stats: Stats,

    /// Holds bootstrapped state
    current_bootstrap_state: SynchronizationBootstrapState,

    /// Indicates that system is shutting down
    shutting_down: bool,
    /// Indicates node mode
    is_sandbox: bool,

    /// Protocol runner pool dedicated to prevalidation
    tezos_protocol_api: Arc<ProtocolRunnerApi>,

    /// Reusable connection to the protocol runner
    reused_protocol_runner_connection: Option<ProtocolRunnerConnection>,

    /// Used just for very first initialization of ChainManager, because ChainManager subscribes to NetworkChannel in [`pre_start`], but this initialization is asynchronous,
    /// so there is possiblity, that PeerManager could open p2p socket before ChainManager is subscribed to p2p messages, this could lead to dismissed p2p messages or PeerBootstrapped messages,
    ///
    /// we dont rely on restarting ChainManager, but if that occures, it is ok, that we ignore this, because tezedge_actor_system's do not loose messages when actor is restarting
    first_initialization_done_result_callback: Arc<Mutex<Option<OneshotResultCallback<()>>>>,
}

/// Reference to [chain manager](ChainManager) actor.
pub type ChainManagerRef = ActorRef<ChainManagerMsg>;

impl ChainManager {
    /// Create new actor instance.
    pub fn actor(
        sys: &ActorSystem,
        block_applier: ChainFeederRef,
        network_channel: NetworkChannelRef,
        shell_automaton: ShellAutomatonSender,
        shell_channel: ShellChannelRef,
        persistent_storage: PersistentStorage,
        tezos_protocol_api: Arc<ProtocolRunnerApi>,
        init_storage_data: StorageInitInfo,
        is_sandbox: bool,
        hydrated_current_head: Head,
        num_of_peers_for_bootstrap_threshold: usize,
        identity: Arc<Identity>,
        first_initialization_done_result_callback: OneshotResultCallback<()>,
    ) -> Result<(ChainManagerRef, ThreadWatcher), CreateError> {
        let (p2p_reader_sender, p2p_reader_thread_watcher) = spawn_p2p_reader_thread(
            identity.peer_id(),
            &persistent_storage,
            shell_automaton.clone(),
            sys.log(),
        )
        .map_err(|e| {
            warn!(sys.log(), "Failed to spawn p2p reader thread"; "reason" => format!("{}", e));
            CreateError::Panicked
        })?;

        sys.actor_of_props::<ChainManager>(
            ChainManager::name(),
            Props::new_args((
                block_applier,
                network_channel,
                shell_automaton,
                shell_channel,
                persistent_storage,
                Arc::new(Mutex::new(p2p_reader_sender)),
                tezos_protocol_api,
                init_storage_data,
                is_sandbox,
                hydrated_current_head,
                num_of_peers_for_bootstrap_threshold,
                Arc::new(Mutex::new(Some(first_initialization_done_result_callback))),
            )),
        )
        .map(|actor| (actor, p2p_reader_thread_watcher))
    }

    /// The `ChainManager` is intended to serve as a singleton actor so that's why
    /// we won't support multiple names per instance.
    fn name() -> &'static str {
        "chain-manager"
    }

    fn process_network_channel_message(
        &mut self,
        ctx: &Context<ChainManagerMsg>,
        msg: NetworkChannelMsg,
    ) -> Result<(), Error> {
        let ChainManager {
            peers,
            chain_state,
            shell_channel,
            shell_automaton,
            block_storage,
            block_meta_storage,
            stats,
            current_head_state,
            remote_current_head_state,
            p2p_reader_sender,
            reused_protocol_runner_connection,
            ..
        } = self;

        match msg {
            NetworkChannelMsg::PeerBootstrapped(peer_id, _, _) => {
                let peer = PeerState::new(peer_id.clone(), chain_state.data_queues_limits());
                // store peer
                self.peers.insert(peer_id.address, peer);

                let log = ctx
                    .system
                    .log()
                    .new(slog::o!("peer" => peer_id.address.to_string()));

                tell_peer(
                    &shell_automaton,
                    &peer_id,
                    GetCurrentBranchMessage::new(chain_state.get_chain_id().as_ref().clone())
                        .into(),
                    &log,
                );
            }
            NetworkChannelMsg::PeerDisconnected(peer) => {
                self.clear_peer_data(peer);
            }
            NetworkChannelMsg::PeerMessageReceived(received) => {
                match peers.get_mut(&received.peer_address) {
                    Some(peer) => {
                        let log = ctx
                            .system
                            .log()
                            .new(slog::o!("peer" => peer.peer_id.address.to_string()));

                        match received.message.message() {
                            PeerMessage::CurrentBranch(message) => {
                                info!(
                                    log,
                                    "received current branch {} from {}",
                                    message
                                        .current_branch()
                                        .message_typed_hash::<BlockHash>()
                                        .unwrap()
                                        .to_base58_check(),
                                    peer.peer_id.address
                                );
                                peer.update_current_head_level(
                                    message.current_branch().current_head().level(),
                                );

                                // at first, check if we can accept branch or just ignore it
                                if !chain_state.can_accept_branch(message, current_head_state)? {
                                    let remote_head = message.current_branch().current_head();
                                    let (local, local_level, local_fitness) =
                                        self.current_head_state.as_ref().to_debug_info();
                                    debug!(log, "Ignoring received (low) current branch";
                                                    "current_head" => local,
                                                    "current_head_level" => local_level,
                                                    "current_head_fitness" => local_fitness,
                                                    "remote_branch" => remote_head.message_typed_hash::<BlockHash>()?.to_base58_check(),
                                                    "remote_level" => remote_head.level(),
                                                    "remote_fitness" => display_fitness(remote_head.fitness()));
                                    if remote_head.level() > 0
                                        && !self.current_bootstrap_state.is_bootstrapped()
                                    {
                                        let peer_id = peer.peer_id.clone();
                                        if let Err(e) = self.resolve_is_bootstrapped(
                                            &PeerBranchSynchronizationDone::new(
                                                peer_id,
                                                remote_head.level(),
                                            ),
                                            &log,
                                        ) {
                                            warn!(log, "Failed to resolve is_bootstrapped for chain manager (current_branch)"; "reason" => format!("{:?}", e));
                                        }
                                    }
                                } else {
                                    let message_current_head = BlockHeaderWithHash::new(
                                        message.current_branch().current_head().clone(),
                                    )?;

                                    // update remote heads
                                    remote_current_head_state
                                        .update_remote_head(&message_current_head);

                                    // schedule to download missing branch blocks
                                    chain_state.schedule_history_bootstrap(
                                        &ctx.system,
                                        &ctx.myself,
                                        peer,
                                        &message_current_head,
                                        message.current_branch().history().to_vec(),
                                    )?;
                                }
                            }
                            PeerMessage::GetCurrentBranch(message) => {
                                if chain_state.get_chain_id().as_ref() == &message.chain_id {
                                    let current_head_local = current_head_state.as_ref();
                                    if let Some(current_head) =
                                        block_storage.get(current_head_local.block_hash())?
                                    {
                                        let chain_id = chain_state.get_chain_id();
                                        let caboose = chain_state.get_caboose(chain_id)?;

                                        ChainManager::advertise_current_branch_to_p2p(
                                            chain_id,
                                            caboose,
                                            &Arc::new(current_head),
                                            std::iter::once(&*peer),
                                            p2p_reader_sender,
                                            &log,
                                        );
                                    }
                                } else {
                                    warn!(log, "Peer is requesting current branch from unsupported chain_id"; "chain_id" => chain_state.get_chain_id().to_base58_check());
                                }
                            }
                            PeerMessage::BlockHeader(message) => {
                                let block_header_with_hash =
                                    BlockHeaderWithHash::new(message.block_header().clone())?;

                                // check, if we requested data from this peer
                                if let Some(requested_data) =
                                    chain_state.requester().block_header_received(
                                        &block_header_with_hash.hash,
                                        peer,
                                        &log,
                                    )?
                                {
                                    // now handle received header
                                    let _ = Self::process_downloaded_header(
                                        &block_header_with_hash,
                                        stats,
                                        chain_state,
                                        shell_channel,
                                        &log,
                                        &peer.peer_id,
                                    )?;

                                    // not needed, just to be explicit
                                    drop(requested_data);
                                }
                            }
                            PeerMessage::GetBlockHeaders(_) => {
                                // redirect to p2p reader
                                self.p2p_reader_sender.lock().map_err(|e| format_err!("Failed to send GetBlockHeaders request to p2p reader, reason: {}", e))?.send(
                                    P2pReaderEvent::SendDataResponse(
                                        peer.peer_id.clone(),
                                        received.message.clone(),
                                    ))?;
                            }
                            PeerMessage::GetOperationsForBlocks(_) => {
                                // redirect to p2p reader
                                self.p2p_reader_sender.lock().map_err(|e| format_err!("Failed to send GetOperationsForBlocks request to p2p reader, reason: {}", e))?.send(
                                    P2pReaderEvent::SendDataResponse(
                                        peer.peer_id.clone(),
                                        received.message.clone(),
                                    ))?;
                            }
                            PeerMessage::GetCurrentHead(_) => {
                                return Ok(());
                            }
                            PeerMessage::OperationsForBlocks(operations) => {
                                if let Some(requested_data) =
                                    chain_state.requester().block_operations_received(
                                        operations.operations_for_block(),
                                        peer,
                                        &log,
                                    )?
                                {
                                    // update stats
                                    stats.unseen_block_operations_last = Instant::now();

                                    // update operations state
                                    let block_hash = operations.operations_for_block().hash();
                                    if chain_state.process_block_operations_from_peer(
                                        block_hash.clone(),
                                        operations,
                                        &peer.peer_id,
                                    )? {
                                        stats.unseen_block_operations_count += 1;

                                        // TODO: TE-369 - is this necessery?
                                        // notify others that new all operations for block were received
                                        let block_meta = block_meta_storage
                                            .get(block_hash)?
                                            .ok_or_else(|| StorageError::MissingKey {
                                                when: "Processing PeerMessage::OperationsForBlocks"
                                                    .into(),
                                            })?;

                                        // notify others that new all operations for block were received
                                        shell_channel.tell(
                                            Publish {
                                                msg: AllBlockOperationsReceived {
                                                    level: block_meta.level(),
                                                }
                                                .into(),
                                                topic: ShellChannelTopic::ShellEvents.into(),
                                            },
                                            None,
                                        );
                                    }

                                    // not needed, just to be explicit
                                    drop(requested_data);
                                }
                            }
                            PeerMessage::CurrentHead(message) => {
                                peer.current_head_response_last = Instant::now();

                                // process current head only if we are bootstrapped
                                if self.current_bootstrap_state.is_bootstrapped() {
                                    if reused_protocol_runner_connection.is_none() {
                                        self.reused_protocol_runner_connection = Some(
                                            self.tezos_protocol_api.readable_connection_sync()?,
                                        );
                                    }

                                    // Was just assigned, unwrap() cannot fail
                                    let connection =
                                        self.reused_protocol_runner_connection.as_mut().unwrap();

                                    // check if we can accept head
                                    match chain_state.can_accept_head(
                                        message,
                                        &current_head_state,
                                        connection,
                                    )? {
                                        BlockAcceptanceResult::AcceptBlock(
                                            same_as_current_head,
                                        ) => {
                                            // update peer remote head
                                            peer.update_current_head_level(
                                                message.current_block_header().level(),
                                            );

                                            // if not the same as current head, we need to download and apply it
                                            if !same_as_current_head {
                                                let message_current_head =
                                                    BlockHeaderWithHash::new(
                                                        message.current_block_header().clone(),
                                                    )?;

                                                // update best remote head
                                                remote_current_head_state
                                                    .update_remote_head(&message_current_head);

                                                // process downloaded block directly
                                                let is_applied = Self::process_downloaded_header(
                                                    &message_current_head,
                                                    stats,
                                                    chain_state,
                                                    shell_channel,
                                                    &log,
                                                    &peer.peer_id,
                                                )?;

                                                if !is_applied {
                                                    // here we accept head, which also means that we know predecessor
                                                    // so we can schedule to download diff (last_applied_block .. current_head)
                                                    let mut history = Vec::with_capacity(2);
                                                    history.push(
                                                        current_head_state
                                                            .as_ref()
                                                            .block_hash()
                                                            .clone(),
                                                    );

                                                    // this schedule, ensure to download all operations from this peer (if not already)
                                                    chain_state.schedule_history_bootstrap(
                                                        &ctx.system,
                                                        &ctx.myself,
                                                        peer,
                                                        &message_current_head,
                                                        history,
                                                    )?;
                                                }
                                            }
                                        }
                                        BlockAcceptanceResult::IgnoreBlock => {
                                            // doing nothing
                                        }
                                        BlockAcceptanceResult::UnknownBranch => {
                                            // ask current_branch from peer
                                            tell_peer(
                                                &shell_automaton,
                                                &peer.peer_id,
                                                GetCurrentBranchMessage::new(
                                                    message.chain_id().clone(),
                                                )
                                                .into(),
                                                &log,
                                            );
                                        }
                                        BlockAcceptanceResult::MutlipassValidationError(error) => {
                                            warn!(log, "Mutlipass validation error detected - blacklisting peer";
                                                       "message_head_level" => message.current_block_header().level(),
                                                       "message_head_proto" => message.current_block_header().proto(),
                                                       "reason" => &error);

                                            // clear peer stuff immediatelly
                                            peer.clear();

                                            // blacklist peer
                                            shell_automaton.send(ShellAutomatonMsg::BlacklistPeer(
                                                peer.peer_id.clone(),
                                                format!("{:?}", error),
                                            )).map_err(|e| format_err!("Failed to send message to shell_automaton for blacklist peer, reason: {}", e))?;
                                        }
                                    };
                                } else {
                                    // if not bootstraped, check if increasing
                                    let was_updated = peer.update_current_head_level(
                                        message.current_block_header().level(),
                                    );

                                    // if increasing, propage to peer_branch_bootstrapper to add to the branch for increase and download latest data
                                    if was_updated {
                                        match chain_state.peer_branch_bootstrapper() {
                                            Some(peer_branch_bootstrapper) => {
                                                // check if we started branch bootstrapper, try to update current_head to peer's pipelines
                                                let message_current_head =
                                                    BlockHeaderWithHash::new(
                                                        message.current_block_header().clone(),
                                                    )?;

                                                peer_branch_bootstrapper.tell(
                                                    UpdateBranchBootstraping::new(
                                                        peer.peer_id.clone(),
                                                        message_current_head,
                                                    ),
                                                    None,
                                                );
                                            }
                                            None => {
                                                // if not started, we need to ask for CurrentBranch of peer
                                                tell_peer(
                                                    &shell_automaton,
                                                    &peer.peer_id,
                                                    GetCurrentBranchMessage::new(
                                                        message.chain_id().clone(),
                                                    )
                                                    .into(),
                                                    &log,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            PeerMessage::GetOperations(_) => {
                                return Ok(());
                            }
                            PeerMessage::Operation(_) => {
                                return Ok(());
                            }
                            ignored_message => {
                                trace!(log, "Ignored message"; "message" => format!("{:?}", ignored_message))
                            }
                        }
                    }
                    None => {
                        warn!(ctx.system.log(), "Received message from non-existing peer actor";
                                                "peer" => received.peer_address.to_string());
                    }
                }
            }
        }

        Ok(())
    }

    fn process_shell_channel_message(&mut self, msg: ShellChannelMsg) {
        if let ShellChannelMsg::ShuttingDown(_) = msg {
            self.shutting_down = true;
        }
    }

    /// Returns true, if block is already applied
    fn process_downloaded_header(
        received_block: &BlockHeaderWithHash,
        stats: &mut Stats,
        chain_state: &mut BlockchainState,
        shell_channel: &ShellChannelRef,
        log: &Logger,
        peer_id: &Arc<PeerId>,
    ) -> Result<bool, Error> {
        // store header
        let (is_new_block, is_applied) =
            chain_state.process_block_header_from_peer(received_block, log, peer_id)?;
        if is_new_block {
            // update stats for new header
            stats.unseen_block_last = Instant::now();
            stats.unseen_block_count += 1;

            // notify others that new block was received
            shell_channel.tell(
                Publish {
                    msg: BlockReceived {
                        hash: received_block.hash.clone(),
                        level: received_block.header.level(),
                    }
                    .into(),
                    topic: ShellChannelTopic::ShellEvents.into(),
                },
                None,
            );
        }

        Ok(is_applied)
    }

    fn process_injected_block(
        &mut self,
        injected_block: InjectBlock,
        result_callback: Option<InjectBlockOneshotResultCallback>,
        ctx: &Context<ChainManagerMsg>,
    ) -> Result<(), Error> {
        let InjectBlock {
            chain_id,
            block_header: block_header_with_hash,
            operations,
            operation_paths,
        } = injected_block;
        let log = ctx
            .system
            .log()
            .new(slog::o!("block" => block_header_with_hash.hash.to_base58_check(), "chain_id" => chain_id.to_base58_check()));

        // this should  allways return [is_new_block==true], as we are injecting a forged new block
        let (block_metadata, is_new_block, are_operations_complete) = match self
            .chain_state
            .process_injected_block_header(&chain_id, &block_header_with_hash, &log)
        {
            Ok(data) => data,
            Err(e) => {
                if let Err(e) = dispatch_oneshot_result(result_callback, || {
                    Err(InjectBlockError {
                        reason: format!(
                            "Failed to store injected block, block_hash: {}, reason: {}",
                            block_header_with_hash.hash.to_base58_check(),
                            e
                        ),
                    })
                }) {
                    warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
                }
                return Err(e.into());
            }
        };
        info!(log, "New block injection";
                   "is_new_block" => is_new_block,
                   "level" => block_header_with_hash.header.level());

        if is_new_block {
            // update stats
            self.stats.unseen_block_last = Instant::now();
            self.stats.unseen_block_count += 1;

            // notify others that new block (header) was received
            self.shell_channel.tell(
                Publish {
                    msg: BlockReceived {
                        hash: block_header_with_hash.hash.clone(),
                        level: block_header_with_hash.header.level(),
                    }
                    .into(),
                    topic: ShellChannelTopic::ShellEvents.into(),
                },
                None,
            );

            // handle operations (if expecting any)
            if !are_operations_complete {
                let operations = match operations {
                    Some(operations) => operations,
                    None => {
                        if let Err(e) = dispatch_oneshot_result(result_callback, || {
                            Err(InjectBlockError {
                                reason: format!(
                                    "Missing operations in request, block_hash: {}",
                                    block_header_with_hash.hash.to_base58_check()
                                ),
                            })
                        }) {
                            warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
                        }
                        return Err(format_err!(
                            "Missing operations in request, block_hash: {}",
                            block_header_with_hash.hash.to_base58_check()
                        ));
                    }
                };
                let op_paths = match operation_paths {
                    Some(op_paths) => op_paths,
                    None => {
                        if let Err(e) = dispatch_oneshot_result(result_callback, || {
                            Err(InjectBlockError {
                                reason: format!(
                                    "Missing operation paths in request, block_hash: {}",
                                    block_header_with_hash.hash.to_base58_check()
                                ),
                            })
                        }) {
                            warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
                        }
                        return Err(format_err!(
                            "Missing operation paths in request, block_hash: {}",
                            block_header_with_hash.hash.to_base58_check()
                        ));
                    }
                };

                // iterate through all validation passes
                for (idx, ops) in operations.into_iter().enumerate() {
                    let opb =
                        OperationsForBlock::new(block_header_with_hash.hash.clone(), idx as i8);

                    // create OperationsForBlocksMessage - the operations are stored in DB as a OperationsForBlocksMessage per validation pass per block
                    // e.g one block -> 4 validation passes -> 4 OperationsForBlocksMessage to store for the block
                    let operation_hashes_path = match op_paths.get(idx) {
                        Some(path) => path.to_owned(),
                        None => {
                            if let Err(e) = dispatch_oneshot_result(result_callback, || {
                                Err(InjectBlockError {reason: format!("Missing operation paths in request for index: {}, block_hash: {}", idx, block_header_with_hash.hash.to_base58_check())})
                            }) {
                                warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
                            }
                            return Err(format_err!(
                                "Missing operation paths in request for index: {}, block_hash: {}",
                                idx,
                                block_header_with_hash.hash.to_base58_check()
                            ));
                        }
                    };

                    let msg: OperationsForBlocksMessage =
                        OperationsForBlocksMessage::new(opb, operation_hashes_path, ops);

                    match self.chain_state.process_block_operations(&msg) {
                        Ok((all_operations_received, _)) => {
                            if all_operations_received {
                                info!(log, "New block injection - operations are complete";
                                           "is_new_block" => is_new_block,
                                           "level" => block_header_with_hash.header.level());

                                // update stats
                                self.stats.unseen_block_operations_last = Instant::now();
                                self.stats.unseen_block_operations_count += 1;

                                // notify others that new all operations for block were received
                                self.shell_channel.tell(
                                    Publish {
                                        msg: AllBlockOperationsReceived {
                                            level: block_metadata.level(),
                                        }
                                        .into(),
                                        topic: ShellChannelTopic::ShellEvents.into(),
                                    },
                                    None,
                                );
                            }
                        }
                        Err(e) => {
                            if let Err(e) = dispatch_oneshot_result(result_callback, || {
                                Err(InjectBlockError {reason: format!("Failed to store injected block operations, block_hash: {}, reason: {}", block_header_with_hash.hash.to_base58_check(), e)})
                            }) {
                                warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
                            }
                            return Err(e.into());
                        }
                    };
                }
            }

            // try apply block
            if let Err(e) = self.chain_state.requester().try_apply_block(
                chain_id,
                block_header_with_hash.hash.clone(),
                Arc::new(ctx.myself()),
                result_callback.clone(),
            ) {
                if let Err(e) = dispatch_oneshot_result(result_callback, || {
                    Err(InjectBlockError {reason: format!("Failed to detect if injected block can be applied, block_hash: {}, reason: {}", block_header_with_hash.hash.to_base58_check(), e)})
                }) {
                    warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
                }
                return Err(e.into());
            };
        } else {
            warn!(log, "Injected duplicated block - will be ignored!");
            if let Err(e) = dispatch_oneshot_result(result_callback, || {
                Err(InjectBlockError {
                    reason: format!(
                        "Injected duplicated block - will be ignored!, block_hash: {}",
                        block_header_with_hash.hash.to_base58_check()
                    ),
                })
            }) {
                warn!(log, "Failed to dispatch result"; "reason" => format!("{}", e));
            }
        }

        Ok(())
    }

    /// Resolves if chain_manager is bootstrapped,
    /// means that we have at_least <> boostrapped peers
    ///
    /// "bootstrapped peer" means, that peer.current_level <= chain_manager.current_level
    fn resolve_is_bootstrapped(
        &mut self,
        msg: &PeerBranchSynchronizationDone,
        log: &Logger,
    ) -> Result<(), StateError> {
        if self.current_bootstrap_state.is_bootstrapped() {
            // TODO: TE-386 - global queue for requested operations
            if let Some(peer_state) = self.peers.get_mut(&msg.peer().address) {
                peer_state.missing_operations_for_blocks.clear();
            }

            return Ok(());
        }

        let chain_manager_current_level = *self.current_head_state.as_ref().level();

        let remote_best_known_level = match self.remote_current_head_state.as_ref() {
            Some(head) => *head.level(),
            None => 0,
        };

        if let Some(peer_state) = self.peers.get_mut(&msg.peer().address) {
            self.current_bootstrap_state.update_by_peer_state(
                msg,
                peer_state,
                remote_best_known_level,
                chain_manager_current_level,
            );

            // TODO: TE-386 - global queue for requested operations
            peer_state.missing_operations_for_blocks.clear();
        }

        {
            // lock and log
            if self.current_bootstrap_state.is_bootstrapped() {
                info!(log, "Bootstrapped (chain_manager)";
                       "num_of_peers_for_bootstrap_threshold" => self.current_bootstrap_state.num_of_peers_for_bootstrap_threshold(),
                       "remote_best_known_level" => remote_best_known_level,
                       "reached_on_level" => chain_manager_current_level);
            }
        }

        Ok(())
    }

    // TODO: StorageError sa tu neriesi

    /// Send CurrentBranch message to the p2p
    fn advertise_current_branch_to_p2p<'a, I: Iterator<Item = &'a PeerState>>(
        chain_id: &ChainId,
        caboose: Option<Head>,
        block_header: &Arc<BlockHeaderWithHash>,
        peers: I,
        p2p_reader_sender: &'a Arc<Mutex<P2pReaderSender>>,
        log: &Logger,
    ) {
        // lock peers
        match p2p_reader_sender.lock() {
            Ok(p2p_reader_sender) => {
                // dispatch in separate thread
                for peer in peers {
                    if let Err(e) = p2p_reader_sender.send(
                        SendCurrentBranchToPeerRequest {
                            peer_id: peer.peer_id.clone(),
                            chain_id: chain_id.clone(),
                            caboose: caboose.clone(),
                            block_header: block_header.clone(),
                        }
                        .into(),
                    ) {
                        warn!(log, "Failed to schedule CurrentBranch message sending"; "reason" => format!("{}", e), "block_header_hash" => block_header.hash.to_base58_check());
                    }
                }
            }
            Err(e) => {
                warn!(log, "Failed to lock for schedule CurrentBranch message sending"; "reason" => format!("{}", e), "block_header_hash" => block_header.hash.to_base58_check());
            }
        }
    }

    /// Handles validated block.
    ///
    /// This logic is equivalent to [chain_validator.ml][let on_request]
    /// if applied block is winner we need to:
    /// - set current head
    /// - set bootstrapped flag
    /// - broadcast new current head/branch to peers (if bootstrapped)
    /// - start test chain (if needed) (TODO: TE-123 - not implemented yet)
    /// - update checkpoint (TODO: TE-210 - not implemented yet)
    /// - reset mempool_prevalidator
    /// ...
    fn process_applied_block(
        &mut self,
        ctx: &Context<ChainManagerMsg>,
        validated_block: ProcessValidatedBlock,
    ) -> Result<(), StateError> {
        let ProcessValidatedBlock {
            block,
            chain_id,
            block_metadata_hash,
            ops_metadata_hash,
            result_roundtrip_timer,
        } = validated_block;
        let result_roundtrip_timer = result_roundtrip_timer.elapsed();
        let log = ctx.system.log();

        // we try to set it as "new current head", if some means set, if none means just ignore block
        if let Some((new_head, new_head_result)) = self
            .current_head_state
            .try_update_new_current_head(&block)?
        {
            let mut is_bootstrapped = self.current_bootstrap_state.is_bootstrapped();

            let shell_automaton_msg = ShellAutomatonMsg::BlockApplied(
                ChainId::clone(&chain_id),
                BlockHeader::clone(&block.header),
                BlockHash::clone(&block.hash),
                block_metadata_hash,
                ops_metadata_hash,
                is_bootstrapped,
            );
            if let Err(err) = self.shell_automaton.send(shell_automaton_msg) {
                warn!(ctx.system.log(), "Failed to send message to shell_automaton"; "reason" => format!("{:?}", err));
            }

            if is_bootstrapped {
                info!(log, "New current head";
                           "block_header_hash" => new_head.block_hash().to_base58_check(),
                           "result_roundtrip_timer" => format!("{:?}", result_roundtrip_timer),
                           "level" => new_head.level(),
                           "result" => format!("{}", new_head_result)
                );
            } else {
                debug!(log, "New current head";
                            "block_header_hash" => new_head.block_hash().to_base58_check(),
                            "result_roundtrip_timer" => format!("{:?}", result_roundtrip_timer),
                            "level" => new_head.level(),
                            "result" => format!("{}", new_head_result)
                );
            }

            // notify other actors that new current head was changed
            self.shell_channel.tell(
                Publish {
                    msg: ShellChannelMsg::NewCurrentHead(Arc::new(
                        NewCurrentHeadNotification::new(
                            chain_id.clone(),
                            block.clone(),
                            is_bootstrapped,
                        ),
                    )),
                    topic: ShellChannelTopic::ShellNewCurrentHead.into(),
                },
                None,
            );

            if !is_bootstrapped {
                let chain_manager_current_level = new_head.level();

                let remote_best_known_level = match self.remote_current_head_state.as_ref() {
                    Some(head) => *head.level(),
                    None => 0,
                };

                is_bootstrapped = self.current_bootstrap_state.update_by_new_local_head(
                    remote_best_known_level,
                    *chain_manager_current_level,
                );

                if is_bootstrapped {
                    info!(log, "Bootstrapped (chain_manager)";
                       "num_of_peers_for_bootstrap_threshold" => self.current_bootstrap_state.num_of_peers_for_bootstrap_threshold(),
                       "remote_best_known_level" => remote_best_known_level,
                       "reached_on_level" => chain_manager_current_level);
                }
            }

            // TODO: TE-369 - lazy feature, if multiple messages are waiting in queue, we just want to send the last one as first one and the other discard

            // broadcast new head/branch to other peers
            // we can do this, only if we are bootstrapped,
            // e.g. if we just start to bootstrap from the scratch, we dont want to spam other nodes (with higher level)
            if is_bootstrapped {
                // advertise new branch or new head
                match new_head_result {
                    HeadResult::BranchSwitch => {
                        ChainManager::advertise_current_branch_to_p2p(
                            &chain_id,
                            self.chain_state.get_caboose(&chain_id)?,
                            &block,
                            self.peers.values(),
                            &self.p2p_reader_sender,
                            &log,
                        );
                    }
                    HeadResult::HeadIncrement => (),
                }
            }
        }

        Ok(())
    }

    pub(crate) fn handle_first_initialization_done(&self, log: Logger) {
        // lets handle first initialization
        match self.first_initialization_done_result_callback.lock() {
            Ok(mut first_initialization_done_result_callback) => {
                // here we take out the callback to be used just once
                if let Some(first_initialization_done_result_callback) =
                    first_initialization_done_result_callback.take()
                {
                    if let Err(e) = dispatch_oneshot_result(
                        Some(first_initialization_done_result_callback),
                        || (),
                    ) {
                        warn!(log, "Failed to dispatch initialization result for ChainManager"; "reason" => format!("{}", e));
                    }
                }
            }
            Err(e) => {
                warn!(log, "Failed to lock first_initialization_done_result_callback"; "reason" => format!("{}", e));
            }
        }
    }

    fn clear_peer_data(&mut self, peer: SocketAddr) {
        // remove peer from inner state
        if let Some(mut peer_state) = self.peers.remove(&peer) {
            let peer_id = peer_state.peer_id.clone();
            // clear innner state (not needed, it will be drop)
            peer_state.clear();
            // tell bootstrapper to clean potential data
            if let Some(peer_branch_bootstrapper) = self.chain_state.peer_branch_bootstrapper() {
                peer_branch_bootstrapper.tell(CleanPeerData(peer_id), None);
            }
        }
    }
}

impl
    ActorFactoryArgs<(
        ChainFeederRef,
        NetworkChannelRef,
        ShellAutomatonSender,
        ShellChannelRef,
        PersistentStorage,
        Arc<Mutex<P2pReaderSender>>,
        Arc<ProtocolRunnerApi>,
        StorageInitInfo,
        bool,
        Head,
        usize,
        Arc<Mutex<Option<OneshotResultCallback<()>>>>,
    )> for ChainManager
{
    fn create_args(
        (
            block_applier,
            network_channel,
            shell_automaton,
            shell_channel,
            persistent_storage,
            p2p_reader_sender,
            tezos_protocol_api,
            init_storage_data,
            is_sandbox,
            hydrated_current_head,
            num_of_peers_for_bootstrap_threshold,
            first_initialization_done_result_callback,
        ): (
            ChainFeederRef,
            NetworkChannelRef,
            ShellAutomatonSender,
            ShellChannelRef,
            PersistentStorage,
            Arc<Mutex<P2pReaderSender>>,
            Arc<ProtocolRunnerApi>,
            StorageInitInfo,
            bool,
            Head,
            usize,
            Arc<Mutex<Option<OneshotResultCallback<()>>>>,
        ),
    ) -> Self {
        ChainManager {
            network_channel,
            shell_automaton: shell_automaton.clone(),
            shell_channel: shell_channel.clone(),
            block_storage: Box::new(BlockStorage::new(&persistent_storage)),
            block_meta_storage: Box::new(BlockMetaStorage::new(&persistent_storage)),
            p2p_reader_sender,
            chain_state: BlockchainState::new(
                shell_automaton,
                block_applier,
                &persistent_storage,
                Arc::new(init_storage_data.chain_id.clone()),
                Arc::new(init_storage_data.genesis_block_header_hash.clone()),
                tezos_protocol_api.tokio_runtime.clone(),
            ),
            peers: HashMap::new(),
            current_head_state: HeadState::new(
                &persistent_storage,
                hydrated_current_head,
                Arc::new(init_storage_data.chain_id),
            ),
            remote_current_head_state: RemoteBestKnownCurrentHead::new(),
            shutting_down: false,
            stats: Stats {
                unseen_block_count: 0,
                unseen_block_last: Instant::now(),
                unseen_block_operations_count: 0,
                unseen_block_operations_last: Instant::now(),
                actor_received_messages_count: 0,
            },
            is_sandbox,
            current_bootstrap_state: SynchronizationBootstrapState::new(
                num_of_peers_for_bootstrap_threshold,
                false,
            ),
            tezos_protocol_api,
            reused_protocol_runner_connection: None,
            first_initialization_done_result_callback,
        }
    }
}

impl Actor for ChainManager {
    type Msg = ChainManagerMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        // subscribe chain_manager to all required channels
        subscribe_with_response_to_network_events(
            &self.network_channel,
            ctx.myself(),
            SubscribedResponse {
                topic: NetworkChannelTopic::NetworkEvents.into(),
            }
            .into(),
        );
        subscribe_to_shell_shutdown(&self.shell_channel, ctx.myself());

        let log = ctx.system.log();

        // just rehydrate and check mempool if needed refresh for current_head (in case of ChainManager's restart - can happen?)
        match self.current_head_state.reload_current_head_state() {
            Ok(Some(previous)) => {
                let (previous_block_hash, previous_level, previous_fitness) =
                    previous.to_debug_info();
                let (current_block_hash, current_level, current_fitness) =
                    self.current_head_state.as_ref().to_debug_info();
                info!(log, "Current head was reloaded";
                           "block_hash" => format!("{} -> {}", previous_block_hash, current_block_hash),
                           "level" => format!("{} -> {}", previous_level, current_level),
                           "fitness" => format!("{} -> {}", previous_fitness, current_fitness))
            }
            Ok(None) => (/* nothing changed, so nothing to do */),
            Err(e) => warn!(log, "Failed to reload current head"; "reason" => e),
        };

        // check is_bootstrapped and potentially run mempool and reset with current_head
        if self.current_bootstrap_state.is_bootstrapped() {
            info!(log, "Bootstrapped on startup (chain_manager)";
                       "num_of_peers_for_bootstrap_threshold" => self.current_bootstrap_state.num_of_peers_for_bootstrap_threshold());

            // if bootstrapped, run mempool with actual current_head
            match self
                .block_storage
                .get(self.current_head_state.as_ref().block_hash())
            {
                Ok(Some(_)) => (),
                Ok(None) => warn!(
                    log,
                    "Failed to find current head block header for reseting mempool"
                ),
                Err(e) => {
                    warn!(log, "Failed to read current head block header for reseting mempool"; "reason" => format!("{}", e))
                }
            }
        }

        ctx.schedule::<Self::Msg, _>(
            ASK_CURRENT_HEAD_INITIAL_DELAY,
            ASK_CURRENT_HEAD_INTERVAL,
            ctx.myself(),
            None,
            AskPeersAboutCurrentHead {
                last_received_timeout: Some(CURRENT_HEAD_LAST_RECEIVED_ACCEPT_TIMEOUT),
            }
            .into(),
        );
        ctx.schedule::<Self::Msg, _>(
            LOG_INTERVAL / 2,
            LOG_INTERVAL,
            ctx.myself(),
            None,
            LogStats.into(),
        );

        let silent_peer_timeout = if self.is_sandbox {
            SILENT_PEER_TIMEOUT_SANDBOX
        } else {
            SILENT_PEER_TIMEOUT
        };
        ctx.schedule::<Self::Msg, _>(
            silent_peer_timeout,
            silent_peer_timeout,
            ctx.myself(),
            None,
            DisconnectStalledPeers {
                silent_peer_timeout,
            }
            .into(),
        );

        info!(log, "Chain manager started";
                   "main_chain_id" => self.chain_state.get_chain_id().to_base58_check());
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.stats.actor_received_messages_count += 1;
        self.receive(ctx, msg, sender);
    }
}

impl Receive<LogStats> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, _msg: LogStats, _sender: Sender) {
        let log = ctx.system.log();
        let (local, local_level, local_fitness) = self.current_head_state.as_ref().to_debug_info();

        let (remote, remote_level, remote_fitness) = match self.remote_current_head_state.as_ref() {
            Some(remote_head) => remote_head.to_debug_info(),
            None => ("-none-".to_string(), 0, "-none-".to_string()),
        };

        info!(log, "Head info";
            "local" => local,
            "local_level" => local_level,
            "local_fitness" => local_fitness,
            "remote" => remote,
            "remote_level" => remote_level,
            "remote_fitness" => remote_fitness,
            "bootstrapped" => self.current_bootstrap_state.is_bootstrapped());
        info!(log, "Blocks, operations, messages info";
            "last_received_block_headers_count" => self.stats.get_and_clear_unseen_block_headers_count(),
            "last_received_block_operations_count" => self.stats.get_and_clear_unseen_block_operations_count(),
            "last_block_secs" => self.stats.unseen_block_last.elapsed().as_secs(),
            "last_block_operations_secs" => self.stats.unseen_block_operations_last.elapsed().as_secs(),
            "mempool_operation_state" => "none",
            "actor_received_messages_count" => self.stats.get_and_clear_actor_received_messages_count(),
            "peer_count" => self.peers.len());
        // TODO: TE-369 - peers stats
        for peer in self.peers.values() {
            info!(log, "Peer state info";
                "peer_id" => format!("{:?}", peer.peer_id),
                "current_head_request_secs" => peer.current_head_request_last.elapsed().as_secs(),
                "current_head_response_secs" => peer.current_head_response_last.elapsed().as_secs(),
                "queued_block_headers" => {
                    match peer.queues.queued_block_headers.try_lock() {
                        Ok(queued_block_headers) => {
                            match queued_block_headers
                                .iter()
                                .map(|(_, requested_time)| requested_time)
                                .minmax_by(|left_requested_time, right_requested_time| left_requested_time.cmp(right_requested_time)) {
                                MinMaxResult::NoElements => "-empty-".to_string(),
                                MinMaxResult::OneElement(x) => format!("(1 item, requested_time: {:?}, {:?})", x.elapsed(), queued_block_headers.iter().map(|(b, requested_time)| format!("{} ({:?})", b.to_base58_check(), requested_time.elapsed())).collect::<Vec<_>>().join(", ")),
                                MinMaxResult::MinMax(x, y) => format!("({} items, oldest_request_elapsed_time: {:?}, last_request_elapsed_time: {:?}, {:?})", queued_block_headers.len(), x.elapsed(), y.elapsed(), queued_block_headers.iter().map(|(b, requested_time)| format!("{} ({:?})", b.to_base58_check(), requested_time.elapsed())).collect::<Vec<_>>().join(", "))
                            }
                        },
                        _ =>  "-failed-to-collect-".to_string()
                    }
                },
                "queued_block_operations" => {
                    match peer.queues.queued_block_operations.try_lock() {
                        Ok(queued_block_operations) => {
                            match queued_block_operations
                                .iter()
                                .map(|(_, (_, requested_time))| requested_time)
                                .minmax_by(|left_requested_time, right_requested_time| left_requested_time.cmp(right_requested_time)) {
                                MinMaxResult::NoElements => "-empty-".to_string(),
                                MinMaxResult::OneElement(x) => format!("(1 item, requested_time: {:?}, {:?})", x.elapsed(), queued_block_operations.iter().map(|(b, (_, requested_time))| format!("{} ({:?})", b.to_base58_check(), requested_time.elapsed())).collect::<Vec<_>>().join(", ")),
                                MinMaxResult::MinMax(x, y) => format!("({} items, oldest_request_elapsed_time: {:?}, last_request_elapsed_time: {:?}, {:?})", queued_block_operations.len(), x.elapsed(), y.elapsed(), queued_block_operations.iter().map(|(b, (_, requested_time))| format!("{} ({:?})", b.to_base58_check(), requested_time.elapsed())).collect::<Vec<_>>().join(", "))
                            }
                        },
                        _ =>  "-failed-to-collect-".to_string()
                    }
                },
                "mempool_queued_mempool_operations" => format!("{}|{}", peer.queued_mempool_operations.len(), peer.queued_mempool_operations.iter().map(|operation_hash| operation_hash.to_base58_check()).collect::<Vec<_>>().join(", ")),
                "mempool_operations_request_secs" => peer.mempool_operations_request_last.map(|mempool_operations_request_last| mempool_operations_request_last.elapsed().as_secs()),
                "mempool_operations_response_secs" => peer.mempool_operations_response_last.map(|mempool_operations_response_last| mempool_operations_response_last.elapsed().as_secs()),
                "current_head_level" => peer.current_head_level,
                "current_head_update_secs" => peer.current_head_update_last.elapsed().as_secs());
        }
    }
}

impl Receive<DisconnectStalledPeers> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: DisconnectStalledPeers, _sender: Sender) {
        let log = ctx.system.log();
        self.peers.iter()
            .for_each(|(_uri, state)| {
                let current_head_response_pending = state.current_head_request_last > state.current_head_response_last;
                let known_higher_head = match state.current_head_level {
                    Some(peer_level) => has_any_higher_than(&self.current_head_state, &self.remote_current_head_state, peer_level),
                    None => true,
                };

                let should_disconnect = if current_head_response_pending && (state.current_head_request_last - state.current_head_response_last > msg.silent_peer_timeout) {
                    warn!(log, "Peer did not respond to our request for current_head on time"; "request_secs" => state.current_head_request_last.elapsed().as_secs(), "response_secs" => state.current_head_response_last.elapsed().as_secs(),
                                            "peer_ip" => state.peer_id.address.to_string());
                    true
                } else if known_higher_head && (state.current_head_update_last.elapsed() > CURRENT_HEAD_LEVEL_UPDATE_TIMEOUT) {
                    warn!(log, "Peer failed to update its current head";
                                            "request_secs" => state.current_head_request_last.elapsed().as_secs(),
                                            "response_secs" => state.current_head_response_last.elapsed().as_secs(),
                                            "current_head_update_last" => state.current_head_update_last.elapsed().as_secs(),
                                            "peer_current_level" => {
                                                if let Some(level) = state.current_head_level {
                                                    level.to_string()
                                                } else {
                                                    "-".to_string()
                                                }
                                            },
                                            "node_current_level_remote" => {
                                                match self.remote_current_head_state.as_ref() {
                                                    Some(remote_head) => {
                                                        let (_, remote_level, _) = remote_head.to_debug_info();
                                                        remote_level.to_string()
                                                    }
                                                    None => "-none-".to_string(),
                                                }
                                            },
                                            "node_current_level_local" => {
                                                let (_, local_level, _) = self.current_head_state.as_ref().to_debug_info();
                                                local_level.to_string()
                                            },
                                            "peer_ip" => state.peer_id.address.to_string());
                    true
                } else if state.mempool_operations_response_pending(msg.silent_peer_timeout) {
                    warn!(ctx.system.log(), "Peer is not providing requested mempool operations";
                                            "queued_count" => state.queued_mempool_operations.len(),
                                            "mempool_operations_request_secs" => state.mempool_operations_request_last.map(|mempool_operations_request_last| mempool_operations_request_last.elapsed().as_secs()),
                                            "mempool_operations_response_secs" => state.mempool_operations_response_last.map(|mempool_operations_response_last| mempool_operations_response_last.elapsed().as_secs()),
                                            "peer_ip" => state.peer_id.address.to_string());
                    true
                } else {
                    false
                };

                if should_disconnect {
                    if let Err(err) = self.shell_automaton.send(ShellAutomatonMsg::PeerStalled(state.peer_id.clone())) {
                        warn!(log, "Failed to send message to shell_automaton (chain_manager)"; "reason" => format!("{:?}", err));
                    }
                }
            });
    }
}

impl Receive<NetworkChannelMsg> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: NetworkChannelMsg, _: Sender) {
        match self.process_network_channel_message(ctx, msg) {
            Ok(_) => (),
            Err(e) => {
                warn!(ctx.system.log(), "Failed to process network channel message"; "reason" => format!("{:?}", e))
            }
        }
    }
}

impl Receive<ShellChannelMsg> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, _: &Context<Self::Msg>, msg: ShellChannelMsg, _sender: Sender) {
        self.process_shell_channel_message(msg);
    }
}

impl Receive<AskPeersAboutCurrentHead> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(
        &mut self,
        ctx: &Context<Self::Msg>,
        msg: AskPeersAboutCurrentHead,
        _sender: Sender,
    ) {
        let ChainManager {
            peers,
            chain_state,
            shell_automaton,
            ..
        } = self;

        let p2p_msg: Arc<PeerMessageResponse> =
            GetCurrentHeadMessage::new(chain_state.get_chain_id().as_ref().clone()).into();
        peers.iter_mut().for_each(|(_, peer)| {
            let can_request = match msg.last_received_timeout {
                Some(last_received_timeout) => {
                    peer.current_head_response_last.elapsed() > last_received_timeout
                }
                None => true,
            };
            if can_request {
                peer.current_head_request_last = Instant::now();
                tell_peer(
                    &shell_automaton,
                    &peer.peer_id,
                    p2p_msg.clone(),
                    &ctx.system.log(),
                );
            }
        });
    }
}

impl Receive<PeerBranchSynchronizationDone> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: PeerBranchSynchronizationDone, _: Sender) {
        if let Err(e) = self.resolve_is_bootstrapped(&msg, &ctx.system.log()) {
            warn!(ctx.system.log(), "Failed to resolve is_bootstrapped for chain manager"; "msg" => format!("{:?}", msg), "reason" => format!("{:?}", e))
        }
    }
}

impl Receive<ProcessValidatedBlock> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: ProcessValidatedBlock, _: Sender) {
        match self.process_applied_block(ctx, msg) {
            Ok(_) => (),
            Err(e) => {
                warn!(ctx.system.log(), "Failed to process validated block"; "reason" => format!("{:?}", e))
            }
        }
    }
}

impl Receive<InjectBlockRequest> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: InjectBlockRequest, _: Sender) {
        let InjectBlockRequest {
            request,
            result_callback,
        } = msg;
        match self.process_injected_block(request, result_callback, ctx) {
            Ok(_) => (),
            Err(e) => {
                warn!(ctx.system.log(), "Failed to inject block"; "reason" => format!("{:?}", e))
            }
        }
    }
}

impl Receive<SubscribedResponse> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SubscribedResponse, _: Sender) {
        if msg.topic == NetworkChannelTopic::NetworkEvents.into() {
            self.handle_first_initialization_done(ctx.system.log());
        }
    }
}

pub enum P2pReaderEvent {
    SendDataResponse(Arc<PeerId>, Arc<PeerMessageResponse>),
    SendCurrentBranchToPeer(SendCurrentBranchToPeerRequest),
    ShuttingDown,
}

pub type P2pReaderSender = std::sync::mpsc::Sender<P2pReaderEvent>;

pub struct SendCurrentBranchToPeerRequest {
    peer_id: Arc<PeerId>,
    chain_id: ChainId,
    caboose: Option<Head>,
    block_header: Arc<BlockHeaderWithHash>,
}

impl From<SendCurrentBranchToPeerRequest> for P2pReaderEvent {
    fn from(request: SendCurrentBranchToPeerRequest) -> Self {
        P2pReaderEvent::SendCurrentBranchToPeer(request)
    }
}

/// Spawn inner thread for heavy readonly operations, like calculation of history...
fn spawn_p2p_reader_thread(
    identity_peer_id: CryptoboxPublicKeyHash,
    persistent_storage: &PersistentStorage,
    shell_automaton: ShellAutomatonSender,
    log: Logger,
) -> Result<(P2pReaderSender, ThreadWatcher), anyhow::Error> {
    // spawn thread which processes event
    let thread_name = String::from("chain-p2p-reader");
    let (event_sender, event_receiver) = std::sync::mpsc::channel();
    let mut thread_watcher = {
        let event_sender = event_sender.clone();
        ThreadWatcher::start(
            thread_name.clone(),
            Box::new(move || {
                event_sender
                    .send(P2pReaderEvent::ShuttingDown)
                    .map_err(|e| e.into())
            }),
        )
    };

    let thread = {
        let run = thread_watcher.thread_running_status().clone();
        let block_storage = BlockStorage::new(persistent_storage);
        let block_meta_storage = BlockMetaStorage::new(persistent_storage);
        let operations_storage = OperationsStorage::new(persistent_storage);

        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                while run.load(Ordering::Acquire) {
                    // let's handle event, if any
                    if let Ok(event) = event_receiver.recv() {
                        match event {
                            P2pReaderEvent::SendCurrentBranchToPeer(SendCurrentBranchToPeerRequest {peer_id, chain_id, caboose, block_header}) => {
                                // we needed to process this in separate thread, because history calculation in synced mainnet took around 100-400ms and varies
                                // so for example when reconnecting, for 100 peers it means, 100x(100-400)ms = 10-40s delay for chain_manager processing

                                // calculate history for peer
                                match BlockchainState::compute_history(
                                    &block_meta_storage,
                                    caboose,
                                    &block_header.hash,
                                    HISTORY_MAX_SIZE,
                                    &Seed::new(&identity_peer_id, &peer_id.public_key_hash),
                                ) {
                                    Ok(history) => {
                                        tell_peer(
                                            &shell_automaton,
                                            &peer_id,
                                            CurrentBranchMessage::new(
                                                chain_id,
                                                CurrentBranch::new(
                                                    block_header.header.as_ref().clone(),
                                                    history,
                                                ),
                                            )
                                                .into(),
                                            &log,
                                        );
                                    }
                                    Err(e) => {
                                        warn!(log, "Failed to calculate history for sending CurrentBranch"; "reason" => e);
                                    }
                                }
                            }
                            P2pReaderEvent::SendDataResponse(peer, request) => {
                                match request.message() {
                                    PeerMessage::GetBlockHeaders(message) => {
                                        for block_hash in message.get_block_headers() {
                                            match block_storage.get(block_hash) {
                                                Ok(Some(block)) => {
                                                    let msg: BlockHeaderMessage =
                                                        (*block.header).clone().into();
                                                    tell_peer(&shell_automaton, &peer, msg.into(), &log);
                                                }
                                                Ok(None) => (),
                                                Err(e) => warn!(log, "Failed to read block header"; "reason" => e, "block_hash" => block_hash.to_base58_check()),
                                            }
                                        }
                                    }
                                    PeerMessage::GetOperationsForBlocks(message) =>{
                                        for get_op in message.get_operations_for_blocks() {
                                            if get_op.validation_pass() < 0 {
                                                continue;
                                            }

                                            let key = get_op.into();
                                            match operations_storage.get(&key) {
                                                Ok(Some(op)) => tell_peer(&shell_automaton, &peer, op.into(), &log),
                                                Ok(None) => (),
                                                Err(e) => warn!(log, "Failed to read block header operations"; "reason" => e, "key" => {
                                                    let OperationKey {
                                                        block_hash,
                                                        validation_pass,
                                                    } = key;
                                                    format!("({}, {})", block_hash.to_base58_check(), validation_pass)
                                                }),
                                            }
                                        }
                                    }
                                    _ => {
                                        // do not handle anything more
                                    },
                                }
                            }
                            P2pReaderEvent::ShuttingDown => {
                                // just finish the loop
                                info!(log, "P2p reader thread worker received shutting down event");
                                break;
                            }
                        }
                    }
                }

                info!(log, "P2p reader thread finished");
            })?
    };
    thread_watcher.set_thread(thread);
    Ok((event_sender, thread_watcher))
}
