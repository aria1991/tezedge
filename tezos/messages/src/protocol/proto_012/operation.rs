// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

//! Comparing to the previous protocol, multiple new operations has been added.
//!

use std::convert::TryFrom;

use crypto::hash::{
    BlockHash, BlockPayloadHash, ContextHash, HashTrait, OperationListListHash, Signature,
};
use tezos_encoding::binary_reader::BinaryReaderError;
use tezos_encoding::{
    enc::BinWriter,
    encoding::HasEncoding,
    nom::{self as nom_utils, NomReader, NomResult},
};

use nom::{combinator, sequence};

use crate::p2p::encoding::{
    block_header::{Fitness, Level},
    limits::BLOCK_HEADER_FITNESS_MAX_SIZE,
    operation::Operation as P2POperation,
};

pub use super::super::proto_011::operation::{
    ActivateAccountOperation, BallotOperation, DelegationOperation, FailingNoopOperation,
    OriginationOperation, ProposalsOperation, RevealOperation, SeedNonceRevelationOperation,
    TransactionOperation,
};

/// Operation contents.
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#operation-alpha-specific].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding)]
pub struct Operation {
    pub branch: BlockHash,
    pub contents: Vec<Contents>,
    pub signature: Signature,
}

impl NomReader for Operation {
    fn nom_read(bytes: &[u8]) -> NomResult<Self> {
        combinator::map(
            sequence::tuple((
                nom_utils::field("Operation::branch", BlockHash::nom_read),
                nom_utils::field("Operation::contents", signed_list(Contents::nom_read)),
                nom_utils::field("Operation::signature", Signature::nom_read),
            )),
            |(branch, contents, signature)| Operation {
                branch,
                contents,
                signature,
            },
        )(bytes)
    }
}

impl TryFrom<P2POperation> for Operation {
    type Error = BinaryReaderError;

    fn try_from(operation: P2POperation) -> Result<Self, Self::Error> {
        use crate::p2p::binary_message::BinaryRead;

        let branch = operation.branch().clone();
        let OperationContents {
            contents,
            signature,
        } = OperationContents::from_bytes(operation.data())?;
        Ok(Operation {
            branch,
            contents,
            signature,
        })
    }
}

/// Operation contents.
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#operation-alpha-specific].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding)]
pub struct OperationContents {
    pub contents: Vec<Contents>,
    pub signature: Signature,
}

#[rustfmt::skip] // TODO: let's add an attribute and derive this impl
impl NomReader for OperationContents {
    fn nom_read(bytes: &[u8]) -> NomResult<Self> {
        combinator::map(
            sequence::tuple((
                nom_utils::field("OperationContents::contents", signed_list(Contents::nom_read)),
                nom_utils::field("OperationContents::signature", Signature::nom_read),
            )),
            |(contents, signature)| OperationContents {
                contents,
                signature,
            },
        )(bytes)
    }
}

impl TryFrom<P2POperation> for OperationContents {
    type Error = BinaryReaderError;

    fn try_from(operation: P2POperation) -> Result<Self, Self::Error> {
        use crate::p2p::binary_message::BinaryRead;
        let OperationContents {
            contents,
            signature,
        } = OperationContents::from_bytes(operation.data())?;
        Ok(OperationContents {
            contents,
            signature,
        })
    }
}

/// Helper parser.
/// Parse all input, keeping place for signature.
#[inline(always)]
fn signed_list<'a, O, F>(parser: F) -> impl FnMut(nom_utils::NomInput<'a>) -> NomResult<'a, Vec<O>>
where
    F: FnMut(nom_utils::NomInput<'a>) -> NomResult<'a, O>,
    O: Clone,
{
    nom_utils::reserve(Signature::hash_size(), nom_utils::list(parser))
}

/// Operation contents.
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#alpha-operation-alpha-contents-determined-from-data-8-bit-tag].
///
/// Comparing to [super::super::proto_011::operation::Content], multiple variants was changed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader)]
#[encoding(tags = "u8")]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Contents {
    /// Seed_nonce_revelation (tag 1).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#seed-nonce-revelation-tag-1].
    #[encoding(tag = 1)]
    #[serde(rename = "seed_nonce_revelation")]
    SeedNonceRevelation(SeedNonceRevelationOperation),

    /// Double_endorsement_evidence (tag 2).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#double-endorsement-evidence-tag-2].
    #[encoding(tag = 2)]
    #[serde(rename = "double_endorsement_evidence")]
    DoubleEndorsementEvidence(DoubleEndorsementEvidenceOperation),

    /// Double_baking_evidence (tag 3).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#double-baking-evidence-tag-3].
    #[encoding(tag = 3)]
    #[serde(rename = "double_baking_evidence")]
    DoubleBakingEvidence(DoubleBakingEvidenceOperation),

    /// Activate_account (tag 4).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#activate-account-tag-4].
    #[encoding(tag = 4)]
    #[serde(rename = "activate_account")]
    ActivateAccount(ActivateAccountOperation),

    /// Proposals (tag 5).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#proposals-tag-5].
    #[encoding(tag = 5)]
    Proposals(ProposalsOperation),

    /// Ballot (tag 6).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#ballot-tag-6].
    #[encoding(tag = 6)]
    Ballot(BallotOperation),

    /// Double_preendorsement_evidence (tag 7).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#double-preendorsement-evidence-tag-7].
    #[encoding(tag = 7)]
    #[serde(rename = "double_preendorsement_evidence")]
    DoublePreendorsementEvidence(DoubleEndorsementEvidenceOperation),

    /// Failing_noop (tag 17).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#failing-noop-tag-17].
    #[encoding(tag = 17)]
    #[serde(rename = "failing_noop")]
    FailingNoop(FailingNoopOperation),

    /// Preendorsement (tag 20).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#id5].
    #[encoding(tag = 20)]
    Preendorsement(EndorsementOperation),

    /// Endorsement (tag 21).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#id6].
    #[encoding(tag = 21)]
    Endorsement(EndorsementOperation),

    /// Reveal (tag 107).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#reveal-tag-107].
    #[encoding(tag = 107)]
    Reveal(RevealOperation),
    /// Transaction (tag 108).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#transaction-tag-108].
    #[encoding(tag = 108)]
    Transaction(TransactionOperation),
    /// Origination (tag 109).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#origination-tag-109].
    #[encoding(tag = 109)]
    Origination(OriginationOperation),
    /// Delegation (tag 110).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#delegation-tag-110].
    #[encoding(tag = 110)]
    Delegation(DelegationOperation),
    // TODO(vlad):
    // Register_global_constant (tag 111)
    // Set_deposits_limit (tag 112)
    // Tx_rollup_origination (tag 150)
    // Tx_rollup_submit_batch (tag 151)
    // Sc_rollup_originate (tag 200)
    // Sc_rollup_add_messages (tag 201)
}

/// Inline endorsement content, Endorsement (tag 0).
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#endorsement-tag-0].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
pub struct InlinedEndorsementVariant {
    pub slot: u16,
    pub level: i32,
    pub round: i32,
    pub block_payload_hash: BlockPayloadHash,
}

/// Inlined endorsement contents.
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#alpha-inlined-endorsement-contents-5-bytes-8-bit-tag].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum InlinedEndorsementContents {
    /// Preendorsement (tag 20).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#endorsement-tag-0].
    #[encoding(tag = 20)]
    Preendorsement(InlinedEndorsementVariant),
    /// Endorsement (tag 21).
    /// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#endorsement-tag-0].
    #[encoding(tag = 21)]
    Endorsement(InlinedEndorsementVariant),
}

/// Inlined endorsement.
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#alpha-inlined-endorsement].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
pub struct InlinedEndorsement {
    pub branch: BlockHash,
    pub operations: InlinedEndorsementContents,
    pub signature: Signature,
}

/// Full Header.
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#endorsement-tag-0].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
pub struct FullHeader {
    #[encoding(builtin = "Int32")]
    pub level: Level,
    pub proto: u8,
    pub predecessor: BlockHash,
    #[encoding(timestamp)]
    pub timestamp: i64,
    pub validation_pass: u8,
    pub operations_hash: OperationListListHash,
    #[encoding(composite(
        dynamic = "BLOCK_HEADER_FITNESS_MAX_SIZE",
        list,
        dynamic,
        list,
        builtin = "Uint8"
    ))]
    pub fitness: Fitness,
    pub context: ContextHash,
    pub payload_hash: BlockPayloadHash,
    pub payload_round: u32,
    #[encoding(sized = "8", bytes)]
    pub proof_of_work_nonce: Vec<u8>,
    #[encoding(option, sized = "32", bytes)]
    pub seed_nonce_hash: Option<Vec<u8>>,
    pub liquidity_baking_escape_vote: bool,
    pub signature: Signature,
}

/// Double_endorsement_evidence (tag 2).
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#double-endorsement-evidence-tag-2].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
pub struct DoubleEndorsementEvidenceOperation {
    #[encoding(dynamic)]
    pub op1: InlinedEndorsement,
    #[encoding(dynamic)]
    pub op2: InlinedEndorsement,
}

/// Double_baking_evidence (tag 3).
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#double-baking-evidence-tag-3].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
pub struct DoubleBakingEvidenceOperation {
    #[encoding(dynamic)]
    pub bh1: FullHeader,
    #[encoding(dynamic)]
    pub bh2: FullHeader,
}

/// Inline endorsement content, Endorsement (tag 0).
/// See [https://tezos.gitlab.io/shell/p2p_api.html?highlight=p2p%20encodings#endorsement-tag-0].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasEncoding, NomReader, BinWriter)]
pub struct EndorsementOperation {
    pub slot: u16,
    pub level: i32,
    pub round: i32,
    pub block_payload_hash: BlockPayloadHash,
}
