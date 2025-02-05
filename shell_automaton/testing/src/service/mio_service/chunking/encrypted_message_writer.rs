// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::io::Write;

use tezos_messages::p2p::binary_message::{BinaryChunk, BinaryWrite, CONTENT_LENGTH_MAX};

use super::extendable_as_writable::ExtendableAsWritable;
use super::{ChunkWriter, WriteMessageError};
use shell_automaton::peer::PeerCrypto;

// BOX_ZERO_BYTES is subtracted since after encryption, chunk size will
// increase and we don't want it to overflow CONTENT_LENGTH_MAX.
const MAX_ENCRYPTED_CHUNK_SIZE: usize = CONTENT_LENGTH_MAX - crypto::crypto_box::BOX_ZERO_BYTES;

#[derive(Debug, Clone)]
pub struct EncryptedMessageWriter {
    bytes: Vec<u8>,
    /// Index of the chunk.
    chunk_index: usize,
    chunk_writer: ChunkWriter,
}

impl EncryptedMessageWriter {
    fn empty_initial_chunk_writer() -> ChunkWriter {
        ChunkWriter::new(BinaryChunk::from_content(&[]).unwrap())
    }

    pub fn try_new<M>(message: &M) -> Result<Self, WriteMessageError>
    where
        M: BinaryWrite,
    {
        Ok(Self {
            bytes: message.as_bytes()?,
            chunk_index: 0,
            chunk_writer: Self::empty_initial_chunk_writer(),
        })
    }

    /// Current chunk that needs to be written.
    ///
    /// Returns None if there's nothing more to send.
    fn current_chunk(&self) -> Option<&[u8]> {
        self.bytes
            .chunks(MAX_ENCRYPTED_CHUNK_SIZE)
            .nth(self.chunk_index)
            .filter(|x| x.len() > 0)
    }

    pub fn write_to<W>(
        &mut self,
        writer: &mut W,
        crypto: &mut PeerCrypto,
    ) -> Result<(), WriteMessageError>
    where
        W: Write,
    {
        if self.chunk_writer.is_empty() {
            if let Some(current_chunk) = self.current_chunk() {
                self.chunk_writer =
                    ChunkWriter::new(BinaryChunk::from_content(&crypto.encrypt(&current_chunk)?)?);
            } else {
                return Ok(());
            }
        }
        loop {
            self.chunk_writer.write_to(writer)?;

            if self.chunk_writer.is_finished() {
                self.chunk_index += 1;
                let chunk = match self.current_chunk() {
                    Some(chunk) => chunk,
                    None => return Ok(()),
                };

                self.chunk_writer =
                    ChunkWriter::new(BinaryChunk::from_content(&crypto.encrypt(&chunk)?)?);
            }
        }
    }

    pub fn write_to_extendable<T>(
        &mut self,
        extendable: &mut T,
        crypto: &mut PeerCrypto,
    ) -> Result<(), WriteMessageError>
    where
        T: Extend<u8>,
    {
        self.write_to(&mut ExtendableAsWritable::from(extendable), crypto)
    }
}
