//! WASM-compatible protocol types for the Autonomi chunk protocol.
//!
//! This crate provides the wire protocol types needed for chunk operations
//! on the Autonomi network. All types are byte-compatible with `ant_node::ant_protocol`
//! and compile to `wasm32-unknown-unknown`.

pub mod chunk;
pub mod pqc_tunnel;

pub use chunk::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, MerkleCandidateQuoteRequest,
    MerkleCandidateQuoteResponse, ProtocolError, CHUNK_PROTOCOL_ID, CLOSE_GROUP_MAJORITY,
    CLOSE_GROUP_SIZE, DATA_TYPE_CHUNK, MAX_CHUNK_SIZE, MAX_WIRE_MESSAGE_SIZE, PROOF_TAG_MERKLE,
    PROOF_TAG_SINGLE_NODE, PROTOCOL_VERSION,
};

/// Content-addressed identifier (32 bytes, BLAKE3 hash).
pub type XorName = [u8; 32];

/// Compute the content address (BLAKE3 hash) for the given data.
#[must_use]
pub fn compute_address(content: &[u8]) -> XorName {
    *blake3::hash(content).as_bytes()
}

/// A chunk of data with its content-addressed identifier.
#[derive(Debug, Clone)]
pub struct DataChunk {
    /// The content-addressed identifier (BLAKE3 of content).
    pub address: XorName,
    /// The raw data content.
    pub content: bytes::Bytes,
}

impl DataChunk {
    #[must_use]
    pub fn new(address: XorName, content: bytes::Bytes) -> Self {
        Self { address, content }
    }

    #[must_use]
    pub fn from_content(content: bytes::Bytes) -> Self {
        let address = compute_address(&content);
        Self { address, content }
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        self.address == compute_address(&self.content)
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.content.len()
    }
}
