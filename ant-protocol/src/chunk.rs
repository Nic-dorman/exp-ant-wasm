//! Chunk message types for the ANT protocol.
//!
//! These types are byte-compatible with `ant_node::ant_protocol::chunk`.
//! Struct definitions, field names, field order, and serde attributes are
//! identical to ensure postcard serialization produces the same bytes.

use serde::{Deserialize, Serialize};

/// Content-addressed identifier (32 bytes).
pub type XorName = [u8; 32];

// =============================================================================
// Constants (identical to ant_node::ant_protocol)
// =============================================================================

/// Protocol identifier for chunk operations.
pub const CHUNK_PROTOCOL_ID: &str = "autonomi/ant/chunk/v1";

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum chunk size in bytes (4MB).
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum wire message size in bytes (5MB).
pub const MAX_WIRE_MESSAGE_SIZE: usize = 5 * 1024 * 1024;

/// Data type identifier for chunks.
pub const DATA_TYPE_CHUNK: u32 = 0;

/// Version byte prefix for single-node payment proofs.
pub const PROOF_TAG_SINGLE_NODE: u8 = 0x01;

/// Version byte prefix for merkle payment proofs.
pub const PROOF_TAG_MERKLE: u8 = 0x02;

/// Number of closest peers for quoting/storage.
pub const CLOSE_GROUP_SIZE: usize = 5;

/// Simple majority: `(CLOSE_GROUP_SIZE / 2) + 1`.
pub const CLOSE_GROUP_MAJORITY: usize = (CLOSE_GROUP_SIZE / 2) + 1;

// =============================================================================
// Message envelope
// =============================================================================

/// Enum of all chunk protocol message types.
///
/// Variant order and naming must match `ant_node::ant_protocol::ChunkMessageBody`
/// exactly — postcard uses sequential discriminants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkMessageBody {
    /// Request to store a chunk.
    PutRequest(ChunkPutRequest),
    /// Response to a PUT request.
    PutResponse(ChunkPutResponse),
    /// Request to retrieve a chunk.
    GetRequest(ChunkGetRequest),
    /// Response to a GET request.
    GetResponse(ChunkGetResponse),
    /// Request a storage quote.
    QuoteRequest(ChunkQuoteRequest),
    /// Response with a storage quote.
    QuoteResponse(ChunkQuoteResponse),
    /// Request a merkle candidate quote for batch payments.
    MerkleCandidateQuoteRequest(MerkleCandidateQuoteRequest),
    /// Response with a merkle candidate quote.
    MerkleCandidateQuoteResponse(MerkleCandidateQuoteResponse),
}

/// Wire-format wrapper pairing a sender-assigned `request_id` with a message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMessage {
    /// Sender-assigned identifier, echoed back in the response.
    pub request_id: u64,
    /// The protocol message body.
    pub body: ChunkMessageBody,
}

impl ChunkMessage {
    /// Encode the message to bytes using postcard.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        postcard::to_stdvec(self).map_err(|e| ProtocolError::SerializationFailed(e.to_string()))
    }

    /// Decode a message from bytes using postcard.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: data.len(),
                max_size: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        postcard::from_bytes(data).map_err(|e| ProtocolError::DeserializationFailed(e.to_string()))
    }
}

// =============================================================================
// PUT Request/Response
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutRequest {
    pub address: XorName,
    pub content: Vec<u8>,
    pub payment_proof: Option<Vec<u8>>,
}

impl ChunkPutRequest {
    #[must_use]
    pub fn new(address: XorName, content: Vec<u8>) -> Self {
        Self {
            address,
            content,
            payment_proof: None,
        }
    }

    #[must_use]
    pub fn with_payment(address: XorName, content: Vec<u8>, payment_proof: Vec<u8>) -> Self {
        Self {
            address,
            content,
            payment_proof: Some(payment_proof),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkPutResponse {
    Success { address: XorName },
    AlreadyExists { address: XorName },
    PaymentRequired { message: String },
    Error(ProtocolError),
}

// =============================================================================
// GET Request/Response
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetRequest {
    pub address: XorName,
}

impl ChunkGetRequest {
    #[must_use]
    pub fn new(address: XorName) -> Self {
        Self { address }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkGetResponse {
    Success { address: XorName, content: Vec<u8> },
    NotFound { address: XorName },
    Error(ProtocolError),
}

// =============================================================================
// Quote Request/Response
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkQuoteRequest {
    pub address: XorName,
    pub data_size: u64,
    pub data_type: u32,
}

impl ChunkQuoteRequest {
    #[must_use]
    pub fn new(address: XorName, data_size: u64) -> Self {
        Self {
            address,
            data_size,
            data_type: DATA_TYPE_CHUNK,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkQuoteResponse {
    Success { quote: Vec<u8>, already_stored: bool },
    Error(ProtocolError),
}

// =============================================================================
// Merkle Candidate Quote Request/Response
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCandidateQuoteRequest {
    pub address: XorName,
    pub data_type: u32,
    pub data_size: u64,
    pub merkle_payment_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MerkleCandidateQuoteResponse {
    Success { candidate_node: Vec<u8> },
    Error(ProtocolError),
}

// =============================================================================
// Protocol Errors
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolError {
    SerializationFailed(String),
    DeserializationFailed(String),
    MessageTooLarge { size: usize, max_size: usize },
    ChunkTooLarge { size: usize, max_size: usize },
    AddressMismatch { expected: XorName, actual: XorName },
    StorageFailed(String),
    PaymentFailed(String),
    QuoteFailed(String),
    Internal(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
            Self::MessageTooLarge { size, max_size } => {
                write!(f, "message size {size} exceeds maximum {max_size}")
            }
            Self::ChunkTooLarge { size, max_size } => {
                write!(f, "chunk size {size} exceeds maximum {max_size}")
            }
            Self::AddressMismatch { expected, actual } => {
                write!(
                    f,
                    "address mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Self::StorageFailed(msg) => write!(f, "storage failed: {msg}"),
            Self::PaymentFailed(msg) => write!(f, "payment failed: {msg}"),
            Self::QuoteFailed(msg) => write!(f, "quote failed: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_get_request_roundtrip() {
        let address = [0xCD; 32];
        let msg = ChunkMessage {
            request_id: 7,
            body: ChunkMessageBody::GetRequest(ChunkGetRequest::new(address)),
        };
        let encoded = msg.encode().expect("encode");
        let decoded = ChunkMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded.request_id, 7);
        match decoded.body {
            ChunkMessageBody::GetRequest(req) => assert_eq!(req.address, address),
            _ => panic!("expected GetRequest"),
        }
    }

    #[test]
    fn test_get_response_success_roundtrip() {
        let address = [0xAB; 32];
        let content = vec![1, 2, 3, 4, 5];
        let msg = ChunkMessage {
            request_id: 42,
            body: ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                address,
                content: content.clone(),
            }),
        };
        let encoded = msg.encode().expect("encode");
        let decoded = ChunkMessage::decode(&encoded).expect("decode");
        match decoded.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success { address: a, content: c }) => {
                assert_eq!(a, address);
                assert_eq!(c, content);
            }
            _ => panic!("expected GetResponse::Success"),
        }
    }

    #[test]
    fn test_get_response_not_found_roundtrip() {
        let address = [0x12; 32];
        let msg = ChunkMessage {
            request_id: 0,
            body: ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address }),
        };
        let encoded = msg.encode().expect("encode");
        let decoded = ChunkMessage::decode(&encoded).expect("decode");
        match decoded.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: a }) => {
                assert_eq!(a, address);
            }
            _ => panic!("expected GetResponse::NotFound"),
        }
    }

    #[test]
    fn test_decode_rejects_oversized() {
        let oversized = vec![0u8; MAX_WIRE_MESSAGE_SIZE + 1];
        let result = ChunkMessage::decode(&oversized);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_constants_match_upstream() {
        assert_eq!(CLOSE_GROUP_SIZE, 5);
        assert_eq!(CLOSE_GROUP_MAJORITY, 3);
        assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024);
        assert_eq!(MAX_WIRE_MESSAGE_SIZE, 5 * 1024 * 1024);
        assert_eq!(DATA_TYPE_CHUNK, 0);
        assert_eq!(PROOF_TAG_SINGLE_NODE, 0x01);
        assert_eq!(PROOF_TAG_MERKLE, 0x02);
    }

    /// Cross-crate compatibility test: verify our encoding matches ant_node's.
    #[test]
    fn test_byte_compatibility_with_ant_node() {
        // Encode a GetRequest with ant-protocol
        let address = [0xAB; 32];
        let our_msg = ChunkMessage {
            request_id: 42,
            body: ChunkMessageBody::GetRequest(ChunkGetRequest::new(address)),
        };
        let our_bytes = our_msg.encode().expect("our encode");

        // Encode the same message with ant_node::ant_protocol
        let their_msg = ant_node::ant_protocol::ChunkMessage {
            request_id: 42,
            body: ant_node::ant_protocol::ChunkMessageBody::GetRequest(
                ant_node::ant_protocol::ChunkGetRequest::new(address),
            ),
        };
        let their_bytes = their_msg.encode().expect("ant_node encode");

        assert_eq!(
            our_bytes, their_bytes,
            "ant-protocol and ant_node::ant_protocol must produce identical bytes"
        );
    }

    /// Cross-crate: verify GetResponse::Success encoding matches.
    #[test]
    fn test_byte_compatibility_get_response_success() {
        let address = [0xCD; 32];
        let content = vec![10, 20, 30, 40, 50];

        let our_msg = ChunkMessage {
            request_id: 99,
            body: ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                address,
                content: content.clone(),
            }),
        };
        let our_bytes = our_msg.encode().expect("our encode");

        let their_msg = ant_node::ant_protocol::ChunkMessage {
            request_id: 99,
            body: ant_node::ant_protocol::ChunkMessageBody::GetResponse(
                ant_node::ant_protocol::ChunkGetResponse::Success { address, content },
            ),
        };
        let their_bytes = their_msg.encode().expect("ant_node encode");

        assert_eq!(our_bytes, their_bytes);
    }

    /// Cross-crate: verify PutRequest encoding matches.
    #[test]
    fn test_byte_compatibility_put_request() {
        let address = [0xEF; 32];
        let content = vec![1, 2, 3];
        let proof = vec![10, 20, 30];

        let our_msg = ChunkMessage {
            request_id: 100,
            body: ChunkMessageBody::PutRequest(ChunkPutRequest::with_payment(
                address,
                content.clone(),
                proof.clone(),
            )),
        };
        let our_bytes = our_msg.encode().expect("our encode");

        let their_msg = ant_node::ant_protocol::ChunkMessage {
            request_id: 100,
            body: ant_node::ant_protocol::ChunkMessageBody::PutRequest(
                ant_node::ant_protocol::ChunkPutRequest::with_payment(address, content, proof),
            ),
        };
        let their_bytes = their_msg.encode().expect("ant_node encode");

        assert_eq!(our_bytes, their_bytes);
    }
}
