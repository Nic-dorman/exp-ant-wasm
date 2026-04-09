//! Application-layer PQC tunnel for WebTransport.
//!
//! Provides envelope framing and symmetric encryption for the ML-KEM-768
//! key exchange tunnel. The ML-KEM operations themselves live in the
//! transport layers (ant-wasm and ant-node); this module handles only
//! the shared wire format and session cipher.
//!
//! # Wire format
//!
//! Every message inside a WebTransport bidi stream uses a 1-byte envelope
//! type discriminator followed by type-specific payload:
//!
//! ```text
//! Type 0x01 ClientHello:  [version: 2B BE u16][ek: 1184B]
//! Type 0x02 ServerAccept: [version: 2B BE u16][ct: 1088B][pubkey: 1952B][sig: 3309B]
//! Type 0x03 Encrypted:    [stream_seq: 4B BE u32][ciphertext...]
//! ```
//!
//! The ServerAccept includes the node's ML-DSA-65 public key and a signature
//! over `AUTH_SIGN_CONTEXT || client_ek || ct`, binding the authentication to
//! this specific handshake and preventing replay.
//!
//! The outer length-prefix framing (4-byte BE u32) is handled by the
//! transport layer, not this module.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};

/// PQC tunnel protocol version.
pub const PQC_VERSION: u16 = 2;

/// ML-KEM-768 encapsulation key size (FIPS 203).
pub const ML_KEM_768_EK_SIZE: usize = 1184;

/// ML-KEM-768 ciphertext size (FIPS 203).
pub const ML_KEM_768_CT_SIZE: usize = 1088;

/// ML-DSA-65 public key size (FIPS 204).
pub const ML_DSA_65_PK_SIZE: usize = 1952;

/// ML-DSA-65 signature size (FIPS 204).
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

/// BLAKE3 key derivation context for session keys.
const KDF_CONTEXT: &str = "ant-wt-pqc-v1";

/// Domain separator for authentication signatures.
/// The signed message is: AUTH_SIGN_CONTEXT || client_ek || ct
pub const AUTH_SIGN_CONTEXT: &[u8] = b"ant-wt-auth-v1";

/// Envelope type discriminator byte.
///
/// There is no plaintext type — the PQC tunnel is mandatory.
/// All WebTransport sessions must complete the authenticated handshake
/// before any data is exchanged.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeType {
    /// ML-KEM-768 ClientHello: version + encapsulation key.
    ClientHello = 0x01,
    /// ML-KEM-768 ServerAccept: version + ciphertext + ML-DSA-65 pubkey + signature.
    ServerAccept = 0x02,
    /// Encrypted ChunkMessage: stream_seq + ChaCha20-Poly1305 ciphertext.
    Encrypted = 0x03,
}

impl EnvelopeType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ClientHello),
            0x02 => Some(Self::ServerAccept),
            0x03 => Some(Self::Encrypted),
            _ => None,
        }
    }
}

/// Direction of a message within a bidi stream, used to construct unique nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// PQC tunnel errors.
#[derive(Debug)]
pub enum TunnelError {
    /// Envelope is too short or has wrong type byte.
    InvalidEnvelope(String),
    /// Version in handshake message is not supported.
    UnsupportedVersion(u16),
    /// ChaCha20-Poly1305 encryption failed.
    EncryptionFailed,
    /// ChaCha20-Poly1305 decryption failed (wrong key, tampered, or wrong nonce).
    DecryptionFailed,
    /// ML-DSA-65 signature verification failed.
    AuthenticationFailed,
    /// PeerId mismatch — derived PeerId does not match expected.
    PeerIdMismatch { expected: [u8; 32], actual: [u8; 32] },
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvelope(msg) => write!(f, "invalid PQC envelope: {msg}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported PQC version: {v}"),
            Self::EncryptionFailed => write!(f, "PQC tunnel encryption failed"),
            Self::DecryptionFailed => write!(f, "PQC tunnel decryption failed"),
            Self::AuthenticationFailed => write!(f, "ML-DSA-65 signature verification failed"),
            Self::PeerIdMismatch { expected, actual } => write!(
                f,
                "PeerId mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            ),
        }
    }
}

impl std::error::Error for TunnelError {}

// =============================================================================
// SessionCipher
// =============================================================================

/// Symmetric cipher for an established PQC tunnel session.
///
/// Wraps a 32-byte key derived from the ML-KEM shared secret via BLAKE3.
/// Encrypts and decrypts ChunkMessage payloads with ChaCha20-Poly1305.
pub struct SessionCipher {
    key: [u8; 32],
}

impl SessionCipher {
    /// Derive a session cipher from a 32-byte ML-KEM shared secret.
    ///
    /// Uses BLAKE3 `derive_key` with a fixed context string so the
    /// session key is domain-separated from any other use of the
    /// shared secret.
    pub fn from_shared_secret(ss: &[u8; 32]) -> Self {
        let key = blake3::derive_key(KDF_CONTEXT, ss);
        Self { key }
    }

    /// Encrypt a plaintext payload for the given stream and direction.
    pub fn encrypt(
        &self,
        stream_seq: u32,
        direction: Direction,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TunnelError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = build_nonce(stream_seq, direction);
        cipher
            .encrypt(&nonce.into(), plaintext)
            .map_err(|_| TunnelError::EncryptionFailed)
    }

    /// Decrypt a ciphertext payload for the given stream and direction.
    pub fn decrypt(
        &self,
        stream_seq: u32,
        direction: Direction,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TunnelError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = build_nonce(stream_seq, direction);
        cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|_| TunnelError::DecryptionFailed)
    }
}

impl Drop for SessionCipher {
    fn drop(&mut self) {
        // Best-effort zeroization of the key material.
        self.key.fill(0);
    }
}

// =============================================================================
// Nonce construction
// =============================================================================

/// Build a 12-byte ChaCha20-Poly1305 nonce from stream sequence and direction.
///
/// ```text
/// Bytes 0-3:  stream_seq (BE u32)
/// Byte  4:    direction (0x00 = C→S, 0x01 = S→C)
/// Bytes 5-11: 0x00
/// ```
///
/// Each bidi stream carries exactly one request and one response, so
/// `(stream_seq, direction)` is a unique nonce for each message in a session.
fn build_nonce(stream_seq: u32, direction: Direction) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&stream_seq.to_be_bytes());
    nonce[4] = match direction {
        Direction::ClientToServer => 0x00,
        Direction::ServerToClient => 0x01,
    };
    nonce
}

// =============================================================================
// Envelope encoding / decoding
// =============================================================================

/// Encode a ClientHello envelope payload (without the outer length prefix).
///
/// Format: `[0x01][version: 2B][ek: 1184B]` = 1187 bytes total.
pub fn encode_client_hello(ek_bytes: &[u8; ML_KEM_768_EK_SIZE]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 2 + ML_KEM_768_EK_SIZE);
    buf.push(EnvelopeType::ClientHello as u8);
    buf.extend_from_slice(&PQC_VERSION.to_be_bytes());
    buf.extend_from_slice(ek_bytes);
    buf
}

/// Decode a ClientHello envelope payload.
///
/// Returns `(version, encapsulation_key_bytes)`.
pub fn decode_client_hello(
    data: &[u8],
) -> Result<(u16, [u8; ML_KEM_768_EK_SIZE]), TunnelError> {
    // Expect: [0x01][version: 2B][ek: 1184B]
    let expected_len = 1 + 2 + ML_KEM_768_EK_SIZE;
    if data.len() < expected_len {
        return Err(TunnelError::InvalidEnvelope(format!(
            "ClientHello too short: {} bytes, expected {expected_len}",
            data.len()
        )));
    }
    if data[0] != EnvelopeType::ClientHello as u8 {
        return Err(TunnelError::InvalidEnvelope(format!(
            "expected ClientHello type 0x01, got 0x{:02x}",
            data[0]
        )));
    }

    let version = u16::from_be_bytes([data[1], data[2]]);
    let mut ek = [0u8; ML_KEM_768_EK_SIZE];
    ek.copy_from_slice(&data[3..3 + ML_KEM_768_EK_SIZE]);
    Ok((version, ek))
}

/// Encode a ServerAccept envelope payload (without the outer length prefix).
///
/// Format: `[0x02][version: 2B][ct: 1088B][pubkey: 1952B][sig: 3309B]` = 6352 bytes total.
///
/// The signature covers `AUTH_SIGN_CONTEXT || client_ek || ct`, binding the
/// authentication to this specific handshake.
pub fn encode_server_accept(
    ct_bytes: &[u8; ML_KEM_768_CT_SIZE],
    pubkey: &[u8; ML_DSA_65_PK_SIZE],
    signature: &[u8; ML_DSA_65_SIG_SIZE],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(1 + 2 + ML_KEM_768_CT_SIZE + ML_DSA_65_PK_SIZE + ML_DSA_65_SIG_SIZE);
    buf.push(EnvelopeType::ServerAccept as u8);
    buf.extend_from_slice(&PQC_VERSION.to_be_bytes());
    buf.extend_from_slice(ct_bytes);
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(signature);
    buf
}

/// Decoded ServerAccept fields.
pub struct ServerAcceptData {
    pub version: u16,
    pub ct: [u8; ML_KEM_768_CT_SIZE],
    pub pubkey: [u8; ML_DSA_65_PK_SIZE],
    pub signature: [u8; ML_DSA_65_SIG_SIZE],
}

/// Decode a ServerAccept envelope payload.
pub fn decode_server_accept(data: &[u8]) -> Result<ServerAcceptData, TunnelError> {
    let expected_len = 1 + 2 + ML_KEM_768_CT_SIZE + ML_DSA_65_PK_SIZE + ML_DSA_65_SIG_SIZE;
    if data.len() < expected_len {
        return Err(TunnelError::InvalidEnvelope(format!(
            "ServerAccept too short: {} bytes, expected {expected_len}",
            data.len()
        )));
    }
    if data[0] != EnvelopeType::ServerAccept as u8 {
        return Err(TunnelError::InvalidEnvelope(format!(
            "expected ServerAccept type 0x02, got 0x{:02x}",
            data[0]
        )));
    }

    let version = u16::from_be_bytes([data[1], data[2]]);

    let ct_start = 3;
    let pk_start = ct_start + ML_KEM_768_CT_SIZE;
    let sig_start = pk_start + ML_DSA_65_PK_SIZE;

    let mut ct = [0u8; ML_KEM_768_CT_SIZE];
    ct.copy_from_slice(&data[ct_start..pk_start]);

    let mut pubkey = [0u8; ML_DSA_65_PK_SIZE];
    pubkey.copy_from_slice(&data[pk_start..sig_start]);

    let mut signature = [0u8; ML_DSA_65_SIG_SIZE];
    signature.copy_from_slice(&data[sig_start..sig_start + ML_DSA_65_SIG_SIZE]);

    Ok(ServerAcceptData {
        version,
        ct,
        pubkey,
        signature,
    })
}

/// Build the message that is signed/verified during the authenticated handshake.
///
/// Format: `AUTH_SIGN_CONTEXT || client_ek || ct`
///
/// This binds the signature to the specific client's encapsulation key and the
/// server's ciphertext, preventing replay across different handshakes.
pub fn build_auth_message(
    client_ek: &[u8; ML_KEM_768_EK_SIZE],
    ct: &[u8; ML_KEM_768_CT_SIZE],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_SIGN_CONTEXT.len() + ML_KEM_768_EK_SIZE + ML_KEM_768_CT_SIZE);
    msg.extend_from_slice(AUTH_SIGN_CONTEXT);
    msg.extend_from_slice(client_ek);
    msg.extend_from_slice(ct);
    msg
}

/// Derive a PeerId (32 bytes) from an ML-DSA-65 public key.
///
/// PeerId = BLAKE3(pubkey), matching the derivation used by saorsa-core.
pub fn derive_peer_id(pubkey: &[u8; ML_DSA_65_PK_SIZE]) -> [u8; 32] {
    *blake3::hash(pubkey).as_bytes()
}

/// Encode an Encrypted envelope payload (without the outer length prefix).
///
/// Format: `[0x03][stream_seq: 4B][ciphertext...]`.
pub fn encode_encrypted(stream_seq: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + ciphertext.len());
    buf.push(EnvelopeType::Encrypted as u8);
    buf.extend_from_slice(&stream_seq.to_be_bytes());
    buf.extend_from_slice(ciphertext);
    buf
}

/// Decode an Encrypted envelope payload.
///
/// Returns `(stream_seq, ciphertext_slice)`.
pub fn decode_encrypted(data: &[u8]) -> Result<(u32, &[u8]), TunnelError> {
    if data.len() < 5 {
        return Err(TunnelError::InvalidEnvelope(format!(
            "Encrypted envelope too short: {} bytes",
            data.len()
        )));
    }
    if data[0] != EnvelopeType::Encrypted as u8 {
        return Err(TunnelError::InvalidEnvelope(format!(
            "expected Encrypted type 0x03, got 0x{:02x}",
            data[0]
        )));
    }

    let stream_seq = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    Ok((stream_seq, &data[5..]))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn session_cipher_roundtrip() {
        let ss = [0xAB; 32];
        let cipher = SessionCipher::from_shared_secret(&ss);

        let plaintext = b"hello, post-quantum world";
        let encrypted = cipher
            .encrypt(1, Direction::ClientToServer, plaintext)
            .expect("encrypt");
        let decrypted = cipher
            .decrypt(1, Direction::ClientToServer, &encrypted)
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let cipher_a = SessionCipher::from_shared_secret(&[0xAA; 32]);
        let cipher_b = SessionCipher::from_shared_secret(&[0xBB; 32]);

        let encrypted = cipher_a
            .encrypt(1, Direction::ClientToServer, b"secret")
            .expect("encrypt");

        let result = cipher_b.decrypt(1, Direction::ClientToServer, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_direction_fails_decryption() {
        let cipher = SessionCipher::from_shared_secret(&[0xCC; 32]);

        let encrypted = cipher
            .encrypt(1, Direction::ClientToServer, b"secret")
            .expect("encrypt");

        let result = cipher.decrypt(1, Direction::ServerToClient, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_stream_seq_fails_decryption() {
        let cipher = SessionCipher::from_shared_secret(&[0xDD; 32]);

        let encrypted = cipher
            .encrypt(1, Direction::ClientToServer, b"secret")
            .expect("encrypt");

        let result = cipher.decrypt(2, Direction::ClientToServer, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn nonce_uniqueness() {
        let n1 = build_nonce(1, Direction::ClientToServer);
        let n2 = build_nonce(1, Direction::ServerToClient);
        let n3 = build_nonce(2, Direction::ClientToServer);

        assert_ne!(n1, n2, "different direction must produce different nonce");
        assert_ne!(n1, n3, "different seq must produce different nonce");
        assert_ne!(n2, n3);
    }

    #[test]
    fn client_hello_roundtrip() {
        let ek = [0x42; ML_KEM_768_EK_SIZE];
        let encoded = encode_client_hello(&ek);
        let (version, decoded_ek) = decode_client_hello(&encoded).expect("decode");
        assert_eq!(version, PQC_VERSION);
        assert_eq!(decoded_ek, ek);
    }

    #[test]
    fn server_accept_roundtrip() {
        let ct = [0x99; ML_KEM_768_CT_SIZE];
        let pubkey = [0xAA; ML_DSA_65_PK_SIZE];
        let sig = [0xBB; ML_DSA_65_SIG_SIZE];
        let encoded = encode_server_accept(&ct, &pubkey, &sig);
        let decoded = decode_server_accept(&encoded).expect("decode");
        assert_eq!(decoded.version, PQC_VERSION);
        assert_eq!(decoded.ct, ct);
        assert_eq!(decoded.pubkey, pubkey);
        assert_eq!(decoded.signature, sig);
    }

    #[test]
    fn encrypted_envelope_roundtrip() {
        let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_encrypted(42, &ciphertext);
        let (seq, decoded_ct) = decode_encrypted(&encoded).expect("decode");
        assert_eq!(seq, 42);
        assert_eq!(decoded_ct, &ciphertext);
    }

    #[test]
    fn decode_rejects_wrong_type() {
        let mut data = encode_client_hello(&[0; ML_KEM_768_EK_SIZE]);
        data[0] = 0x02; // ServerAccept type byte, but ClientHello payload
        assert!(decode_client_hello(&data).is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_client_hello(&[0x01, 0x00]).is_err());
        assert!(decode_server_accept(&[0x02, 0x00]).is_err());
        assert!(decode_encrypted(&[0x03]).is_err());
    }

    #[test]
    fn envelope_sizes_match_spec() {
        let hello = encode_client_hello(&[0; ML_KEM_768_EK_SIZE]);
        assert_eq!(hello.len(), 1 + 2 + ML_KEM_768_EK_SIZE); // 1187

        let accept = encode_server_accept(
            &[0; ML_KEM_768_CT_SIZE],
            &[0; ML_DSA_65_PK_SIZE],
            &[0; ML_DSA_65_SIG_SIZE],
        );
        assert_eq!(
            accept.len(),
            1 + 2 + ML_KEM_768_CT_SIZE + ML_DSA_65_PK_SIZE + ML_DSA_65_SIG_SIZE
        ); // 6352
    }

    #[test]
    fn auth_message_construction() {
        let ek = [0x11; ML_KEM_768_EK_SIZE];
        let ct = [0x22; ML_KEM_768_CT_SIZE];
        let msg = build_auth_message(&ek, &ct);
        assert_eq!(
            msg.len(),
            AUTH_SIGN_CONTEXT.len() + ML_KEM_768_EK_SIZE + ML_KEM_768_CT_SIZE
        );
        assert!(msg.starts_with(AUTH_SIGN_CONTEXT));
        assert_eq!(&msg[AUTH_SIGN_CONTEXT.len()..AUTH_SIGN_CONTEXT.len() + ML_KEM_768_EK_SIZE], &ek);
        assert_eq!(&msg[AUTH_SIGN_CONTEXT.len() + ML_KEM_768_EK_SIZE..], &ct);
    }

    #[test]
    fn peer_id_derivation_is_blake3() {
        let pubkey = [0x42; ML_DSA_65_PK_SIZE];
        let peer_id = derive_peer_id(&pubkey);
        let expected = *blake3::hash(&pubkey).as_bytes();
        assert_eq!(peer_id, expected);
    }
}
