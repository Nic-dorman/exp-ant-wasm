//! WebTransport server implementation using wtransport.
//!
//! Accepts incoming WebTransport sessions, spawns a task per session, and
//! handles each bidirectional stream as a single chunk protocol
//! request/response exchange with 4-byte big-endian length-prefix framing.
//!
//! TLS is configured with X25519MLKEM768 hybrid post-quantum key exchange
//! via the aws-lc-rs CryptoProvider, providing quantum-resistant transport
//! encryption alongside the application-layer PQC tunnel.

use crate::ant_protocol::{ChunkGetResponse, ChunkMessage, ChunkMessageBody, MAX_WIRE_MESSAGE_SIZE};
use crate::storage::AntProtocol;
use ant_protocol::pqc_tunnel::{
    self, decode_client_hello, encode_server_accept, Direction, SessionCipher, TunnelError,
};
use bytes::Bytes;
use fips203::ml_kem_768;
use fips203::traits::{Encaps, SerDes};
use saorsa_core::identity::NodeIdentity;
use saorsa_core::P2PNode;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::{MlDsa65, MlDsaOperations};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wtransport::{Endpoint, Identity, ServerConfig};
use zeroize::Zeroize;

/// Maximum concurrent stream handlers across all sessions (global).
const MAX_CONCURRENT_STREAMS: usize = 64;

/// Maximum concurrent streams per individual session.
const MAX_STREAMS_PER_SESSION: usize = 8;

/// Maximum stream sequence number before the session must be torn down.
///
/// ChaCha20-Poly1305 nonce reuse is catastrophic. The nonce includes a u32
/// stream_seq, so we must never wrap. Leave headroom below u32::MAX.
const MAX_STREAM_SEQ: u32 = u32::MAX - 1;

/// Generated identity with its certificate hash for discovery.
pub struct ServerIdentity {
    /// The wtransport identity (cert + key).
    pub identity: Identity,
    /// SHA-256 hash of the certificate as hex string (no colons).
    pub cert_hash_hex: String,
}

/// Generate a self-signed identity for the WebTransport server.
///
/// Returns the identity and its SHA-256 cert hash so callers can
/// publish the hash for client discovery (e.g. in the devnet manifest).
pub fn generate_identity(
    listen_addr: SocketAddr,
) -> Result<ServerIdentity, Box<dyn std::error::Error + Send + Sync>> {
    let identity =
        Identity::self_signed(["localhost", "127.0.0.1", &listen_addr.ip().to_string()])?;

    let cert_hash_hex = identity
        .certificate_chain()
        .as_slice()
        .first()
        .map(|cert| {
            let hash = cert.hash();
            // hash Display is "aa:bb:cc:..." — strip colons
            hash.to_string().replace(':', "")
        })
        .unwrap_or_default();

    Ok(ServerIdentity {
        identity,
        cert_hash_hex,
    })
}

/// Build a rustls ServerConfig with X25519MLKEM768 post-quantum key exchange.
///
/// Uses the aws-lc-rs CryptoProvider with X25519MLKEM768 prepended as the
/// preferred key exchange group, providing hybrid PQ+classical key agreement.
/// Browsers that support it (Chrome 131+, Firefox, Edge) will negotiate PQ
/// automatically; others fall back to X25519.
fn build_pq_tls_config(
    identity: &Identity,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // Prepend X25519MLKEM768 as the preferred key exchange group
    provider
        .kx_groups
        .insert(0, rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768);

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = identity
        .certificate_chain()
        .as_slice()
        .iter()
        .map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec()))
        .collect();

    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.private_key().secret_der().to_vec(),
    );

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("rustls version config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(|e| format!("rustls cert config: {e}"))?;

    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Start the WebTransport server with a pre-generated identity.
pub async fn serve_with_identity(
    listen_addr: SocketAddr,
    server_identity: ServerIdentity,
    protocol: Arc<AntProtocol>,
    p2p_node: Option<Arc<P2PNode>>,
    node_identity: Option<Arc<NodeIdentity>>,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("WebTransport certificate SHA-256: {}", server_identity.cert_hash_hex);

    // Build TLS config with X25519MLKEM768 post-quantum key exchange
    let tls_config = build_pq_tls_config(&server_identity.identity)?;
    info!("WebTransport TLS configured with X25519MLKEM768 hybrid PQ key exchange");

    let config = ServerConfig::builder()
        .with_bind_address(listen_addr)
        .with_custom_tls(tls_config)
        .build();

    let endpoint = Endpoint::server(config)?;
    info!("WebTransport server listening on https://{listen_addr}");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS));

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("WebTransport server shutting down");
                break;
            }
            incoming = endpoint.accept() => {
                let protocol = Arc::clone(&protocol);
                let p2p = p2p_node.clone();
                let nid = node_identity.clone();
                let sem = Arc::clone(&semaphore);

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(session_request) => {
                            let remote = session_request.remote_address();
                            debug!("WebTransport session request from {remote}");
                            match session_request.accept().await {
                                Ok(connection) => {
                                    handle_session(connection, protocol, p2p, nid, sem).await;
                                }
                                Err(e) => warn!("Session accept error: {e}"),
                            }
                        }
                        Err(e) => warn!("Incoming session error: {e}"),
                    }
                });
            }
        }
    }

    Ok(())
}

/// Handle a single WebTransport session (one browser tab / client).
///
/// The first bidirectional stream is used for the ML-KEM-768 PQC handshake.
/// All subsequent streams carry encrypted ChunkMessage payloads.
async fn handle_session(
    connection: wtransport::Connection,
    protocol: Arc<AntProtocol>,
    p2p_node: Option<Arc<P2PNode>>,
    node_identity: Option<Arc<NodeIdentity>>,
    global_semaphore: Arc<Semaphore>,
) {
    let remote = connection.remote_address();
    info!("WebTransport session established from {remote}");

    // Stream 0: PQC handshake (authenticated with ML-DSA-65)
    let cipher = match connection.accept_bi().await {
        Ok((send, recv)) => match perform_server_handshake(send, recv, node_identity.as_deref()).await {
            Ok(cipher) => {
                info!("PQC tunnel established with {remote} (ML-KEM-768)");
                Arc::new(cipher)
            }
            Err(e) => {
                warn!("PQC handshake failed with {remote}: {e}");
                return;
            }
        },
        Err(e) => {
            debug!("WebTransport session from {remote} ended before handshake: {e}");
            return;
        }
    };

    // Per-session semaphore limits concurrent streams from a single client
    let session_semaphore = Arc::new(Semaphore::new(MAX_STREAMS_PER_SESSION));

    // Subsequent streams: encrypted chunk protocol messages
    let stream_seq = Arc::new(AtomicU32::new(1));

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let seq = stream_seq.fetch_add(1, Ordering::Relaxed);

                // Guard against nonce reuse from stream_seq overflow
                if seq >= MAX_STREAM_SEQ {
                    warn!("Session with {remote} reached stream limit — closing to prevent nonce reuse");
                    break;
                }

                let protocol = Arc::clone(&protocol);
                let p2p = p2p_node.clone();
                let cipher = Arc::clone(&cipher);

                // Acquire both global and per-session permits
                let global_permit = match global_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!("WebTransport backpressure: too many concurrent streams (global)");
                        continue;
                    }
                };
                let session_permit = match session_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!("WebTransport backpressure: too many concurrent streams from {remote}");
                        continue;
                    }
                };

                tokio::spawn(async move {
                    handle_encrypted_stream(send, recv, seq, &cipher, protocol, p2p).await;
                    drop(global_permit);
                    drop(session_permit);
                });
            }
            Err(e) => {
                debug!("WebTransport session from {remote} ended: {e}");
                break;
            }
        }
    }
}

/// Perform the server side of the ML-KEM-768 PQC handshake on stream 0.
///
/// 1. Read ClientHello (encapsulation key)
/// 2. Encapsulate to produce shared secret + ciphertext
/// 3. Sign with ML-DSA-65 for authentication
/// 4. Send ServerAccept (ciphertext + pubkey + signature)
/// 5. Derive session cipher from shared secret
async fn perform_server_handshake(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    node_identity: Option<&NodeIdentity>,
) -> Result<SessionCipher, Box<dyn std::error::Error + Send + Sync>> {
    let identity = node_identity.ok_or("NodeIdentity required for authenticated PQC handshake")?;

    // Read length-prefixed ClientHello
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 4096 {
        return Err("PQC handshake message too large".into());
    }

    let mut msg_buf = vec![0u8; len];
    recv.read_exact(&mut msg_buf).await?;

    // Decode ClientHello
    let (version, ek_bytes) = decode_client_hello(&msg_buf)?;
    if version != pqc_tunnel::PQC_VERSION {
        return Err(TunnelError::UnsupportedVersion(version).into());
    }

    // ML-KEM-768 encapsulation
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
        .map_err(|_| "invalid ML-KEM-768 encapsulation key")?;
    let (ss, ct) = ek.try_encaps().map_err(|_| "ML-KEM-768 encapsulation failed")?;

    let ct_bytes: [u8; 1088] = ct.into_bytes();

    // ML-DSA-65 authentication: sign (context || client_ek || ct)
    let auth_message = pqc_tunnel::build_auth_message(&ek_bytes, &ct_bytes);

    let pub_key_bytes = identity.public_key().as_bytes().to_vec();
    let mut sk_bytes = identity.secret_key_bytes().to_vec();
    let sk = MlDsaSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("Failed to deserialize ML-DSA-65 secret key: {e}"))?;
    // Zeroize the secret key bytes now that they've been parsed
    sk_bytes.zeroize();

    let ml_dsa = MlDsa65::new();
    let sig = ml_dsa
        .sign(&sk, &auth_message)
        .map_err(|e| format!("ML-DSA-65 signing failed: {e}"))?;
    let sig_bytes = sig.as_bytes();

    let mut pubkey_arr = [0u8; pqc_tunnel::ML_DSA_65_PK_SIZE];
    pubkey_arr.copy_from_slice(&pub_key_bytes);
    let mut sig_arr = [0u8; pqc_tunnel::ML_DSA_65_SIG_SIZE];
    sig_arr.copy_from_slice(sig_bytes);

    // Send length-prefixed ServerAccept with authentication
    let accept_payload = encode_server_accept(&ct_bytes, &pubkey_arr, &sig_arr);

    #[allow(clippy::cast_possible_truncation)]
    let accept_len = (accept_payload.len() as u32).to_be_bytes();
    send.write_all(&accept_len).await?;
    send.write_all(&accept_payload).await?;
    send.finish().await?;

    // Derive session cipher, then zeroize the shared secret
    let mut ss_bytes: [u8; 32] = ss.into_bytes();
    let cipher = SessionCipher::from_shared_secret(&ss_bytes);
    ss_bytes.zeroize();

    Ok(cipher)
}

/// Handle a single encrypted bidirectional stream.
///
/// Decrypts the incoming request, dispatches to the protocol handler,
/// encrypts the response, and sends it back.
async fn handle_encrypted_stream(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    stream_seq: u32,
    cipher: &SessionCipher,
    protocol: Arc<AntProtocol>,
    p2p_node: Option<Arc<P2PNode>>,
) {
    // Read length-prefixed encrypted envelope
    let mut len_buf = [0u8; 4];
    if recv.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_WIRE_MESSAGE_SIZE + 256 {
        warn!("WebTransport encrypted message too large: {len} bytes");
        return;
    }

    let mut msg_buf = vec![0u8; len];
    if recv.read_exact(&mut msg_buf).await.is_err() {
        return;
    }

    // Decode and decrypt envelope
    let (envelope_seq, ciphertext) = match pqc_tunnel::decode_encrypted(&msg_buf) {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to decode encrypted envelope: {e}");
            return;
        }
    };

    if envelope_seq != stream_seq {
        warn!(
            "Stream sequence mismatch: expected {stream_seq}, got {envelope_seq}"
        );
        return;
    }

    let plaintext = match cipher.decrypt(stream_seq, Direction::ClientToServer, ciphertext) {
        Ok(pt) => pt,
        Err(e) => {
            warn!("PQC tunnel decryption failed: {e}");
            return;
        }
    };

    // Process through AntProtocol (unchanged — same postcard bytes)
    let response = match protocol.try_handle_request(&plaintext).await {
        Ok(Some(resp)) => try_network_fetch(&resp, p2p_node.as_deref())
            .await
            .unwrap_or_else(|| resp.to_vec()),
        Ok(None) => return,
        Err(e) => {
            warn!("Protocol handler error: {e}");
            return;
        }
    };

    // Encrypt and send response
    let encrypted = match cipher.encrypt(stream_seq, Direction::ServerToClient, &response) {
        Ok(ct) => ct,
        Err(e) => {
            warn!("PQC tunnel encryption failed: {e}");
            return;
        }
    };

    let envelope = pqc_tunnel::encode_encrypted(stream_seq, &encrypted);

    #[allow(clippy::cast_possible_truncation)]
    let resp_len = (envelope.len() as u32).to_be_bytes();
    let _ = send.write_all(&resp_len).await;
    let _ = send.write_all(&envelope).await;
    let _ = send.finish().await;
}

/// If the response is `GetResponse::NotFound` and we have a P2P node,
/// attempt to fetch the chunk from the DHT network.
async fn try_network_fetch(
    local_response: &Bytes,
    p2p_node: Option<&P2PNode>,
) -> Option<Vec<u8>> {
    let p2p = p2p_node?;

    let resp_msg = ChunkMessage::decode(local_response).ok()?;
    let request_id = resp_msg.request_id;
    let address = match &resp_msg.body {
        ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address }) => *address,
        _ => return None,
    };

    let addr_hex = hex::encode(address);
    debug!("Local storage miss for {addr_hex}, attempting DHT network fetch");

    // Find closest peers
    let closest = match p2p
        .dht()
        .find_closest_nodes(&address, crate::CLOSE_GROUP_SIZE)
        .await
    {
        Ok(nodes) => nodes,
        Err(e) => {
            debug!("DHT lookup failed for {addr_hex}: {e}");
            return None;
        }
    };

    if closest.is_empty() {
        return None;
    }

    // Build request to send to peers
    let get_msg = ChunkMessage {
        request_id: rand::random(),
        body: ChunkMessageBody::GetRequest(crate::ChunkGetRequest::new(address)),
    };
    let get_bytes = get_msg.encode().ok()?;

    for dht_node in &closest {
        let result = crate::client::send_and_await_chunk_response(
            p2p,
            &dht_node.peer_id,
            get_bytes.clone(),
            get_msg.request_id,
            std::time::Duration::from_secs(10),
            &dht_node.addresses,
            |body| match body {
                ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                    address: addr,
                    content,
                }) => {
                    let computed = crate::client::compute_address(&content);
                    if computed == addr {
                        Some(Ok(content))
                    } else {
                        None
                    }
                }
                ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => {
                    Some(Err("not found on peer".to_string()))
                }
                _ => None,
            },
            |e| format!("send error: {e}"),
            || "timeout".to_string(),
        )
        .await;

        if let Ok(content) = result {
            debug!("Network fetch successful for {addr_hex} ({} bytes)", content.len());
            let success_msg = ChunkMessage {
                request_id,
                body: ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                    address,
                    content,
                }),
            };
            return success_msg.encode().ok();
        }
    }

    debug!("Network fetch failed for {addr_hex}");
    None
}
