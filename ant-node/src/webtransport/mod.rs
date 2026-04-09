//! WebTransport (HTTP/3 over QUIC) listener for browser clients.
//!
//! Provides an HTTP/3 endpoint that browsers can connect to using the W3C
//! WebTransport API. Browsers open bidirectional streams and send chunk
//! protocol messages; the server handles them using the same [`AntProtocol`]
//! handler that serves P2P peers.
//!
//! A self-signed TLS certificate is generated at startup. The SHA-256 hash
//! is published for client discovery (e.g. in the devnet manifest) so
//! browser clients can pin it via `serverCertificateHashes`.

pub mod server;

pub use server::{generate_identity, ServerIdentity};

use crate::storage::AntProtocol;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::P2PNode;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Start the WebTransport server with a pre-generated identity.
pub async fn run(
    listen_addr: SocketAddr,
    identity: ServerIdentity,
    protocol: Arc<AntProtocol>,
    p2p_node: Option<Arc<P2PNode>>,
    node_identity: Option<Arc<NodeIdentity>>,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    server::serve_with_identity(listen_addr, identity, protocol, p2p_node, node_identity, shutdown)
        .await
}
