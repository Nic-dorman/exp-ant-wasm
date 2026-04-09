//! Browser WASM client for downloading data from the Autonomi network.
//!
//! Connects to network nodes via WebTransport (HTTP/3 over QUIC) and fetches
//! content-addressed chunks, then decrypts using self-encryption.
//!
//! # Usage from JavaScript
//!
//! ```js
//! import init, { WasmClient } from './ant_wasm.js';
//!
//! await init();
//! const client = await WasmClient.connect("https://node-ip:port");
//! const data = await client.download("abcdef1234...");  // hex address
//! // data is a Uint8Array
//! client.close();
//! ```

mod client;
mod transport;

use client::DownloadClient;
use transport::WtTransport;
use wasm_bindgen::prelude::*;

fn set_panic_hook() {
    // console_error_panic_hook can be added later for better error messages
}

/// Log a message to the browser console.
fn log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

/// Browser client for downloading data from the Autonomi network.
///
/// Connects to a network node via WebTransport (HTTP/3 over QUIC)
/// and fetches chunks using the native chunk protocol.
#[wasm_bindgen]
pub struct WasmClient {
    inner: DownloadClient,
}

#[wasm_bindgen]
impl WasmClient {
    /// Connect to an Autonomi network node via WebTransport.
    ///
    /// `url` is the HTTPS URL of the node's WebTransport endpoint
    /// (e.g., `https://192.168.1.10:4433`).
    #[wasm_bindgen]
    pub async fn connect(url: &str) -> Result<WasmClient, JsValue> {
        set_panic_hook();
        log(&format!("Connecting to {url}..."));

        let transport = WtTransport::connect(url, None, None)
            .await
            .map_err(|e| JsValue::from_str(&format!("Connection failed: {e}")))?;

        log("WebTransport connection established");

        Ok(WasmClient {
            inner: DownloadClient::new(transport),
        })
    }

    /// Connect with a specific server certificate hash (for self-signed certs in dev).
    ///
    /// `cert_hash` is the SHA-256 hash of the server's TLS certificate (32 bytes).
    #[wasm_bindgen]
    pub async fn connect_with_cert_hash(
        url: &str,
        cert_hash: &[u8],
    ) -> Result<WasmClient, JsValue> {
        set_panic_hook();
        log(&format!("Connecting to {url} (with cert hash)..."));

        let transport = WtTransport::connect(url, Some(cert_hash), None)
            .await
            .map_err(|e| JsValue::from_str(&format!("Connection failed: {e}")))?;

        log("WebTransport connection established (cert pinned)");

        Ok(WasmClient {
            inner: DownloadClient::new(transport),
        })
    }

    /// Connect with certificate hash pinning AND PQ identity verification.
    ///
    /// `cert_hash` is the SHA-256 hash of the server's TLS certificate (32 bytes).
    /// `peer_id` is the expected BLAKE3 hash of the server's ML-DSA-65 public key
    /// (32 bytes). The handshake will fail if the server's identity does not match.
    #[wasm_bindgen]
    pub async fn connect_with_identity(
        url: &str,
        cert_hash: &[u8],
        peer_id: &[u8],
    ) -> Result<WasmClient, JsValue> {
        set_panic_hook();
        log(&format!("Connecting to {url} (cert pinned + PQ identity)..."));

        let peer_id_arr = parse_peer_id(peer_id)
            .map_err(|e| JsValue::from_str(&format!("Invalid peer_id: {e}")))?;

        let transport = WtTransport::connect(url, Some(cert_hash), Some(&peer_id_arr))
            .await
            .map_err(|e| JsValue::from_str(&format!("Connection failed: {e}")))?;

        log("WebTransport connection established (cert pinned + PQ identity verified)");

        Ok(WasmClient {
            inner: DownloadClient::new(transport),
        })
    }

    /// Download data by its network address (hex-encoded BLAKE3 hash).
    ///
    /// The address points to a DataMap on the network. The client fetches
    /// the DataMap, then fetches all referenced chunks, verifies integrity,
    /// and decrypts the original content.
    ///
    /// Returns the decrypted content as a `Uint8Array`.
    #[wasm_bindgen]
    pub async fn download(&self, address_hex: &str) -> Result<js_sys::Uint8Array, JsValue> {
        let address = parse_hex_address(address_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid address: {e}")))?;

        log(&format!(
            "Downloading from address {}...",
            &address_hex[..8.min(address_hex.len())]
        ));

        let data = self
            .inner
            .download_from_address(&address)
            .await
            .map_err(|e| JsValue::from_str(&format!("Download failed: {e}")))?;

        log(&format!("Download complete: {} bytes", data.len()));

        Ok(js_sys::Uint8Array::from(data.as_ref()))
    }

    /// Fetch a single raw chunk by address (hex-encoded BLAKE3 hash).
    ///
    /// Returns raw chunk bytes without DataMap interpretation or decryption.
    #[wasm_bindgen]
    pub async fn fetch_chunk(&self, address_hex: &str) -> Result<js_sys::Uint8Array, JsValue> {
        let address = parse_hex_address(address_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid address: {e}")))?;

        let chunk = self
            .inner
            .chunk_get(&address)
            .await
            .map_err(|e| JsValue::from_str(&format!("Fetch failed: {e}")))?
            .ok_or_else(|| JsValue::from_str("Chunk not found"))?;

        log(&format!("Chunk fetched: {} bytes", chunk.content.len()));

        Ok(js_sys::Uint8Array::from(chunk.content.as_ref()))
    }

    /// Close the WebTransport connection.
    #[wasm_bindgen]
    pub fn close(&self) {
        self.inner.close();
        log("Connection closed");
    }
}

/// Parse a hex-encoded 32-byte address.
fn parse_hex_address(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut address = [0u8; 32];
    address.copy_from_slice(&bytes);
    Ok(address)
}

/// Parse a 32-byte peer_id from a byte slice.
fn parse_peer_id(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(bytes);
    Ok(id)
}
