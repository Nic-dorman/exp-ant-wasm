//! Browser WASM client for downloading data from the Autonomi network.
//!
//! Connects to network nodes via WebRTC data channels and fetches
//! content-addressed chunks, then decrypts using self-encryption.
//!
//! # Usage from JavaScript
//!
//! ```js
//! import init, { WasmClient } from './ant_wasm.js';
//!
//! await init();
//! const client = await WasmClient.connect("http://node-ip:port");
//! const data = await client.download("abcdef1234...");  // hex address
//! // data is a Uint8Array
//! client.close();
//! ```

mod client;
mod signaling;
mod transport;

use client::DownloadClient;
use transport::WebRtcTransport;
use wasm_bindgen::prelude::*;

/// Initialize console_error_panic_hook for better WASM error messages.
fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Log a message to the browser console.
fn log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

/// Browser client for downloading data from the Autonomi network.
///
/// Connects to a network node via WebRTC and fetches chunks
/// using the native chunk protocol.
#[wasm_bindgen]
pub struct WasmClient {
    inner: DownloadClient,
}

#[wasm_bindgen]
impl WasmClient {
    /// Connect to an Autonomi network node via WebRTC.
    ///
    /// `signaling_url` is the HTTP URL of the node's WebRTC signaling
    /// endpoint (e.g., `http://192.168.1.10:8080`).
    ///
    /// Returns a connected client ready to download data.
    #[wasm_bindgen]
    pub async fn connect(signaling_url: &str) -> Result<WasmClient, JsValue> {
        set_panic_hook();
        log(&format!("Connecting to {signaling_url}..."));

        let transport = WebRtcTransport::connect(signaling_url)
            .await
            .map_err(|e| JsValue::from_str(&format!("Connection failed: {e}")))?;

        log("WebRTC data channel established");

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

    /// Close the WebRTC connection.
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
