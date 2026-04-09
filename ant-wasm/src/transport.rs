//! WebTransport-based transport for chunk protocol messages.
//!
//! Uses the browser's WebTransport API (HTTP/3 over QUIC with TLS 1.3).
//! An application-layer PQC tunnel (ML-KEM-768 + ChaCha20-Poly1305) with
//! ML-DSA-65 server authentication is established on the first bidirectional
//! stream, providing full PQ-authenticated key exchange.

use ant_protocol::pqc_tunnel::{
    self, decode_server_accept, encode_client_hello, Direction, SessionCipher,
};
use ant_protocol::MAX_WIRE_MESSAGE_SIZE;
use crate::log;
use fips203::ml_kem_768;
use fips203::traits::{Decaps, KeyGen, SerDes};
use fips204::ml_dsa_65;
use fips204::traits::Verifier;
use rand_core::OsRng;
use js_sys::Uint8Array;
use std::cell::Cell;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WebTransport, WritableStreamDefaultWriter};
use zeroize::Zeroize;

/// Maximum stream sequence number before the session must be torn down.
///
/// ChaCha20-Poly1305 nonce reuse is catastrophic. The nonce includes a u32
/// stream_seq, so we must never wrap. Leave headroom below u32::MAX.
const MAX_STREAM_SEQ: u32 = u32::MAX - 1;

pub struct WtTransport {
    wt: WebTransport,
    cipher: SessionCipher,
    stream_seq: Cell<u32>,
}

impl WtTransport {
    /// Connect to a WebTransport server and establish a PQC tunnel.
    ///
    /// If `cert_hash` is provided (SHA-256, 32 bytes), it is passed as
    /// `serverCertificateHashes` for self-signed certificate pinning in dev.
    ///
    /// If `expected_peer_id` is provided (BLAKE3 hash of the server's ML-DSA-65
    /// public key, 32 bytes), the handshake will fail if the server's identity
    /// does not match.
    ///
    /// After the WebTransport session is ready, stream 0 is used for an
    /// ML-KEM-768 handshake to derive a shared session key.
    pub async fn connect(
        url: &str,
        cert_hash: Option<&[u8]>,
        expected_peer_id: Option<&[u8; 32]>,
    ) -> Result<Self, String> {
        log(&format!("transport: connecting to {url}"));

        let wt = if let Some(hash) = cert_hash {
            let options = web_sys::WebTransportOptions::new();
            let hash_obj = web_sys::WebTransportHash::new();
            hash_obj.set_algorithm("sha-256");
            hash_obj.set_value_u8_array(&Uint8Array::from(hash));
            options.set_server_certificate_hashes(&[hash_obj]);
            WebTransport::new_with_options(url, &options)
                .map_err(|e| format!("WebTransport creation failed: {e:?}"))?
        } else {
            WebTransport::new(url)
                .map_err(|e| format!("WebTransport creation failed: {e:?}"))?
        };

        JsFuture::from(wt.ready())
            .await
            .map_err(|e| format!("WebTransport connection failed: {e:?}"))?;

        log("transport: connected, starting PQC handshake");

        // Stream 0: ML-KEM-768 handshake with ML-DSA-65 authentication
        let cipher = Self::perform_handshake(&wt, expected_peer_id).await?;

        log("transport: PQC tunnel established (ML-KEM-768 + ML-DSA-65)");
        Ok(Self {
            wt,
            cipher,
            stream_seq: Cell::new(1),
        })
    }

    /// Perform the client side of the authenticated PQC handshake on stream 0.
    ///
    /// 1. Generate ML-KEM-768 keypair
    /// 2. Send ClientHello (encapsulation key) to server
    /// 3. Read ServerAccept (ciphertext + pubkey + signature) from server
    /// 4. Verify ML-DSA-65 signature over (context || ek || ct)
    /// 5. If expected_peer_id provided, verify BLAKE3(pubkey) matches
    /// 6. Decapsulate to recover shared secret
    /// 7. Derive session cipher
    async fn perform_handshake(
        wt: &WebTransport,
        expected_peer_id: Option<&[u8; 32]>,
    ) -> Result<SessionCipher, String> {
        // Generate ML-KEM-768 keypair
        let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
            .map_err(|_| "ML-KEM-768 keygen failed".to_string())?;

        // Open bidi stream 0
        let bidi: web_sys::WebTransportBidirectionalStream =
            JsFuture::from(wt.create_bidirectional_stream())
                .await
                .map_err(|e| format!("failed to create handshake stream: {e:?}"))?
                .dyn_into()
                .map_err(|_| "handshake stream type error".to_string())?;

        let writable: web_sys::WebTransportSendStream = bidi.writable();
        let readable: web_sys::WebTransportReceiveStream = bidi.readable();

        let writable_stream: &web_sys::WritableStream = writable.as_ref();
        let writer: WritableStreamDefaultWriter = writable_stream
            .get_writer()
            .map_err(|e| format!("get_writer failed: {e:?}"))?;

        // Send ClientHello: [4B len][0x01][version][ek]
        let ek_bytes = SerDes::into_bytes(ek);
        let hello_payload = encode_client_hello(&ek_bytes);

        let mut framed = Vec::with_capacity(4 + hello_payload.len());
        let len = (hello_payload.len() as u32).to_be_bytes();
        framed.extend_from_slice(&len);
        framed.extend_from_slice(&hello_payload);

        JsFuture::from(writer.write_with_chunk(&Uint8Array::from(framed.as_slice())))
            .await
            .map_err(|e| format!("handshake write failed: {e:?}"))?;

        // Close write side to signal end of ClientHello
        JsFuture::from(writer.close())
            .await
            .map_err(|e| format!("handshake close writer failed: {e:?}"))?;

        // Read ServerAccept response (bounded to prevent OOM)
        let readable_stream: &web_sys::ReadableStream = readable.as_ref();
        let reader: ReadableStreamDefaultReader = readable_stream
            .get_reader()
            .dyn_into()
            .map_err(|_| "not a ReadableStreamDefaultReader".to_string())?;

        // ServerAccept is ~6.4KB; cap at 16KB for safety
        const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;
        let mut response_buf = Vec::new();
        loop {
            let result = JsFuture::from(reader.read())
                .await
                .map_err(|e| format!("handshake read failed: {e:?}"))?;

            let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
                .unwrap_or(JsValue::TRUE);

            if done.is_truthy() {
                break;
            }

            let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
                .map_err(|e| format!("handshake read value failed: {e:?}"))?;

            if !value.is_undefined() {
                let chunk = Uint8Array::new(&value);
                response_buf.extend_from_slice(&chunk.to_vec());
                if response_buf.len() > MAX_HANDSHAKE_RESPONSE {
                    return Err("handshake response exceeds size limit".to_string());
                }
            }
        }

        // Strip 4-byte length prefix
        if response_buf.len() < 4 {
            return Err(format!(
                "handshake response too short: {} bytes",
                response_buf.len()
            ));
        }
        let accept_payload = &response_buf[4..];

        // Decode ServerAccept (v2: ct + pubkey + signature)
        let accept = decode_server_accept(accept_payload)
            .map_err(|e| format!("invalid ServerAccept: {e}"))?;

        if accept.version != pqc_tunnel::PQC_VERSION {
            return Err(format!("unsupported PQC version: {}", accept.version));
        }

        // Verify ML-DSA-65 signature before decapsulating
        let auth_message = pqc_tunnel::build_auth_message(&ek_bytes, &accept.ct);

        let vk = <ml_dsa_65::PublicKey as fips204::traits::SerDes>::try_from_bytes(accept.pubkey)
            .map_err(|_| "invalid ML-DSA-65 public key".to_string())?;

        let valid = vk.verify(&auth_message, &accept.signature, &[]);

        if !valid {
            return Err("ML-DSA-65 signature verification failed — server not authenticated".to_string());
        }

        log("transport: ML-DSA-65 signature verified");

        // Verify PeerId if expected
        let derived_peer_id = pqc_tunnel::derive_peer_id(&accept.pubkey);
        if let Some(expected) = expected_peer_id {
            if derived_peer_id != *expected {
                return Err(format!(
                    "PeerId mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(derived_peer_id)
                ));
            }
            log("transport: PeerId verified");
        }

        // ML-KEM-768 decapsulation (only after authentication succeeds)
        let ct = <ml_kem_768::CipherText as SerDes>::try_from_bytes(accept.ct)
            .map_err(|_| "invalid ML-KEM-768 ciphertext".to_string())?;
        let ss: fips203::SharedSecretKey =
            Decaps::try_decaps(&dk, &ct)
                .map_err(|_| "ML-KEM-768 decapsulation failed".to_string())?;

        // Derive session cipher, then zeroize the shared secret
        let mut ss_bytes: [u8; 32] = SerDes::into_bytes(ss);
        let cipher = SessionCipher::from_shared_secret(&ss_bytes);
        ss_bytes.zeroize();

        Ok(cipher)
    }

    /// Send a request and receive a response over a new encrypted bidi stream.
    ///
    /// The plaintext ChunkMessage is encrypted with the session cipher before
    /// transmission, and the response is decrypted before returning.
    pub async fn send_request(&self, message_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let seq = self.stream_seq.get();
        if seq >= MAX_STREAM_SEQ {
            return Err("session stream limit reached — reconnect required to prevent nonce reuse".to_string());
        }
        self.stream_seq.set(seq + 1);

        // Encrypt the plaintext message
        let encrypted = self
            .cipher
            .encrypt(seq, Direction::ClientToServer, message_bytes)
            .map_err(|e| format!("PQC encryption failed: {e}"))?;

        let envelope = pqc_tunnel::encode_encrypted(seq, &encrypted);

        // Open a bidirectional stream
        let bidi: web_sys::WebTransportBidirectionalStream =
            JsFuture::from(self.wt.create_bidirectional_stream())
                .await
                .map_err(|e| format!("failed to create bidi stream: {e:?}"))?
                .dyn_into()
                .map_err(|_| "bidi stream is not WebTransportBidirectionalStream".to_string())?;

        let writable: web_sys::WebTransportSendStream = bidi.writable();
        let readable: web_sys::WebTransportReceiveStream = bidi.readable();

        // Get writer from writable side
        let writable_stream: &web_sys::WritableStream = writable.as_ref();
        let writer: WritableStreamDefaultWriter = writable_stream
            .get_writer()
            .map_err(|e| format!("get_writer failed: {e:?}"))?;

        // Write: 4-byte big-endian length prefix + encrypted envelope
        let len = (envelope.len() as u32).to_be_bytes();
        let mut framed = Vec::with_capacity(4 + envelope.len());
        framed.extend_from_slice(&len);
        framed.extend_from_slice(&envelope);

        JsFuture::from(writer.write_with_chunk(&Uint8Array::from(framed.as_slice())))
            .await
            .map_err(|e| format!("write failed: {e:?}"))?;

        // Close write side to signal end of request
        JsFuture::from(writer.close())
            .await
            .map_err(|e| format!("close writer failed: {e:?}"))?;

        // Read encrypted response from readable side (bounded)
        let readable_stream: &web_sys::ReadableStream = readable.as_ref();
        let reader: ReadableStreamDefaultReader = readable_stream
            .get_reader()
            .dyn_into()
            .map_err(|_| "not a ReadableStreamDefaultReader".to_string())?;

        // Cap response at MAX_WIRE_MESSAGE_SIZE + overhead for envelope framing + auth tag
        let max_response = MAX_WIRE_MESSAGE_SIZE + 512;
        let mut response_buf = Vec::new();
        loop {
            let result = JsFuture::from(reader.read())
                .await
                .map_err(|e| format!("read failed: {e:?}"))?;

            let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
                .unwrap_or(JsValue::TRUE);

            if done.is_truthy() {
                break;
            }

            let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
                .map_err(|e| format!("read value failed: {e:?}"))?;

            if !value.is_undefined() {
                let chunk = Uint8Array::new(&value);
                response_buf.extend_from_slice(&chunk.to_vec());
                if response_buf.len() > max_response {
                    return Err(format!(
                        "response exceeds size limit: {} > {max_response}",
                        response_buf.len()
                    ));
                }
            }
        }

        // Strip 4-byte length prefix
        if response_buf.len() < 4 {
            return Err(format!("response too short: {} bytes", response_buf.len()));
        }
        let envelope_payload = &response_buf[4..];

        // Decode and decrypt response envelope
        let (resp_seq, ciphertext) = pqc_tunnel::decode_encrypted(envelope_payload)
            .map_err(|e| format!("invalid response envelope: {e}"))?;

        if resp_seq != seq {
            return Err(format!(
                "response sequence mismatch: expected {seq}, got {resp_seq}"
            ));
        }

        let plaintext = self
            .cipher
            .decrypt(seq, Direction::ServerToClient, ciphertext)
            .map_err(|e| format!("PQC decryption failed: {e}"))?;

        Ok(plaintext)
    }

    pub fn close(&self) {
        self.wt.close();
    }
}
