//! Download client logic.
//!
//! Mirrors the download path from `ant-core/src/data/client/data.rs`
//! and `ant-core/src/data/client/chunk.rs`, adapted for WASM.

use crate::transport::WebRtcTransport;
use ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, DataChunk,
};
use bytes::Bytes;
use lru::LruCache;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Default chunk cache capacity.
const CACHE_CAPACITY: usize = 1024;

/// Download client wrapping a WebRTC transport.
pub struct DownloadClient {
    transport: WebRtcTransport,
    next_request_id: AtomicU64,
    cache: RefCell<LruCache<[u8; 32], Bytes>>,
}

impl DownloadClient {
    pub fn new(transport: WebRtcTransport) -> Self {
        Self {
            transport,
            next_request_id: AtomicU64::new(1),
            cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            )),
        }
    }

    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Fetch a single chunk by its content address.
    ///
    /// Checks the local cache first. On cache miss, sends a `ChunkGetRequest`
    /// to the connected node, verifies the BLAKE3 hash, and caches the result.
    pub async fn chunk_get(&self, address: &[u8; 32]) -> Result<Option<DataChunk>, String> {
        // Cache check with integrity verification
        if let Some(cached) = self.cache.borrow_mut().get(address).cloned() {
            let computed = ant_protocol::compute_address(&cached);
            if computed == *address {
                return Ok(Some(DataChunk::new(*address, cached)));
            }
            // Cache corruption — evict
            self.cache.borrow_mut().pop(address);
        }

        let request_id = self.next_request_id();
        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::GetRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| format!("failed to encode request: {e}"))?;

        let response_bytes = self
            .transport
            .send_request(request_id, &message_bytes)
            .await?;

        let response =
            ChunkMessage::decode(&response_bytes).map_err(|e| format!("decode error: {e}"))?;

        match response.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success { address: addr, content }) => {
                // Verify address matches
                if addr != *address {
                    return Err(format!(
                        "address mismatch: expected {}, got {}",
                        hex::encode(address),
                        hex::encode(addr)
                    ));
                }

                // Verify content hash
                let computed = ant_protocol::compute_address(&content);
                if computed != addr {
                    return Err(format!(
                        "content hash mismatch: expected {}, got {}",
                        hex::encode(addr),
                        hex::encode(computed)
                    ));
                }

                let content = Bytes::from(content);
                // Cache the chunk
                self.cache.borrow_mut().put(*address, content.clone());

                Ok(Some(DataChunk::new(addr, content)))
            }
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => Ok(None),
            ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => {
                Err(format!("remote error: {e}"))
            }
            _ => Err("unexpected response type".to_string()),
        }
    }

    /// Download data from a network address.
    ///
    /// Fetches the chunk at `address`, interprets it as a serialized DataMap,
    /// then fetches and decrypts all referenced chunks.
    ///
    /// Note: self_encryption integration is stubbed pending the WASM fork.
    /// Currently returns the raw DataMap chunk bytes.
    pub async fn download_from_address(&self, address: &[u8; 32]) -> Result<Bytes, String> {
        // Step 1: Fetch the DataMap chunk
        let datamap_chunk = self
            .chunk_get(address)
            .await?
            .ok_or_else(|| format!("DataMap not found at {}", hex::encode(address)))?;

        // TODO: Phase 1 — integrate self_encryption WASM fork
        //
        // When the self_encryption fork with WASM feature gates is ready:
        //   1. Deserialize DataMap: rmp_serde::from_slice(&datamap_chunk.content)
        //   2. Extract chunk addresses from data_map.infos()
        //   3. Fetch each chunk via chunk_get()
        //   4. Decrypt: self_encryption::decrypt(&data_map, &encrypted_chunks)
        //   5. Return decrypted bytes
        //
        // For now, return the raw DataMap bytes to prove the transport works.

        Ok(datamap_chunk.content)
    }

    /// Close the underlying WebRTC connection.
    pub fn close(&self) {
        self.transport.close();
    }
}
