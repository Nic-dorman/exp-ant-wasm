//! Download client logic.
//!
//! Mirrors the download path from `ant-core`, adapted for WASM.
//! Fetches chunks via WebTransport and decrypts using self_encryption.

use crate::log;
use crate::transport::WtTransport;
use ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, DataChunk,
};
use bytes::Bytes;
use lru::LruCache;
use self_encryption::{decrypt, DataMap, EncryptedChunk};
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Default chunk cache capacity.
const CACHE_CAPACITY: usize = 1024;

/// Download client wrapping a WebTransport transport.
pub struct DownloadClient {
    transport: WtTransport,
    next_request_id: AtomicU64,
    cache: RefCell<LruCache<[u8; 32], Bytes>>,
}

impl DownloadClient {
    pub fn new(transport: WtTransport) -> Self {
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
        // Cache check
        if let Some(cached) = self.cache.borrow_mut().get(address).cloned() {
            let computed = ant_protocol::compute_address(&cached);
            if computed == *address {
                return Ok(Some(DataChunk::new(*address, cached)));
            }
            self.cache.borrow_mut().pop(address);
        }

        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage {
            request_id: self.next_request_id(),
            body: ChunkMessageBody::GetRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| format!("failed to encode request: {e}"))?;

        let response_bytes = self.transport.send_request(&message_bytes).await?;

        let response =
            ChunkMessage::decode(&response_bytes).map_err(|e| format!("decode error: {e}"))?;

        match response.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                address: addr,
                content,
            }) => {
                if addr != *address {
                    return Err(format!(
                        "address mismatch: expected {}, got {}",
                        hex::encode(address),
                        hex::encode(addr)
                    ));
                }

                let computed = ant_protocol::compute_address(&content);
                if computed != addr {
                    return Err(format!(
                        "content hash mismatch: expected {}, got {}",
                        hex::encode(addr),
                        hex::encode(computed)
                    ));
                }

                let content = Bytes::from(content);
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
    /// 1. Fetches the chunk at `address` (the serialized DataMap)
    /// 2. Deserializes the DataMap using bincode
    /// 3. Fetches all referenced encrypted chunks
    /// 4. Decrypts using self-encryption
    /// 5. Returns the original content
    pub async fn download_from_address(&self, address: &[u8; 32]) -> Result<Bytes, String> {
        log(&format!(
            "Fetching DataMap at {}...",
            &hex::encode(address)[..16]
        ));
        let datamap_chunk = self
            .chunk_get(address)
            .await?
            .ok_or_else(|| format!("DataMap not found at {}", hex::encode(address)))?;

        // DataMap is serialized with bincode
        let data_map: DataMap = DataMap::from_bytes(&datamap_chunk.content)
            .map_err(|e| format!("failed to deserialize DataMap: {e}"))?;

        let chunk_infos = data_map.infos();
        log(&format!("DataMap has {} chunks to fetch", chunk_infos.len()));

        // Fetch all encrypted chunks
        let mut encrypted_chunks = Vec::with_capacity(chunk_infos.len());
        for (i, info) in chunk_infos.iter().enumerate() {
            let addr: [u8; 32] = info.dst_hash.0;
            let chunk = self
                .chunk_get(&addr)
                .await?
                .ok_or_else(|| {
                    format!(
                        "Missing chunk {}/{}: {}",
                        i + 1,
                        chunk_infos.len(),
                        hex::encode(addr)
                    )
                })?;

            encrypted_chunks.push(EncryptedChunk {
                content: chunk.content,
            });

            if (i + 1) % 10 == 0 || i + 1 == chunk_infos.len() {
                log(&format!(
                    "Fetched {}/{} chunks",
                    i + 1,
                    chunk_infos.len()
                ));
            }
        }

        // Decrypt
        log("Decrypting...");
        let content = decrypt(&data_map, &encrypted_chunks)
            .map_err(|e| format!("decryption failed: {e}"))?;

        log(&format!("Download complete: {} bytes", content.len()));

        Ok(content)
    }

    pub fn close(&self) {
        self.transport.close();
    }
}
