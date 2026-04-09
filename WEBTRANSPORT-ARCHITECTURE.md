## WebTransport Browser Access Layer: Technical Architecture & Security Analysis

### What Was Built

A WebTransport (HTTP/3 over QUIC) listener added **alongside** the existing P2P QUIC transport in ant-node. Browser WASM clients connect directly to network nodes, fetch content-addressed chunks, and decrypt locally using self_encryption. No relays, gateways, or daemons.

```
                    ┌─────────────────────────────────┐
                    │           ant-node               │
  P2P Peers ───────│  saorsa-transport (QUIC/ML-KEM)  │
  (ML-KEM-768 +    │         ↕                        │
   ML-DSA-65)      │    AntProtocol handler            │
                    │         ↕                        │
  Browser WASM ────│  wtransport (WebTransport/H3)    │
  (TLS 1.3 ECDH)  │                                   │
                    └─────────────────────────────────┘
```

Both transports share the same `AntProtocol::try_handle_request()` — the handler is fully transport-agnostic. It receives postcard-encoded bytes, processes them, returns postcard-encoded bytes.

---

### 1. PQC Posture: The Asymmetry

The existing P2P layer is **pure post-quantum**. The WebTransport layer is **not**.

**P2P QUIC (saorsa-transport v0.30.1):**
- Key exchange: **ML-KEM-768** (FIPS 203, NIST Level 3) — no classical fallback
- Authentication: **ML-DSA-65** (FIPS 204, NIST Level 3) — mutual, via RFC 7250 Raw Public Keys
- The TLS negotiation **rejects non-PQC algorithms entirely** — `NegotiationResult::Failed` if no PQC group available
- Peer identity: `PeerId = BLAKE3(ML-DSA-65 public key)` — cryptographically bound

**WebTransport (wtransport v0.7.0 / rustls 0.23):**
- Key exchange: **X25519 ECDH** (classical) — rustls 0.23 cannot negotiate ML-KEM
- Server cert: **ECDSA P-256** self-signed — not post-quantum
- Even when Chrome advertises `X25519MLKEM768` (hybrid PQ), the server doesn't recognize it and falls back to classical X25519
- **Result: zero PQ protection on the transport channel**

This is a fundamental limitation of the current rustls/wtransport ecosystem, not an architectural choice. The upgrade path is:
1. rustls adds native ML-KEM support (in progress, estimated 2025-2026)
2. wtransport inherits it
3. Our WebTransport listener gets PQ key exchange for free

**However**, the data itself is protected:

| Layer | Algorithm | PQ-Safe? |
|-------|-----------|----------|
| P2P transport (node-to-node) | ML-KEM-768 + ML-DSA-65 | Yes |
| WebTransport (browser-to-node) | X25519 ECDH + ECDSA P-256 | **No** |
| Chunk encryption (self_encryption) | ChaCha20-Poly1305, 256-bit keys | Yes |
| Content addressing | BLAKE3 (256-bit) | Yes |
| Binary signing (auto-upgrade) | ML-DSA-65 | Yes |

The content flowing over WebTransport is **already encrypted** with PQ-safe symmetric crypto (ChaCha20-Poly1305). An adversary doing "harvest now, decrypt later" on the TLS channel would recover encrypted chunks, which they'd still need to break ChaCha20 to read. Symmetric crypto at 256-bit key strength is considered quantum-resistant (Grover's algorithm halves effective key length to 128-bit, still secure).

**Net assessment:** The WebTransport TLS channel is classically-protected only, but the payload is double-encrypted — once by self_encryption (PQ-safe symmetric) and once by TLS. The practical quantum risk is limited to metadata exposure (which addresses are being fetched), not content exposure.

---

### 2. Authentication Model: Mutual vs One-Way

**P2P QUIC — Mutual Authentication:**
- Both peers present ML-DSA-65 public keys during TLS handshake
- `client_auth_mandatory()` returns `true` — client auth is **required**
- Server verifies client's ML-DSA-65 signature; client verifies server's
- Peer identity is cryptographically bound: `PeerId = BLAKE3(pubkey)`
- Adaptive trust engine scores peers based on interaction history
- IP diversity enforcement prevents Sybil clustering

**WebTransport — Anonymous Read Access:**
- Server presents self-signed cert; client pins via SHA-256 hash
- **No client authentication** — any browser can connect
- No peer identity, no trust scoring, no IP diversity
- This is intentional: browsers are anonymous readers, not network participants

The WebTransport listener is a **read-optimised edge proxy**, not a P2P peer. It doesn't participate in the DHT, doesn't store trust scores for clients, doesn't enforce identity. It serves chunks from its local LMDB storage (or fetches from the DHT on cache miss).

---

### 3. Security Considerations

**What's solid:**

- **PUT requests require payment verification** — WebTransport clients cannot write without a valid Arbitrum EVM payment proof. The payment verifier is always-on with no disable flag.
- **GET is free by design** — "pay to store, free to read" is the existing network model. WebTransport doesn't change this.
- **Content integrity** — BLAKE3 hash verification on every chunk, both server-side and client-side. Tampered chunks are rejected.
- **Backpressure** — Semaphore limits concurrent stream handlers to 64.
- **Message size bounds** — Rejects messages > 5MB before deserialization.

**What needs attention:**

1. **DHT amplification** — When a GET request misses local storage, the server queries `CLOSE_GROUP_SIZE` DHT peers on behalf of the anonymous client. A malicious client can trigger expensive DHT lookups by requesting non-existent addresses. This needs per-client rate limiting on DHT operations, and a negative cache for recent misses.

2. **No per-client rate limiting** — The 64-stream semaphore is global, not per-IP. One client can consume all slots or spam sequential requests within a single stream. Needs IP-based rate limiting.

3. **Chunk inventory probing** — Any client can enumerate which chunks a node stores by sending GET requests and observing Success vs NotFound responses. This is inherent to content-addressed storage with free reads, but worth noting for nodes storing sensitive data patterns.

4. **Client access pattern tracking** — The WebTransport server sees the source IP and all requested addresses. Unlike P2P where all peers are structurally equivalent, this creates a client-server relationship where the server can profile access patterns.

---

### 4. Transport Architecture

**Wire protocol** — identical on both transports:
- 4-byte big-endian length prefix + postcard-encoded `ChunkMessage`
- `ChunkMessage { request_id: u64, body: ChunkMessageBody }`
- Request/response correlation: on P2P, by `request_id` across a shared channel. On WebTransport, each bidi stream IS the correlation (one request, one response, stream closes).

**WebTransport specifics:**
- Each browser request opens a new bidirectional stream (lightweight, multiplexed over one QUIC connection)
- Write side closed after sending request (signals end-of-message)
- Server reads, processes, writes response, finishes stream
- QUIC flow control and congestion control apply at the connection level

**Certificate discovery:**
- Self-signed cert generated at node startup via `wtransport::Identity::self_signed()`
- SHA-256 hash published in devnet manifest (or eventually, the DHT)
- Browser uses `serverCertificateHashes` W3C API to pin cert
- Production path: cert hashes become part of peer discovery records in the DHT — node runners configure nothing

---

### 5. self_encryption in WASM

The WASM client performs the same decryption as the native client:
1. Fetch DataMap chunk (bincode-serialized `DataMap`)
2. Extract `ChunkInfo` entries with `dst_hash` (destination addresses)
3. Fetch each encrypted chunk
4. Decrypt: XOR deobfuscation -> ChaCha20-Poly1305 -> Brotli decompression

Changes required for WASM compatibility were minimal:
- `rayon` (thread-based parallelism) gated behind `parallel` feature — sequential fallback for WASM
- `tempfile` and `tokio` moved to platform-conditional deps
- `STREAM_DECRYPT_BATCH_SIZE` LazyLock uses `std::env::var` — hardcoded fallback for WASM
- Core crypto (ChaCha20-Poly1305, BLAKE3, bincode) works unchanged on `wasm32-unknown-unknown`

---

### 6. Network Impact

**What this does NOT change:**
- P2P QUIC transport — untouched, still pure PQC
- DHT routing, peer discovery, trust engine — all unchanged
- Payment model — still "pay to store, free to read"
- Storage layer — same LMDB, same chunk format
- Data format — same postcard encoding, same DataMap structure

**What this adds:**
- A new listening socket (separate port, separate QUIC endpoint)
- A new code path from network ingress to `AntProtocol::try_handle_request()`
- An optional DHT fetch path for cache misses (browser asks for chunk not stored locally -> server queries network)
- Feature-gated (`webtransport` feature) — zero impact when disabled

**Scaling considerations:**
- Each node's WebTransport listener is independent — no coordination between nodes
- Browser clients connect to ONE node (not a mesh) — that node becomes their gateway to the network
- The DHT fetch path means any node can serve any chunk (eventually), not just chunks it stores locally
- Load distribution depends on how browsers discover nodes (currently: devnet manifest; production: bootstrap/DHT-based discovery)

---

### 7. Recommendations

**Before production use:**

1. **Rate limiting** — Add per-IP request rate limiting and DHT lookup rate limiting. The DHT amplification vector is the most acute issue.

2. **Negative cache** — Cache NotFound responses for a TTL to prevent repeated DHT queries for the same non-existent address.

3. **Read-only mode** — Consider restricting the WebTransport handler to GET-only (reject PUT/QUOTE/MerkleCandidateQuote from browser clients). Browser uploads should go through the CLI/SDK via P2P.

4. **PQ transparency** — Log or expose whether the negotiated TLS cipher suite includes PQ key exchange, so operators and clients can verify their PQ posture.

**When rustls ships ML-KEM support:**

5. **Upgrade wtransport** — The WebTransport channel gets PQ key exchange with no application-level changes. This is the single most impactful future improvement.

6. **PQ server certs** — Replace ECDSA P-256 self-signed certs with ML-DSA-65 signed certs. Requires browser support for ML-DSA in X.509 (not yet available).
