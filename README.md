# exp-ant-wasm

Experimental browser-direct downloads from the Autonomi network over HTTP/3 QUIC with post-quantum cryptography. No intermediary servers — the browser connects directly to network nodes via WebTransport.

> **Status:** This is an experimental project, currently paused. The E2E demo was working as of 2026-04-02. The PQC tunnel and security hardening are implemented but the TLS authentication gap (ECDSA P-256) depends on upstream browser support (~2028+). The app-layer PQC tunnel will remain the primary PQ authentication mechanism until then.

## Architecture

The system uses a dual-transport design: P2P traffic between nodes uses saorsa-core's native QUIC with full PQ crypto, while browser clients connect via WebTransport (HTTP/3) with an application-layer PQC tunnel layered inside the TLS session.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser (WASM)                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  ant-wasm                                                     │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐  │  │
│  │  │ WasmClient  │→ │DownloadClient│→ │ self_encryption     │  │  │
│  │  │ (JS API)    │  │(chunk cache) │  │ (decrypt locally)   │  │  │
│  │  └─────────────┘  └──────┬───────┘  └─────────────────────┘  │  │
│  │                          │                                    │  │
│  │  ┌───────────────────────▼───────────────────────────────┐   │  │
│  │  │ WtTransport                                           │   │  │
│  │  │  PQC Tunnel: ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly  │   │  │
│  │  └───────────────────────┬───────────────────────────────┘   │  │
│  └──────────────────────────┼────────────────────────────────────┘  │
│                             │                                       │
│  ┌──────────────────────────▼────────────────────────────────────┐  │
│  │  Browser TLS Stack (black box)                                │  │
│  │  X25519MLKEM768 key exchange + ECDSA P-256 auth               │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
└─────────────────────────────┼───────────────────────────────────────┘
                              │
                    WebTransport / HTTP/3 / QUIC
                              │
┌─────────────────────────────┼───────────────────────────────────────┐
│  ant-node                   │                                       │
│  ┌──────────────────────────▼────────────────────────────────────┐  │
│  │  wtransport (TLS: X25519MLKEM768 + ECDSA P-256)              │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             │                                       │
│  ┌──────────────────────────▼───────────────────────────────────┐   │
│  │  PQC Tunnel Server                                           │   │
│  │  ML-KEM-768 encapsulation + ML-DSA-65 signing                │   │
│  │  ChaCha20-Poly1305 per-stream encryption                     │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                             │                                       │
│  ┌──────────────────────────▼───────┐  ┌────────────────────────┐   │
│  │  AntProtocol (chunk handler)     │→ │ LMDB storage           │   │
│  │  GET/PUT/Quote over postcard     │  │ + DHT fallback         │   │
│  └──────────────────────────────────┘  └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Network Flow: Browser Download

```
Browser (WASM)                              ant-node
     │                                           │
     │  ──── TLS 1.3 (X25519MLKEM768) ────────→ │  Hybrid PQ key exchange
     │  ←──── TLS established ───────────────── │
     │                                           │
     │  Stream 0: PQC Handshake                  │
     │                                           │
     │  ClientHello [ek: 1184B] ──────────────→  │  ML-KEM-768 encapsulation key
     │                                           │  Server: encaps(ek) → (ss, ct)
     │                                           │  Server: sign(ctx‖ek‖ct) with ML-DSA-65
     │  ←── ServerAccept [ct+pubkey+sig: 6.3KB]  │
     │                                           │
     │  Client: verify ML-DSA-65 signature       │
     │  Client: verify PeerId = BLAKE3(pubkey)   │
     │  Client: decaps(ct) → ss                  │
     │  Both: session_key = BLAKE3(ss)           │
     │                                           │
     │  ════ PQC tunnel established ════════════ │
     │                                           │
     │  Stream 1: Fetch DataMap                  │
     │                                           │
     │  [ChaCha20-Poly1305 encrypted]            │
     │  ChunkGetRequest(address) ─────────────→  │  Lookup LMDB (or DHT fallback)
     │  ←──── ChunkGetResponse(datamap bytes)    │
     │                                           │
     │  Client: deserialize DataMap              │
     │  Client: extract chunk_infos[]            │
     │                                           │
     │  Streams 2..N: Fetch encrypted chunks     │
     │                                           │
     │  ChunkGetRequest(chunk_addr) ──────────→  │  Each on its own bidi stream
     │  ←──── ChunkGetResponse(chunk_bytes)      │  Each with unique nonce
     │  ... repeat for all chunks ...            │
     │                                           │
     │  Client: verify BLAKE3(chunk) == address  │
     │  Client: self_encryption::decrypt()       │
     │  Client: reassemble original file         │
     │                                           │
     │  ← Uint8Array returned to JavaScript      │
     │                                           │
```

## Post-Quantum Security Posture

| Layer | Algorithm | Quantum-Safe | Notes |
|-------|-----------|:---:|-------|
| TLS Key Exchange | X25519MLKEM768 | **Yes** | Hybrid PQ+classical via aws-lc-rs. Browsers negotiate automatically. |
| TLS Authentication | ECDSA P-256 | No | Blocked by browsers — no PQ signature verification until ~2028 (Google MTCs). |
| App-layer Key Exchange | ML-KEM-768 (FIPS 203) | **Yes** | NIST Level 3. Fresh keypair per session. |
| App-layer Authentication | ML-DSA-65 (FIPS 204) | **Yes** | NIST Level 3. Server signs handshake, client verifies. PeerId binding available. |
| Session Encryption | ChaCha20-Poly1305 | **Yes** | 256-bit symmetric — inherently quantum-safe. |
| Content Addressing | BLAKE3 | **Yes** | 256-bit hash — quantum-safe. Verified client-side and server-side. |
| Self-Encryption Keys | BLAKE3 XOF + ChaCha20-Poly1305 | **Yes** | Convergent encryption with symmetric primitives. |
| Payment Quote Signatures | ML-DSA-65 | **Yes** | Quotes signed with node's PQ identity. |
| P2P Transport (node-to-node) | ML-KEM-768 + ML-DSA-65 | **Yes** | Full PQ via saorsa-core. |

**The one remaining gap** — TLS authentication — cannot be fixed from our side. The browser's TLS stack is a black box; no browser accepts PQ signatures for certificate verification today. Google's Merkle Tree Certificates (targeting Q3 2027) are the most likely path. The app-layer ML-DSA-65 authentication fully covers this with PQ server identity verification now.

## Crate Structure

| Crate | Purpose |
|-------|---------|
| `ant-wasm` | Browser WASM client — WebTransport + PQC tunnel + download logic |
| `ant-protocol` | Shared wire protocol types + PQC tunnel envelope/cipher (WASM-compatible) |
| `ant-node` | P2P network node — storage, payment verification, WebTransport server |
| `ant-client` | CLI + SDK for node management and data operations |
| `self_encryption` | Convergent encryption library (BLAKE3 + ChaCha20-Poly1305) |
| `tools` | Dev utilities (chunk injection, WebTransport test client) |

## Security Hardening (2026-04-09)

Fixes applied from an in-depth PQ cryptography review:

- **Nonce reuse prevention**: `stream_seq` (u32) checked before every request; session torn down at `u32::MAX - 1` to prevent ChaCha20-Poly1305 nonce wrap.
- **Key material zeroization**: Shared secrets (`ss_bytes`) and ML-DSA private key bytes (`sk_bytes`) explicitly zeroized after use via the `zeroize` crate. `SessionCipher` already zeroizes on drop.
- **PeerId verification**: New `connect_with_identity(url, cert_hash, peer_id)` JS API verifies the server's ML-DSA-65 public key matches an expected BLAKE3 hash, preventing MITM even if TLS is broken.
- **Per-session rate limiting**: 8 concurrent streams per WebTransport session (+ 64 global) to prevent single-client resource exhaustion.
- **Response size bounds**: Client-side reads capped at `MAX_WIRE_MESSAGE_SIZE + 512` to prevent OOM from malicious servers.
- **PQ TLS**: WebTransport server configured with `X25519MLKEM768` as preferred key exchange via aws-lc-rs `CryptoProvider` and wtransport's `with_custom_tls()`.

