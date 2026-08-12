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
| TLS Key Exchange | X25519MLKEM768 | ✅ | Hybrid PQ+classical via aws-lc-rs. Browsers negotiate automatically. |
| TLS Authentication | ECDSA P-256 | ❌ | Blocked by browsers — no PQ signature verification until ~2028 (Google MTCs). |
| App-layer Key Exchange | ML-KEM-768 (FIPS 203) | ✅ | NIST Level 3. Fresh keypair per session. |
| App-layer Authentication | ML-DSA-65 (FIPS 204) | ✅ | NIST Level 3. Server signs handshake, client verifies. PeerId binding available. |
| Session Encryption | ChaCha20-Poly1305 | ✅ | 256-bit symmetric — inherently quantum-safe. |
| Content Addressing | BLAKE3 | ✅ | 256-bit hash — quantum-safe. Verified client-side and server-side. |
| Self-Encryption Keys | BLAKE3 XOF + ChaCha20-Poly1305 | ✅ | Convergent encryption with symmetric primitives. |
| Payment Quote Signatures | ML-DSA-65 | ✅ | Quotes signed with node's PQ identity. |
| P2P Transport (node-to-node) | ML-KEM-768 + ML-DSA-65 | ✅ | Full PQ via saorsa-core. |

**The one remaining gap** — TLS authentication — cannot be fixed from our side. The browser's TLS stack is a black box; no browser accepts PQ signatures for certificate verification today. Google's Merkle Tree Certificates (targeting Q3 2027) are the most likely path. The app-layer ML-DSA-65 authentication fully covers this with PQ server identity verification now.

## Why WebTransport (not WebRTC)?

The project's earliest demo used WebRTC data channels (`test-file.txt` is a relic of it). The switch to WebTransport came down to the PQ-first goal — status re-verified 2026-08-12:

| Consideration | WebTransport | WebRTC |
|-------|:---:|:---:|
| PQ key exchange in browsers today | ✅ QUIC/TLS 1.3 negotiates X25519MLKEM768 by default | ❌ DTLS 1.2 has no PQ path; DTLS 1.3 PQC is a Chrome field trial |
| PQ-capable Rust server stack | ✅ rustls + aws-lc-rs (this repo) | ❌ webrtc-rs is DTLS 1.2-only, no PQ code |
| Rust stack maturity | ✅ quinn/wtransport stable | ⚠️ legacy line stalls >16 KiB writes; new sans-IO core is pre-1.0 alpha |

Details (as of 2026-08): Chrome now ships DTLS 1.3 ([enabled by default](https://issues.chromium.org/issues/382915276)) and libwebrtc carries a [`WebRTC-EnableDtlsPqc` field trial](https://webrtc.googlesource.com/src/+/dae879ac73e0cd06f08a0fd160da764263dc3c24) — so transport-layer-PQ WebRTC is no longer impossible, just experimental on the browser side and unsupported by any Rust server stack. On the Rust side, webrtc-dtls rejected Chrome's ClientHello outright until [0.12.0 (2025-05)](https://github.com/webrtc-rs/webrtc/pull/654), webrtc-data's `poll_write` still reports parked writes as complete in the latest 0.17.2 release (the >16 KiB stall), and the rewritten [`rtc` core](https://github.com/webrtc-rs/rtc) remains DTLS 1.2-only. WebRTC keeps one structural advantage — true P2P with self-signed certs via SDP fingerprints, proved viable against production by [autonomi-webrtc-direct-poc](https://github.com/rid-dim/autonomi-webrtc-direct-poc) — so this is worth revisiting if DTLS PQC ships by default and a Rust server stack catches up.

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

