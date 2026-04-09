# Application-Layer PQC Tunnel for WebTransport

**Author:** Nic Dorman
**Date:** 2026-04-09
**Status:** Proposal

---

## 1. Problem Statement

The experimental browser-direct download path uses WebTransport (HTTP/3 over QUIC) to connect browser WASM clients to ant-node storage nodes. The P2P layer (saorsa-transport) provides pure PQ security via ML-KEM-768 + ML-DSA-65 at the QUIC/TLS 1.3 level. The WebTransport bridge does not.

**Current WebTransport crypto:**

| Layer | Algorithm | PQ Status |
|-------|-----------|-----------|
| TLS 1.3 key exchange | X25519 ECDH | Vulnerable |
| TLS 1.3 authentication | ECDSA P-256 (self-signed) | Vulnerable |
| Wire framing | Plaintext postcard over length-prefix | N/A |
| App-layer payload | ChaCha20-Poly1305 (self_encryption) | Safe (symmetric) |

The TLS handshake is vulnerable to harvest-now-decrypt-later. A passive adversary recording WebTransport sessions today can, with a future cryptographically-relevant quantum computer, recover the TLS session keys and observe all wire traffic including chunk addresses, request patterns, and DataMap contents.

The self_encryption layer protects chunk *payloads* (convergent encryption with ChaCha20-Poly1305 produces ciphertext that is PQ-safe at the symmetric level), but the DataMap itself, chunk addresses, and request/response metadata are exposed at the wire level.

**Why not fix at the transport layer?**
- `wtransport 0.7` does not expose rustls `CryptoProvider` configuration
- rustls 0.23 has experimental ML-KEM via `rustls-post-quantum`, but wtransport doesn't surface it
- Browser-side TLS is opaque — Chrome/Edge negotiate X25519Kyber768 hybrid if the server advertises it, but we cannot control or verify this from WASM
- A fork of wtransport to inject `rustls-post-quantum` is viable long-term but couples us to wtransport internals

## 2. Proposal: Application-Layer ML-KEM-768 Tunnel

Establish a PQ-secure key exchange *inside* the WebTransport session using ML-KEM-768 (FIPS 203), then encrypt all subsequent wire messages with ChaCha20-Poly1305 keyed from the ML-KEM shared secret. The classical TLS layer remains as a defense-in-depth outer shell.

```
┌─────────────────────────────────────────────────────────┐
│  Browser                              ant-node          │
│                                                         │
│  ┌──────────────┐                  ┌──────────────┐     │
│  │  ant-wasm    │   WebTransport   │  webtransport│     │
│  │  (WASM)      │   (HTTP/3/QUIC)  │  server      │     │
│  │              │                  │              │     │
│  │  ┌────────┐  │  TLS 1.3 (classical outer)     │     │
│  │  │ fips203│  │◄────────────────►│  wtransport  │     │
│  │  │ML-KEM  │  │                  │              │     │
│  │  │-768    │  │  ML-KEM-768 handshake (stream 0)│     │
│  │  └────────┘  │─ ─ ─ ─ ─ ─ ─ ─ ►│  ┌────────┐  │     │
│  │              │  ek (1184 B)     │  │ fips203│  │     │
│  │              │◄ ─ ─ ─ ─ ─ ─ ─ ─│  │ML-KEM  │  │     │
│  │              │  ct (1088 B)     │  │-768    │  │     │
│  │              │                  │  └────────┘  │     │
│  │  ss = Decaps(dk, ct)            │              │     │
│  │  k = BLAKE3::derive_key(ss)     │  ss = encap │     │
│  │              │                  │  k = BLAKE3  │     │
│  │              │  Encrypted ChunkMessages        │     │
│  │              │  (ChaCha20-Poly1305, key=k)     │     │
│  │              │◄────────────────►│              │     │
│  └──────────────┘                  └──────────────┘     │
│                                                         │
│  PQ-safe channel established regardless of TLS config   │
└─────────────────────────────────────────────────────────┘
```

### 2.1 Threat Model

**In scope:**
- Passive harvest-now-decrypt-later (HNDL) adversary recording WebTransport sessions
- Future quantum computer breaking X25519/ECDSA to recover classical TLS session keys
- Adversary with access to network taps but not endpoint compromise

**Out of scope (deferred):**
- Active real-time quantum MITM (requires breaking TLS *and* ML-KEM simultaneously during handshake)
- Endpoint compromise (if the browser or node is owned, game over regardless)
- Traffic analysis (request timing, chunk sizes are not hidden — padding is a separate concern)

**What this protects:**
- DataMap contents (the index of all chunk addresses for a file)
- Chunk addresses in GET requests (reveals what content is being fetched)
- Request/response correlation (which addresses map to which payloads)
- Any future PUT/quote request payloads over WebTransport

**What remains exposed even with this tunnel:**
- Connection metadata (IP addresses, session timing, stream count)
- Chunk payload confidentiality is already PQ-safe (ChaCha20-Poly1305 symmetric encryption from self_encryption is not quantum-vulnerable)

### 2.2 Why ML-KEM Only (No ML-DSA at This Layer)

Server authentication via ML-DSA-65 signatures on the handshake would provide PQ-authenticated key exchange, preventing a quantum MITM from substituting ML-KEM ciphertexts. However:

1. A quantum MITM must break the classical TLS *in real-time during the handshake* — this is a fundamentally harder attack than passive HNDL
2. Adding ML-DSA requires the client to know the server's ML-DSA-65 public key (1952 bytes) before connecting — this means publishing it in the devnet manifest or a discovery protocol, adding a trust bootstrap problem
3. The P2P layer already authenticates nodes via ML-DSA-65 PeerIds — a WebTransport client connecting to a node whose PeerId is known from the DHT could verify the ML-DSA signature, but this requires DHT awareness in the browser client (currently out of scope)

**Decision:** ML-KEM-768 only for the initial implementation. ML-DSA-65 server authentication is a follow-up once the browser client has a trust anchor for node identities.

## 3. Protocol Specification

### 3.1 Wire Format Changes

Current wire format (per bidi stream):
```
Request:  [4B length (BE u32)][postcard ChunkMessage]
Response: [4B length (BE u32)][postcard ChunkMessage]
```

New wire format adds a 1-byte envelope type discriminator:

```
[4B length (BE u32)][1B type][payload...]

Type 0x00: Plaintext (backward compat, rejected when PQC is required)
  payload = [postcard ChunkMessage]

Type 0x01: PQC Handshake Client Hello
  payload = [2B version (BE u16)][1184B ML-KEM-768 encapsulation key]

Type 0x02: PQC Handshake Server Accept
  payload = [2B version (BE u16)][1088B ML-KEM-768 ciphertext]

Type 0x03: PQC Encrypted
  payload = [4B stream_seq (BE u32)][encrypted blob]
  where encrypted blob = ChaCha20-Poly1305(
    key   = session_key,
    nonce = stream_seq ‖ direction_byte ‖ 0x00..00  (12 bytes),
    aad   = empty,
    plaintext = [postcard ChunkMessage]
  )
```

### 3.2 Handshake Protocol

Performed once per WebTransport session, on the first bidirectional stream (stream 0).

```
Client                                          Server
  │                                               │
  │  1. (ek, dk) = ML-KEM-768::KeyGen()           │
  │                                               │
  │  ── ClientHello(version=1, ek) ──────────────►│
  │     [4B len][0x01][0x00 0x01][ek: 1184B]      │
  │                                               │
  │                    2. (ss, ct) = ML-KEM-768::Encaps(ek)
  │                       session_key = BLAKE3::derive_key(
  │                         "ant-wt-pqc-v1", ss)  │
  │                                               │
  │  ◄── ServerAccept(version=1, ct) ─────────────│
  │     [4B len][0x02][0x00 0x01][ct: 1088B]      │
  │                                               │
  │  3. ss = ML-KEM-768::Decaps(dk, ct)            │
  │     session_key = BLAKE3::derive_key(          │
  │       "ant-wt-pqc-v1", ss)                    │
  │                                               │
  │  Session key established. dk zeroized.         │
  │  Stream 0 closed.                              │
  │                                               │
  │  All subsequent streams use Type 0x03.         │
```

**Key derivation:**
```rust
let session_key: [u8; 32] = blake3::derive_key("ant-wt-pqc-v1", &shared_secret);
```

**Nonce construction (12 bytes):**
```
Bytes 0-3:  stream_seq (BE u32) — monotonic counter per session, starts at 1
Byte  4:   direction — 0x00 for client→server, 0x01 for server→client
Bytes 5-11: 0x00 (zero-padded)
```

Each bidi stream carries exactly one request and one response, so `stream_seq` uniquely identifies the stream, and `direction` disambiguates the two messages. No nonce reuse is possible as long as `stream_seq` is monotonic (which it is — the client creates streams sequentially).

### 3.3 Error Handling

| Condition | Behavior |
|-----------|----------|
| Server receives Type 0x00 when PQC is enforced | Close session, log warning |
| Client receives malformed ServerAccept | Close session, surface error to JS |
| ML-KEM Decaps fails | Close session (indicates tampering or corruption) |
| Server receives Type 0x03 before handshake complete | Close stream, log error |
| Version mismatch | Server responds with ServerAccept using its highest supported version; client checks compatibility |

### 3.4 Sizes and Overhead

| Message | Current Size | With PQC Tunnel |
|---------|-------------|-----------------|
| Handshake (client) | N/A | 4 + 1 + 2 + 1184 = **1191 bytes** (one-time) |
| Handshake (server) | N/A | 4 + 1 + 2 + 1088 = **1095 bytes** (one-time) |
| GET request (~34B postcard) | 4 + 34 = 38B | 4 + 1 + 4 + 34 + 16 = **59 bytes** (+55%) |
| GET response (~1MB chunk) | 4 + ~1MB | 4 + 1 + 4 + ~1MB + 16 = **~1MB + 25 bytes** (~0%) |

Handshake adds ~2.3KB one-time cost per session. Per-message overhead is 21 bytes (type + seq + auth tag) — negligible for chunk transfers.

## 4. Implementation Plan

### 4.1 Dependency Changes

**ant-wasm (WASM client):**
```toml
# Use fips203/fips204 directly — saorsa-pqc has tokio/rayon deps that block wasm32
fips203 = { version = "0.4", features = ["default-rng", "ml-kem-768"] }
chacha20poly1305 = "0.10"
blake3 = "1"   # already present
getrandom = { version = "0.2", features = ["js"] }  # WASM RNG entropy source
```

**Why fips203 directly, not saorsa-pqc?**
`saorsa-pqc` v0.5 unconditionally depends on `tokio` (rt, net, sync, time), `rayon`, and `libc` — none of which compile for `wasm32-unknown-unknown`. The underlying `fips203` crate from integritychain is `#![no_std]`, pure Rust, zero system deps, and has an official `wasm/` demo. The API is straightforward:

```rust
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

// Client: generate keypair
let (ek, dk) = ml_kem_768::KG::try_keygen().unwrap();
let ek_bytes: [u8; 1184] = ek.into_bytes();

// Server: encapsulate
let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).unwrap();
let (ss, ct) = ek.try_encaps().unwrap();
let ct_bytes: [u8; 1088] = ct.into_bytes();
let shared_secret: [u8; 32] = ss.into_bytes();

// Client: decapsulate
let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes).unwrap();
let ss = dk.try_decaps(&ct).unwrap();
let shared_secret: [u8; 32] = ss.into_bytes();
```

**ant-node (server):**
```toml
# Can use saorsa-pqc (already an indirect dep via saorsa-core), or fips203 directly
# Using fips203 directly for consistency with the WASM side
fips203 = { version = "0.4", features = ["default-rng", "ml-kem-768"], optional = true }
chacha20poly1305 = { version = "0.10", optional = true }

[features]
webtransport = ["dep:wtransport", "dep:fips203", "dep:chacha20poly1305"]
```

Note: `chacha20poly1305 0.10` and `blake3 1` are already transitive dependencies via `self_encryption`. Adding them as direct deps adds no new code to the binary.

### 4.2 New Module: `pqc_tunnel`

Shared types and logic, usable from both WASM and native. Could live in `ant-protocol` (already WASM-compatible) or as a thin module duplicated in each crate.

**Recommended: add to `ant-protocol`** since it already bridges both sides.

```
ant-protocol/
  src/
    lib.rs
    chunk.rs
    pqc_tunnel.rs   ← new
```

`pqc_tunnel.rs` contains:
- `PqcEnvelope` enum (Plaintext / ClientHello / ServerAccept / Encrypted)
- Envelope encode/decode (trivial — 1-byte discriminator + fixed-size fields)
- `SessionCipher` struct wrapping a `[u8; 32]` session key with encrypt/decrypt methods
- Nonce construction from `(stream_seq: u32, direction: Direction)`

This module has **no** `fips203` dependency — it only handles framing and symmetric crypto. The ML-KEM operations happen in the transport layers (`ant-wasm/src/transport.rs` and `ant-node/src/webtransport/server.rs`) which call fips203 directly.

```rust
// ant-protocol/src/pqc_tunnel.rs

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

pub const PQC_VERSION: u16 = 1;
pub const ML_KEM_768_EK_SIZE: usize = 1184;
pub const ML_KEM_768_CT_SIZE: usize = 1088;

#[repr(u8)]
pub enum EnvelopeType {
    Plaintext = 0x00,
    ClientHello = 0x01,
    ServerAccept = 0x02,
    Encrypted = 0x03,
}

pub enum Direction {
    ClientToServer,  // 0x00
    ServerToClient,  // 0x01
}

pub struct SessionCipher {
    key: [u8; 32],  // derived from ML-KEM shared secret via BLAKE3
}

impl SessionCipher {
    pub fn from_shared_secret(ss: &[u8; 32]) -> Self {
        let key = blake3::derive_key("ant-wt-pqc-v1", ss);
        Self { key }
    }

    pub fn encrypt(
        &self,
        stream_seq: u32,
        direction: Direction,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, /* ... */> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = build_nonce(stream_seq, direction);
        cipher.encrypt(&nonce, plaintext)
    }

    pub fn decrypt(
        &self,
        stream_seq: u32,
        direction: Direction,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, /* ... */> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = build_nonce(stream_seq, direction);
        cipher.decrypt(&nonce, ciphertext)
    }
}

fn build_nonce(stream_seq: u32, direction: Direction) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&stream_seq.to_be_bytes());
    nonce[4] = match direction {
        Direction::ClientToServer => 0x00,
        Direction::ServerToClient => 0x01,
    };
    nonce.into()
}
```

### 4.3 Client-Side Changes (ant-wasm)

**`ant-wasm/src/transport.rs`:**

```rust
// Current state:
pub struct WtTransport {
    wt: WebTransport,
}

// After:
pub struct WtTransport {
    wt: WebTransport,
    cipher: SessionCipher,
    stream_seq: Cell<u32>,
}
```

Changes to `WtTransport`:

1. **`connect()` / `connect_with_cert_hash()`**: After WebTransport session is ready, open stream 0 and perform ML-KEM handshake:
   ```rust
   // Generate ML-KEM-768 keypair
   let (ek, dk) = ml_kem_768::KG::try_keygen().unwrap();

   // Send ClientHello: [4B len][0x01][version][ek]
   let mut hello = Vec::with_capacity(1191);
   hello.push(0x01);
   hello.extend_from_slice(&PQC_VERSION.to_be_bytes());
   hello.extend_from_slice(&ek.into_bytes());
   // ... send via bidi stream, read ServerAccept ...

   // Parse ServerAccept: [0x02][version][ct]
   let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes).unwrap();
   let ss = dk.try_decaps(&ct).unwrap();
   let cipher = SessionCipher::from_shared_secret(&ss.into_bytes());
   // dk is dropped and zeroized here
   ```

2. **`send_request()`**: Wrap ChunkMessage in encrypted envelope:
   ```rust
   // Before (current):
   // [4B len][postcard ChunkMessage]

   // After:
   let seq = self.stream_seq.get();
   self.stream_seq.set(seq + 1);

   let encrypted = self.cipher.encrypt(seq, Direction::ClientToServer, &message_bytes)?;
   // Frame: [4B len][0x03][4B seq][encrypted]

   // Read response, decrypt:
   let decrypted = self.cipher.decrypt(seq, Direction::ServerToClient, &encrypted_response)?;
   ```

### 4.4 Server-Side Changes (ant-node)

**`ant-node/src/webtransport/server.rs`:**

1. **`handle_session()`**: Accept the first bidi stream as PQC handshake:
   ```rust
   // First stream: PQC handshake
   let (send, recv) = connection.accept_bi().await?;
   // Read ClientHello, validate version
   // Encapsulate:
   let (ss, ct) = ek.try_encaps().unwrap();
   // Send ServerAccept with ct
   let cipher = Arc::new(SessionCipher::from_shared_secret(&ss.into_bytes()));
   // ss zeroized on drop

   // All subsequent streams use this cipher
   let stream_seq = AtomicU32::new(1);
   loop {
       let (send, recv) = connection.accept_bi().await?;
       let seq = stream_seq.fetch_add(1, Ordering::Relaxed);
       let cipher = cipher.clone();
       tokio::spawn(handle_encrypted_stream(send, recv, seq, cipher, protocol.clone()));
   }
   ```

2. **`handle_encrypted_stream()`**: New function replacing `handle_stream()`:
   ```rust
   // Read envelope: [4B len][0x03][4B seq][ciphertext]
   // Decrypt with cipher.decrypt(seq, Direction::ClientToServer, &ciphertext)
   // Dispatch to protocol.try_handle_request(&plaintext)
   // Encrypt response: cipher.encrypt(seq, Direction::ServerToClient, &response)
   // Write envelope: [4B len][0x03][4B seq][encrypted_response]
   ```

### 4.5 Files Changed Summary

| File | Change |
|------|--------|
| `ant-protocol/Cargo.toml` | Add `chacha20poly1305 = "0.10"` |
| `ant-protocol/src/lib.rs` | Add `pub mod pqc_tunnel;` |
| `ant-protocol/src/pqc_tunnel.rs` | **New.** Envelope types, `SessionCipher`, nonce construction |
| `ant-wasm/Cargo.toml` | Add `fips203`, `getrandom` with `js` feature |
| `ant-wasm/src/transport.rs` | Add PQC handshake to `connect()`, encrypt/decrypt in `send_request()` |
| `ant-wasm/src/lib.rs` | No change (transport is internal) |
| `ant-wasm/src/client.rs` | No change (operates on decrypted ChunkMessages) |
| `ant-node/Cargo.toml` | Add `fips203` (optional, gated on `webtransport`) |
| `ant-node/src/webtransport/server.rs` | PQC handshake on stream 0, encrypted stream handler |
| `ant-node/src/webtransport/mod.rs` | No change (run() signature unchanged) |

**`client.rs` and the protocol handler are untouched.** The PQC tunnel is transparent to the application layer — `DownloadClient` sends/receives `ChunkMessage` exactly as before, and `AntProtocol::try_handle_request()` receives the same postcard bytes. The tunnel is purely a transport concern.

## 5. What This Does NOT Change

- **Node-to-node P2P**: Untouched. saorsa-transport's ML-KEM-768 + ML-DSA-65 QUIC continues as-is.
- **AntProtocol handler**: Receives identical postcard `ChunkMessage` bytes. Zero code changes.
- **self_encryption**: Chunk encryption/decryption is unaffected. The tunnel protects the *wire protocol*, not the *storage layer*.
- **Certificate generation**: wtransport's self-signed cert flow is unchanged. The PQC tunnel sits above it.
- **devnet manifest**: No new fields required (unless we later add ML-DSA node identity for authenticated handshake).

## 6. Security Properties

| Property | Classical TLS (current) | With PQC Tunnel |
|----------|------------------------|-----------------|
| Confidentiality (classical adversary) | Yes (TLS 1.3) | Yes (TLS + ML-KEM) |
| Confidentiality (quantum passive/HNDL) | **No** | **Yes** (ML-KEM-768 = NIST Level 3) |
| Confidentiality (quantum active MITM) | No | **Yes** — ML-DSA-65 authenticated handshake (Phase 2 implemented) |
| Server authentication (classical) | Yes (cert pinning) | Yes (unchanged + ML-DSA-65) |
| Server authentication (quantum) | No (ECDSA broken) | **Yes** — ML-DSA-65 (FIPS 204, NIST Level 3) |
| Forward secrecy | Yes (TLS ephemeral) | Yes (ML-KEM keypair is per-session, dk zeroized after decaps) |
| Replay protection | Yes (TLS record layer) | Yes (monotonic stream_seq in nonce prevents replay; stream_seq reuse across sessions is safe because session_key differs) |

### 6.1 KNOWN GAP: Unauthenticated Key Exchange (Quantum Active MITM)

**This tunnel does NOT provide post-quantum server authentication. This is a deliberate deferral, not an oversight. It must be addressed in Phase 2 before any production deployment.**

#### The Attack

The ML-KEM-768 handshake in this proposal is unauthenticated — the client has no PQ-secure way to verify that the ServerAccept came from the real node and not an intermediary. An adversary with a real-time cryptographically-relevant quantum computer (CRQC) could perform a relay attack:

```
Browser                     Adversary (CRQC)                   Node
  |                              |                               |
  |  TLS ClientHello ----------->|  (breaks TLS in real-time)    |
  |  <--- TLS ServerHello ------|  (forges ECDSA cert)          |
  |                              |  TLS ClientHello ------------>|
  |                              |  <--- TLS ServerHello -------|
  |                              |                               |
  |  ML-KEM ek_client --------->|                               |
  |                              |  ML-KEM ek_adversary -------->|
  |                              |  <---- ct_real (for ek_adv) -|
  |                              |  ss_server = Decaps(dk_adv, ct_real)
  |                              |                               |
  |                              |  (ss_client, ct_fake) = Encaps(ek_client)
  |  <---- ct_fake -------------|                               |
  |  ss_client = Decaps(dk, ct_fake)                             |
  |                              |                               |
  |  Encrypted traffic -------->|  decrypt with ss_client        |
  |                              |  re-encrypt with ss_server     |
  |                              |  ---------------------------->|
  |                              |  <----------------------------|
  |                              |  decrypt with ss_server        |
  |  <--------------------------|  re-encrypt with ss_client     |
  |                              |                               |
  |  Both sides believe they     |  Adversary reads all traffic  |
  |  have a PQ-secure channel    |  in plaintext                 |
```

The adversary holds two independent session keys (`ss_client` and `ss_server`) and proxies all traffic, decrypting and re-encrypting each message. Neither the browser nor the node can detect this.

#### Why This Is Deferred (Not Ignored)

This attack requires **all three** conditions simultaneously:

1. **A real-time CRQC** — a quantum computer capable of breaking X25519 ECDH and forging ECDSA signatures during the TLS handshake (seconds, not offline). No such machine exists today; most estimates place CRQCs at 2030-2040+.
2. **Active network position** — the adversary must be on the network path between browser and node, not just passively recording.
3. **Live interception** — the adversary must operate during the session, not after the fact. Recorded sessions cannot be MITM'd retroactively.

By contrast, the **harvest-now-decrypt-later** threat (which this tunnel fully mitigates) requires only passive recording today and a quantum computer at any future date. HNDL is the urgent threat; active quantum MITM is a future threat.

**However: this gap means the tunnel provides PQ confidentiality against passive adversaries only. It does not provide PQ-authenticated key exchange. Any claim of "full PQC" for the WebTransport path would be inaccurate until Phase 2 is complete.**

#### What Phase 2 Requires to Close This Gap

Adding ML-DSA-65 server authentication to the handshake:

1. **Node identity**: Each node generates an ML-DSA-65 keypair (public key: 1952 bytes, signature: 3309 bytes). This may already exist in the P2P layer — nodes have ML-DSA-65 identities via saorsa-transport PeerIds.

2. **Trust anchor distribution**: The client must know the server's ML-DSA-65 public key *before* the handshake. Options:
   - Publish in the devnet manifest alongside the cert hash (simplest, sufficient for devnet)
   - Embed in a PKI or certificate chain (production-grade, more complex)
   - Fetch from DHT via a secondary trusted channel (requires browser DHT awareness)

3. **Handshake change**: Server signs the ML-KEM ciphertext (or the full ServerAccept message) with its ML-DSA-65 secret key. Client verifies the signature against the known public key before decapsulating.

4. **Wire format**: ServerAccept grows by ~3309 bytes (ML-DSA-65 signature). One-time cost per session.

5. **WASM impact**: `fips204` (ML-DSA) is also `#![no_std]` pure Rust, WASM-compatible. Add `fips204 = { version = "0.4", features = ["ml-dsa-65"] }` to ant-wasm.

**Phase 2 is not blocked by any technical dependency — only by the design decision of how to distribute node ML-DSA public keys to browser clients. This decision should be made before production deployment.**

## 7. Performance Budget

**ML-KEM-768 operations (benchmarked on fips203 v0.4, x86_64):**
- KeyGen: ~50 μs
- Encaps: ~60 μs
- Decaps: ~55 μs

**WASM penalty (estimated 3-5x):**
- KeyGen: ~150-250 μs
- Encaps: ~180-300 μs
- Decaps: ~165-275 μs

**ChaCha20-Poly1305 (per message):**
- ~1 GB/s on native, ~200 MB/s in WASM
- A 1MB chunk response: ~5 ms in WASM

**Total per-session overhead:**
- Handshake: ~0.5 ms (WASM keygen + 2 stream messages + WASM decaps)
- Per-chunk-request: ~5 μs encrypt + ~5 ms decrypt (dominated by 1MB chunk decryption)

For a typical download (1 DataMap + N chunks), the handshake is amortized over all chunk fetches. The per-message ChaCha20 overhead is negligible compared to network RTT and self_encryption decryption.

## 8. Upgrade Path

This design is explicitly temporary — a bridge until transport-layer PQ is available:

1. **Phase 1 (this proposal):** App-layer ML-KEM-768 tunnel. Protects against HNDL. No upstream deps.
2. **Phase 2:** Add ML-DSA-65 server authentication to the handshake. Requires node identity in devnet manifest. Protects against quantum active MITM.
3. **Phase 3:** `rustls-post-quantum` matures, wtransport exposes `CryptoProvider` config. Fork or upstream PR to enable transport-layer PQ. App-layer tunnel becomes redundant.
4. **Phase 4:** Remove app-layer tunnel. WebTransport has native PQ at TLS level, matching saorsa-transport's P2P security posture.

At Phase 4, the wire format reverts to Type 0x00 (plaintext postcard), the `pqc_tunnel` module is removed, and `fips203` is dropped from ant-wasm. The protocol version field in the handshake enables graceful negotiation during the transition.

## 9. Open Questions

1. **Per-session vs per-stream key exchange?** This proposal uses per-session (one ML-KEM handshake, all streams use derived key). Per-stream would provide stronger isolation but adds ~0.5ms and 2.3KB per chunk request. Recommendation: per-session is sufficient given forward secrecy from ephemeral session keys.

2. **Mandatory or optional?** Should the server reject plaintext (Type 0x00) connections when PQC is available? Recommendation: make it mandatory when the `webtransport` feature includes PQC, with a `webtransport-no-pqc` feature flag for testing.

3. **saorsa-pqc vs fips203 on the node side?** The node already has saorsa-pqc as a transitive dep. Using fips203 directly is simpler and avoids version conflicts, but diverges from the saorsa-labs ecosystem convention. Either works — the ML-KEM-768 output is standardized (FIPS 203), so the ciphertext and shared secret bytes are identical regardless of implementation.

4. **Compression before encryption?** Postcard messages are already compact, but DataMap payloads (list of chunk addresses) could benefit from compression before encryption. Not in initial scope, but the envelope format has room for a compression flag in the type byte.
