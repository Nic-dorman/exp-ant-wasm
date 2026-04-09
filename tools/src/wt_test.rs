//! Quick WebTransport test client - performs authenticated PQC handshake
//! (ML-KEM-768 + ML-DSA-65), then sends an encrypted ChunkGetRequest.

use ant_node::{ChunkGetRequest, ChunkMessage, ChunkMessageBody};
use ant_protocol::pqc_tunnel::{
    self, decode_server_accept, encode_client_hello, encode_encrypted, decode_encrypted,
    Direction, SessionCipher,
};
use fips203::ml_kem_768;
use fips203::traits::{KeyGen, SerDes};
use fips204::ml_dsa_65;
use fips204::traits::Verifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: wt-test <url> <address-hex> <cert-hash-hex> [expected-peer-id-hex]");
        eprintln!("  e.g.: wt-test https://127.0.0.1:15000 8125253e... ab12cd34... [peer-id-hex]");
        std::process::exit(1);
    }

    let url = &args[1];
    let address_hex = &args[2];
    let cert_hash_hex = &args[3];
    let expected_peer_id_hex = args.get(4);

    let address_bytes = hex::decode(address_hex)?;
    let mut address = [0u8; 32];
    address.copy_from_slice(&address_bytes);

    let cert_hash = hex::decode(cert_hash_hex)?;

    let expected_peer_id: Option<[u8; 32]> = if let Some(hex_str) = expected_peer_id_hex {
        let bytes = hex::decode(hex_str)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    };

    println!("Connecting to {url}...");

    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(
            cert_hash.try_into().map_err(|_| "cert hash must be 32 bytes")?,
        )])
        .build();

    let endpoint = wtransport::Endpoint::client(config)?;
    let connection = endpoint.connect(url).await?;
    println!("Connected!");

    // --- Authenticated PQC Handshake on stream 0 ---
    println!("Starting authenticated PQC handshake (ML-KEM-768 + ML-DSA-65)...");

    let (mut hs_send, mut hs_recv) = connection.open_bi().await?.await?;

    // Generate ML-KEM-768 keypair
    let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut rand_core::OsRng)
        .map_err(|e| format!("ML-KEM keygen failed: {e}"))?;

    // Send ClientHello
    let ek_bytes: [u8; 1184] = SerDes::into_bytes(ek);
    let hello_payload = encode_client_hello(&ek_bytes);
    let hello_len = (hello_payload.len() as u32).to_be_bytes();
    hs_send.write_all(&hello_len).await?;
    hs_send.write_all(&hello_payload).await?;

    // Read ServerAccept (v2: ct + pubkey + signature)
    let mut accept_len_buf = [0u8; 4];
    hs_recv.read_exact(&mut accept_len_buf).await?;
    let accept_len = u32::from_be_bytes(accept_len_buf) as usize;
    let mut accept_buf = vec![0u8; accept_len];
    hs_recv.read_exact(&mut accept_buf).await?;

    let accept = decode_server_accept(&accept_buf)?;
    if accept.version != pqc_tunnel::PQC_VERSION {
        return Err(format!("unsupported PQC version: {}", accept.version).into());
    }

    // Verify ML-DSA-65 signature
    let auth_message = pqc_tunnel::build_auth_message(&ek_bytes, &accept.ct);
    let vk = <ml_dsa_65::PublicKey as fips204::traits::SerDes>::try_from_bytes(accept.pubkey)
        .map_err(|_| "invalid ML-DSA-65 public key")?;

    let valid = vk.verify(&auth_message, &accept.signature, &[]);
    if !valid {
        return Err("ML-DSA-65 signature verification FAILED".into());
    }
    println!("ML-DSA-65 signature verified!");

    // Derive and check PeerId
    let derived_peer_id = pqc_tunnel::derive_peer_id(&accept.pubkey);
    println!("Server PeerId: {}", hex::encode(derived_peer_id));

    if let Some(expected) = expected_peer_id {
        if derived_peer_id != expected {
            return Err(format!(
                "PeerId mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(derived_peer_id)
            ).into());
        }
        println!("PeerId verified against expected!");
    }

    // Decapsulate
    let ct = <ml_kem_768::CipherText as SerDes>::try_from_bytes(accept.ct)
        .map_err(|_| "invalid ciphertext")?;
    let ss: fips203::SharedSecretKey = fips203::traits::Decaps::try_decaps(&dk, &ct)
        .map_err(|_| "decapsulation failed")?;
    let ss_bytes: [u8; 32] = SerDes::into_bytes(ss);
    let cipher = SessionCipher::from_shared_secret(&ss_bytes);

    println!("Authenticated PQC tunnel established!");

    // --- Encrypted chunk request on stream 1 ---
    let stream_seq: u32 = 1;

    let message = ChunkMessage {
        request_id: 1,
        body: ChunkMessageBody::GetRequest(ChunkGetRequest::new(address)),
    };
    let message_bytes = message.encode()?;

    let encrypted = cipher.encrypt(stream_seq, Direction::ClientToServer, &message_bytes)
        .map_err(|e| format!("encryption failed: {e}"))?;
    let envelope = encode_encrypted(stream_seq, &encrypted);

    let (mut send, mut recv) = connection.open_bi().await?.await?;

    let len = (envelope.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&envelope).await?;
    println!("Sent encrypted GetRequest for {}", &address_hex[..16.min(address_hex.len())]);

    let mut resp_len_buf = [0u8; 4];
    recv.read_exact(&mut resp_len_buf).await?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
    println!("Response length: {resp_len} bytes (encrypted)");

    let mut resp_buf = vec![0u8; resp_len];
    recv.read_exact(&mut resp_buf).await?;

    let (resp_seq, ciphertext) = decode_encrypted(&resp_buf)?;
    if resp_seq != stream_seq {
        return Err(format!("sequence mismatch: expected {stream_seq}, got {resp_seq}").into());
    }

    let plaintext = cipher.decrypt(stream_seq, Direction::ServerToClient, ciphertext)
        .map_err(|e| format!("decryption failed: {e}"))?;

    let response = ChunkMessage::decode(&plaintext)?;
    match response.body {
        ChunkMessageBody::GetResponse(ant_node::ChunkGetResponse::Success { address, content }) => {
            println!("SUCCESS: {} bytes at {}", content.len(), hex::encode(address));
            if let Ok(text) = std::str::from_utf8(&content) {
                println!("Content: {text}");
            }
        }
        ChunkMessageBody::GetResponse(ant_node::ChunkGetResponse::NotFound { address }) => {
            println!("NOT FOUND: {}", hex::encode(address));
        }
        ChunkMessageBody::GetResponse(ant_node::ChunkGetResponse::Error(e)) => {
            println!("ERROR: {e}");
        }
        other => {
            println!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}
