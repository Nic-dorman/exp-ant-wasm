//! Directly inject a chunk into a node's LMDB storage, bypassing payment.
//! For testing only.

use ant_node::{LmdbStorage, LmdbStorageConfig};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: inject-chunk <node-data-dir> <content-string>");
        eprintln!("  Stores content as a chunk, prints the BLAKE3 address.");
        std::process::exit(1);
    }

    let node_dir = PathBuf::from(&args[1]);
    let content = args[2].as_bytes().to_vec();

    let address: [u8; 32] = *blake3::hash(&content).as_bytes();
    let address_hex = hex::encode(address);

    let config = LmdbStorageConfig {
        root_dir: node_dir,
        verify_on_read: false,
        max_chunks: 0,
        max_map_size: 0,
    };

    let storage = LmdbStorage::new(config).await?;
    storage.put(&address, &content).await?;

    println!("{address_hex}");
    eprintln!("Stored {} bytes at address {address_hex}", content.len());

    Ok(())
}
