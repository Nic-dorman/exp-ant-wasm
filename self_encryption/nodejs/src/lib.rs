//! Node.js bindings for self-encryption.
//!
//! This library provides Node.js bindings for the self-encryption library, which
//! provides convergent encryption on file-based data and produces a `DataMap` type and
//! several chunks of encrypted data. Each chunk is up to 1MB in size and has an index and a name.
//! This name is the SHA3-256 hash of the content, which allows the chunks to be self-validating.
//!
//! Storage of the encrypted chunks or DataMap is outside the scope of this library
//! and must be implemented by the user.

use napi::JsBuffer;
use napi::JsObject;
use napi::NapiRaw;
use napi::Result;
use napi::Status;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use self_encryption::bytes::Bytes;
use self_encryption::xor_name::XOR_NAME_LEN;
use std::path::Path;

pub mod util;

// Convert Rust errors to JavaScript errors
fn map_error<E>(err: E) -> napi::Error
where
    E: std::error::Error,
{
    let mut err_str = String::new();
    err_str.push_str(&format!("{err:?}: {err}\n"));
    let mut source = err.source();
    while let Some(err) = source {
        err_str.push_str(&format!(" Caused by: {err:?}: {err}\n"));
        source = err.source();
    }

    napi::Error::new(Status::GenericFailure, err_str)
}

fn try_from_big_int<T: TryFrom<u64>>(value: BigInt, arg: &str) -> Result<T> {
    let (_signed, value, losless) = value.get_u64();
    if losless {
        if let Ok(value) = T::try_from(value) {
            return Ok(value);
        }
    }

    Err(napi::Error::new(
        Status::InvalidArg,
        format!(
            "expected `{arg}` to fit in a {}",
            std::any::type_name::<T>()
        ),
    ))
}

/// The minimum size (before compression) of an individual chunk of a file, defined as 1B.
#[napi]
pub const MIN_CHUNK_SIZE: usize = self_encryption::MIN_CHUNK_SIZE;
/// The maximum size (before compression) of an individual chunk of a file, defaulting as 4MiB.
#[napi]
pub const MAX_CHUNK_SIZE: usize = self_encryption::MAX_CHUNK_SIZE;
/// Controls the compression-speed vs compression-density tradeoffs. The higher the quality, the slower the compression. Range is 0 to 11.
#[napi]
pub const COMPRESSION_QUALITY: i32 = self_encryption::COMPRESSION_QUALITY;
/// The minimum size (before compression) of data to be self-encrypted, defined as 3B.
#[napi]
pub const MIN_ENCRYPTABLE_BYTES: usize = self_encryption::MIN_ENCRYPTABLE_BYTES;

/// A 256-bit number, viewed as a point in XOR space.
///
/// This wraps an array of 32 bytes, i. e. a number between 0 and 2<sup>256</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
#[napi]
#[derive(Clone)]
pub struct XorName(self_encryption::XorName);

#[napi]
impl XorName {
    /// Create a new XorName from content bytes.
    #[napi(factory)]
    pub fn from_content(content: Uint8Array) -> Self {
        Self(self_encryption::hash::content_hash(content.as_ref()))
    }

    /// Get the underlying bytes of the XorName.
    #[napi]
    pub fn as_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.0.0.to_vec())
    }

    #[napi]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.0)
    }

    #[napi]
    pub fn from_hex(hex: String) -> Result<Self> {
        let mut bytes = [0u8; XOR_NAME_LEN];
        hex::decode_to_slice(hex, &mut bytes)
            .map_err(|e| napi::Error::new(Status::InvalidArg, e.to_string()))?;
        Ok(Self(self_encryption::XorName(bytes)))
    }
}

/// This is - in effect - a partial decryption key for an encrypted chunk of data.
///
/// It holds pre- and post-encryption hashes as well as the original
/// (pre-compression) size for a given chunk.
/// This information is required for successful recovery of a chunk, as well as for the
/// encryption/decryption of it's two immediate successors, modulo the number of chunks in the
/// corresponding DataMap.
#[napi]
pub struct ChunkInfo(self_encryption::ChunkInfo);

#[napi]
impl ChunkInfo {
    #[napi(constructor)]
    pub fn new(index: u32, dst_hash: &XorName, src_hash: &XorName, src_size: u32) -> Self {
        Self(self_encryption::ChunkInfo {
            index: index as usize,
            dst_hash: dst_hash.0,
            src_hash: src_hash.0,
            src_size: src_size as usize,
        })
    }

    #[napi(getter)]
    pub fn index(&self) -> u32 {
        self.0.index as u32
    }

    #[napi(getter)]
    pub fn dst_hash(&self) -> XorName {
        XorName(self.0.dst_hash)
    }

    #[napi(getter)]
    pub fn src_hash(&self) -> XorName {
        XorName(self.0.src_hash)
    }

    #[napi(getter)]
    pub fn src_size(&self) -> u32 {
        self.0.src_size as u32
    }
}

/// Holds the information that is required to recover the content of the encrypted file.
/// This is held as a vector of `ChunkInfo`, i.e. a list of the file's chunk hashes.
/// Only files larger than 3072 bytes (3 * MIN_CHUNK_SIZE) can be self-encrypted.
/// Smaller files will have to be batched together.
#[napi]
pub struct DataMap(self_encryption::DataMap);

#[napi]
#[allow(clippy::len_without_is_empty)]
impl DataMap {
    /// A new instance from a vec of partial keys.
    ///
    /// Sorts on instantiation.
    /// The algorithm requires this to be a sorted list to allow get_pad_iv_key to obtain the
    /// correct pre-encryption hashes for decryption/encryption.
    #[napi]
    pub fn new(keys: Vec<&ChunkInfo>) -> Self {
        Self(self_encryption::DataMap::new(
            keys.iter().map(|ci| ci.0.clone()).collect(),
        ))
    }

    /// Creates a new DataMap with a specified child value
    #[napi]
    pub fn with_child(keys: Vec<&ChunkInfo>, child: BigInt) -> Result<Self> {
        let child = try_from_big_int(child, "child")?;

        Ok(Self(self_encryption::DataMap::with_child(
            keys.iter().map(|ci| ci.0.clone()).collect(),
            child,
        )))
    }

    /// Original (pre-encryption) size of the file.
    #[napi]
    pub fn original_file_size(&self) -> usize {
        self.0.original_file_size()
    }

    /// Returns the list of chunks pre and post encryption hashes if present.
    #[napi]
    pub fn infos(&self) -> Vec<ChunkInfo> {
        self.0.infos().iter().cloned().map(ChunkInfo).collect()
    }

    /// Returns the child value if set
    #[napi]
    pub fn child(&self) -> Option<usize> {
        self.0.child
    }

    /// Returns the number of chunks in the DataMap
    #[napi]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if this DataMap has a child value
    #[napi]
    pub fn is_child(&self) -> bool {
        self.0.is_child()
    }
}

/// A JavaScript wrapper for the EncryptedChunk struct.
///
/// EncryptedChunk represents an encrypted piece of data along with its
/// metadata like size and hash. Chunks are stored separately and
/// referenced by the DataMap.
#[napi]
#[derive(Clone)]
pub struct EncryptedChunk(self_encryption::EncryptedChunk);

#[napi]
impl EncryptedChunk {
    /// Get the size of the original content before encryption.
    #[napi]
    pub fn content_size(&self) -> u32 {
        self.0.content.len() as u32
    }

    /// Get the hash of the encrypted chunk.
    #[napi]
    pub fn hash(&self) -> Uint8Array {
        Uint8Array::from(
            self_encryption::hash::content_hash(&self.0.content)
                .0
                .to_vec(),
        )
    }

    /// Get the content of the encrypted chunk.
    #[napi]
    pub fn content(&self) -> Uint8Array {
        Uint8Array::from(self.0.content.to_vec())
    }
}

/// Encrypt raw data into chunks.
///
/// This function takes raw data, splits it into chunks, encrypts them,
/// and returns a DataMap and list of encrypted chunks.
#[napi]
pub fn encrypt(data: Uint8Array) -> Result<EncryptResult> {
    let data = Bytes::copy_from_slice(data.as_ref());
    let (data_map, chunks) = self_encryption::encrypt(data).map_err(map_error)?;

    Ok(EncryptResult { data_map, chunks })
}

/// Decrypts data using chunks retrieved from any storage backend via the provided retrieval function.
#[napi]
pub fn decrypt(data_map: &DataMap, chunks: Vec<&EncryptedChunk>) -> Result<Uint8Array> {
    let inner_chunks = chunks
        .into_iter()
        .map(|chunk| chunk.0.clone())
        .collect::<Vec<_>>();

    let bytes = self_encryption::decrypt(&data_map.0, &inner_chunks).map_err(map_error)?;

    Ok(Uint8Array::from(bytes.to_vec()))
}

/// Decrypts data using a DataMap and stored chunks.
///
/// This function retrieves encrypted chunks using the provided callback,
/// decrypts them according to the DataMap, and writes the result to a file.
#[napi]
pub fn decrypt_from_storage(
    env: Env,
    data_map: &DataMap,
    output_file: String,
    #[napi(ts_arg_type = "(xorName: XorName) => Uint8Array")] get_chunk: JsFunction,
) -> Result<()> {
    let output_path = Path::new(&output_file);

    // Wrap the single-chunk JS callback into a parallel batch callback for streaming_decrypt
    let get_chunk_parallel = |hashes: &[(usize, self_encryption::XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
        hashes
            .iter()
            .map(|(i, hash)| {
                let xor_name = XorName(*hash);
                let xor_name_val = unsafe { XorName::to_napi_value(env.raw(), xor_name) }
                    .map_err(|e| self_encryption::Error::Generic(format!("Failed to convert XorName: {e}")))?;
                let xor_name_js = unsafe { napi::JsUnknown::from_napi_value(env.raw(), xor_name_val) }
                    .map_err(|e| self_encryption::Error::Generic(format!("Failed to create JsUnknown: {e}")))?;

                let result = get_chunk.call(None, &[xor_name_js]).map_err(|e| {
                    self_encryption::Error::Generic(format!("`getChunk` call resulted in error: {e}\n"))
                })?;

                let data = unsafe { Uint8Array::from_napi_value(env.raw(), result.raw()) }
                    .map_err(|e| {
                        self_encryption::Error::Generic(format!(
                            "Could not convert getChunk result to Uint8Array: {e}\n"
                        ))
                    })?;

                Ok((*i, Bytes::copy_from_slice(data.as_ref())))
            })
            .collect()
    };

    let stream =
        self_encryption::streaming_decrypt(&data_map.0, &get_chunk_parallel).map_err(map_error)?;

    let mut output = std::fs::File::create(output_path)
        .map_err(|e| napi::Error::from_reason(format!("Failed to create output file: {e}")))?;

    for chunk_result in stream {
        let chunk = chunk_result.map_err(map_error)?;
        std::io::Write::write_all(&mut output, &chunk)
            .map_err(|e| napi::Error::from_reason(format!("Failed to write output: {e}")))?;
    }

    Ok(())
}

/// Decrypts data from storage in a streaming fashion using parallel chunk retrieval.
///
/// This function retrieves the encrypted chunks in parallel using the provided `getChunkParallel` function,
/// decrypts them, and writes the decrypted data directly to the specified output file path.
#[napi]
pub fn streaming_decrypt_from_storage(
    env: Env,
    data_map: &DataMap,
    output_file: String,
    #[napi(ts_arg_type = "(xorNames: XorName[]) => Uint8Array[]")] get_chunk_parallel: JsFunction,
) -> Result<()> {
    use std::io::Write;

    let output_path = Path::new(&output_file);

    let get_chunk_parallel_wrapper =
        |xor_name: &[(usize, self_encryption::XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
            let xor_names = xor_name
                .iter()
                .map(|(_i, xor_name)| {
                    let xor_name = XorName(*xor_name);
                    let xor_name = unsafe { XorName::to_napi_value(env.raw(), xor_name) }.unwrap();
                    unsafe { napi::JsUnknown::from_napi_value(env.raw(), xor_name) }.unwrap()
                })
                .collect::<Vec<_>>();

            let xor_names = Array::from_vec(&env, xor_names)
                .map_err(|e| {
                    self_encryption::Error::Generic(format!("Could not create array: {e}\n"))
                })?
                .coerce_to_object()
                .map_err(|e| {
                    self_encryption::Error::Generic(format!("Could not create array: {e}\n"))
                })?
                .into_unknown();

            let result = get_chunk_parallel.call(None, &[xor_names]).map_err(|e| {
                self_encryption::Error::Generic(format!(
                    "`getChunkParallel` call resulted in error: {e}\n"
                ))
            })?;

            let data =
                unsafe { JsObject::from_napi_value(env.raw(), result.raw()) }.map_err(|e| {
                    self_encryption::Error::Generic(format!(
                        "Could not convert getChunkParallel result to Array: {e}\n"
                    ))
                })?;

            let mut data_vec = vec![];
            for i in 0..data.get_array_length().map_err(|e| {
                self_encryption::Error::Generic(format!(
                    "Expect getChunkParallel to return array: {e}\n"
                ))
            })? {
                let item = data.get_element::<JsBuffer>(i).map_err(|e| {
                    self_encryption::Error::Generic(format!(
                        "Could not get element from getChunkParallel result: {e}\n"
                    ))
                })?;
                let item = item.into_ref().map_err(|e| {
                    self_encryption::Error::Generic(format!(
                        "Could not get element from getChunkParallel result: {e}\n"
                    ))
                })?;

                data_vec.push((i as usize, Bytes::copy_from_slice(item.as_ref())));
            }

            Ok(data_vec)
        };

    // Use streaming_decrypt internally, writing output to file
    let stream = self_encryption::streaming_decrypt(&data_map.0, get_chunk_parallel_wrapper)
        .map_err(map_error)?;

    let mut file = std::fs::File::create(output_path).map_err(|e| {
        napi::Error::new(
            Status::GenericFailure,
            format!("Failed to create output file: {e}"),
        )
    })?;

    for chunk_result in stream {
        let chunk = chunk_result.map_err(map_error)?;
        file.write_all(&chunk)
            .map_err(|e| napi::Error::new(Status::GenericFailure, format!("Write error: {e}")))?;
    }

    Ok(())
}

// Reads a file in chunks, encrypts them, and stores them using a provided functor. Returns a DataMap.
#[napi]
pub fn streaming_encrypt_from_file(
    env: Env,
    file_path: String,
    #[napi(ts_arg_type = "(xorName: XorName, bytes: Uint8Array) => undefined")]
    chunk_store: JsFunction,
) -> Result<DataMap> {
    use std::io::Read;

    let file_path = Path::new(&file_path);

    let file = std::fs::File::open(file_path).map_err(map_error)?;
    let data_size = file.metadata().map_err(map_error)?.len() as usize;
    let mut reader = std::io::BufReader::new(file);

    // Track read errors so they aren't silently swallowed by the iterator
    let read_error: std::rc::Rc<std::cell::RefCell<Option<std::io::Error>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let read_error_clone = read_error.clone();

    let data_iter = std::iter::from_fn(move || {
        let mut buffer = vec![0u8; 8192];
        match reader.read(&mut buffer) {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some(Bytes::from(buffer))
            }
            Err(e) => {
                *read_error_clone.borrow_mut() = Some(e);
                None
            }
        }
    });

    let mut stream = self_encryption::stream_encrypt(data_size, data_iter).map_err(map_error)?;

    // Iterate chunks and call the JS chunk_store callback
    for chunk_result in stream.chunks() {
        let (hash, content) = chunk_result.map_err(map_error)?;

        let xor_name = XorName(hash);
        let xor_name_val = unsafe { XorName::to_napi_value(env.raw(), xor_name) }.unwrap();
        let xor_name_js =
            unsafe { napi::JsUnknown::from_napi_value(env.raw(), xor_name_val) }.unwrap();

        let bytes = Uint8Array::from(content.to_vec());
        let bytes_val = unsafe { Uint8Array::to_napi_value(env.raw(), bytes) }.unwrap();
        let bytes_js = unsafe { napi::JsUnknown::from_napi_value(env.raw(), bytes_val) }.unwrap();

        let _ = chunk_store
            .call(None, &[xor_name_js, bytes_js])
            .map_err(|e| {
                napi::Error::new(
                    Status::GenericFailure,
                    format!("`chunkStore` call resulted in error: {e}\n"),
                )
            })?;
    }

    if let Some(e) = read_error.borrow_mut().take() {
        return Err(napi::Error::new(
            Status::GenericFailure,
            format!("Failed to read input file: {e}"),
        ));
    }

    let datamap = stream.into_datamap().ok_or_else(|| {
        napi::Error::new(
            Status::GenericFailure,
            "Encryption did not produce a DataMap — ensure chunks() iterator was fully consumed",
        )
    })?;

    Ok(DataMap(datamap))
}

/// Encrypt a file and store its chunks.
///
/// This function reads a file, splits it into chunks, encrypts them,
/// and stores them in the specified directory.
#[napi]
pub fn encrypt_from_file(input_file: String, output_dir: String) -> Result<EncryptFromFileResult> {
    use std::io::{Read, Write};

    let input_path = Path::new(&input_file);
    let output_path = Path::new(&output_dir);

    let file = std::fs::File::open(input_path).map_err(map_error)?;
    let data_size = file.metadata().map_err(map_error)?.len() as usize;
    let mut reader = std::io::BufReader::new(file);

    // Track read errors so they aren't silently swallowed by the iterator
    let read_error: std::rc::Rc<std::cell::RefCell<Option<std::io::Error>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let read_error_clone = read_error.clone();

    let data_iter = std::iter::from_fn(move || {
        let mut buffer = vec![0u8; 8192];
        match reader.read(&mut buffer) {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some(Bytes::from(buffer))
            }
            Err(e) => {
                *read_error_clone.borrow_mut() = Some(e);
                None
            }
        }
    });

    let mut stream = self_encryption::stream_encrypt(data_size, data_iter).map_err(map_error)?;

    let mut chunk_names = Vec::new();
    for chunk_result in stream.chunks() {
        let (hash, content) = chunk_result.map_err(map_error)?;
        chunk_names.push(hex::encode(hash.0));

        let chunk_path = output_path.join(hex::encode(hash));
        let mut output_file = std::fs::File::create(&chunk_path).map_err(|e| {
            napi::Error::new(
                Status::GenericFailure,
                format!("Failed to create chunk file: {e}"),
            )
        })?;
        output_file.write_all(&content).map_err(|e| {
            napi::Error::new(
                Status::GenericFailure,
                format!("Failed to write chunk: {e}"),
            )
        })?;
    }

    if let Some(e) = read_error.borrow_mut().take() {
        return Err(napi::Error::new(
            Status::GenericFailure,
            format!("Failed to read input file: {e}"),
        ));
    }

    let data_map = stream.into_datamap().ok_or_else(|| {
        napi::Error::new(
            Status::GenericFailure,
            "Encryption did not produce a DataMap — ensure chunks() iterator was fully consumed",
        )
    })?;

    Ok(EncryptFromFileResult {
        data_map,
        chunk_names,
    })
}

/// Result type for the encrypt_from_file function
#[napi]
pub struct EncryptFromFileResult {
    pub(crate) data_map: self_encryption::DataMap,
    pub(crate) chunk_names: Vec<String>,
}

#[napi]
impl EncryptFromFileResult {
    #[napi(getter)]
    pub fn data_map(&self) -> DataMap {
        DataMap(self.data_map.clone())
    }

    #[napi(getter)]
    pub fn chunk_names(&self) -> Vec<String> {
        self.chunk_names.clone()
    }
}

/// Result type for the encrypt function
#[napi]
pub struct EncryptResult {
    pub(crate) data_map: self_encryption::DataMap,
    pub(crate) chunks: Vec<self_encryption::EncryptedChunk>,
}

#[napi]
impl EncryptResult {
    #[napi(getter)]
    pub fn data_map(&self) -> DataMap {
        DataMap(self.data_map.clone())
    }

    #[napi(getter)]
    pub fn chunks(&self) -> Vec<EncryptedChunk> {
        self.chunks
            .iter()
            .map(|chunk| EncryptedChunk(chunk.clone()))
            .collect()
    }
}
