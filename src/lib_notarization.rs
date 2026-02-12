use rustler::{Binary, NifResult};
use serde::{Deserialize, Serialize};

// IOTA SDK v1.15.0 (matching the notarization crate's dependency)
use iota_sdk_v15::types::base_types::ObjectID;
use iota_sdk_v15::IotaClientBuilder;

// KeyPairSigner from iota_interaction (v0.8.10, same version as notarization)
use iota_interaction::KeyPairSigner;

// Official IOTA Notarization client
use notarization::client::{NotarizationClient, NotarizationClientReadOnly};
use notarization::core::types::{Data, State};

use std::sync::OnceLock;
use tokio::runtime::Runtime;

// Reuse key decoding from lib_ledger
use crate::lib_ledger;

/// Result structure for notarization
#[derive(Serialize, Deserialize, Debug)]
pub struct NotarizationPayload {
    pub tag: String,
    pub data_hash: String,
    pub timestamp: u64,
    pub payload_hex: String,
}

/// Result structure for verification
#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub tag: String,
    pub data_hash: String,
    pub timestamp: u64,
}

/// Error atoms for Erlang
mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

/// Create a notarization payload for anchoring data on IOTA Tangle
/// 
/// Takes a data hash (hex string) and an optional tag
/// Returns a payload ready to be submitted to the Tangle
#[rustler::nif]
pub fn create_notarization_payload(
    data_hash: Binary,
    tag: Binary,
) -> NifResult<(rustler::Atom, String)> {
    // Safely convert binaries to UTF-8 strings
    let data_hash = match std::str::from_utf8(data_hash.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid data_hash: not valid UTF-8".to_string())),
    };
    let tag = match std::str::from_utf8(tag.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid tag: not valid UTF-8".to_string())),
    };
    
    // Validate the hash format (should be hex)
    if !is_valid_hex(data_hash) {
        return Ok((atoms::error(), "Invalid hash format: expected hex string".to_string()));
    }

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Create the payload structure
    let payload_data = format!("{}:{}:{}", tag, data_hash, timestamp);
    let payload_hex = hex::encode(payload_data.as_bytes());

    let result = NotarizationPayload {
        tag: tag.to_string(),
        data_hash: data_hash.to_string(),
        timestamp,
        payload_hex,
    };

    match serde_json::to_string(&result) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), format!("Serialization failed: {}", e))),
    }
}

/// Verify a notarization payload
/// 
/// Takes a payload hex string and returns the extracted data
#[rustler::nif]
pub fn verify_notarization_payload(payload_hex: Binary) -> NifResult<(rustler::Atom, String)> {
    // Safely convert binary to UTF-8 string
    let payload_hex_str = match std::str::from_utf8(payload_hex.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid payload: not valid UTF-8".to_string())),
    };
    
    // Decode the hex payload
    let payload_bytes = match hex::decode(payload_hex_str) {
        Ok(bytes) => bytes,
        Err(e) => return Ok((atoms::error(), format!("Invalid hex payload: {}", e))),
    };

    // Convert to string
    let payload_str = match String::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(e) => return Ok((atoms::error(), format!("Invalid UTF-8 in payload: {}", e))),
    };

    // Parse the payload format: tag:hash:timestamp
    let parts: Vec<&str> = payload_str.split(':').collect();
    if parts.len() != 3 {
        return Ok((atoms::error(), "Invalid payload format: expected tag:hash:timestamp".to_string()));
    }

    let tag = parts[0].to_string();
    let data_hash = parts[1].to_string();
    let timestamp: u64 = match parts[2].parse() {
        Ok(ts) => ts,
        Err(_) => return Ok((atoms::error(), "Invalid timestamp in payload".to_string())),
    };

    // Validate the hash
    let is_valid = is_valid_hex(&data_hash);

    let result = VerificationResult {
        is_valid,
        tag,
        data_hash,
        timestamp,
    };

    match serde_json::to_string(&result) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), format!("Serialization failed: {}", e))),
    }
}

/// Hash data using SHA-256 and return hex string
/// 
/// Useful for creating the data_hash parameter for notarization
/// Accepts any binary data, including non-UTF8 bytes
#[rustler::nif]
pub fn hash_data(data: Binary) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_slice());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Validate if a string is valid hexadecimal
#[rustler::nif]
pub fn is_valid_hex_string(input: Binary) -> bool {
    // Convert to string if valid UTF-8, otherwise it can't be valid hex
    match std::str::from_utf8(input.as_slice()) {
        Ok(s) => is_valid_hex(s),
        Err(_) => false,
    }
}

/// Internal helper to validate hex strings
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ================================================================
// Ledger Operations — Official IOTA Notarization Library
// ================================================================

/// Default gas budget for notarization transactions (in IOTA nanos)
const DEFAULT_GAS_BUDGET: u64 = 50_000_000;

/// Global Tokio runtime for async operations (shared with lib_ledger)
fn runtime() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().ok()).as_ref()
}

/// Helper: safely convert a Binary to a UTF-8 string, returning an error tuple if invalid.
fn binary_to_str<'a>(bin: &'a Binary, name: &str) -> Result<&'a str, (rustler::Atom, String)> {
    std::str::from_utf8(bin.as_slice())
        .map_err(|_| (atoms::error(), format!("Invalid {}: not valid UTF-8", name)))
}

/// Create a KeyPairSigner from an Ed25519 private key string.
///
/// Accepts Bech32m (`iotaprivkey1...`) or Base64-encoded private keys.
/// Uses iota_interaction's KeyPairSigner which is compatible with NotarizationClient.
fn create_keypair_signer(secret_key: &str) -> Result<KeyPairSigner, String> {
    // Decode the raw 32-byte Ed25519 private key
    let raw_key_bytes: Vec<u8> = if secret_key.starts_with("iotaprivkey") {
        lib_ledger::decode_bech32m_privkey(secret_key)?
    } else {
        lib_ledger::decode_base64_privkey(secret_key)?
    };

    if raw_key_bytes.len() != 32 {
        return Err(format!(
            "Invalid Ed25519 private key: expected 32 bytes, got {}",
            raw_key_bytes.len()
        ));
    }

    // Convert to ed25519_dalek types to derive the public key
    let key_bytes: [u8; 32] = raw_key_bytes.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    // Build a 64-byte keypair (secret + public) for IotaKeyPair construction
    let mut keypair_bytes = Vec::with_capacity(64);
    keypair_bytes.extend_from_slice(&key_bytes);
    keypair_bytes.extend_from_slice(verifying_key.as_bytes());

    // Construct IotaKeyPair::Ed25519 via base64 decoding
    // Format: flag byte (0x00 = Ed25519) + secret key (32) + public key (32) = 65 bytes
    let mut flagged_bytes = Vec::with_capacity(65);
    flagged_bytes.push(0x00); // Ed25519 flag
    flagged_bytes.extend_from_slice(&keypair_bytes);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&flagged_bytes);
    let keypair = iota_sdk_v15::types::crypto::IotaKeyPair::decode(&b64)
        .map_err(|e| format!("Failed to create IotaKeyPair: {:?}", e))?;

    Ok(KeyPairSigner::new(keypair))
}

/// Create a locked notarization on the IOTA Rebased ledger.
///
/// Creates an immutable (locked) notarization — the state cannot be changed
/// after creation. This is ideal for proof-of-existence use cases such as
/// notarizing document hashes.
///
/// Uses the official IOTA notarization library (`NotarizationClient`).
///
/// Parameters:
/// - node_url: URL of the IOTA node (e.g., "http://127.0.0.1:9000")
/// - secret_key: Ed25519 private key (Bech32m `iotaprivkey1...` or Base64)
/// - notarize_pkg_id: ObjectID of the deployed notarization Move package
/// - state_data: The data to notarize (e.g., a document hash as a string)
/// - description: Immutable description label (can be empty)
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn create_notarization(
    node_url: Binary,
    secret_key: Binary,
    notarize_pkg_id: Binary,
    state_data: Binary,
    description: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let rt = match runtime() {
        Some(rt) => rt,
        None => return Ok((atoms::error(), "Failed to create async runtime".to_string())),
    };

    let node_url_str = match binary_to_str(&node_url, "node_url") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let secret_key_str = match binary_to_str(&secret_key, "secret_key") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let pkg_id_str = match binary_to_str(&notarize_pkg_id, "notarize_pkg_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let state_data_str = match binary_to_str(&state_data, "state_data") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let description_str = match binary_to_str(&description, "description") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };

    if node_url_str.is_empty() {
        return Ok((atoms::error(), "node_url cannot be empty".to_string()));
    }
    if secret_key_str.is_empty() {
        return Ok((atoms::error(), "secret_key cannot be empty".to_string()));
    }
    if pkg_id_str.is_empty() {
        return Ok((atoms::error(), "notarize_pkg_id cannot be empty".to_string()));
    }
    if state_data_str.is_empty() {
        return Ok((atoms::error(), "state_data cannot be empty".to_string()));
    }

    match rt.block_on(create_notarization_async(
        node_url_str,
        secret_key_str,
        pkg_id_str,
        state_data_str,
        description_str,
        true, // locked
    )) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Create a dynamic notarization on the IOTA Rebased ledger.
///
/// Creates a mutable (dynamic) notarization — the state can be updated
/// after creation. Useful for tracking changing states (e.g., document
/// versions, status updates).
///
/// Parameters: same as create_notarization
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn create_dynamic_notarization(
    node_url: Binary,
    secret_key: Binary,
    notarize_pkg_id: Binary,
    state_data: Binary,
    description: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let rt = match runtime() {
        Some(rt) => rt,
        None => return Ok((atoms::error(), "Failed to create async runtime".to_string())),
    };

    let node_url_str = match binary_to_str(&node_url, "node_url") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let secret_key_str = match binary_to_str(&secret_key, "secret_key") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let pkg_id_str = match binary_to_str(&notarize_pkg_id, "notarize_pkg_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let state_data_str = match binary_to_str(&state_data, "state_data") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let description_str = match binary_to_str(&description, "description") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };

    if node_url_str.is_empty() {
        return Ok((atoms::error(), "node_url cannot be empty".to_string()));
    }
    if secret_key_str.is_empty() {
        return Ok((atoms::error(), "secret_key cannot be empty".to_string()));
    }
    if pkg_id_str.is_empty() {
        return Ok((atoms::error(), "notarize_pkg_id cannot be empty".to_string()));
    }
    if state_data_str.is_empty() {
        return Ok((atoms::error(), "state_data cannot be empty".to_string()));
    }

    match rt.block_on(create_notarization_async(
        node_url_str,
        secret_key_str,
        pkg_id_str,
        state_data_str,
        description_str,
        false, // dynamic
    )) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Read a notarization from the IOTA Rebased ledger.
///
/// Retrieves the full state and metadata of a notarization by its object ID.
/// No signing key is required (read-only operation).
///
/// Parameters:
/// - node_url: URL of the IOTA node
/// - object_id: ObjectID of the notarization to read
/// - notarize_pkg_id: ObjectID of the deployed notarization Move package
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn read_notarization(
    node_url: Binary,
    object_id: Binary,
    notarize_pkg_id: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let rt = match runtime() {
        Some(rt) => rt,
        None => return Ok((atoms::error(), "Failed to create async runtime".to_string())),
    };

    let node_url_str = match binary_to_str(&node_url, "node_url") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let object_id_str = match binary_to_str(&object_id, "object_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let pkg_id_str = match binary_to_str(&notarize_pkg_id, "notarize_pkg_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };

    if node_url_str.is_empty() {
        return Ok((atoms::error(), "node_url cannot be empty".to_string()));
    }
    if object_id_str.is_empty() {
        return Ok((atoms::error(), "object_id cannot be empty".to_string()));
    }
    if pkg_id_str.is_empty() {
        return Ok((atoms::error(), "notarize_pkg_id cannot be empty".to_string()));
    }

    match rt.block_on(read_notarization_async(node_url_str, object_id_str, pkg_id_str)) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Update the state of a dynamic notarization on the ledger.
///
/// Only works for dynamic notarizations (created with create_dynamic_notarization).
/// Locked notarizations cannot be updated.
///
/// Parameters:
/// - node_url: URL of the IOTA node
/// - secret_key: Ed25519 private key
/// - notarize_pkg_id: ObjectID of the notarization package
/// - object_id: ObjectID of the notarization to update
/// - new_state_data: New state data string
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn update_notarization_state(
    node_url: Binary,
    secret_key: Binary,
    notarize_pkg_id: Binary,
    object_id: Binary,
    new_state_data: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let rt = match runtime() {
        Some(rt) => rt,
        None => return Ok((atoms::error(), "Failed to create async runtime".to_string())),
    };

    let node_url_str = match binary_to_str(&node_url, "node_url") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let secret_key_str = match binary_to_str(&secret_key, "secret_key") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let pkg_id_str = match binary_to_str(&notarize_pkg_id, "notarize_pkg_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let object_id_str = match binary_to_str(&object_id, "object_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let new_state_str = match binary_to_str(&new_state_data, "new_state_data") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };

    if node_url_str.is_empty() {
        return Ok((atoms::error(), "node_url cannot be empty".to_string()));
    }
    if secret_key_str.is_empty() {
        return Ok((atoms::error(), "secret_key cannot be empty".to_string()));
    }
    if pkg_id_str.is_empty() {
        return Ok((atoms::error(), "notarize_pkg_id cannot be empty".to_string()));
    }
    if object_id_str.is_empty() {
        return Ok((atoms::error(), "object_id cannot be empty".to_string()));
    }
    if new_state_str.is_empty() {
        return Ok((atoms::error(), "new_state_data cannot be empty".to_string()));
    }

    match rt.block_on(update_notarization_state_async(
        node_url_str,
        secret_key_str,
        pkg_id_str,
        object_id_str,
        new_state_str,
    )) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Destroy a notarization on the ledger.
///
/// Permanently removes the notarization object from the ledger.
///
/// Parameters:
/// - node_url: URL of the IOTA node
/// - secret_key: Ed25519 private key
/// - notarize_pkg_id: ObjectID of the notarization package
/// - object_id: ObjectID of the notarization to destroy
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn destroy_notarization(
    node_url: Binary,
    secret_key: Binary,
    notarize_pkg_id: Binary,
    object_id: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let rt = match runtime() {
        Some(rt) => rt,
        None => return Ok((atoms::error(), "Failed to create async runtime".to_string())),
    };

    let node_url_str = match binary_to_str(&node_url, "node_url") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let secret_key_str = match binary_to_str(&secret_key, "secret_key") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let pkg_id_str = match binary_to_str(&notarize_pkg_id, "notarize_pkg_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let object_id_str = match binary_to_str(&object_id, "object_id") {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };

    if node_url_str.is_empty() {
        return Ok((atoms::error(), "node_url cannot be empty".to_string()));
    }
    if secret_key_str.is_empty() {
        return Ok((atoms::error(), "secret_key cannot be empty".to_string()));
    }
    if pkg_id_str.is_empty() {
        return Ok((atoms::error(), "notarize_pkg_id cannot be empty".to_string()));
    }
    if object_id_str.is_empty() {
        return Ok((atoms::error(), "object_id cannot be empty".to_string()));
    }

    match rt.block_on(destroy_notarization_async(
        node_url_str,
        secret_key_str,
        pkg_id_str,
        object_id_str,
    )) {
        Ok(json) => Ok((atoms::ok(), json)),
        Err(e) => Ok((atoms::error(), e)),
    }
}

// ================================================================
// Async Implementations
// ================================================================

/// Create a notarization (locked or dynamic) using the official NotarizationClient.
async fn create_notarization_async(
    node_url: &str,
    secret_key: &str,
    notarize_pkg_id: &str,
    state_data: &str,
    description: &str,
    locked: bool,
) -> Result<String, String> {
    // 1. Parse package ID
    let package_id = notarize_pkg_id
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid notarize_pkg_id '{}': {}", notarize_pkg_id, e))?;

    // 2. Create signer from Ed25519 key — uses KeyPairSigner from iota_interaction
    let signer = create_keypair_signer(secret_key)?;

    // 3. Connect to the IOTA node
    let iota_client = IotaClientBuilder::default()
        .build(node_url)
        .await
        .map_err(|e| format!("Failed to connect to IOTA node '{}': {}", node_url, e))?;

    // 4. Create NotarizationClient
    let read_client = NotarizationClientReadOnly::new_with_pkg_id(iota_client, package_id)
        .await
        .map_err(|e| format!("Failed to create notarization client: {}", e))?;

    let notarization_client = NotarizationClient::new(read_client, signer)
        .await
        .map_err(|e| format!("Failed to configure signer: {}", e))?;

    // 5. Build and execute the create transaction
    let method_str;
    let result = if locked {
        method_str = "locked";
        let mut builder = notarization_client.create_locked_notarization()
            .with_string_state(state_data.to_string(), None);

        if !description.is_empty() {
            builder = builder.with_immutable_description(description.to_string());
        }

        builder
            .finish()
            .map_err(|e| format!("Failed to build locked notarization: {}", e))?
            .with_gas_budget(DEFAULT_GAS_BUDGET)
            .build_and_execute(&notarization_client)
            .await
            .map_err(|e| format!("Failed to create locked notarization: {}", e))?
    } else {
        method_str = "dynamic";
        let mut builder = notarization_client.create_dynamic_notarization()
            .with_string_state(state_data.to_string(), None);

        if !description.is_empty() {
            builder = builder.with_immutable_description(description.to_string());
        }

        builder
            .finish()
            .with_gas_budget(DEFAULT_GAS_BUDGET)
            .build_and_execute(&notarization_client)
            .await
            .map_err(|e| format!("Failed to create dynamic notarization: {}", e))?
    };

    // 6. Extract result data
    let tx_digest = result.response.digest.to_string();
    let on_chain_notarization = result.output;

    // Extract the object ID from the OnChainNotarization
    let notarization_id = format!("{:?}", on_chain_notarization.id);

    let result_json = serde_json::json!({
        "object_id": notarization_id,
        "tx_digest": tx_digest,
        "state_data": state_data,
        "description": description,
        "method": method_str,
    });

    serde_json::to_string(&result_json)
        .map_err(|e| format!("Failed to serialize result: {}", e))
}

/// Read a notarization from the ledger (read-only, no signer needed).
async fn read_notarization_async(
    node_url: &str,
    object_id_str: &str,
    notarize_pkg_id: &str,
) -> Result<String, String> {
    // 1. Parse IDs
    let package_id = notarize_pkg_id
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid notarize_pkg_id '{}': {}", notarize_pkg_id, e))?;
    let object_id = object_id_str
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid object_id '{}': {}", object_id_str, e))?;

    // 2. Connect to the IOTA node
    let iota_client = IotaClientBuilder::default()
        .build(node_url)
        .await
        .map_err(|e| format!("Failed to connect to IOTA node '{}': {}", node_url, e))?;

    // 3. Create read-only client
    let read_client = NotarizationClientReadOnly::new_with_pkg_id(iota_client, package_id)
        .await
        .map_err(|e| format!("Failed to create notarization client: {}", e))?;

    // 4. Fetch notarization data via individual read-only calls
    let state = read_client
        .state(object_id)
        .await
        .map_err(|e| format!("Failed to read notarization state: {}", e))?;

    let description = read_client
        .description(object_id)
        .await
        .map_err(|e| format!("Failed to read notarization description: {}", e))?;

    let method = read_client
        .notarization_method(object_id)
        .await
        .map_err(|e| format!("Failed to read notarization method: {}", e))?;

    let created_at = read_client
        .created_at_ts(object_id)
        .await
        .map_err(|e| format!("Failed to read created_at timestamp: {}", e))?;

    let last_change = read_client
        .last_state_change_ts(object_id)
        .await
        .map_err(|e| format!("Failed to read last_state_change timestamp: {}", e))?;

    let version_count = read_client
        .state_version_count(object_id)
        .await
        .map_err(|e| format!("Failed to read state_version_count: {}", e))?;

    // 5. Extract state data
    let state_data_str = match state.data {
        Data::Text(s) => s,
        Data::Bytes(b) => hex::encode(&b),
    };

    let method_str = format!("{:?}", method);

    // 6. Build response
    let result = serde_json::json!({
        "object_id": object_id.to_string(),
        "state_data": state_data_str,
        "state_metadata": state.metadata,
        "description": description,
        "method": method_str,
        "created_at": created_at,
        "last_state_change_at": last_change,
        "state_version_count": version_count,
    });

    serde_json::to_string(&result)
        .map_err(|e| format!("Failed to serialize result: {}", e))
}

/// Update the state of a dynamic notarization.
async fn update_notarization_state_async(
    node_url: &str,
    secret_key: &str,
    notarize_pkg_id: &str,
    object_id_str: &str,
    new_state_data: &str,
) -> Result<String, String> {
    // 1. Parse IDs
    let package_id = notarize_pkg_id
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid notarize_pkg_id '{}': {}", notarize_pkg_id, e))?;
    let object_id = object_id_str
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid object_id '{}': {}", object_id_str, e))?;

    // 2. Create signer from Ed25519 key
    let signer = create_keypair_signer(secret_key)?;

    // 3. Connect and create client
    let iota_client = IotaClientBuilder::default()
        .build(node_url)
        .await
        .map_err(|e| format!("Failed to connect to IOTA node '{}': {}", node_url, e))?;

    let read_client = NotarizationClientReadOnly::new_with_pkg_id(iota_client, package_id)
        .await
        .map_err(|e| format!("Failed to create notarization client: {}", e))?;

    let notarization_client = NotarizationClient::new(read_client, signer)
        .await
        .map_err(|e| format!("Failed to configure signer: {}", e))?;

    // 4. Update state
    let new_state = State::from_string(new_state_data.to_string(), None);

    let result = notarization_client
        .update_state(new_state, object_id)
        .with_gas_budget(DEFAULT_GAS_BUDGET)
        .build_and_execute(&notarization_client)
        .await
        .map_err(|e| format!("Failed to update notarization state: {}", e))?;

    let tx_digest = result.response.digest.to_string();

    let result_json = serde_json::json!({
        "object_id": object_id.to_string(),
        "tx_digest": tx_digest,
        "new_state_data": new_state_data,
    });

    serde_json::to_string(&result_json)
        .map_err(|e| format!("Failed to serialize result: {}", e))
}

/// Destroy a notarization on the ledger.
async fn destroy_notarization_async(
    node_url: &str,
    secret_key: &str,
    notarize_pkg_id: &str,
    object_id_str: &str,
) -> Result<String, String> {
    // 1. Parse IDs
    let package_id = notarize_pkg_id
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid notarize_pkg_id '{}': {}", notarize_pkg_id, e))?;
    let object_id = object_id_str
        .parse::<ObjectID>()
        .map_err(|e| format!("Invalid object_id '{}': {}", object_id_str, e))?;

    // 2. Create signer from Ed25519 key
    let signer = create_keypair_signer(secret_key)?;

    // 3. Connect and create client
    let iota_client = IotaClientBuilder::default()
        .build(node_url)
        .await
        .map_err(|e| format!("Failed to connect to IOTA node '{}': {}", node_url, e))?;

    let read_client = NotarizationClientReadOnly::new_with_pkg_id(iota_client, package_id)
        .await
        .map_err(|e| format!("Failed to create notarization client: {}", e))?;

    let notarization_client = NotarizationClient::new(read_client, signer)
        .await
        .map_err(|e| format!("Failed to configure signer: {}", e))?;

    // 4. Destroy
    let result = notarization_client
        .destroy(object_id)
        .with_gas_budget(DEFAULT_GAS_BUDGET)
        .build_and_execute(&notarization_client)
        .await
        .map_err(|e| format!("Failed to destroy notarization: {}", e))?;

    let tx_digest = result.response.digest.to_string();

    let result_json = serde_json::json!({
        "object_id": object_id.to_string(),
        "tx_digest": tx_digest,
    });

    serde_json::to_string(&result_json)
        .map_err(|e| format!("Failed to serialize result: {}", e))
}

// Note: NIF registration is done in lib.rs
