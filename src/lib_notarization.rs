use rustler::{Binary, NifResult};
use serde::{Deserialize, Serialize};

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

// Note: NIF registration is done in lib.rs
