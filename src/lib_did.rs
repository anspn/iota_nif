use rustler::{Binary, NifResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

// IOTA Identity imports
use identity_iota::iota::IotaDocument;
use identity_iota::verification::{MethodScope, VerificationMethod};
use identity_iota::verification::jose::jwk::{EdCurve, Jwk, JwkParamsOkp};
use identity_iota::core::ToJson;

// Ed25519 key generation
use ed25519_dalek::SigningKey;
use base64::Engine;
use sha2::{Sha256, Digest};

/// Cache for interned network names to avoid memory leaks from Box::leak
/// Limited to known valid network names only
fn get_static_network_name(name: &str) -> Option<&'static str> {
    static NETWORK_NAMES: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    let map = NETWORK_NAMES.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("iota", "iota");
        m.insert("smr", "smr");
        m.insert("rms", "rms");
        m.insert("atoi", "atoi");
        m
    });
    map.get(name).copied()
}

/// Result structure for DID generation
#[derive(Serialize, Deserialize, Debug)]
pub struct DidResult {
    pub did: String,
    pub document: String,
    pub verification_method_fragment: String,
    /// The private key JWK (JSON) for the verification method.
    /// The caller should store this securely for signing operations.
    pub private_key_jwk: String,
}

/// Error atoms for Erlang
mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

/// Generate a new IOTA DID document with a verification method
/// 
/// Supported networks: "iota", "smr", "rms", "atoi"
/// Returns: {:ok, json_string} | {:error, reason}
/// 
/// Note: This NIF uses DirtyCpu scheduler because it performs cryptographic
/// operations that may exceed the 1ms time slice for normal schedulers.
#[rustler::nif(schedule = "DirtyCpu")]
pub fn generate_did(network_name: Binary) -> NifResult<(rustler::Atom, String)> {
    // Safely convert binary to UTF-8 string
    let network_name_str = match std::str::from_utf8(network_name.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid network name: not valid UTF-8".to_string())),
    };
    
    let result = generate_did_sync(network_name_str);

    match result {
        Ok(did_result) => {
            let json = serde_json::to_string(&did_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// DID generation implementation (synchronous — no storage/network needed)
fn generate_did_sync(network_name: &str) -> Result<DidResult, String> {
    use product_common::network_name::NetworkName;
    
    // Use cached static network names to avoid memory leaks
    // Only known valid network names are supported
    let network_static: &'static str = get_static_network_name(network_name)
        .ok_or_else(|| format!(
            "Invalid network name '{}': must be one of 'iota', 'smr', 'rms', 'atoi'",
            network_name
        ))?;
    
    // Parse the network name (should always succeed for cached names)
    let network = NetworkName::try_from(network_static)
        .map_err(|e| format!("Invalid network name '{}': {}", network_name, e))?;
    
    // Create a new DID document for the specified network
    let mut document = IotaDocument::new(&network);
    
    // Generate an Ed25519 keypair for the verification method
    let signing_key = {
        use rand::RngCore;
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        SigningKey::from_bytes(&key_bytes)
    };
    let verifying_key = signing_key.verifying_key();

    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut params = JwkParamsOkp::new();
    params.crv = EdCurve::Ed25519.name().to_string();
    params.x = b64url.encode(verifying_key.as_bytes());
    params.d = Some(b64url.encode(signing_key.to_bytes()));
    let mut full_jwk = Jwk::from_params(params);
    full_jwk.set_alg("EdDSA");

    // Compute JWK Thumbprint (RFC 7638) as kid
    let canonical = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        b64url.encode(verifying_key.as_bytes())
    );
    let thumbprint = Sha256::digest(canonical.as_bytes());
    let kid = b64url.encode(thumbprint);
    full_jwk.set_kid(kid);

    let public_jwk = full_jwk
        .to_public()
        .ok_or_else(|| "Failed to derive public JWK".to_string())?;

    let method = VerificationMethod::new_from_jwk(
        document.id().clone(),
        public_jwk,
        None,
    )
    .map_err(|e| format!("Failed to create verification method: {}", e))?;

    let fragment = method
        .id()
        .fragment()
        .ok_or_else(|| "Verification method missing fragment".to_string())?
        .to_string();

    document
        .insert_method(method, MethodScope::VerificationMethod)
        .map_err(|e| format!("Failed to insert verification method: {}", e))?;

    let private_key_jwk_json = serde_json::to_string(&full_jwk)
        .map_err(|e| format!("Failed to serialize private key JWK: {}", e))?;
    
    // Get the DID string
    let did = document.id().to_string();
    
    // Serialize the document to JSON
    let document_json = document
        .to_json()
        .map_err(|e| format!("Failed to serialize document: {}", e))?;
    
    Ok(DidResult {
        did,
        document: document_json,
        verification_method_fragment: fragment,
        private_key_jwk: private_key_jwk_json,
    })
}

/// Get the DID from a DID document JSON string
#[rustler::nif]
pub fn extract_did_from_document(document_json: Binary) -> NifResult<(rustler::Atom, String)> {
    // Safely convert binary to UTF-8 string (JSON must be UTF-8)
    let json_str = match std::str::from_utf8(document_json.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid JSON: not valid UTF-8".to_string())),
    };
    
    match serde_json::from_str::<serde_json::Value>(json_str) {
        Ok(doc) => {
            if let Some(id) = doc.get("id").and_then(|v| v.as_str()) {
                Ok((atoms::ok(), id.to_string()))
            } else {
                Ok((atoms::error(), "No 'id' field found in document".to_string()))
            }
        }
        Err(e) => Ok((atoms::error(), format!("Invalid JSON: {}", e))),
    }
}

/// Create a DID URL with a fragment
/// Returns the formatted URL or an error tuple if input is not valid UTF-8
#[rustler::nif]
pub fn create_did_url(did: Binary, fragment: Binary) -> NifResult<(rustler::Atom, String)> {
    let did_str = match std::str::from_utf8(did.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid DID: not valid UTF-8".to_string())),
    };
    let fragment_str = match std::str::from_utf8(fragment.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok((atoms::error(), "Invalid fragment: not valid UTF-8".to_string())),
    };
    Ok((atoms::ok(), format!("{}#{}", did_str, fragment_str)))
}

/// Verify that a string is a valid IOTA DID format
/// IOTA mainnet: did:iota:<tag> (3 parts)
/// Other networks: did:iota:<network>:<tag> (4 parts)
/// Returns false for non-UTF8 input
#[rustler::nif]
pub fn is_valid_iota_did(did: Binary) -> bool {
    let did_str = match std::str::from_utf8(did.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    if !did_str.starts_with("did:iota:") {
        return false;
    }
    let parts: Vec<&str> = did_str.split(':').collect();
    // Valid formats:
    // - did:iota:0x... (mainnet, 3 parts)
    // - did:iota:smr:0x... (other networks, 4 parts)
    parts.len() >= 3 && (parts.len() == 3 || parts.len() == 4)
}

// Note: NIF registration is done in lib.rs

