use rustler::{Binary, NifResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

// IOTA Identity imports
use identity_iota::iota::IotaDocument;
use identity_iota::storage::{JwkDocumentExt, JwkMemStore, KeyIdMemstore, Storage};
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_iota::core::ToJson;

/// Global Tokio runtime for async operations
/// Returns None if runtime creation fails (instead of panicking)
fn runtime() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Runtime::new().ok()
    }).as_ref()
}

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
    
    // Get the runtime safely (no panic)
    let rt = match runtime() {
        Some(rt) => rt,
        None => return Ok((atoms::error(), "Failed to initialize async runtime".to_string())),
    };
    
    let result = rt.block_on(async {
        generate_did_async(network_name_str).await
    });

    match result {
        Ok(did_result) => {
            let json = serde_json::to_string(&did_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Async DID generation implementation
async fn generate_did_async(network_name: &str) -> Result<DidResult, String> {
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
    
    // Create in-memory storage for keys
    let storage: Storage<JwkMemStore, KeyIdMemstore> = 
        Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
    
    // Generate a new verification method with Ed25519
    let fragment = document
        .generate_method(
            &storage,
            JwkMemStore::ED25519_KEY_TYPE,
            JwsAlgorithm::EdDSA,
            None,
            MethodScope::VerificationMethod,
        )
        .await
        .map_err(|e| format!("Failed to generate method: {}", e))?;
    
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

