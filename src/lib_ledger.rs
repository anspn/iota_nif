use rustler::{Binary, NifResult};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

// IOTA Identity imports (Rebased/MoveVM compatible)
use identity_iota::iota::rebased::client::{IdentityClient, IdentityClientReadOnly};
use identity_iota::iota::{IotaDID, IotaDocument};
use identity_iota::storage::{
    JwkDocumentExt, JwkMemStore, JwkStorage, KeyIdMemstore, Storage, StorageSigner,
};
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_iota::core::ToJson;

// IOTA SDK imports (Rebased/MoveVM)
use iota_sdk::types::base_types::ObjectID;
use iota_sdk::IotaClientBuilder;

// JWK construction for Ed25519 key import
use identity_iota::verification::jose::jwk::{EdCurve, Jwk, JwkParamsOkp};

// Ed25519 key derivation (derive public key from private key)
use ed25519_dalek::SigningKey;
use base64::Engine;

/// Default gas budget for DID transactions (in IOTA nanos)
const DEFAULT_GAS_BUDGET: u64 = 50_000_000;

/// Global Tokio runtime for async operations
/// Returns None if runtime creation fails (instead of panicking)
fn runtime() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().ok()).as_ref()
}

/// Error atoms for Erlang
mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

/// Result structure for DID publication
#[derive(Serialize, Deserialize, Debug)]
pub struct PublishResult {
    /// The published DID (with real tag derived from on-chain object)
    pub did: String,
    /// The full DID document as JSON
    pub document: String,
    /// The fragment ID of the generated verification method
    pub verification_method_fragment: String,
    /// The network name
    pub network: String,
    /// The sender address that published the DID
    pub sender_address: String,
}

/// Result structure for DID resolution
#[derive(Serialize, Deserialize, Debug)]
pub struct ResolveResult {
    /// The resolved DID
    pub did: String,
    /// The full DID document as JSON
    pub document: String,
}

/// Parse an ObjectID from a string, returning None for empty strings.
fn parse_optional_object_id(id_str: &str) -> Result<Option<ObjectID>, String> {
    if id_str.is_empty() {
        Ok(None)
    } else {
        let id = id_str
            .parse::<ObjectID>()
            .map_err(|e| format!("Invalid ObjectID '{}': {}", id_str, e))?;
        Ok(Some(id))
    }
}

/// Decode an Ed25519 private key and construct a JWK.
///
/// Accepts three formats:
/// - **Bech32m** (`iotaprivkey1...`): Native IOTA CLI format from
///   `iota keytool export --key-identity <address>`
/// - **Base64** (33 bytes): IOTA keystore format (0x00 scheme flag + 32-byte key)
/// - **Base64** (32 bytes): Raw Ed25519 private key
pub fn decode_ed25519_key_to_jwk(secret_key_input: &str) -> Result<Jwk, String> {
    let raw_key_bytes: Vec<u8> = if secret_key_input.starts_with("iotaprivkey") {
        // Bech32m-encoded IOTA private key (iotaprivkey1...)
        decode_bech32m_privkey(secret_key_input)?
    } else {
        // Base64-encoded key (raw 32 bytes or IOTA keystore 33 bytes)
        decode_base64_privkey(secret_key_input)?
    };

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&raw_key_bytes);

    // Derive public key from private key
    let signing_key = SigningKey::from_bytes(&key_array);
    let public_key = signing_key.verifying_key();

    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Construct Ed25519 JWK with both private and public components
    let mut params = JwkParamsOkp::new();
    params.crv = EdCurve::Ed25519.name().to_string();
    params.x = b64url.encode(public_key.as_bytes());
    params.d = Some(b64url.encode(&key_array));

    let mut jwk = Jwk::from_params(params);
    jwk.set_alg("EdDSA");

    Ok(jwk)
}

/// Decode a Bech32m-encoded IOTA private key (`iotaprivkey1...`).
///
/// Format: HRP "iotaprivkey" + Bech32m data = [scheme_flag (1 byte) + key (32 bytes)]
/// Scheme flag 0x00 = Ed25519.
pub fn decode_bech32m_privkey(input: &str) -> Result<Vec<u8>, String> {
    let (hrp, data) = bech32::decode(input)
        .map_err(|e| format!("Invalid Bech32m key '{}...': {}", &input[..20.min(input.len())], e))?;

    if hrp.as_str() != "iotaprivkey" {
        return Err(format!(
            "Invalid key prefix: expected 'iotaprivkey', got '{}'",
            hrp
        ));
    }

    if data.len() != 33 {
        return Err(format!(
            "Invalid Bech32m key payload: expected 33 bytes (1 scheme + 32 key), got {}",
            data.len()
        ));
    }

    if data[0] != 0x00 {
        return Err(format!(
            "Unsupported key scheme: expected 0x00 (Ed25519), got 0x{:02x}",
            data[0]
        ));
    }

    Ok(data[1..].to_vec())
}

/// Decode a Base64-encoded Ed25519 private key.
///
/// Accepts:
/// - 33 bytes: IOTA keystore format (0x00 scheme flag + 32-byte key)
/// - 32 bytes: Raw Ed25519 private key
pub fn decode_base64_privkey(input: &str) -> Result<Vec<u8>, String> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Invalid base64 key: {}", e))?;

    if key_bytes.len() == 33 && key_bytes[0] == 0x00 {
        Ok(key_bytes[1..].to_vec())
    } else if key_bytes.len() == 32 {
        Ok(key_bytes)
    } else {
        Err(format!(
            "Invalid key length: expected 32 or 33 bytes, got {}. \
             Provide a base64-encoded Ed25519 private key (32 bytes) or \
             IOTA keystore format (33 bytes with 0x00 prefix).",
            key_bytes.len()
        ))
    }
}

// ================================================================
// NIF Functions
// ================================================================

/// Create a new IOTA DID and publish it to the IOTA Rebased ledger.
///
/// Uses the caller's Ed25519 private key to sign the transaction.
/// The key's address must have sufficient gas coins (use `iota client faucet`
/// to obtain gas on testnets).
///
/// Parameters:
/// - node_url: URL of the IOTA node (e.g., "http://127.0.0.1:9000")
/// - secret_key: Ed25519 private key in one of:
///   - Bech32m format (`iotaprivkey1...`) from `iota keytool export`
///   - Base64-encoded raw key (32 bytes) or IOTA keystore format (33 bytes)
/// - gas_coin_id: Hex ObjectID of gas coin to use, or empty binary
///   for automatic gas coin selection
/// - identity_pkg_id: ObjectID of the deployed iota_identity Move package
///   (required for local/unofficial networks). Pass empty binary for
///   auto-discovery on official networks.
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn create_and_publish_did(
    node_url: Binary,
    secret_key: Binary,
    gas_coin_id: Binary,
    identity_pkg_id: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let node_url_str = match std::str::from_utf8(node_url.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok((atoms::error(), "Invalid node URL: not valid UTF-8".to_string())),
    };
    let key_str = match std::str::from_utf8(secret_key.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok((atoms::error(), "Invalid key: not valid UTF-8".to_string())),
    };
    let gas_str = match std::str::from_utf8(gas_coin_id.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid gas coin ID: not valid UTF-8".to_string(),
            ))
        }
    };
    let pkg_str = match std::str::from_utf8(identity_pkg_id.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid identity package ID: not valid UTF-8".to_string(),
            ))
        }
    };

    let package_id = match parse_optional_object_id(&pkg_str) {
        Ok(id) => id,
        Err(e) => return Ok((atoms::error(), e)),
    };

    let rt = match runtime() {
        Some(rt) => rt,
        None => {
            return Ok((
                atoms::error(),
                "Failed to initialize async runtime".to_string(),
            ))
        }
    };

    let result = rt.block_on(async {
        create_and_publish_did_async(&node_url_str, &key_str, &gas_str, package_id).await
    });

    match result {
        Ok(publish_result) => {
            let json = serde_json::to_string(&publish_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Resolve a DID document from the IOTA Rebased ledger.
///
/// Connects to the specified IOTA node and retrieves the DID document
/// associated with the given DID. No signing key is required.
///
/// Parameters:
/// - node_url: URL of the IOTA node
/// - did_str: The DID to resolve (e.g., "did:iota:0xabc...")
/// - identity_pkg_id: ObjectID of the deployed iota_identity Move package,
///   or empty binary for auto-discovery
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn resolve_did(
    node_url: Binary,
    did_str: Binary,
    identity_pkg_id: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let node_url_str = match std::str::from_utf8(node_url.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok((atoms::error(), "Invalid node URL: not valid UTF-8".to_string())),
    };
    let did_string = match std::str::from_utf8(did_str.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok((atoms::error(), "Invalid DID: not valid UTF-8".to_string())),
    };
    let pkg_str = match std::str::from_utf8(identity_pkg_id.as_slice()) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid identity package ID: not valid UTF-8".to_string(),
            ))
        }
    };

    let package_id = match parse_optional_object_id(&pkg_str) {
        Ok(id) => id,
        Err(e) => return Ok((atoms::error(), e)),
    };

    let rt = match runtime() {
        Some(rt) => rt,
        None => {
            return Ok((
                atoms::error(),
                "Failed to initialize async runtime".to_string(),
            ))
        }
    };

    let result = rt.block_on(async {
        resolve_did_async(&node_url_str, &did_string, package_id).await
    });

    match result {
        Ok(resolve_result) => {
            let json = serde_json::to_string(&resolve_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

// ================================================================
// Async Implementations
// ================================================================

/// Create and publish a DID document using the caller's Ed25519 key
async fn create_and_publish_did_async(
    node_url: &str,
    secret_key_input: &str,
    _gas_coin_id: &str, // Reserved for future explicit gas coin selection
    package_id: Option<ObjectID>,
) -> Result<PublishResult, String> {
    // Decode the secret key and create JWK
    let jwk = decode_ed25519_key_to_jwk(secret_key_input)?;

    // Create in-memory storage and import the user's key
    let storage: Storage<JwkMemStore, KeyIdMemstore> =
        Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

    let key_id = storage
        .key_storage()
        .insert(jwk.clone())
        .await
        .map_err(|e| format!("Failed to import key into storage: {:?}", e))?;

    let public_jwk = jwk
        .to_public()
        .ok_or_else(|| "Failed to derive public JWK from private key".to_string())?;

    // Create a signer from the imported key
    let signer = StorageSigner::new(&storage, key_id, public_jwk);

    // Connect to the IOTA node
    let iota_client = IotaClientBuilder::default()
        .build(node_url)
        .await
        .map_err(|e| format!("Failed to connect to IOTA node '{}': {}", node_url, e))?;

    // Build the IdentityClientReadOnly
    let read_only_client = match package_id {
        Some(pkg_id) => IdentityClientReadOnly::new_with_pkg_id(iota_client, pkg_id)
            .await
            .map_err(|e| format!("Failed to create identity client: {}", e))?,
        None => IdentityClientReadOnly::new(iota_client)
            .await
            .map_err(|e| format!("Failed to create identity client: {}", e))?,
    };

    // Create identity client with signer
    let identity_client = IdentityClient::new(read_only_client, signer)
        .await
        .map_err(|e| format!("Failed to configure signer: {}", e))?;

    // Create a new DID document for the connected network
    let mut document = IotaDocument::new(identity_client.network());

    // Generate an Ed25519 verification method for the DID document
    // (This is a separate key from the transaction signing key)
    let fragment = document
        .generate_method(
            &storage,
            JwkMemStore::ED25519_KEY_TYPE,
            JwsAlgorithm::EdDSA,
            None,
            MethodScope::VerificationMethod,
        )
        .await
        .map_err(|e| format!("Failed to generate verification method: {}", e))?;

    // Publish the DID document to the IOTA Rebased ledger
    let published = identity_client
        .publish_did_document(document)
        .with_gas_budget(DEFAULT_GAS_BUDGET)
        .build_and_execute(&identity_client)
        .await
        .map_err(|e| format!("Failed to publish DID to ledger: {}", e))?
        .output;

    let did = published.id().to_string();
    let doc_json = published
        .to_json()
        .map_err(|e| format!("Failed to serialize published document: {}", e))?;

    Ok(PublishResult {
        did,
        document: doc_json,
        verification_method_fragment: fragment,
        network: identity_client.network().to_string(),
        sender_address: identity_client.address().to_string(),
    })
}

/// Resolve a DID document from the ledger (read-only, no signer needed)
async fn resolve_did_async(
    node_url: &str,
    did_str: &str,
    package_id: Option<ObjectID>,
) -> Result<ResolveResult, String> {
    // Connect to the IOTA node
    let iota_client = IotaClientBuilder::default()
        .build(node_url)
        .await
        .map_err(|e| format!("Failed to connect to IOTA node '{}': {}", node_url, e))?;

    // Create a read-only identity client (no signer needed for resolution)
    let read_only_client = match package_id {
        Some(pkg_id) => IdentityClientReadOnly::new_with_pkg_id(iota_client, pkg_id)
            .await
            .map_err(|e| format!("Failed to create identity client: {}", e))?,
        None => IdentityClientReadOnly::new(iota_client)
            .await
            .map_err(|e| format!("Failed to create identity client: {}", e))?,
    };

    // Parse the DID string
    let did = IotaDID::parse(did_str)
        .map_err(|e| format!("Invalid DID '{}': {}", did_str, e))?;

    // Resolve the DID document from the ledger
    let document = read_only_client
        .resolve_did(&did)
        .await
        .map_err(|e| format!("Failed to resolve DID '{}': {}", did_str, e))?;

    let did_string = document.id().to_string();
    let document_json = document
        .to_json()
        .map_err(|e| format!("Failed to serialize document: {}", e))?;

    Ok(ResolveResult {
        did: did_string,
        document: document_json,
    })
}

// Note: NIF registration is done in lib.rs
