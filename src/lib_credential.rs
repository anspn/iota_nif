use rustler::{Binary, NifResult};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

// IOTA Identity imports
use identity_iota::core::{FromJson, Object, Url};
use identity_iota::credential::{
    Credential, CredentialBuilder, DecodedJwtCredential, FailFast, Jwt,
    JwtCredentialValidationOptions, JwtCredentialValidator, Subject,
};
use identity_iota::credential::{
    DecodedJwtPresentation, JwtPresentationOptions, JwtPresentationValidationOptions,
    JwtPresentationValidator, Presentation, PresentationBuilder,
};
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::IotaDocument;
use identity_iota::did::DID;
use identity_iota::storage::{JwkDocumentExt, JwkMemStore, JwkStorage, JwsSignatureOptions, KeyIdMemstore, KeyIdStorage, MethodDigest, Storage};
use identity_iota::verification::jose::jwk::Jwk;

// EdDSA verifier for JWT validation
use identity_eddsa_verifier::EdDSAJwsVerifier;

/// Global Tokio runtime for async operations
fn runtime() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| Runtime::new().ok())
        .as_ref()
}

/// Error atoms for Erlang
mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

/// Result for credential creation (issuer side)
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateCredentialResult {
    /// The signed credential as a JWT string
    pub credential_jwt: String,
    /// The issuer DID
    pub issuer_did: String,
    /// The subject/holder DID
    pub subject_did: String,
    /// The credential type(s)
    pub credential_type: String,
}

/// Result for credential verification
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyCredentialResult {
    /// Whether the credential is valid
    pub valid: bool,
    /// The issuer DID extracted from the credential
    pub issuer_did: String,
    /// The subject/holder DID extracted from the credential
    pub subject_did: String,
    /// The credential claims as JSON
    pub claims: String,
}

/// Result for presentation creation (holder side)
#[derive(Serialize, Deserialize, Debug)]
pub struct CreatePresentationResult {
    /// The signed presentation as a JWT string
    pub presentation_jwt: String,
    /// The holder DID
    pub holder_did: String,
}

/// Result for presentation verification
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyPresentationResult {
    /// Whether the presentation is valid
    pub valid: bool,
    /// The holder DID
    pub holder_did: String,
    /// Number of credentials in the presentation
    pub credential_count: usize,
    /// The credential JWTs contained in the presentation
    pub credentials: Vec<String>,
}

// ================================================================
// NIF Functions
// ================================================================

/// Create a Verifiable Credential (VC) as a signed JWT.
///
/// The issuer creates a credential about a subject (holder) and signs it
/// using a caller-supplied private key that corresponds to an existing
/// verification method in the issuer's DID document.
///
/// Parameters:
/// - issuer_doc_json: The issuer's DID document as JSON
/// - subject_did: The subject/holder's DID string
/// - credential_type: The credential type (e.g., "UniversityDegreeCredential")
/// - claims_json: JSON object with the credential claims/properties
/// - private_key_jwk: The private key JWK (JSON) for signing
/// - fragment: The verification method fragment in the issuer document
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn create_credential(
    issuer_doc_json: Binary,
    subject_did: Binary,
    credential_type: Binary,
    claims_json: Binary,
    private_key_jwk: Binary,
    fragment: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let issuer_doc_str = match std::str::from_utf8(issuer_doc_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid issuer document: not valid UTF-8".to_string(),
            ))
        }
    };
    let subject_did_str = match std::str::from_utf8(subject_did.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid subject DID: not valid UTF-8".to_string(),
            ))
        }
    };
    let cred_type_str = match std::str::from_utf8(credential_type.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid credential type: not valid UTF-8".to_string(),
            ))
        }
    };
    let claims_str = match std::str::from_utf8(claims_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid claims JSON: not valid UTF-8".to_string(),
            ))
        }
    };
    let private_key_str = match std::str::from_utf8(private_key_jwk.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid private key JWK: not valid UTF-8".to_string(),
            ))
        }
    };
    let fragment_str = match std::str::from_utf8(fragment.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid fragment: not valid UTF-8".to_string(),
            ))
        }
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
        create_credential_async(
            issuer_doc_str, subject_did_str, cred_type_str, claims_str,
            private_key_str, fragment_str,
        ).await
    });

    match result {
        Ok(cred_result) => {
            let json = serde_json::to_string(&cred_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Verify a Verifiable Credential JWT.
///
/// Validates the credential's signature, structure, and dates using the
/// issuer's DID document.
///
/// Parameters:
/// - credential_jwt: The credential JWT string to verify
/// - issuer_doc_json: The issuer's DID document as JSON
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn verify_credential(
    credential_jwt: Binary,
    issuer_doc_json: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let jwt_str = match std::str::from_utf8(credential_jwt.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid credential JWT: not valid UTF-8".to_string(),
            ))
        }
    };
    let issuer_doc_str = match std::str::from_utf8(issuer_doc_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid issuer document: not valid UTF-8".to_string(),
            ))
        }
    };

    let result = verify_credential_sync(jwt_str, issuer_doc_str);

    match result {
        Ok(verify_result) => {
            let json = serde_json::to_string(&verify_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Create a Verifiable Presentation (VP) as a signed JWT.
///
/// The holder wraps one or more credential JWTs into a presentation and
/// signs it using a caller-supplied private key that corresponds to an
/// existing verification method in the holder's DID document. A challenge
/// (nonce) can be included to prevent replay attacks.
///
/// Parameters:
/// - holder_doc_json: The holder's DID document as JSON
/// - credential_jwts_json: JSON array of credential JWT strings
/// - challenge: A nonce/challenge string (can be empty)
/// - expires_in_seconds: Expiration time in seconds from now (0 = no expiry)
/// - private_key_jwk: The private key JWK (JSON) for signing
/// - fragment: The verification method fragment in the holder document
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn create_presentation(
    holder_doc_json: Binary,
    credential_jwts_json: Binary,
    challenge: Binary,
    expires_in_seconds: u64,
    private_key_jwk: Binary,
    fragment: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let holder_doc_str = match std::str::from_utf8(holder_doc_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid holder document: not valid UTF-8".to_string(),
            ))
        }
    };
    let creds_str = match std::str::from_utf8(credential_jwts_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid credential JWTs: not valid UTF-8".to_string(),
            ))
        }
    };
    let challenge_str = match std::str::from_utf8(challenge.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid challenge: not valid UTF-8".to_string(),
            ))
        }
    };
    let private_key_str = match std::str::from_utf8(private_key_jwk.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid private key JWK: not valid UTF-8".to_string(),
            ))
        }
    };
    let fragment_str = match std::str::from_utf8(fragment.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid fragment: not valid UTF-8".to_string(),
            ))
        }
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
        create_presentation_async(
            holder_doc_str, creds_str, challenge_str, expires_in_seconds,
            private_key_str, fragment_str,
        ).await
    });

    match result {
        Ok(pres_result) => {
            let json = serde_json::to_string(&pres_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

/// Verify a Verifiable Presentation JWT.
///
/// Validates the presentation's signature and structure using the holder's
/// DID document. Also validates each contained credential JWT against the
/// provided issuer documents.
///
/// Parameters:
/// - presentation_jwt: The presentation JWT string to verify
/// - holder_doc_json: The holder's DID document as JSON
/// - issuer_docs_json: JSON array of issuer DID documents (one per credential)
/// - challenge: The expected challenge/nonce (can be empty to skip check)
///
/// Returns: {:ok, json_string} | {:error, reason}
#[rustler::nif(schedule = "DirtyCpu")]
pub fn verify_presentation(
    presentation_jwt: Binary,
    holder_doc_json: Binary,
    issuer_docs_json: Binary,
    challenge: Binary,
) -> NifResult<(rustler::Atom, String)> {
    let jwt_str = match std::str::from_utf8(presentation_jwt.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid presentation JWT: not valid UTF-8".to_string(),
            ))
        }
    };
    let holder_doc_str = match std::str::from_utf8(holder_doc_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid holder document: not valid UTF-8".to_string(),
            ))
        }
    };
    let issuer_docs_str = match std::str::from_utf8(issuer_docs_json.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid issuer documents: not valid UTF-8".to_string(),
            ))
        }
    };
    let challenge_str = match std::str::from_utf8(challenge.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Ok((
                atoms::error(),
                "Invalid challenge: not valid UTF-8".to_string(),
            ))
        }
    };

    let result =
        verify_presentation_sync(jwt_str, holder_doc_str, issuer_docs_str, challenge_str);

    match result {
        Ok(verify_result) => {
            let json = serde_json::to_string(&verify_result)
                .map_err(|_| rustler::Error::Term(Box::new("serialization_failed")))?;
            Ok((atoms::ok(), json))
        }
        Err(e) => Ok((atoms::error(), e)),
    }
}

// ================================================================
// Async/Sync Implementations
// ================================================================

/// Create a credential JWT using the issuer's DID document and
/// a caller-supplied private key.
///
/// The private key must correspond to an existing verification method
/// (identified by `fragment`) in the issuer's DID document. This ensures
/// the resulting JWT can be verified against the published document.
async fn create_credential_async(
    issuer_doc_json: &str,
    subject_did: &str,
    credential_type: &str,
    claims_json: &str,
    private_key_jwk_json: &str,
    fragment: &str,
) -> Result<CreateCredentialResult, String> {
    // Parse the issuer DID document
    let issuer_document = IotaDocument::from_json(issuer_doc_json)
        .map_err(|e| format!("Failed to parse issuer document: {}", e))?;

    let issuer_did = issuer_document.id().to_string();

    // Verify the fragment exists in the document
    let method = issuer_document
        .resolve_method(fragment, None)
        .ok_or_else(|| {
            format!(
                "Verification method '{}' not found in issuer document",
                fragment
            )
        })?;

    // Parse the caller-supplied private key JWK
    let private_jwk: Jwk = serde_json::from_str(private_key_jwk_json)
        .map_err(|e| format!("Failed to parse private key JWK: {}", e))?;

    // Create in-memory storage and import the caller's key
    let storage: Storage<JwkMemStore, KeyIdMemstore> =
        Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

    let key_id = storage
        .key_storage()
        .insert(private_jwk)
        .await
        .map_err(|e| format!("Failed to import private key: {:?}", e))?;

    // Map the verification method to the imported key
    let method_digest = MethodDigest::new(method)
        .map_err(|e| format!("Failed to compute method digest: {}", e))?;

    storage
        .key_id_storage()
        .insert_key_id(method_digest, key_id)
        .await
        .map_err(|e| format!("Failed to map key to method: {:?}", e))?;

    // Parse the claims JSON
    let mut claims: serde_json::Value = serde_json::from_str(claims_json)
        .map_err(|e| format!("Failed to parse claims JSON: {}", e))?;

    // Ensure the subject "id" field is set to the subject DID
    if let Some(obj) = claims.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(subject_did.to_string()));
    } else {
        return Err("Claims must be a JSON object".to_string());
    }

    // Build the credential subject
    let subject = Subject::from_json_value(claims)
        .map_err(|e| format!("Failed to create credential subject: {}", e))?;

    // Build the credential
    let credential: Credential = CredentialBuilder::default()
        .issuer(
            Url::parse(&issuer_did)
                .map_err(|e| format!("Invalid issuer DID URL: {}", e))?,
        )
        .type_(credential_type)
        .subject(subject)
        .build()
        .map_err(|e| format!("Failed to build credential: {}", e))?;

    // Sign the credential as a JWT using the caller's key
    let credential_jwt: Jwt = issuer_document
        .create_credential_jwt(
            &credential,
            &storage,
            fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await
        .map_err(|e| format!("Failed to sign credential: {}", e))?;

    Ok(CreateCredentialResult {
        credential_jwt: credential_jwt.as_str().to_string(),
        issuer_did,
        subject_did: subject_did.to_string(),
        credential_type: credential_type.to_string(),
    })
}

/// Verify a credential JWT against an issuer's DID document (synchronous).
fn verify_credential_sync(
    jwt_str: &str,
    issuer_doc_json: &str,
) -> Result<VerifyCredentialResult, String> {
    // Parse the issuer DID document
    let issuer_document = IotaDocument::from_json(issuer_doc_json)
        .map_err(|e| format!("Failed to parse issuer document: {}", e))?;

    let jwt = Jwt::new(jwt_str.to_string());

    // Validate the credential JWT
    let decoded: DecodedJwtCredential<Object> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
            .validate::<_, Object>(
                &jwt,
                &issuer_document,
                &JwtCredentialValidationOptions::default(),
                FailFast::FirstError,
            )
            .map_err(|e| format!("Credential validation failed: {}", e))?;

    let credential = &decoded.credential;

    // Extract issuer DID
    let issuer_did = credential.issuer.url().to_string();

    // Extract subject DID from the first subject
    let subject_did = credential
        .credential_subject
        .first()
        .and_then(|s| s.id.as_ref())
        .map(|url| url.to_string())
        .unwrap_or_default();

    // Serialize the credential claims
    let claims = serde_json::to_string(&credential.credential_subject)
        .map_err(|e| format!("Failed to serialize claims: {}", e))?;

    Ok(VerifyCredentialResult {
        valid: true,
        issuer_did,
        subject_did,
        claims,
    })
}

/// Create a presentation JWT using the holder's DID document and
/// a caller-supplied private key.
///
/// The private key must correspond to an existing verification method
/// (identified by `fragment`) in the holder's DID document.
async fn create_presentation_async(
    holder_doc_json: &str,
    credential_jwts_json: &str,
    challenge: &str,
    expires_in_seconds: u64,
    private_key_jwk_json: &str,
    fragment: &str,
) -> Result<CreatePresentationResult, String> {
    // Parse the holder DID document
    let holder_document = IotaDocument::from_json(holder_doc_json)
        .map_err(|e| format!("Failed to parse holder document: {}", e))?;

    let holder_did = holder_document.id().to_string();

    // Verify the fragment exists in the document
    let method = holder_document
        .resolve_method(fragment, None)
        .ok_or_else(|| {
            format!(
                "Verification method '{}' not found in holder document",
                fragment
            )
        })?;

    // Parse the caller-supplied private key JWK
    let private_jwk: Jwk = serde_json::from_str(private_key_jwk_json)
        .map_err(|e| format!("Failed to parse private key JWK: {}", e))?;

    // Create in-memory storage and import the caller's key
    let storage: Storage<JwkMemStore, KeyIdMemstore> =
        Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

    let key_id = storage
        .key_storage()
        .insert(private_jwk)
        .await
        .map_err(|e| format!("Failed to import private key: {:?}", e))?;

    // Map the verification method to the imported key
    let method_digest = MethodDigest::new(method)
        .map_err(|e| format!("Failed to compute method digest: {}", e))?;

    storage
        .key_id_storage()
        .insert_key_id(method_digest, key_id)
        .await
        .map_err(|e| format!("Failed to map key to method: {:?}", e))?;

    // Parse the credential JWTs array
    let credential_jwt_strings: Vec<String> = serde_json::from_str(credential_jwts_json)
        .map_err(|e| format!("Failed to parse credential JWTs JSON array: {}", e))?;

    if credential_jwt_strings.is_empty() {
        return Err("At least one credential JWT is required".to_string());
    }

    // Build the presentation with the credential JWTs
    let holder_url = holder_document.id().to_url().into();
    let mut builder = PresentationBuilder::new(holder_url, Default::default());
    for jwt_str in &credential_jwt_strings {
        builder = builder.credential(Jwt::new(jwt_str.clone()));
    }
    let presentation: Presentation<Jwt> = builder
        .build()
        .map_err(|e| format!("Failed to build presentation: {}", e))?;

    // Set up signature options
    let mut jws_options = JwsSignatureOptions::default();
    if !challenge.is_empty() {
        jws_options = jws_options.nonce(challenge.to_owned());
    }

    // Set up presentation options (expiry)
    let mut pres_options = JwtPresentationOptions::default();
    if expires_in_seconds > 0 {
        use identity_iota::core::{Duration, Timestamp};
        let expires = Timestamp::now_utc()
            .checked_add(Duration::seconds(expires_in_seconds as u32))
            .ok_or_else(|| "Failed to compute expiration timestamp".to_string())?;
        pres_options = pres_options.expiration_date(expires);
    }

    // Sign the presentation as a JWT using the caller's key
    let presentation_jwt: Jwt = holder_document
        .create_presentation_jwt(
            &presentation,
            &storage,
            fragment,
            &jws_options,
            &pres_options,
        )
        .await
        .map_err(|e| format!("Failed to sign presentation: {}", e))?;

    Ok(CreatePresentationResult {
        presentation_jwt: presentation_jwt.as_str().to_string(),
        holder_did,
    })
}

/// Verify a presentation JWT against holder and issuer documents (synchronous).
fn verify_presentation_sync(
    jwt_str: &str,
    holder_doc_json: &str,
    issuer_docs_json: &str,
    challenge: &str,
) -> Result<VerifyPresentationResult, String> {
    // Parse the holder DID document
    let holder_document = IotaDocument::from_json(holder_doc_json)
        .map_err(|e| format!("Failed to parse holder document: {}", e))?;

    let holder_did = holder_document.id().to_string();

    // Parse the issuer documents array
    let issuer_doc_values: Vec<serde_json::Value> = serde_json::from_str(issuer_docs_json)
        .map_err(|e| format!("Failed to parse issuer documents JSON array: {}", e))?;

    let issuer_documents: Vec<IotaDocument> = issuer_doc_values
        .iter()
        .map(|v| {
            let json_str = serde_json::to_string(v)
                .map_err(|e| format!("Failed to serialize issuer doc: {}", e))?;
            IotaDocument::from_json(&json_str)
                .map_err(|e| format!("Failed to parse issuer document: {}", e))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let jwt = Jwt::new(jwt_str.to_string());

    // Set up verification options with challenge if provided
    let mut verifier_options = JwsVerificationOptions::default();
    if !challenge.is_empty() {
        verifier_options = verifier_options.nonce(challenge.to_owned());
    }

    let presentation_validation_options = JwtPresentationValidationOptions::default()
        .presentation_verifier_options(verifier_options);

    // Validate the presentation JWT
    let decoded: DecodedJwtPresentation<Jwt> =
        JwtPresentationValidator::with_signature_verifier(EdDSAJwsVerifier::default())
            .validate(&jwt, &holder_document, &presentation_validation_options)
            .map_err(|e| format!("Presentation validation failed: {}", e))?;

    // Extract the credential JWTs from the presentation
    let jwt_credentials: &Vec<Jwt> = &decoded.presentation.verifiable_credential;
    let credential_count = jwt_credentials.len();

    // Validate each credential against its issuer document
    let credential_validator =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
    let validation_options = JwtCredentialValidationOptions::default();

    let mut credential_strings = Vec::new();
    for (i, jwt_vc) in jwt_credentials.iter().enumerate() {
        let issuer_doc = issuer_documents.get(i).ok_or_else(|| {
            format!(
                "Missing issuer document for credential {} (provided {} issuer docs for {} credentials)",
                i, issuer_documents.len(), credential_count
            )
        })?;

        credential_validator
            .validate::<_, Object>(jwt_vc, issuer_doc, &validation_options, FailFast::FirstError)
            .map_err(|e| format!("Credential {} validation failed: {}", i, e))?;

        credential_strings.push(jwt_vc.as_str().to_string());
    }

    Ok(VerifyPresentationResult {
        valid: true,
        holder_did,
        credential_count,
        credentials: credential_strings,
    })
}
