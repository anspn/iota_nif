# IOTA DID NIF for Erlang

A Rust NIF (Native Implemented Function) library that provides IOTA DID (Decentralized Identifier) operations for Erlang/Elixir projects. Supports the **IOTA Rebased** network (MoveVM-based).

## Features

- **Local DID operations**: Generate DID documents, extract DIDs, create DID URLs, validate DIDs
- **Ledger publishing**: Publish DID documents on-chain via IOTA Rebased MoveVM transactions
- **DID resolution**: Resolve published DIDs from the IOTA ledger
- **Verifiable Credentials (VC)**: Create and verify W3C Verifiable Credentials as signed JWTs
- **Verifiable Presentations (VP)**: Create and verify W3C Verifiable Presentations with challenge/expiry support
- **Notarization**: Hash and notarize data payloads (local and on-chain)
- **On-chain notarization**: Create, read, update, and destroy notarizations on the IOTA Rebased ledger via the [official IOTA notarization library](https://github.com/iotaledger/notarization)
- **Key format support**: Accepts Ed25519 keys in Bech32 (`iotaprivkey1...`), Base64 (33-byte keystore), or raw Base64 (32-byte) formats
- **Library-first design**: All sensitive parameters (keys, node URLs, package IDs) are passed explicitly by the consuming application — no hidden environment variable or application config reads

## Prerequisites

- Rust (1.70+)
- Erlang/OTP 27+
- rebar3
- An IOTA Rebased node (local or testnet) for ledger operations

## Quick Start

### 1. Build

```bash
git clone https://github.com/anspn/iota_nif.git
cd iota_nif
rebar3 compile
```

### 2. Configure environment

```bash
# Copy the example env file
cp .env.example .env

# Export your Ed25519 private key from the IOTA CLI
iota keytool export --key-identity $(iota client active-address)

# Edit .env and paste your key
nano .env
```

The `.env` file supports these variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `IOTA_SECRET_KEY` | Yes | Ed25519 private key (Bech32 `iotaprivkey1...` or Base64) |
| `IOTA_NODE_URL` | No | IOTA node URL (default: `http://127.0.0.1:9000`) |
| `IOTA_IDENTITY_PKG_ID` | No | Identity package ObjectID (empty = auto-discover) |
| `IOTA_NOTARIZE_PKG_ID` | No | Notarization package ObjectID (empty = auto-discover) |

> **Note:** The `.env` file is gitignored. The library itself never reads environment
> variables — they are used only by the test suites and by your consuming application.

### 3. Set up IOTA CLI (for ledger operations)

```bash
# Request gas coins from the faucet (local node or testnet)
iota client faucet

# Check your address and gas coins
iota client active-address
iota client gas

# Export your Ed25519 private key
iota keytool export <your-address>

# Find the identity package ID for your network
# (check your network's documentation or deploy the iota_identity Move package)
```

### 4. Publish a DID

```erlang
SecretKey = <<"iotaprivkey1qz...">>,       %% from `iota keytool export`
NodeUrl = <<"http://127.0.0.1:9000">>,     %% your IOTA node
IdentityPkgId = <<"0xabc123...">>,         %% identity package ObjectID

{ok, ResultJson} = iota_did_nif:create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId).
```

## Installation as rebar3 Dependency

Add to your `rebar.config`:

```erlang
{deps, [
    {iota_nif, {git, "https://github.com/anspn/iota_nif.git", {branch, "main"}}}
]}.
```

Then run:

```bash
rebar3 compile
```

The Rust NIF will be automatically compiled during the build process.

## Usage

### Key Formats

All ledger operations require an Ed25519 private key. Three formats are accepted:

| Format | Example | Source |
|--------|---------|--------|
| **Bech32** | `iotaprivkey1qz...` | `iota keytool export --key-identity <addr>` |
| **Base64 (33 bytes)** | `AJ8uNnI...` | IOTA keystore file (0x00 prefix + key) |
| **Base64 (32 bytes)** | `ny43cj...` | Raw Ed25519 private key |

### Local DID Operations (no network required)

```erlang
%% Generate a new DID (IOTA mainnet, offline)
{ok, ResultJson} = iota_did_nif:generate_did().

%% Generate for a specific network
{ok, ResultJson} = iota_did_nif:generate_did(<<"iota">>).   %% mainnet
{ok, ResultJson} = iota_did_nif:generate_did(<<"atoi">>).   %% testnet

%% NOTE: Locally generated DIDs have placeholder tags (all zeros).
%% Use create_and_publish_did to get a real on-chain DID.

%% Extract DID from a document
{ok, Did} = iota_did_nif:extract_did_from_document(DocumentJson).

%% Create a DID URL with fragment
{ok, Url} = iota_did_nif:create_did_url(<<"did:iota:0x123">>, <<"key-1">>).
%% => <<"did:iota:0x123#key-1">>

%% Validate DID format
true = iota_did_nif:is_valid_iota_did(<<"did:iota:0x123456">>).
```

### Ledger Operations (IOTA Rebased)

All ledger functions require explicit parameters — the library never reads from
environment variables or application config.

```erlang
SecretKey = <<"iotaprivkey1qz...">>,
NodeUrl = <<"http://127.0.0.1:9000">>,
IdentityPkgId = <<"0xabc123...">>,          %% identity package ObjectID

%% Publish a new DID (auto gas coin selection)
{ok, ResultJson} = iota_did_nif:create_and_publish_did(
    SecretKey, NodeUrl, IdentityPkgId
).

%% Publish with explicit gas coin selection
GasCoinId = <<"0xdef456...">>,
{ok, ResultJson} = iota_did_nif:create_and_publish_did(
    SecretKey, NodeUrl, IdentityPkgId, GasCoinId
).

%% Parse the publish result (using jsx or json module)
Result = json:decode(ResultJson).
%% Result contains:
%%   did              - The published DID string (real on-chain tag)
%%   document         - The full DID document as JSON
%%   verification_method_fragment - Fragment ID of the generated key
%%   network          - Network name
%%   sender_address   - Address that published the DID

%% Resolve a published DID
{ok, ResolveJson} = iota_did_nif:resolve_did(
    <<"did:iota:0xabc...">>, NodeUrl
).

%% Resolve with explicit identity package ID
{ok, ResolveJson} = iota_did_nif:resolve_did(
    <<"did:iota:0xabc...">>, NodeUrl, IdentityPkgId
).
```

### Elixir Usage

```elixir
# Add to your mix.exs dependencies
{:iota_nif, git: "https://github.com/anspn/iota_nif.git"}

# Generate a DID locally (no network)
{:ok, result_json} = :iota_did_nif.generate_did()
result = Jason.decode!(result_json)

# Publish a DID on-chain
secret_key = "iotaprivkey1qz..."
node_url = "http://127.0.0.1:9000"
pkg_id = "0xabc123..."
{:ok, result_json} = :iota_did_nif.create_and_publish_did(secret_key, node_url, pkg_id)
result = Jason.decode!(result_json)

# Create a Verifiable Credential
issuer_doc = result["document"]
holder_did = "did:iota:0x..."
claims = Jason.encode!(%{"name" => "Alice", "degree" => %{"type" => "BachelorDegree"}})
{:ok, cred_json} = :iota_credential_nif.create_credential(issuer_doc, holder_did, "DegreeCredential", claims)
cred = Jason.decode!(cred_json)
credential_jwt = cred["credential_jwt"]

# Create a Verifiable Presentation
holder_doc = "..."  # holder's DID document JSON
cred_jwts = Jason.encode!([credential_jwt])
{:ok, pres_json} = :iota_credential_nif.create_presentation(holder_doc, cred_jwts, "challenge-nonce")
```

### Verifiable Credentials (VC)

Verifiable Credentials allow an issuer to make tamper-evident claims about a subject (holder).
The credential is signed as a JWT using the issuer's DID document.

```erlang
%% 1. Generate DIDs for issuer and holder
{ok, IssuerJson} = iota_did_nif:generate_did(<<"iota">>),
IssuerResult = json:decode(IssuerJson),
IssuerDocJson = maps:get(<<"document">>, IssuerResult),

{ok, HolderJson} = iota_did_nif:generate_did(<<"iota">>),
HolderResult = json:decode(HolderJson),
HolderDid = maps:get(<<"did">>, HolderResult),

%% 2. Create a Verifiable Credential
Claims = <<"{\"name\": \"Alice\", \"degree\": {\"type\": \"BachelorDegree\", \"name\": \"BSc Computer Science\"}, \"GPA\": \"4.0\"}">>,

{ok, CredResultJson} = iota_credential_nif:create_credential(
    IssuerDocJson,
    HolderDid,
    <<"UniversityDegreeCredential">>,
    Claims
),

CredResult = json:decode(CredResultJson),
CredentialJwt = maps:get(<<"credential_jwt">>, CredResult).
%% CredentialJwt is a compact JWT string: eyJhbGciOi...

%% 3. Verify the credential
{ok, VerifyJson} = iota_credential_nif:verify_credential(CredentialJwt, IssuerDocJson),
VerifyResult = json:decode(VerifyJson).
%% VerifyResult contains: valid, issuer_did, subject_did, claims
```

### Verifiable Presentations (VP)

Verifiable Presentations allow a holder to wrap one or more VCs and prove control
by signing the presentation. A challenge (nonce) prevents replay attacks.

```erlang
%% Using holder DID document and credential JWT from above

%% 1. Wrap credentials into a JSON array
HolderDocJson = maps:get(<<"document">>, HolderResult),
CredJwtsJson = iolist_to_binary(json:encode([CredentialJwt])),

%% 2. Create a presentation with challenge and 10-minute expiry
Challenge = <<"unique-challenge-nonce-12345">>,
{ok, PresResultJson} = iota_credential_nif:create_presentation(
    HolderDocJson,
    CredJwtsJson,
    Challenge,
    600  %% expires in 600 seconds
),

PresResult = json:decode(PresResultJson),
PresentationJwt = maps:get(<<"presentation_jwt">>, PresResult).

%% 3. Verify the presentation (verifier side)
IssuerDocsJson = iolist_to_binary(json:encode([json:decode(IssuerDocJson)])),
{ok, VpVerifyJson} = iota_credential_nif:verify_presentation(
    PresentationJwt,
    HolderDocJson,
    IssuerDocsJson,
    Challenge
).
```

### Notarization — Local Operations

```erlang
%% Hash data with SHA-256
DataHash = iota_notarization_nif:hash_data(<<"My document content">>).
%% => <<"a1b2c3d4...">> (64-char hex string)

%% Create a notarization payload (local, no network)
{ok, PayloadJson} = iota_notarization_nif:create_notarization_payload(DataHash, <<"doc-v1">>).

%% Verify a notarization payload
{ok, VerifyJson} = iota_notarization_nif:verify_notarization_payload(PayloadHex).
```

### Notarization — On-Chain (IOTA Rebased)

On-chain notarization uses the [official IOTA notarization library](https://github.com/iotaledger/notarization).
The notarization Move package is natively available on IOTA mainnet/testnet.

#### Create a Locked Notarization (Immutable)

```erlang
SecretKey = <<"iotaprivkey1qz...">>,
NodeUrl = <<"http://127.0.0.1:9000">>,
NotarizePkgId = <<"0xabc123...">>,          %% notarization package ObjectID

%% Hash your data
DataHash = iota_notarization_nif:hash_data(<<"Legal contract content...">>),

%% Create a locked notarization (immutable — ideal for proof-of-existence)
{ok, ResultJson} = iota_notarization_nif:create_notarization(
    SecretKey, NodeUrl, NotarizePkgId, DataHash
).

%% With optional description
{ok, ResultJson} = iota_notarization_nif:create_notarization(
    SecretKey, NodeUrl, NotarizePkgId, DataHash, <<"contract-2026-001">>
).

%% Result contains:
%%   object_id        - On-chain notarization object ID
%%   tx_digest        - Transaction digest
%%   state_data       - The notarized data
%%   description      - Description label
%%   method           - "locked"
```

#### Read a Notarization

```erlang
%% Read using the object ID from create
{ok, ReadJson} = iota_notarization_nif:read_notarization(
    NodeUrl, ObjectId, NotarizePkgId
).

%% Result contains:
%%   object_id          - The notarization object ID
%%   state_data         - The notarized data
%%   state_metadata     - Optional metadata
%%   description        - Description label
%%   method             - "Locked" or "Dynamic"
%%   created_at         - Creation timestamp
%%   last_state_change_at - Last state change timestamp
%%   state_version_count  - Number of state updates
```

#### Dynamic Notarizations (Updatable)

```erlang
%% Create a dynamic notarization (state can be updated)
{ok, ResultJson} = iota_notarization_nif:create_dynamic_notarization(
    SecretKey, NodeUrl, NotarizePkgId, <<"Status: Active">>, <<"Service Monitor">>
).

%% Update the state
{ok, UpdateJson} = iota_notarization_nif:update_notarization_state(
    SecretKey, NodeUrl, NotarizePkgId, ObjectId, <<"Status: Inactive">>
).

%% Destroy a notarization
{ok, DestroyJson} = iota_notarization_nif:destroy_notarization(
    SecretKey, NodeUrl, NotarizePkgId, ObjectId
).
```

## API Reference

All functions are organized in three Erlang modules. Every parameter is a binary.
Return values follow the `{ok, Result}` / `{error, Reason}` convention (unless noted).

---

### `iota_did_nif` — DID Operations

#### Local Operations (no network required)

##### `generate_did() -> {ok, binary()} | {error, binary()}`

Generate a new IOTA DID for the mainnet (default). Equivalent to `generate_did(<<"iota">>)`.

The generated DID has a placeholder tag (`0x0000...`) because it has not been published. Use `create_and_publish_did` around a key to get a real on-chain DID.

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | The DID string (placeholder with zero tag) |
| `document` | string | Full DID document as JSON |
| `verification_method_fragment` | string | Fragment ID of the generated Ed25519 key |

---

##### `generate_did(Network) -> {ok, binary()} | {error, binary()}`

Generate a new IOTA DID for the specified network.

| Param | Type | Description |
|-------|------|-------------|
| `Network` | binary | `<<"iota">>` (mainnet), `<<"smr">>` (Shimmer), `<<"rms">>` (Shimmer testnet), `<<"atoi">>` (IOTA testnet) |

**Returns** — same JSON as `generate_did/0`.

---

##### `extract_did_from_document(DocumentJson) -> {ok, binary()} | {error, binary()}`

Extract the DID string from a DID document JSON.

| Param | Type | Description |
|-------|------|-------------|
| `DocumentJson` | binary | A DID document as a JSON binary |

**Returns** — the `id` field value from the document.

---

##### `create_did_url(Did, Fragment) -> {ok, binary()} | {error, binary()}`

Create a DID URL by appending a fragment with `#`.

| Param | Type | Description |
|-------|------|-------------|
| `Did` | binary | The base DID string (e.g., `<<"did:iota:0x123">>`) |
| `Fragment` | binary | The fragment identifier (e.g., `<<"key-1">>`) |

**Returns** — e.g., `<<"did:iota:0x123#key-1">>`.

---

##### `is_valid_iota_did(Did) -> boolean()`

Check if a string is a valid IOTA DID format. Does **not** check on-chain existence.

| Param | Type | Description |
|-------|------|-------------|
| `Did` | binary | The DID string to validate |

**Returns** — `true` if format is valid (`did:iota:0x...` or `did:iota:<network>:0x...`), `false` otherwise.

---

#### Ledger Operations (require IOTA Rebased node)

##### `create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId) -> {ok, binary()} | {error, binary()}`

Create and publish a new DID to the IOTA Rebased ledger with automatic gas coin selection.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key (Bech32, Base64 33-byte, or Base64 32-byte) |
| `NodeUrl` | binary | URL of the IOTA node (e.g., `<<"http://127.0.0.1:9000">>`) |
| `IdentityPkgId` | binary | ObjectID of the identity Move package, or `<<>>` for auto-discovery |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | The published DID string (real on-chain tag) |
| `document` | string | Full DID document as JSON |
| `verification_method_fragment` | string | Fragment ID of the generated key |
| `network` | string | Network name |
| `sender_address` | string | Address that published the DID |

---

##### `create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId, GasCoinId) -> {ok, binary()} | {error, binary()}`

Same as above but with explicit gas coin selection.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key |
| `NodeUrl` | binary | IOTA node URL |
| `IdentityPkgId` | binary | Identity package ObjectID, or `<<>>` |
| `GasCoinId` | binary | Hex ObjectID of gas coin, or `<<>>` for automatic selection |

---

##### `resolve_did(Did, NodeUrl) -> {ok, binary()} | {error, binary()}`

Resolve a published DID from the IOTA ledger. No signing key required.

| Param | Type | Description |
|-------|------|-------------|
| `Did` | binary | The DID to resolve (e.g., `<<"did:iota:0xabc...">>`) |
| `NodeUrl` | binary | IOTA node URL |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | The resolved DID |
| `document` | string | Full DID document as JSON |

---

##### `resolve_did(Did, NodeUrl, IdentityPkgId) -> {ok, binary()} | {error, binary()}`

Same as above with explicit identity package ID.

| Param | Type | Description |
|-------|------|-------------|
| `Did` | binary | The DID to resolve |
| `NodeUrl` | binary | IOTA node URL |
| `IdentityPkgId` | binary | Identity package ObjectID, or `<<>>` |

---

##### `deactivate_did(SecretKey, Did, NodeUrl) -> {ok, binary()} | {error, binary()}`

Permanently deactivate (revoke) a DID on the ledger. **Irreversible**.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key of a controller |
| `Did` | binary | The DID to deactivate |
| `NodeUrl` | binary | IOTA node URL |

**Returns** — `{ok, <<"deactivated">>}` on success.

---

##### `deactivate_did(SecretKey, Did, NodeUrl, IdentityPkgId) -> {ok, binary()} | {error, binary()}`

Same as above with explicit identity package ID.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key of a controller |
| `Did` | binary | The DID to deactivate |
| `NodeUrl` | binary | IOTA node URL |
| `IdentityPkgId` | binary | Identity package ObjectID, or `<<>>` |

---

### `iota_credential_nif` — Verifiable Credentials & Presentations

#### Verifiable Credentials

##### `create_credential(IssuerDocJson, SubjectDid, CredentialType, ClaimsJson) -> {ok, binary()} | {error, binary()}`

Create a Verifiable Credential (VC) as a signed JWT. The issuer signs the credential
using a freshly generated Ed25519 verification method.

| Param | Type | Description |
|-------|------|-------------|
| `IssuerDocJson` | binary | The issuer's DID document as JSON (from `generate_did`) |
| `SubjectDid` | binary | The subject/holder's DID string |
| `CredentialType` | binary | Credential type (e.g., `<<"UniversityDegreeCredential">>`) |
| `ClaimsJson` | binary | JSON object with credential claims. The `"id"` field is auto-set to `SubjectDid`. |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `credential_jwt` | string | The signed credential as a compact JWT (`header.payload.signature`) |
| `issuer_did` | string | The issuer's DID |
| `subject_did` | string | The subject/holder's DID |
| `credential_type` | string | The credential type |

**Example claims JSON:**

```json
{
  "name": "Alice",
  "degree": {
    "type": "BachelorDegree",
    "name": "Bachelor of Science and Arts"
  },
  "GPA": "4.0"
}
```

---

##### `verify_credential(CredentialJwt, IssuerDocJson) -> {ok, binary()} | {error, binary()}`

Verify a Verifiable Credential JWT. Validates the EdDSA signature, semantic structure,
issuance date (not in the future), and expiration date (not in the past).

| Param | Type | Description |
|-------|------|-------------|
| `CredentialJwt` | binary | The credential JWT string |
| `IssuerDocJson` | binary | The issuer's DID document as JSON (must contain the signing key) |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | `true` if validation passed |
| `issuer_did` | string | The issuer's DID extracted from the credential |
| `subject_did` | string | The subject/holder's DID |
| `claims` | string | The credential claims as a JSON string |

---

#### Verifiable Presentations

##### `create_presentation(HolderDocJson, CredentialJwtsJson, Challenge) -> {ok, binary()} | {error, binary()}`

Create a Verifiable Presentation (VP) as a signed JWT with no expiration.

| Param | Type | Description |
|-------|------|-------------|
| `HolderDocJson` | binary | The holder's DID document as JSON |
| `CredentialJwtsJson` | binary | JSON array of credential JWT strings (e.g., `<<"[\"eyJ...\"]">>`) |
| `Challenge` | binary | Nonce for replay protection. Pass `<<>>` to omit. |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `presentation_jwt` | string | The signed presentation as a compact JWT |
| `holder_did` | string | The holder's DID |

---

##### `create_presentation(HolderDocJson, CredentialJwtsJson, Challenge, ExpiresInSeconds) -> {ok, binary()} | {error, binary()}`

Create a Verifiable Presentation with expiration.

| Param | Type | Description |
|-------|------|-------------|
| `HolderDocJson` | binary | The holder's DID document as JSON |
| `CredentialJwtsJson` | binary | JSON array of credential JWT strings |
| `Challenge` | binary | Nonce for replay protection. Pass `<<>>` to omit. |
| `ExpiresInSeconds` | integer | Expiration in seconds from now. `0` = no expiration. |

---

##### `verify_presentation(PresentationJwt, HolderDocJson, IssuerDocsJson) -> {ok, binary()} | {error, binary()}`

Verify a Verifiable Presentation JWT and all contained credential JWTs.

| Param | Type | Description |
|-------|------|-------------|
| `PresentationJwt` | binary | The presentation JWT string |
| `HolderDocJson` | binary | The holder's DID document as JSON |
| `IssuerDocsJson` | binary | JSON array of issuer DID documents (one per credential, in order) |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | `true` if validation passed |
| `holder_did` | string | The holder's DID |
| `credential_count` | integer | Number of credentials in the presentation |
| `credentials` | array | Array of credential JWT strings |

---

##### `verify_presentation(PresentationJwt, HolderDocJson, IssuerDocsJson, Challenge) -> {ok, binary()} | {error, binary()}`

Verify a Verifiable Presentation with challenge (nonce) verification for replay protection.

| Param | Type | Description |
|-------|------|-------------|
| `PresentationJwt` | binary | The presentation JWT string |
| `HolderDocJson` | binary | The holder's DID document as JSON |
| `IssuerDocsJson` | binary | JSON array of issuer DID documents |
| `Challenge` | binary | The expected challenge/nonce. Pass `<<>>` to skip challenge check. |

---

### `iota_notarization_nif` — Notarization Operations

#### Local Operations (no network required)

##### `hash_data(Data) -> binary()`

Compute the SHA-256 hash of the input data.

| Param | Type | Description |
|-------|------|-------------|
| `Data` | binary | The data to hash |

**Returns** — 64-character lowercase hex string (e.g., `<<"a1b2c3d4...">>`).

---

##### `create_notarization_payload(DataHash, Tag) -> {ok, binary()} | {error, binary()}`

Create a hex-encoded notarization payload with a timestamp.

| Param | Type | Description |
|-------|------|-------------|
| `DataHash` | binary | SHA-256 hex hash of the data |
| `Tag` | binary | A tag/label for the notarization |

**Returns** — hex-encoded payload string in format `tag:hash:timestamp`.

---

##### `verify_notarization_payload(PayloadHex) -> {ok, binary()} | {error, binary()}`

Verify and decode a hex-encoded notarization payload.

| Param | Type | Description |
|-------|------|-------------|
| `PayloadHex` | binary | The hex-encoded payload to verify |

**Returns** JSON with the extracted tag, hash, and timestamp.

---

##### `is_valid_hex_string(Input) -> boolean()`

Check if a string is a valid hexadecimal string.

| Param | Type | Description |
|-------|------|-------------|
| `Input` | binary | The string to validate |

**Returns** — `true` if the string contains only valid hex characters, `false` otherwise.

---

#### Ledger Operations (require IOTA node + notarization package)

##### `create_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData) -> {ok, binary()} | {error, binary()}`

Create a locked (immutable) notarization on-chain. Ideal for proof-of-existence.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key |
| `NodeUrl` | binary | IOTA node URL |
| `NotarizePkgId` | binary | Notarization package ObjectID |
| `StateData` | binary | The data to notarize |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `object_id` | string | On-chain notarization object ID |
| `tx_digest` | string | Transaction digest |
| `state_data` | string | The notarized data |
| `description` | string | Description label |
| `method` | string | `"locked"` |

---

##### `create_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData, Description) -> {ok, binary()} | {error, binary()}`

Same as above with a description label.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key |
| `NodeUrl` | binary | IOTA node URL |
| `NotarizePkgId` | binary | Notarization package ObjectID |
| `StateData` | binary | The data to notarize |
| `Description` | binary | A human-readable description label |

---

##### `create_dynamic_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData) -> {ok, binary()} | {error, binary()}`

Create a dynamic (updatable) notarization on-chain.

Parameters and return value are the same as `create_notarization/4`, except `method` is `"dynamic"`.

---

##### `create_dynamic_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData, Description) -> {ok, binary()} | {error, binary()}`

Same as above with a description label.

---

##### `read_notarization(NodeUrl, ObjectId, NotarizePkgId) -> {ok, binary()} | {error, binary()}`

Read a notarization from the ledger by object ID. Read-only, no key required.

| Param | Type | Description |
|-------|------|-------------|
| `NodeUrl` | binary | IOTA node URL |
| `ObjectId` | binary | The on-chain notarization object ID |
| `NotarizePkgId` | binary | Notarization package ObjectID |

**Returns** JSON with:

| Field | Type | Description |
|-------|------|-------------|
| `object_id` | string | The notarization object ID |
| `state_data` | string | The notarized data |
| `state_metadata` | string | Optional metadata |
| `description` | string | Description label |
| `method` | string | `"Locked"` or `"Dynamic"` |
| `created_at` | string | Creation timestamp |
| `last_state_change_at` | string | Last state change timestamp |
| `state_version_count` | integer | Number of state updates |

---

##### `update_notarization_state(SecretKey, NodeUrl, NotarizePkgId, ObjectId, NewStateData) -> {ok, binary()} | {error, binary()}`

Update the state of a dynamic notarization. Only works on dynamic (non-locked) notarizations.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key |
| `NodeUrl` | binary | IOTA node URL |
| `NotarizePkgId` | binary | Notarization package ObjectID |
| `ObjectId` | binary | The on-chain notarization object ID |
| `NewStateData` | binary | The new state data |

---

##### `destroy_notarization(SecretKey, NodeUrl, NotarizePkgId, ObjectId) -> {ok, binary()} | {error, binary()}`

Destroy a notarization from the ledger.

| Param | Type | Description |
|-------|------|-------------|
| `SecretKey` | binary | Ed25519 private key |
| `NodeUrl` | binary | IOTA node URL |
| `NotarizePkgId` | binary | Notarization package ObjectID |
| `ObjectId` | binary | The on-chain notarization object ID |

## Project Structure

```
iota_nif/
├── .env.example              # Environment variables template (copy to .env)
├── rebar.config              # rebar3 configuration with Rust build hooks
├── Cargo.toml                # Rust dependencies
├── include/
│   └── iota_nif.hrl          # Shared macros
├── src/
│   ├── iota_nif.app.src      # OTP application spec
│   ├── iota_nif.erl          # NIF loader (private)
│   ├── lib.rs                # Rust NIF entry point
│   ├── lib_did.rs            # Local DID operations (Rust)
│   ├── lib_ledger.rs         # Ledger publish/resolve/deactivate (Rust)
│   ├── lib_credential.rs     # Verifiable Credentials & Presentations (Rust)
│   ├── lib_notarization.rs   # Notarization local + ledger (Rust, uses official library)
│   ├── identity/
│   │   └── iota_did_nif.erl  # Public Erlang API for DID operations
│   ├── credential/
│   │   └── iota_credential_nif.erl  # Public Erlang API for VC/VP operations
│   └── notarization/
│       └── iota_notarization_nif.erl  # Public Erlang API for notarization
├── test/
│   ├── iota_did_nif_SUITE.erl
│   ├── iota_credential_nif_SUITE.erl
│   ├── iota_notarization_nif_SUITE.erl
│   ├── nif_resilience_SUITE.erl
│   └── iota_client_mock.erl
└── priv/
    └── libiota_nif.so         # Compiled NIF (after build)
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Erlang/Elixir  │────▶│   Rust NIF       │────▶│  IOTA Identity   │
│     Process     │     │   (rustler)      │     │  SDK v1.8.0-β2   │
└─────────────────┘     └──────────────────┘     └──────────────────┘
        │                       │                        │
        │                       │                        ▼
        │                       │                 ┌──────────────────┐
        │                       │                 │  IOTA Rebased    │
        │                       │                 │  Node (MoveVM)   │
        │                       ▼                 └──────────────────┘
        │                ┌──────────────────┐            ▲
        │                │  IOTA Notarize   │────────────┘
        │                │  Library v0.1    │
        │                └──────────────────┘
        │
        │  Erlang Modules:
        │  ├── iota_did_nif        → DID create/publish/resolve/deactivate
        │  ├── iota_credential_nif → VC create/verify, VP create/verify
        │  └── iota_notarization_nif → Notarize/hash/verify
        │
        │  Rust Modules:
        │  ├── lib_did             → Local DID generation
        │  ├── lib_ledger          → On-chain DID operations
        │  ├── lib_credential      → VC/VP signing & validation
        │  └── lib_notarization    → Notarization (local + on-chain)
```

## Running Tests

```bash
# Run all tests (local operations, mock, error handling, VC/VP)
rebar3 ct

# Run only specific suites
rebar3 ct --suite=iota_did_nif_SUITE
rebar3 ct --suite=iota_credential_nif_SUITE
rebar3 ct --suite=iota_notarization_nif_SUITE
rebar3 ct --suite=nif_resilience_SUITE

# Run ledger integration tests using .env variables
# (requires a funded IOTA_SECRET_KEY in .env — see .env.example)
export $(grep -v '^#' .env | xargs) && rebar3 ct --suite=iota_did_nif_SUITE --group=ledger_integration
export $(grep -v '^#' .env | xargs) && rebar3 ct --suite=iota_notarization_nif_SUITE --group=ledger_integration
```

## License

MIT
