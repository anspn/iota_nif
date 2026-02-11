# IOTA DID NIF for Erlang

A Rust NIF (Native Implemented Function) library that provides IOTA DID (Decentralized Identifier) operations for Erlang/Elixir projects. Supports the **IOTA Rebased** network (MoveVM-based).

## Features

- **Local DID operations**: Generate DID documents, extract DIDs, create DID URLs, validate DIDs
- **Ledger publishing**: Publish DID documents on-chain via IOTA Rebased MoveVM transactions
- **DID resolution**: Resolve published DIDs from the IOTA ledger
- **Notarization**: Hash and notarize data payloads
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

### 2. Set up IOTA CLI (for ledger operations)

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

### 3. Publish a DID

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
```

## API Reference

### DID Operations (local, no network)

| Function | Description |
|----------|-------------|
| `generate_did()` | Generate DID with default network |
| `generate_did(Network)` | Generate DID for specific network |
| `extract_did_from_document(DocJson)` | Extract DID from JSON document |
| `create_did_url(Did, Fragment)` | Create DID URL with fragment |
| `is_valid_iota_did(Did)` | Validate DID format |

### Ledger Operations (require IOTA node)

| Function | Description |
|----------|-------------|
| `create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId)` | Publish DID (auto gas coin) |
| `create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId, GasCoinId)` | Publish DID with specific gas coin |
| `resolve_did(Did, NodeUrl)` | Resolve a published DID |
| `resolve_did(Did, NodeUrl, IdentityPkgId)` | Resolve with explicit package ID |

## Project Structure

```
iota_nif/
├── rebar.config              # rebar3 configuration with Rust build hooks
├── Cargo.toml                # Rust dependencies
├── include/
│   └── iota_nif.hrl          # Shared macros
├── src/
│   ├── iota_nif.app.src      # OTP application spec
│   ├── iota_nif.erl          # NIF loader (private)
│   ├── lib.rs                # Rust NIF entry point
│   ├── lib_did.rs            # Local DID operations (Rust)
│   ├── lib_ledger.rs         # Ledger publish/resolve (Rust)
│   ├── lib_notarization.rs   # Notarization (Rust)
│   └── identity/
│       └── iota_did_nif.erl  # Public Erlang API for DID operations
├── test/
│   ├── iota_did_nif_SUITE.erl
│   ├── iota_notarization_nif_SUITE.erl
│   └── nif_resilience_SUITE.erl
└── priv/
    └── libiota_nif.so         # Compiled NIF (after build)
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Erlang/Elixir  │────▶│   Rust NIF       │────▶│  IOTA Identity   │
│     Process     │     │   (rustler)      │     │  SDK v1.8.0-β2   │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                                         │
                                                         ▼
                                                  ┌──────────────────┐
                                                  │  IOTA Rebased    │
                                                  │  Node (MoveVM)   │
                                                  └──────────────────┘
```

## Running Tests

```bash
# Run all tests (local operations, mock, error handling)
rebar3 ct

# Run only specific suite
rebar3 ct --suite=iota_did_nif_SUITE

# Run integration tests against a local IOTA node
# Required environment variables:
#   IOTA_TEST_SECRET_KEY   - Ed25519 private key (Bech32 or Base64)
#   IOTA_IDENTITY_PKG_ID   - ObjectID of the iota_identity Move package
# Optional:
#   IOTA_TEST_GAS_COIN_ID  - Specific gas coin ObjectID (auto-selected if omitted)
#   IOTA_TEST_NODE_URL     - Node URL (defaults to http://127.0.0.1:9000)
IOTA_TEST_SECRET_KEY="iotaprivkey1qz..." \
IOTA_IDENTITY_PKG_ID="0x..." \
rebar3 ct --suite=iota_did_nif_SUITE --group=ledger_integration
```

## License

MIT
