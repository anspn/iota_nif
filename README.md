# IOTA DID NIF for Erlang

A Rust NIF (Native Implemented Function) library that provides IOTA DID (Decentralized Identifier) generation for Erlang/Elixir projects. Designed for publishing DIDs on the **IOTA mainnet**.

## Features

- Generate new IOTA DID documents with Ed25519 verification methods
- Extract DID from document JSON
- Create DID URLs with fragments
- Validate IOTA DID format
- Ready to use as a rebar3 dependency

## Prerequisites

- Rust (1.70+)
- Erlang/OTP (24+)
- rebar3

## Installation as rebar3 Dependency

Add to your `rebar.config`:

```erlang
{deps, [
    {iota_did_nif, {git, "https://github.com/anspn/iota_nif.git", {branch, "main"}}}
]}.
```

Then run:

```bash
rebar3 compile
```

The Rust NIF will be automatically compiled during the build process.

## Manual Build

```bash
# Clone and build
git clone https://github.com/anspn/iota_nif.git
cd iota_nif
rebar3 compile

# Or use the build script
chmod +x build.sh
./build.sh
```

## Usage in Erlang

**Note:** All string parameters must be passed as binaries (`<<"...">>`)

```erlang
%% Generate a new DID for IOTA mainnet (default)
{ok, ResultJson} = iota_did_nif:generate_did().

%% Or specify network explicitly
{ok, ResultJson} = iota_did_nif:generate_did(<<"iota">>).

%% The result is a JSON binary containing:
%% - did: The DID string (placeholder until published to network)
%% - document: The full DID document as JSON
%% - verification_method_fragment: The fragment ID of the generated key

%% Parse the JSON result (requires jsx or jiffy library)
%% Result = jsx:decode(ResultJson, [return_maps]).

%% Extract DID from a document
{ok, Did} = iota_did_nif:extract_did_from_document(<<"{\"id\": \"did:iota:0x123\"}">>).

%% Create a DID URL
DidUrl = iota_did_nif:create_did_url(<<"did:iota:0x123">>, <<"key-1">>).
%% Returns: <<"did:iota:0x123#key-1">>

%% Validate a DID
true = iota_did_nif:is_valid_iota_did(<<"did:iota:0x123456">>).
false = iota_did_nif:is_valid_iota_did(<<"invalid">>).
```

## Usage in Elixir

```elixir
# Add to your mix.exs dependencies
{:iota_did_nif, git: "https://github.com/anspn/iota_nif.git"}

# Generate a DID for IOTA mainnet
{:ok, result_json} = :iota_did_nif.generate_did()
result = Jason.decode!(result_json)

# Access the DID components
did = result["did"]
document = result["document"]
fragment = result["verification_method_fragment"]
```

## Network Names

| Network | Name | Description |
|---------|------|-------------|
| IOTA Mainnet | `<<"iota">>` | **Default** - Production network |
| IOTA Testnet | `<<"atoi">>` | IOTA test network |
| Shimmer | `<<"smr">>` | Shimmer mainnet |
| Shimmer Testnet | `<<"rms">>` | Shimmer test network |

## Understanding the DID Document

The generated DID document follows the W3C DID specification. Example output for IOTA mainnet:

```json
{
  "did": "did:iota:0x000...",
  "document": {
    "doc": {
      "id": "did:iota:0x000...",
      "verificationMethod": [{
        "id": "did:iota:0x000...#fragmentId",
        "controller": "did:iota:0x000...",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "OKP",
          "alg": "EdDSA",
          "crv": "Ed25519",
          "x": "base64-encoded-public-key"
        }
      }]
    },
    "meta": {
      "created": "2026-01-30T15:00:00Z",
      "updated": "2026-01-30T15:00:00Z"
    }
  },
  "verification_method_fragment": "fragmentId"
}
```

**Note:** The DID contains placeholder zeros (`0x000...`) until published to the IOTA network. Publishing requires an IOTA client connection and funds for the transaction.

## Project Structure

```
iota_nif/
├── rebar.config          # rebar3 configuration with Rust build hooks
├── Cargo.toml            # Rust dependencies
├── src/
│   ├── iota_did_nif.app.src   # OTP application spec
│   ├── iota_did_nif.erl       # Erlang NIF module
│   └── lib.rs                  # Rust NIF implementation
├── priv/
│   └── libiota_nif.so         # Compiled NIF (after build)
└── _build/                     # rebar3 build output
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Erlang/Elixir  │────▶│   Rust NIF       │────▶│  IOTA Identity  │
│     Process     │     │   (rustler)      │     │     SDK 1.5     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## License

MIT
