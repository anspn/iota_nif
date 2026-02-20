%%%-------------------------------------------------------------------
%%% @doc IOTA DID NIF Module (Rebased / MoveVM)
%%%
%%% This module provides functions for generating, publishing, and
%%% resolving IOTA Decentralized Identifiers (DIDs) on the IOTA
%%% Rebased network (MoveVM-based).
%%%
%%% This is a library module — all parameters (node URL, secret key,
%%% identity package ID, etc.) must be passed explicitly by the
%%% consuming application. No secrets are read from environment
%%% variables or application configuration.
%%%
%%% All string parameters must be passed as binaries.
%%%
%%% == Key Formats ==
%%%
%%% Ed25519 secret keys are accepted in three formats:
%%% <ul>
%%%   <li><b>Bech32</b> (`iotaprivkey1...'): Native IOTA CLI format from
%%%       `iota keytool export --key-identity <address>'</li>
%%%   <li><b>Base64</b> (33 bytes): IOTA keystore format (0x00 prefix + key)</li>
%%%   <li><b>Base64</b> (32 bytes): Raw Ed25519 private key</li>
%%% </ul>
%%%
%%% == Ledger Parameters ==
%%%
%%% For ledger operations, the consuming application must provide:
%%% <ul>
%%%   <li>`NodeUrl' - URL of the IOTA Rebased node
%%%       (e.g., `<<"http://127.0.0.1:9000">>')</li>
%%%   <li>`SecretKey' - Ed25519 private key for transaction signing</li>
%%%   <li>`IdentityPkgId' - ObjectID of the deployed `iota_identity'
%%%       Move package. Required for local/unofficial networks.
%%%       Pass `<<>>' for auto-discovery on official networks.</li>
%%%   <li>`GasCoinId' - (Optional) ObjectID of a specific gas coin.
%%%       Pass `<<>>' for automatic selection.</li>
%%% </ul>
%%% @end
%%%-------------------------------------------------------------------
-module(iota_did_nif).

-include("iota_nif.hrl").

%% API exports
-export([
    %% Local DID operations (no network required)
    generate_did/0,
    generate_did/1,
    extract_did_from_document/1,
    create_did_url/2,
    is_valid_iota_did/1,
    %% Ledger operations (IOTA Rebased)
    create_and_publish_did/3,
    create_and_publish_did/4,
    deactivate_did/3,
    deactivate_did/4,
    resolve_did/2,
    resolve_did/3
]).

%%%===================================================================
%%% API Functions - Local DID Operations
%%%===================================================================

%% @doc Generate a new IOTA DID for the IOTA mainnet (default).
%%
%% Equivalent to calling `generate_did(<<"iota">>)'.
%%
%% NOTE: The generated DID has an all-zeros tag (0x0000...0000) because
%% it has not been published to the ledger yet. The real DID tag is
%% assigned upon publishing. Use `create_and_publish_did/0,2' to get a
%% DID with a real, unique tag.
%%
%% @returns `{ok, JsonBinary}' on success where JsonBinary contains the DID,
%%          document, and verification_method_fragment as JSON.
%%          `{error, Reason}' on failure.
%% @see generate_did/1
%% @see create_and_publish_did/0
-spec generate_did() -> {ok, binary()} | {error, binary()}.
generate_did() ->
    generate_did(<<"iota">>).

%% @doc Generate a new IOTA DID for the specified network.
%%
%% Creates a new DID document with an Ed25519 verification method.
%% The DID is created locally and has NOT been published to the ledger.
%%
%% @param Network The network identifier as a binary:
%%        <ul>
%%          <li>`<<"iota">>' - IOTA mainnet</li>
%%          <li>`<<"smr">>' - Shimmer mainnet</li>
%%          <li>`<<"rms">>' - Shimmer testnet</li>
%%          <li>`<<"atoi">>' - IOTA testnet</li>
%%        </ul>
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`did' - The DID string (placeholder with zero tag)</li>
%%            <li>`document' - The full DID document as JSON</li>
%%            <li>`verification_method_fragment' - The fragment ID of the generated key</li>
%%          </ul>
%%          `{error, Reason}' on failure.
-spec generate_did(Network :: binary()) -> {ok, binary()} | {error, binary()}.
generate_did(Network) ->
    iota_nif:generate_did(Network).

%% @doc Extract the DID string from a DID document JSON.
%%
%% Parses the JSON document and extracts the `id' field.
%%
%% @param DocumentJson A binary containing the DID document as JSON.
%% @returns `{ok, Did}' where Did is the extracted DID string,
%%          or `{error, Reason}' if parsing fails or no `id' field exists.
-spec extract_did_from_document(DocumentJson :: binary()) -> {ok, binary()} | {error, binary()}.
extract_did_from_document(DocumentJson) ->
    iota_nif:extract_did_from_document(DocumentJson).

%% @doc Create a DID URL by combining a DID with a fragment.
%%
%% @param Did The base DID string as a binary.
%% @param Fragment The fragment identifier as a binary (without the `#').
%% @returns `{ok, Url}' where Url is the complete DID URL binary,
%%          or `{error, Reason}' if inputs are invalid.
%%
%% Example:
%% ```
%% {ok, <<"did:iota:rms:0x123#key-1">>} = iota_did_nif:create_did_url(
%%     <<"did:iota:rms:0x123">>,
%%     <<"key-1">>).
%% '''
-spec create_did_url(Did :: binary(), Fragment :: binary()) -> 
    {ok, binary()} | {error, binary()}.
create_did_url(Did, Fragment) ->
    iota_nif:create_did_url(Did, Fragment).

%% @doc Check if a string is a valid IOTA DID format.
%%
%% Validates that the DID follows the IOTA DID method specification.
%% Valid formats:
%% <ul>
%%   <li>`did:iota:0x...' - IOTA mainnet (3 parts)</li>
%%   <li>`did:iota:smr:0x...' - Other networks (4 parts)</li>
%% </ul>
%%
%% @param Did The DID string to validate as a binary.
%% @returns `true' if valid, `false' otherwise.
-spec is_valid_iota_did(Did :: binary()) -> boolean().
is_valid_iota_did(Did) ->
    iota_nif:is_valid_iota_did(Did).

%%%===================================================================
%%% API Functions - Ledger Operations (IOTA Rebased)
%%%===================================================================

%% @doc Create and publish a new DID to the IOTA Rebased ledger.
%%
%% This function:
%% <ol>
%%   <li>Connects to the IOTA Rebased node at `NodeUrl'</li>
%%   <li>Uses the provided Ed25519 secret key for signing</li>
%%   <li>Creates a DID document with an Ed25519 verification method</li>
%%   <li>Publishes the document on-chain via MoveVM transaction</li>
%% </ol>
%%
%% The resulting DID has a real, unique tag derived from the on-chain
%% object — unlike `generate_did/0,1' which produces a placeholder.
%%
%% The address derived from `SecretKey' must have gas coins. Use
%% `iota client faucet' to obtain gas on testnets/local networks.
%%
%% Automatic gas coin selection is used. Pass `<<>>' as
%% `IdentityPkgId' for auto-discovery on official networks.
%%
%% @param SecretKey Ed25519 private key (Bech32, Base64 33-byte, or
%%        Base64 32-byte format).
%% @param NodeUrl URL of the IOTA node (e.g., `<<"http://127.0.0.1:9000">>').
%% @param IdentityPkgId ObjectID of the deployed `iota_identity' Move
%%        package (e.g., `<<"0xd34e...">>'). Pass `<<>>' for auto-discovery.
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`did' - The published DID string</li>
%%            <li>`document' - The full DID document as JSON</li>
%%            <li>`verification_method_fragment' - The fragment ID</li>
%%            <li>`network' - The network name</li>
%%            <li>`sender_address' - The address that published the DID</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see create_and_publish_did/4
-spec create_and_publish_did(
    SecretKey :: binary(), NodeUrl :: binary(), IdentityPkgId :: binary()
) ->
    {ok, binary()} | {error, binary()}.
create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId) ->
    create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId, <<>>).

%% @doc Create and publish a new DID with explicit gas coin selection.
%%
%% Same as `create_and_publish_did/3' but allows specifying a gas coin
%% ObjectID instead of automatic selection.
%%
%% @param SecretKey Ed25519 private key.
%% @param NodeUrl URL of the IOTA node.
%% @param IdentityPkgId ObjectID of the identity Move package, or `<<>>'.
%% @param GasCoinId Hex ObjectID of gas coin to use (e.g.,
%%        `<<"0xabc123...">>'). Pass `<<>>' for automatic gas coin selection.
%% @returns `{ok, JsonBinary}' on success, `{error, Reason}' on failure.
-spec create_and_publish_did(
    SecretKey :: binary(), NodeUrl :: binary(),
    IdentityPkgId :: binary(), GasCoinId :: binary()
) ->
    {ok, binary()} | {error, binary()}.
create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId, GasCoinId) ->
    iota_nif:create_and_publish_did(NodeUrl, SecretKey, GasCoinId, IdentityPkgId).

%% @doc Deactivate (revoke) a DID on the IOTA Rebased ledger.
%%
%% Permanently deactivates the DID document on-chain. After deactivation,
%% the DID can no longer be resolved to an active document. The caller
%% must be a controller of the DID's on-chain identity.
%%
%% <b>Warning</b>: This operation is irreversible. Once deactivated, the
%% DID cannot be reactivated.
%%
%% Pass `<<>>' as `IdentityPkgId' for auto-discovery on official networks.
%%
%% @param SecretKey Ed25519 private key of a controller (Bech32, Base64
%%        33-byte, or Base64 32-byte format).
%% @param Did The DID to deactivate (e.g., `<<"did:iota:0xabc...">>'').
%% @param NodeUrl URL of the IOTA node.
%% @returns `{ok, <<"deactivated">>}' on success,
%%          `{error, Reason}' on failure.
%% @see deactivate_did/4
-spec deactivate_did(
    SecretKey :: binary(), Did :: binary(), NodeUrl :: binary()
) ->
    {ok, binary()} | {error, binary()}.
deactivate_did(SecretKey, Did, NodeUrl) ->
    deactivate_did(SecretKey, Did, NodeUrl, <<>>).

%% @doc Deactivate (revoke) a DID with explicit identity package ID.
%%
%% Same as `deactivate_did/3' but allows specifying the identity package ID
%% for local/unofficial networks.
%%
%% @param SecretKey Ed25519 private key of a controller.
%% @param Did The DID to deactivate.
%% @param NodeUrl URL of the IOTA node.
%% @param IdentityPkgId ObjectID of the identity Move package, or `<<>>'
%%        for auto-discovery.
%% @returns `{ok, <<"deactivated">>}' on success, `{error, Reason}' on failure.
-spec deactivate_did(
    SecretKey :: binary(), Did :: binary(),
    NodeUrl :: binary(), IdentityPkgId :: binary()
) ->
    {ok, binary()} | {error, binary()}.
deactivate_did(SecretKey, Did, NodeUrl, IdentityPkgId) ->
    iota_nif:deactivate_did(NodeUrl, SecretKey, Did, IdentityPkgId).

%% @doc Resolve a DID from the IOTA ledger.
%%
%% Connects to the specified IOTA node and retrieves the DID document.
%% No signing key is required for resolution.
%%
%% @param Did The DID to resolve (e.g., `<<"did:iota:0xabc...">>'').
%% @param NodeUrl URL of the IOTA node to query.
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`did' - The resolved DID string</li>
%%            <li>`document' - The full DID document as JSON</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see resolve_did/3
-spec resolve_did(Did :: binary(), NodeUrl :: binary()) ->
    {ok, binary()} | {error, binary()}.
resolve_did(Did, NodeUrl) ->
    resolve_did(Did, NodeUrl, <<>>).

%% @doc Resolve a DID from the IOTA ledger with explicit package ID.
%%
%% @param Did The DID to resolve.
%% @param NodeUrl URL of the IOTA node to query.
%% @param IdentityPkgId ObjectID of the identity Move package, or `<<>>'
%%        for auto-discovery.
%% @returns `{ok, JsonBinary}' on success, `{error, Reason}' on failure.
-spec resolve_did(Did :: binary(), NodeUrl :: binary(), IdentityPkgId :: binary()) ->
    {ok, binary()} | {error, binary()}.
resolve_did(Did, NodeUrl, IdentityPkgId) ->
    iota_nif:resolve_did(NodeUrl, Did, IdentityPkgId).

