%%%-------------------------------------------------------------------
%%% @doc IOTA Notarization NIF Module
%%%
%%% This module provides functions for notarizing data, both locally
%%% and on the IOTA Rebased ledger (MoveVM) using the official IOTA
%%% notarization library.
%%%
%%% <b>Local operations:</b> Create and verify notarization payloads
%%% without a network connection.
%%%
%%% <b>Ledger operations:</b> Create, read, update, and destroy
%%% notarization objects on-chain via the official IOTA notarization
%%% package. All external parameters (node URL, secret key, package ID)
%%% must be explicitly passed by the consuming application.
%%%
%%% All string parameters must be passed as binaries.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_notarization_nif).

%% API exports
-export([
    %% Local operations
    create_notarization_payload/2,
    verify_notarization_payload/1,
    hash_data/1,
    is_valid_hex_string/1,
    %% Ledger operations (IOTA Rebased / MoveVM — official notarization library)
    create_notarization/4,
    create_notarization/5,
    create_dynamic_notarization/4,
    create_dynamic_notarization/5,
    read_notarization/3,
    update_notarization_state/5,
    destroy_notarization/4
]).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Create a notarization payload for anchoring data on IOTA Tangle.
%%
%% Creates a payload containing the data hash, tag, and timestamp that
%% can be submitted to the IOTA Tangle as proof of existence.
%%
%% @param DataHash The SHA-256 hash of the data to notarize (hex string).
%% @param Tag A tag/label for the notarization (e.g., `<<"document-v1">>').
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`tag' - The tag used</li>
%%            <li>`data_hash' - The hash of the notarized data</li>
%%            <li>`timestamp' - Unix timestamp of notarization</li>
%%            <li>`payload_hex' - Hex-encoded payload ready for Tangle</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see hash_data/1
-spec create_notarization_payload(DataHash :: binary(), Tag :: binary()) ->
    {ok, binary()} | {error, binary()}.
create_notarization_payload(DataHash, Tag) ->
    iota_nif:create_notarization_payload(DataHash, Tag).

%% @doc Verify a notarization payload.
%%
%% Decodes and validates a notarization payload, extracting the
%% original tag, data hash, and timestamp.
%%
%% @param PayloadHex The hex-encoded payload from the Tangle.
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`is_valid' - Whether the payload format is valid</li>
%%            <li>`tag' - The extracted tag</li>
%%            <li>`data_hash' - The extracted data hash</li>
%%            <li>`timestamp' - The extracted timestamp</li>
%%          </ul>
%%          `{error, Reason}' on failure.
-spec verify_notarization_payload(PayloadHex :: binary()) ->
    {ok, binary()} | {error, binary()}.
verify_notarization_payload(PayloadHex) ->
    iota_nif:verify_notarization_payload(PayloadHex).

%% @doc Hash data using SHA-256.
%%
%% Computes the SHA-256 hash of the input data and returns it
%% as a hexadecimal string. Use this to create the data_hash
%% parameter for `create_notarization_payload/2'.
%%
%% @param Data The data to hash as a binary.
%% @returns The SHA-256 hash as a hex-encoded binary.
%%
%% Example:
%% ```
%% Hash = iota_notarization_nif:hash_data(<<"Hello, World!">>).
%% %% Returns: <<"dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f">>
%% '''
-spec hash_data(Data :: binary()) -> binary().
hash_data(Data) ->
    iota_nif:hash_data(Data).

%% @doc Check if a string is valid hexadecimal.
%%
%% @param Input The string to validate.
%% @returns `true' if valid hex, `false' otherwise.
-spec is_valid_hex_string(Input :: binary()) -> boolean().
is_valid_hex_string(Input) ->
    iota_nif:is_valid_hex_string(Input).

%%%===================================================================
%%% Ledger API Functions (IOTA Rebased / MoveVM — official notarization library)
%%%===================================================================

%% @doc Create a locked (immutable) notarization on the IOTA Rebased ledger.
%%
%% Creates a notarization whose state cannot be changed after creation.
%% This is the recommended mode for proof-of-existence use cases such as
%% notarizing document hashes.
%%
%% Uses the official IOTA notarization library (`NotarizationClient`).
%%
%% <b>Prerequisite:</b> The IOTA notarization Move package must be deployed
%% on the target network (it is natively available on mainnet/testnet).
%%
%% @param SecretKey Ed25519 private key in Bech32m (`iotaprivkey1...')
%%        or Base64 format. The key's address must hold gas coins.
%% @param NodeUrl URL of the IOTA node (e.g., `<<"http://127.0.0.1:9000">>').
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @param StateData The data to notarize (e.g., a document hash as a string).
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`object_id' - The on-chain notarization object ID</li>
%%            <li>`tx_digest' - Transaction digest</li>
%%            <li>`state_data' - The notarized data</li>
%%            <li>`description' - Immutable description (empty if not set)</li>
%%            <li>`method' - "locked"</li>
%%            <li>`sender_address' - Sender's IOTA address</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see create_notarization/5
%% @see read_notarization/3
-spec create_notarization(
    SecretKey :: binary(),
    NodeUrl :: binary(),
    NotarizePkgId :: binary(),
    StateData :: binary()
) -> {ok, binary()} | {error, binary()}.
create_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData) ->
    create_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData, <<>>).

%% @doc Create a locked notarization with an immutable description.
%%
%% Same as `create_notarization/4' but allows specifying a description
%% that is permanently attached to the notarization object.
%%
%% @param SecretKey Ed25519 private key (Bech32m or Base64).
%% @param NodeUrl URL of the IOTA node.
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @param StateData The data to notarize.
%% @param Description Immutable description label for the notarization.
%% @returns `{ok, JsonBinary}' | `{error, Reason}'
%% @see create_notarization/4
-spec create_notarization(
    SecretKey :: binary(),
    NodeUrl :: binary(),
    NotarizePkgId :: binary(),
    StateData :: binary(),
    Description :: binary()
) -> {ok, binary()} | {error, binary()}.
create_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData, Description) ->
    iota_nif:create_notarization(NodeUrl, SecretKey, NotarizePkgId, StateData, Description).

%% @doc Create a dynamic (updatable) notarization on the IOTA Rebased ledger.
%%
%% Creates a notarization whose state can be updated after creation via
%% `update_notarization_state/5'. Useful for tracking changing states
%% (e.g., document versions, status updates).
%%
%% @param SecretKey Ed25519 private key (Bech32m or Base64).
%% @param NodeUrl URL of the IOTA node.
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @param StateData The initial data to notarize.
%% @returns `{ok, JsonBinary}' | `{error, Reason}'
%% @see create_dynamic_notarization/5
%% @see update_notarization_state/5
-spec create_dynamic_notarization(
    SecretKey :: binary(),
    NodeUrl :: binary(),
    NotarizePkgId :: binary(),
    StateData :: binary()
) -> {ok, binary()} | {error, binary()}.
create_dynamic_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData) ->
    create_dynamic_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData, <<>>).

%% @doc Create a dynamic notarization with an immutable description.
%%
%% @param SecretKey Ed25519 private key (Bech32m or Base64).
%% @param NodeUrl URL of the IOTA node.
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @param StateData The initial data to notarize.
%% @param Description Immutable description label.
%% @returns `{ok, JsonBinary}' | `{error, Reason}'
-spec create_dynamic_notarization(
    SecretKey :: binary(),
    NodeUrl :: binary(),
    NotarizePkgId :: binary(),
    StateData :: binary(),
    Description :: binary()
) -> {ok, binary()} | {error, binary()}.
create_dynamic_notarization(SecretKey, NodeUrl, NotarizePkgId, StateData, Description) ->
    iota_nif:create_dynamic_notarization(NodeUrl, SecretKey, NotarizePkgId, StateData, Description).

%% @doc Read a notarization from the IOTA Rebased ledger.
%%
%% Retrieves the full state and metadata of a notarization by its object ID.
%% No signing key is required (read-only operation).
%%
%% @param NodeUrl URL of the IOTA node.
%% @param ObjectId The on-chain notarization object ID (hex string).
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`object_id' - The notarization object ID</li>
%%            <li>`state_data' - The current state data</li>
%%            <li>`state_metadata' - Optional state metadata</li>
%%            <li>`description' - Immutable description</li>
%%            <li>`method' - "Dynamic" or "Locked"</li>
%%            <li>`created_at' - Creation timestamp</li>
%%            <li>`last_state_change_at' - Last state change timestamp</li>
%%            <li>`state_version_count' - Number of state updates</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see create_notarization/4
-spec read_notarization(
    NodeUrl :: binary(),
    ObjectId :: binary(),
    NotarizePkgId :: binary()
) -> {ok, binary()} | {error, binary()}.
read_notarization(NodeUrl, ObjectId, NotarizePkgId) ->
    iota_nif:read_notarization(NodeUrl, ObjectId, NotarizePkgId).

%% @doc Update the state of a dynamic notarization.
%%
%% Only works for dynamic notarizations. Locked notarizations cannot
%% be updated and will return an error.
%%
%% @param SecretKey Ed25519 private key (Bech32m or Base64).
%% @param NodeUrl URL of the IOTA node.
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @param ObjectId The on-chain notarization object ID to update.
%% @param NewStateData The new state data string.
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`object_id' - The notarization object ID</li>
%%            <li>`tx_digest' - Transaction digest</li>
%%            <li>`new_state_data' - The updated state data</li>
%%            <li>`sender_address' - Sender's IOTA address</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see create_dynamic_notarization/4
-spec update_notarization_state(
    SecretKey :: binary(),
    NodeUrl :: binary(),
    NotarizePkgId :: binary(),
    ObjectId :: binary(),
    NewStateData :: binary()
) -> {ok, binary()} | {error, binary()}.
update_notarization_state(SecretKey, NodeUrl, NotarizePkgId, ObjectId, NewStateData) ->
    iota_nif:update_notarization_state(NodeUrl, SecretKey, NotarizePkgId, ObjectId, NewStateData).

%% @doc Destroy a notarization on the ledger.
%%
%% Permanently removes the notarization object from the ledger.
%%
%% @param SecretKey Ed25519 private key (Bech32m or Base64).
%% @param NodeUrl URL of the IOTA node.
%% @param NotarizePkgId ObjectID of the deployed notarization Move package.
%% @param ObjectId The on-chain notarization object ID to destroy.
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`object_id' - The destroyed notarization object ID</li>
%%            <li>`tx_digest' - Transaction digest</li>
%%            <li>`sender_address' - Sender's IOTA address</li>
%%          </ul>
%%          `{error, Reason}' on failure.
-spec destroy_notarization(
    SecretKey :: binary(),
    NodeUrl :: binary(),
    NotarizePkgId :: binary(),
    ObjectId :: binary()
) -> {ok, binary()} | {error, binary()}.
destroy_notarization(SecretKey, NodeUrl, NotarizePkgId, ObjectId) ->
    iota_nif:destroy_notarization(NodeUrl, SecretKey, NotarizePkgId, ObjectId).
