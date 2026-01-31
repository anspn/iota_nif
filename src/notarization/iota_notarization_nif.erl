%%%-------------------------------------------------------------------
%%% @doc IOTA Notarization NIF Module
%%%
%%% This module provides functions for notarizing data on the IOTA Tangle.
%%%
%%% Notarization creates a timestamped proof that specific data existed
%%% at a certain point in time by anchoring its hash on the Tangle.
%%%
%%% All string parameters must be passed as binaries.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_notarization_nif).

%% API exports
-export([
    create_notarization_payload/2,
    verify_notarization_payload/1,
    hash_data/1,
    is_valid_hex_string/1
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
