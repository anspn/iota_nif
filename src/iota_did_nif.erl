%%%-------------------------------------------------------------------
%%% @doc IOTA DID NIF Module
%%%
%%% This module provides Native Implemented Functions (NIFs) for
%%% generating and manipulating IOTA Decentralized Identifiers (DIDs).
%%%
%%% All string parameters must be passed as binaries.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_did_nif).

%% API exports
-export([
    generate_did/0,
    generate_did/1,
    extract_did_from_document/1,
    create_did_url/2,
    is_valid_iota_did/1
]).

%% NIF loading
-on_load(init/0).

-define(APPNAME, iota_did_nif).
-define(LIBNAME, libiota_nif).

%%%===================================================================
%%% NIF Loading
%%%===================================================================

%% @private
%% @doc Load the NIF library.
init() ->
    PrivDir = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            %% Application not started yet, find priv relative to beam file
            EbinDir = filename:dirname(code:which(?MODULE)),
            filename:join(filename:dirname(EbinDir), "priv");
        Dir ->
            Dir
    end,
    SoName = filename:join(PrivDir, atom_to_list(?LIBNAME)),
    erlang:load_nif(SoName, 0).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Generate a new IOTA DID for the IOTA mainnet (default).
%%
%% Equivalent to calling `generate_did(<<"iota">>)'.
%%
%% @returns `{ok, JsonBinary}' on success where JsonBinary contains the DID,
%%          document, and verification_method_fragment as JSON.
%%          `{error, Reason}' on failure.
%% @see generate_did/1
-spec generate_did() -> {ok, binary()} | {error, binary()}.
generate_did() ->
    generate_did(<<"iota">>).

%% @doc Generate a new IOTA DID for the specified network.
%%
%% Creates a new DID document with an Ed25519 verification method.
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
%%            <li>`did' - The DID string</li>
%%            <li>`document' - The full DID document as JSON</li>
%%            <li>`verification_method_fragment' - The fragment ID of the generated key</li>
%%          </ul>
%%          `{error, Reason}' on failure.
-spec generate_did(Network :: binary()) -> {ok, binary()} | {error, binary()}.
generate_did(_Network) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Extract the DID string from a DID document JSON.
%%
%% Parses the JSON document and extracts the `id' field.
%%
%% @param DocumentJson A binary containing the DID document as JSON.
%% @returns `{ok, Did}' where Did is the extracted DID string,
%%          or `{error, Reason}' if parsing fails or no `id' field exists.
-spec extract_did_from_document(DocumentJson :: binary()) -> {ok, binary()} | {error, binary()}.
extract_did_from_document(_DocumentJson) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Create a DID URL by combining a DID with a fragment.
%%
%% @param Did The base DID string as a binary.
%% @param Fragment The fragment identifier as a binary (without the `#').
%% @returns A binary containing the complete DID URL.
%%
%% Example:
%% ```
%% <<"did:iota:rms:0x123#key-1">> = iota_did_nif:create_did_url(
%%     <<"did:iota:rms:0x123">>,
%%     <<"key-1">>).
%% '''
-spec create_did_url(Did :: binary(), Fragment :: binary()) -> binary().
create_did_url(_Did, _Fragment) ->
    erlang:nif_error(nif_not_loaded).

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
is_valid_iota_did(_Did) ->
    erlang:nif_error(nif_not_loaded).

%%%===================================================================
%%% Internal Functions
%%%===================================================================
