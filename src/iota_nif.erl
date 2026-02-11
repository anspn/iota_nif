%%%-------------------------------------------------------------------
%%% @doc IOTA NIF Loader
%%%
%%% This module loads the shared NIF library and provides access to
%%% all NIF functions. Domain-specific modules delegate to this module.
%%%
%%% @private
%%% @end
%%%-------------------------------------------------------------------
-module(iota_nif).

-include("iota_nif.hrl").

%% API exports - all NIF functions
-export([
    %% Identity NIFs
    generate_did/1,
    extract_did_from_document/1,
    create_did_url/2,
    is_valid_iota_did/1,
    %% Ledger NIFs (IOTA Rebased / MoveVM)
    create_and_publish_did/4,
    resolve_did/3,
    %% Notarization NIFs
    create_notarization_payload/2,
    verify_notarization_payload/1,
    hash_data/1,
    is_valid_hex_string/1
]).

%% NIF loading
-on_load(init/0).

-define(LIBNAME, libiota_nif).

%%%===================================================================
%%% NIF Loading
%%%===================================================================

%% @private
init() ->
    PrivDir = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            EbinDir = filename:dirname(code:which(?MODULE)),
            filename:join(filename:dirname(EbinDir), "priv");
        Dir ->
            Dir
    end,
    SoName = filename:join(PrivDir, atom_to_list(?LIBNAME)),
    erlang:load_nif(SoName, 0).

%%%===================================================================
%%% Identity NIFs
%%%===================================================================

%% @private
-spec generate_did(binary()) -> {ok, binary()} | {error, binary()}.
generate_did(_Network) ->
    erlang:nif_error(nif_not_loaded).

%% @private
-spec extract_did_from_document(binary()) -> {ok, binary()} | {error, binary()}.
extract_did_from_document(_DocumentJson) ->
    erlang:nif_error(nif_not_loaded).

%% @private
-spec create_did_url(binary(), binary()) -> {ok, binary()} | {error, binary()}.
create_did_url(_Did, _Fragment) ->
    erlang:nif_error(nif_not_loaded).

%% @private
-spec is_valid_iota_did(binary()) -> boolean().
is_valid_iota_did(_Did) ->
    erlang:nif_error(nif_not_loaded).

%%%===================================================================
%%% Ledger NIFs (IOTA Rebased / MoveVM)
%%%===================================================================

%% @private
%% @doc Create and publish a DID using an Ed25519 secret key.
%% GasCoinId can be an empty binary for automatic gas coin selection.
%% IdentityPkgId can be an empty binary for auto-discovery on known networks.
-spec create_and_publish_did(binary(), binary(), binary(), binary()) -> {ok, binary()} | {error, binary()}.
create_and_publish_did(_NodeUrl, _SecretKey, _GasCoinId, _IdentityPkgId) ->
    erlang:nif_error(nif_not_loaded).

%% @private
%% IdentityPkgId can be an empty binary for auto-discovery on known networks.
-spec resolve_did(binary(), binary(), binary()) -> {ok, binary()} | {error, binary()}.
resolve_did(_NodeUrl, _Did, _IdentityPkgId) ->
    erlang:nif_error(nif_not_loaded).

%%%===================================================================
%%% Notarization NIFs
%%%===================================================================

%% @private
-spec create_notarization_payload(binary(), binary()) -> {ok, binary()} | {error, binary()}.
create_notarization_payload(_DataHash, _Tag) ->
    erlang:nif_error(nif_not_loaded).

%% @private
-spec verify_notarization_payload(binary()) -> {ok, binary()} | {error, binary()}.
verify_notarization_payload(_PayloadHex) ->
    erlang:nif_error(nif_not_loaded).

%% @private
-spec hash_data(binary()) -> binary().
hash_data(_Data) ->
    erlang:nif_error(nif_not_loaded).

%% @private
-spec is_valid_hex_string(binary()) -> boolean().
is_valid_hex_string(_Input) ->
    erlang:nif_error(nif_not_loaded).
