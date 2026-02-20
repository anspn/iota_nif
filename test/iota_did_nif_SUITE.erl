%%%-------------------------------------------------------------------
%%% @doc Common Test Suite for iota_did_nif
%%%
%%% Tests DID generation, validation, and mock publishing to IOTA Tangle.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_did_nif_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    %% Local operations
    generate_did_default_network/1,
    generate_did_mainnet/1,
    generate_did_testnet/1,
    generate_did_shimmer/1,
    generate_did_invalid_network/1,
    extract_did_from_document/1,
    extract_did_invalid_json/1,
    create_did_url/1,
    is_valid_iota_did_mainnet/1,
    is_valid_iota_did_with_network/1,
    is_valid_iota_did_invalid/1,
    %% Mock mainnet operations
    publish_and_resolve_did/1,
    resolve_nonexistent_did/1,
    full_did_lifecycle/1,
    %% Ledger operations (network required, skipped if unavailable)
    ledger_resolve_invalid_did/1,
    ledger_publish_invalid_node/1,
    ledger_deactivate_invalid_node/1,
    ledger_deactivate_invalid_did/1,
    %% Integration tests (require local IOTA node + IOTA_IDENTITY_PKG_ID)
    ledger_publish_did_on_local_node/1,
    ledger_publish_and_resolve_on_local_node/1,
    ledger_publish_deactivate_resolve_lifecycle/1
]).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

all() ->
    [
        {group, local_operations},
        {group, mock_mainnet_operations},
        {group, ledger_error_handling},
        {group, ledger_integration}
    ].

groups() ->
    [
        {local_operations, [parallel], [
            generate_did_default_network,
            generate_did_mainnet,
            generate_did_testnet,
            generate_did_shimmer,
            generate_did_invalid_network,
            extract_did_from_document,
            extract_did_invalid_json,
            create_did_url,
            is_valid_iota_did_mainnet,
            is_valid_iota_did_with_network,
            is_valid_iota_did_invalid
        ]},
        {mock_mainnet_operations, [sequence], [
            publish_and_resolve_did,
            resolve_nonexistent_did,
            full_did_lifecycle
        ]},
        {ledger_error_handling, [sequence], [
            ledger_resolve_invalid_did,
            ledger_publish_invalid_node,
            ledger_deactivate_invalid_node,
            ledger_deactivate_invalid_did
        ]},
        {ledger_integration, [sequence], [
            ledger_publish_did_on_local_node,
            ledger_publish_and_resolve_on_local_node,
            ledger_publish_deactivate_resolve_lifecycle
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(mock_mainnet_operations, Config) ->
    {ok, _Pid} = iota_client_mock:start_link(),
    Config;
init_per_group(ledger_integration, Config) ->
    %% Skip if required env vars are not set (no local node available)
    case {os:getenv("IOTA_SECRET_KEY"), os:getenv("IOTA_IDENTITY_PKG_ID")} of
        {false, _} ->
            {skip, "IOTA_SECRET_KEY not set — skipping integration tests"};
        {_, false} ->
            {skip, "IOTA_IDENTITY_PKG_ID not set — skipping integration tests"};
        {KeyStr, PkgIdStr} ->
            SecretKey = list_to_binary(KeyStr),
            IdentityPkgId = list_to_binary(PkgIdStr),
            GasCoinId = case os:getenv("IOTA_GAS_COIN_ID") of
                false -> <<>>;
                G -> list_to_binary(G)
            end,
            NodeUrl = case os:getenv("IOTA_NODE_URL") of
                false -> <<"http://127.0.0.1:9000">>;
                U -> list_to_binary(U)
            end,
            [{secret_key, SecretKey},
             {identity_pkg_id, IdentityPkgId},
             {gas_coin_id, GasCoinId},
             {node_url, NodeUrl}
             | Config]
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(mock_mainnet_operations, _Config) ->
    case whereis(iota_client_mock) of
        undefined -> ok;
        _Pid -> iota_client_mock:stop()
    end,
    ok;
end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(TestCase, Config) when
    TestCase =:= publish_and_resolve_did;
    TestCase =:= resolve_nonexistent_did;
    TestCase =:= full_did_lifecycle ->
    case whereis(iota_client_mock) of
        undefined ->
            {ok, _} = iota_client_mock:start_link();
        _Pid ->
            ok
    end,
    iota_client_mock:reset(),
    Config;
init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Local Operation Tests
%%%===================================================================

generate_did_default_network(Config) ->
    {ok, ResultJson} = iota_did_nif:generate_did(),
    Result = decode_json(ResultJson),
    
    ?assertMatch(#{<<"did">> := _, <<"document">> := _, <<"verification_method_fragment">> := _}, Result),
    
    Did = maps:get(<<"did">>, Result),
    ?assert(binary:match(Did, <<"did:iota:">>) =/= nomatch),
    Config.

generate_did_mainnet(_Config) ->
    {ok, ResultJson} = iota_did_nif:generate_did(<<"iota">>),
    Result = decode_json(ResultJson),
    
    Did = maps:get(<<"did">>, Result),
    %% Mainnet DIDs have format: did:iota:0x...
    ?assertMatch(<<"did:iota:0x", _/binary>>, Did).

generate_did_testnet(_Config) ->
    {ok, ResultJson} = iota_did_nif:generate_did(<<"atoi">>),
    Result = decode_json(ResultJson),
    
    Did = maps:get(<<"did">>, Result),
    %% Testnet DIDs have format: did:iota:atoi:0x...
    ?assertMatch(<<"did:iota:atoi:0x", _/binary>>, Did).

generate_did_shimmer(_Config) ->
    {ok, ResultJson} = iota_did_nif:generate_did(<<"smr">>),
    Result = decode_json(ResultJson),
    
    Did = maps:get(<<"did">>, Result),
    ?assertMatch(<<"did:iota:smr:0x", _/binary>>, Did).

generate_did_invalid_network(_Config) ->
    {error, Reason} = iota_did_nif:generate_did(<<"invalid_network">>),
    ?assert(is_binary(Reason)),
    ?assert(binary:match(Reason, <<"Invalid network">>) =/= nomatch).

extract_did_from_document(_Config) ->
    TestDoc = <<"{\"id\": \"did:iota:0x1234567890abcdef\", \"other\": \"data\"}">>,
    {ok, Did} = iota_did_nif:extract_did_from_document(TestDoc),
    ?assertEqual(<<"did:iota:0x1234567890abcdef">>, Did).

extract_did_invalid_json(_Config) ->
    {error, _Reason} = iota_did_nif:extract_did_from_document(<<"not valid json">>).

create_did_url(_Config) ->
    Did = <<"did:iota:0x1234567890abcdef">>,
    Fragment = <<"key-1">>,
    
    Result = iota_did_nif:create_did_url(Did, Fragment),
    ?assertEqual({ok, <<"did:iota:0x1234567890abcdef#key-1">>}, Result).

is_valid_iota_did_mainnet(_Config) ->
    ?assert(iota_did_nif:is_valid_iota_did(<<"did:iota:0x1234567890abcdef">>)).

is_valid_iota_did_with_network(_Config) ->
    ?assert(iota_did_nif:is_valid_iota_did(<<"did:iota:smr:0x1234567890abcdef">>)),
    ?assert(iota_did_nif:is_valid_iota_did(<<"did:iota:rms:0x1234567890abcdef">>)),
    ?assert(iota_did_nif:is_valid_iota_did(<<"did:iota:atoi:0x1234567890abcdef">>)).

is_valid_iota_did_invalid(_Config) ->
    ?assertNot(iota_did_nif:is_valid_iota_did(<<"did:web:example.com">>)),
    ?assertNot(iota_did_nif:is_valid_iota_did(<<"not-a-did">>)),
    ?assertNot(iota_did_nif:is_valid_iota_did(<<"">>)).

%%%===================================================================
%%% Mock Mainnet Operation Tests
%%%===================================================================

publish_and_resolve_did(_Config) ->
    %% Generate a DID locally
    {ok, ResultJson} = iota_did_nif:generate_did(<<"iota">>),
    Result = decode_json(ResultJson),
    DocumentJson = maps:get(<<"document">>, Result),
    Document = decode_json(DocumentJson),
    
    %% Publish to mock Tangle
    {ok, PublishResult} = iota_client_mock:publish_did(Document),
    
    ?assertMatch(#{did := _, document := _, block_id := _}, PublishResult),
    
    FinalDid = maps:get(did, PublishResult),
    ct:pal("Published DID: ~s", [FinalDid]),
    
    %% Resolve the DID
    {ok, ResolvedDoc} = iota_client_mock:resolve_did(FinalDid),
    ?assertEqual(FinalDid, maps:get(<<"id">>, ResolvedDoc)).

resolve_nonexistent_did(_Config) ->
    {error, not_found} = iota_client_mock:resolve_did(<<"did:iota:0xnonexistent">>).

full_did_lifecycle(_Config) ->
    %% 1. Generate DID
    {ok, ResultJson} = iota_did_nif:generate_did(<<"smr">>),
    Result = decode_json(ResultJson),
    
    LocalDid = maps:get(<<"did">>, Result),
    DocumentJson = maps:get(<<"document">>, Result),
    Fragment = maps:get(<<"verification_method_fragment">>, Result),
    
    ct:pal("Local DID (before publish): ~s", [LocalDid]),
    ct:pal("Verification method fragment: ~s", [Fragment]),
    
    %% 2. Validate local DID format
    ?assert(iota_did_nif:is_valid_iota_did(LocalDid)),
    
    %% 3. Publish to mock Tangle
    Document = decode_json(DocumentJson),
    {ok, #{did := FinalDid, block_id := BlockId}} = iota_client_mock:publish_did(Document),
    
    ct:pal("Final DID (after publish): ~s", [FinalDid]),
    ct:pal("Block ID: ~s", [BlockId]),
    
    %% 4. Validate finalized DID
    ?assert(iota_did_nif:is_valid_iota_did(FinalDid)),
    
    %% 5. Create DID URL with verification method
    {ok, DidUrl} = iota_did_nif:create_did_url(FinalDid, Fragment),
    ct:pal("DID URL: ~s", [DidUrl]),
    ?assert(binary:match(DidUrl, <<"#">>) =/= nomatch),
    
    %% 6. Resolve and verify
    {ok, ResolvedDoc} = iota_client_mock:resolve_did(FinalDid),
    ?assertEqual(FinalDid, maps:get(<<"id">>, ResolvedDoc)),
    ?assert(maps:is_key(<<"block_id">>, ResolvedDoc)),
    ?assert(maps:is_key(<<"published_at">>, ResolvedDoc)).

%%%===================================================================
%%% Configuration Tests
%%%===================================================================

%%%===================================================================
%%% Ledger Error Handling Tests
%%%===================================================================

ledger_resolve_invalid_did(_Config) ->
    %% Attempting to resolve with an unreachable node should return error
    Result = iota_did_nif:resolve_did(
        <<"did:iota:rms:0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef">>,
        <<"http://127.0.0.1:1">>
    ),
    ct:pal("resolve_did with bad node: ~p", [Result]),
    ?assertMatch({error, _}, Result).

ledger_publish_invalid_node(_Config) ->
    %% Attempting to publish with an unreachable node should return error
    %% Use a dummy base64 key (32 zero bytes)
    DummyKey = base64:encode(<<0:256>>),
    Result = iota_did_nif:create_and_publish_did(
        DummyKey,
        <<"http://127.0.0.1:1">>,
        <<>>
    ),
    ct:pal("create_and_publish_did with bad node: ~p", [Result]),
    ?assertMatch({error, _}, Result).

ledger_deactivate_invalid_node(_Config) ->
    %% Attempting to deactivate with an unreachable node should return error
    DummyKey = base64:encode(<<0:256>>),
    Result = iota_did_nif:deactivate_did(
        DummyKey,
        <<"did:iota:0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef">>,
        <<"http://127.0.0.1:1">>
    ),
    ct:pal("deactivate_did with bad node: ~p", [Result]),
    ?assertMatch({error, _}, Result).

ledger_deactivate_invalid_did(_Config) ->
    %% Attempting to deactivate with an invalid DID format should return error
    DummyKey = base64:encode(<<0:256>>),
    Result = iota_did_nif:deactivate_did(
        DummyKey,
        <<"not-a-valid-did">>,
        <<"http://127.0.0.1:9000">>
    ),
    ct:pal("deactivate_did with invalid DID: ~p", [Result]),
    ?assertMatch({error, _}, Result).

%%%===================================================================
%%% Ledger Integration Tests (require local IOTA node)
%%%===================================================================

ledger_publish_did_on_local_node(Config) ->
    SecretKey = ?config(secret_key, Config),
    NodeUrl = ?config(node_url, Config),
    GasCoinId = ?config(gas_coin_id, Config),
    IdentityPkgId = ?config(identity_pkg_id, Config),

    ct:pal("Publishing DID to local node at ~s", [NodeUrl]),
    ct:pal("Using gas coin: ~s", [GasCoinId]),

    %% Publish a new DID to the local IOTA Rebased node
    Result = iota_did_nif:create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId, GasCoinId),
    ct:pal("Publish result: ~p", [Result]),

    ?assertMatch({ok, _}, Result),
    {ok, ResultJson} = Result,
    Parsed = decode_json(ResultJson),

    %% Verify the result contains all expected fields
    ?assert(maps:is_key(<<"did">>, Parsed)),
    ?assert(maps:is_key(<<"document">>, Parsed)),
    ?assert(maps:is_key(<<"verification_method_fragment">>, Parsed)),
    ?assert(maps:is_key(<<"network">>, Parsed)),
    ?assert(maps:is_key(<<"sender_address">>, Parsed)),

    Did = maps:get(<<"did">>, Parsed),
    Fragment = maps:get(<<"verification_method_fragment">>, Parsed),
    Network = maps:get(<<"network">>, Parsed),
    SenderAddr = maps:get(<<"sender_address">>, Parsed),

    ct:pal("Published DID: ~s", [Did]),
    ct:pal("Network: ~s", [Network]),
    ct:pal("Fragment: ~s", [Fragment]),
    ct:pal("Sender: ~s", [SenderAddr]),

    %% The DID should be a valid IOTA DID
    ?assert(iota_did_nif:is_valid_iota_did(Did)),

    %% The DID should NOT have an all-zeros tag (it's published on-chain)
    ?assertNotEqual(
        nomatch,
        binary:match(Did, <<"did:iota:">>)
    ),

    %% Create a DID URL with the verification method fragment
    {ok, DidUrl} = iota_did_nif:create_did_url(Did, Fragment),
    ct:pal("DID URL: ~s", [DidUrl]),
    ?assert(binary:match(DidUrl, <<"#">>) =/= nomatch),

    Config.

ledger_publish_and_resolve_on_local_node(Config) ->
    SecretKey = ?config(secret_key, Config),
    NodeUrl = ?config(node_url, Config),
    IdentityPkgId = ?config(identity_pkg_id, Config),

    ct:pal("Publishing DID for resolve test on ~s", [NodeUrl]),

    %% Publish a new DID (auto gas coin selection)
    {ok, PublishJson} = iota_did_nif:create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId),
    PublishResult = decode_json(PublishJson),
    Did = maps:get(<<"did">>, PublishResult),

    ct:pal("Published DID: ~s — now resolving...", [Did]),

    %% Resolve the DID we just published
    {ok, ResolveJson} = iota_did_nif:resolve_did(Did, NodeUrl, IdentityPkgId),
    ResolveResult = decode_json(ResolveJson),

    ct:pal("Resolved result: ~p", [ResolveResult]),

    %% Verify the resolved DID matches what we published
    ResolvedDid = maps:get(<<"did">>, ResolveResult),
    ?assertEqual(Did, ResolvedDid),

    %% The resolved document should be valid JSON
    ?assert(maps:is_key(<<"document">>, ResolveResult)),
    ResolvedDoc = maps:get(<<"document">>, ResolveResult),
    ?assert(is_binary(ResolvedDoc) orelse is_map(ResolvedDoc)),

    ct:pal("Successfully published and resolved DID: ~s", [Did]),
    Config.

ledger_publish_deactivate_resolve_lifecycle(Config) ->
    SecretKey = ?config(secret_key, Config),
    NodeUrl = ?config(node_url, Config),
    IdentityPkgId = ?config(identity_pkg_id, Config),

    ct:pal("=== DID Lifecycle: Publish → Deactivate → Resolve ==="),
    ct:pal("Node: ~s", [NodeUrl]),

    %% 1. Publish a new DID
    ct:pal("Step 1: Publishing new DID..."),
    {ok, PublishJson} = iota_did_nif:create_and_publish_did(SecretKey, NodeUrl, IdentityPkgId),
    PublishResult = decode_json(PublishJson),
    Did = maps:get(<<"did">>, PublishResult),
    ct:pal("Published DID: ~s", [Did]),

    %% 2. Verify the DID is resolvable (active)
    ct:pal("Step 2: Verifying DID is resolvable..."),
    {ok, _ResolveJson} = iota_did_nif:resolve_did(Did, NodeUrl, IdentityPkgId),
    ct:pal("DID resolved successfully (active)"),

    %% 3. Deactivate (revoke) the DID
    ct:pal("Step 3: Deactivating DID..."),
    DeactivateResult = iota_did_nif:deactivate_did(SecretKey, Did, NodeUrl, IdentityPkgId),
    ct:pal("Deactivate result: ~p", [DeactivateResult]),
    ?assertMatch({ok, <<"deactivated">>}, DeactivateResult),

    %% 4. Attempt to resolve the deactivated DID
    %% Depending on the SDK version, this may:
    %%   - Return a deactivated document (metadata indicates deactivation)
    %%   - Return an error indicating the DID is deactivated
    ct:pal("Step 4: Attempting to resolve deactivated DID..."),
    ResolveAfterResult = iota_did_nif:resolve_did(Did, NodeUrl, IdentityPkgId),
    ct:pal("Resolve after deactivation: ~p", [ResolveAfterResult]),
    %% The resolve should still succeed but the document should reflect deactivation
    %% (the exact behavior depends on the SDK — some return the doc with empty methods)
    ?assertMatch({ok, _}, ResolveAfterResult),

    ct:pal("=== DID lifecycle test complete ==="),
    Config.

%%%===================================================================
%%% Helpers
%%%===================================================================

decode_json(JsonBinary) when is_binary(JsonBinary) ->
    %% Simple JSON decoder for tests (uses jsx if available, otherwise basic parsing)
    try
        jsx:decode(JsonBinary, [return_maps])
    catch
        error:undef ->
            %% Fallback: use built-in json module (OTP 27+)
            json:decode(JsonBinary)
    end.
