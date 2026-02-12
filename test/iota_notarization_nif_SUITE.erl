%%%-------------------------------------------------------------------
%%% @doc Common Test Suite for iota_notarization_nif
%%%
%%% Tests notarization payload creation, verification, and mock 
%%% publishing to IOTA Tangle.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_notarization_nif_SUITE).

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
    hash_data_basic/1,
    hash_data_deterministic/1,
    hash_data_different_inputs/1,
    is_valid_hex_string_valid/1,
    is_valid_hex_string_invalid/1,
    create_notarization_payload_basic/1,
    create_notarization_payload_invalid_hash/1,
    verify_notarization_payload_basic/1,
    verify_notarization_payload_invalid/1,
    roundtrip_notarization/1,
    %% Mock mainnet operations
    notarize_and_retrieve/1,
    notarize_document/1,
    verify_retrieved_payload/1,
    full_notarization_lifecycle/1,
    %% Ledger error handling (no live node needed)
    create_empty_node_url/1,
    create_empty_secret_key/1,
    create_empty_pkg_id/1,
    create_empty_state_data/1,
    create_invalid_pkg_id_format/1,
    create_connection_refused/1,
    read_empty_node_url/1,
    read_empty_object_id/1,
    read_empty_pkg_id/1,
    read_invalid_object_id/1,
    read_connection_refused/1,
    %% Ledger integration (requires live node — skipped by default)
    create_and_read_integration/1
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
            hash_data_basic,
            hash_data_deterministic,
            hash_data_different_inputs,
            is_valid_hex_string_valid,
            is_valid_hex_string_invalid,
            create_notarization_payload_basic,
            create_notarization_payload_invalid_hash,
            verify_notarization_payload_basic,
            verify_notarization_payload_invalid,
            roundtrip_notarization
        ]},
        {mock_mainnet_operations, [sequence], [
            notarize_and_retrieve,
            notarize_document,
            verify_retrieved_payload,
            full_notarization_lifecycle
        ]},
        {ledger_error_handling, [parallel], [
            create_empty_node_url,
            create_empty_secret_key,
            create_empty_pkg_id,
            create_empty_state_data,
            create_invalid_pkg_id_format,
            create_connection_refused,
            read_empty_node_url,
            read_empty_object_id,
            read_empty_pkg_id,
            read_invalid_object_id,
            read_connection_refused
        ]},
        {ledger_integration, [sequence], [
            create_and_read_integration
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
    %% Skip integration tests unless IOTA_NODE_URL and IOTA_SECRET_KEY are set
    case {os:getenv("IOTA_NODE_URL"), os:getenv("IOTA_SECRET_KEY"), os:getenv("IOTA_NOTARIZE_PKG_ID")} of
        {false, _, _} ->
            {skip, "IOTA_NODE_URL not set — skipping ledger integration tests"};
        {_, false, _} ->
            {skip, "IOTA_SECRET_KEY not set — skipping ledger integration tests"};
        {_, _, false} ->
            {skip, "IOTA_NOTARIZE_PKG_ID not set — skipping ledger integration tests"};
        {NodeUrl, SecretKey, PkgId} ->
            [{node_url, list_to_binary(NodeUrl)},
             {secret_key, list_to_binary(SecretKey)},
             {notarize_pkg_id, list_to_binary(PkgId)}
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
    TestCase =:= notarize_and_retrieve;
    TestCase =:= notarize_document;
    TestCase =:= verify_retrieved_payload;
    TestCase =:= full_notarization_lifecycle ->
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

hash_data_basic(_Config) ->
    Hash = iota_notarization_nif:hash_data(<<"Hello World">>),
    
    ?assert(is_binary(Hash)),
    ?assertEqual(64, byte_size(Hash)), %% SHA-256 = 32 bytes = 64 hex chars
    ?assert(iota_notarization_nif:is_valid_hex_string(Hash)).

hash_data_deterministic(_Config) ->
    Input = <<"test data for hashing">>,
    Hash1 = iota_notarization_nif:hash_data(Input),
    Hash2 = iota_notarization_nif:hash_data(Input),
    
    ?assertEqual(Hash1, Hash2).

hash_data_different_inputs(_Config) ->
    Hash1 = iota_notarization_nif:hash_data(<<"input1">>),
    Hash2 = iota_notarization_nif:hash_data(<<"input2">>),
    
    ?assertNotEqual(Hash1, Hash2).

is_valid_hex_string_valid(_Config) ->
    ?assert(iota_notarization_nif:is_valid_hex_string(<<"0123456789abcdef">>)),
    ?assert(iota_notarization_nif:is_valid_hex_string(<<"ABCDEF">>)),
    ?assert(iota_notarization_nif:is_valid_hex_string(<<"aAbBcCdDeEfF">>)).

is_valid_hex_string_invalid(_Config) ->
    ?assertNot(iota_notarization_nif:is_valid_hex_string(<<"">>)),
    ?assertNot(iota_notarization_nif:is_valid_hex_string(<<"ghijkl">>)),
    ?assertNot(iota_notarization_nif:is_valid_hex_string(<<"12345g">>)),
    ?assertNot(iota_notarization_nif:is_valid_hex_string(<<"hello world">>)).

create_notarization_payload_basic(_Config) ->
    Hash = iota_notarization_nif:hash_data(<<"test document">>),
    Tag = <<"document-v1">>,
    
    {ok, ResultJson} = iota_notarization_nif:create_notarization_payload(Hash, Tag),
    Result = decode_json(ResultJson),
    
    ?assertMatch(#{
        <<"tag">> := <<"document-v1">>,
        <<"data_hash">> := _,
        <<"timestamp">> := _,
        <<"payload_hex">> := _
    }, Result),
    
    ?assertEqual(Hash, maps:get(<<"data_hash">>, Result)),
    ?assert(is_integer(maps:get(<<"timestamp">>, Result))),
    ?assert(iota_notarization_nif:is_valid_hex_string(maps:get(<<"payload_hex">>, Result))).

create_notarization_payload_invalid_hash(_Config) ->
    {error, Reason} = iota_notarization_nif:create_notarization_payload(<<"not-hex!">>, <<"tag">>),
    ?assert(binary:match(Reason, <<"Invalid hash">>) =/= nomatch).

verify_notarization_payload_basic(_Config) ->
    %% Create a payload first
    Hash = iota_notarization_nif:hash_data(<<"test">>),
    {ok, CreateJson} = iota_notarization_nif:create_notarization_payload(Hash, <<"my-tag">>),
    CreateResult = decode_json(CreateJson),
    PayloadHex = maps:get(<<"payload_hex">>, CreateResult),
    
    %% Verify it
    {ok, VerifyJson} = iota_notarization_nif:verify_notarization_payload(PayloadHex),
    VerifyResult = decode_json(VerifyJson),
    
    ?assertMatch(#{
        <<"is_valid">> := true,
        <<"tag">> := <<"my-tag">>,
        <<"data_hash">> := _,
        <<"timestamp">> := _
    }, VerifyResult),
    
    ?assertEqual(Hash, maps:get(<<"data_hash">>, VerifyResult)).

verify_notarization_payload_invalid(_Config) ->
    {error, _} = iota_notarization_nif:verify_notarization_payload(<<"not-hex!">>),
    {error, _} = iota_notarization_nif:verify_notarization_payload(<<"deadbeef">>). %% Valid hex but invalid format

roundtrip_notarization(_Config) ->
    %% Original data
    OriginalData = <<"This is a legal contract signed on 2026-01-31">>,
    Tag = <<"contract-2026-001">>,
    
    %% Create hash
    DataHash = iota_notarization_nif:hash_data(OriginalData),
    ct:pal("Data hash: ~s", [DataHash]),
    
    %% Create payload
    {ok, PayloadJson} = iota_notarization_nif:create_notarization_payload(DataHash, Tag),
    Payload = decode_json(PayloadJson),
    PayloadHex = maps:get(<<"payload_hex">>, Payload),
    Timestamp1 = maps:get(<<"timestamp">>, Payload),
    
    ct:pal("Payload hex: ~s", [PayloadHex]),
    ct:pal("Timestamp: ~p", [Timestamp1]),
    
    %% Verify roundtrip
    {ok, VerifyJson} = iota_notarization_nif:verify_notarization_payload(PayloadHex),
    Verified = decode_json(VerifyJson),
    
    ?assertEqual(true, maps:get(<<"is_valid">>, Verified)),
    ?assertEqual(Tag, maps:get(<<"tag">>, Verified)),
    ?assertEqual(DataHash, maps:get(<<"data_hash">>, Verified)),
    ?assertEqual(Timestamp1, maps:get(<<"timestamp">>, Verified)).

%%%===================================================================
%%% Mock Mainnet Operation Tests
%%%===================================================================

notarize_and_retrieve(_Config) ->
    %% Create notarization payload
    Data = <<"Document content to notarize">>,
    Hash = iota_notarization_nif:hash_data(Data),
    {ok, PayloadJson} = iota_notarization_nif:create_notarization_payload(Hash, <<"doc-1">>),
    Payload = decode_json(PayloadJson),
    PayloadHex = maps:get(<<"payload_hex">>, Payload),
    
    %% Send to mock Tangle
    {ok, #{block_id := BlockId}} = iota_client_mock:send_tagged_data(<<"notarization">>, PayloadHex),
    ct:pal("Block ID: ~s", [BlockId]),
    
    %% Retrieve from mock Tangle
    {ok, Retrieved} = iota_client_mock:get_tagged_data(BlockId),
    ?assertEqual(PayloadHex, maps:get(payload, Retrieved)),
    ?assertEqual(<<"notarization">>, maps:get(tag, Retrieved)).

notarize_document(_Config) ->
    %% Simulate notarizing a real document
    Document = #{
        <<"title">> => <<"Service Agreement">>,
        <<"parties">> => [<<"Alice">>, <<"Bob">>],
        <<"date">> => <<"2026-01-31">>,
        <<"content">> => <<"Terms and conditions...">>
    },
    
    %% Serialize and hash
    DocJson = iolist_to_binary(json:encode(Document)),
    DocHash = iota_notarization_nif:hash_data(DocJson),
    
    %% Create notarization
    {ok, PayloadJson} = iota_notarization_nif:create_notarization_payload(DocHash, <<"agreement-v1">>),
    Payload = decode_json(PayloadJson),
    
    %% Send to Tangle
    {ok, #{block_id := BlockId, timestamp := TangleTimestamp}} = 
        iota_client_mock:send_tagged_data(<<"legal">>, maps:get(<<"payload_hex">>, Payload)),
    
    ct:pal("Document notarized at block: ~s", [BlockId]),
    ct:pal("Tangle timestamp: ~p", [TangleTimestamp]),
    
    ?assert(is_binary(BlockId)),
    ?assert(TangleTimestamp > 0).

verify_retrieved_payload(_Config) ->
    %% Setup: create and send a notarization
    OriginalData = <<"Proof of existence">>,
    DataHash = iota_notarization_nif:hash_data(OriginalData),
    {ok, PayloadJson} = iota_notarization_nif:create_notarization_payload(DataHash, <<"proof">>),
    Payload = decode_json(PayloadJson),
    PayloadHex = maps:get(<<"payload_hex">>, Payload),
    
    {ok, #{block_id := BlockId}} = iota_client_mock:send_tagged_data(<<"proof">>, PayloadHex),
    
    %% Retrieve and verify
    {ok, Retrieved} = iota_client_mock:get_tagged_data(BlockId),
    RetrievedPayload = maps:get(payload, Retrieved),
    
    {ok, VerifyJson} = iota_notarization_nif:verify_notarization_payload(RetrievedPayload),
    Verified = decode_json(VerifyJson),
    
    ?assertEqual(true, maps:get(<<"is_valid">>, Verified)),
    ?assertEqual(DataHash, maps:get(<<"data_hash">>, Verified)),
    ?assertEqual(<<"proof">>, maps:get(<<"tag">>, Verified)).

full_notarization_lifecycle(_Config) ->
    ct:pal("=== Full Notarization Lifecycle Test ==="),
    
    %% 1. Original document
    Document = <<"This document was created on January 31, 2026 and proves existence.">>,
    ct:pal("1. Original document: ~s", [Document]),
    
    %% 2. Hash the document
    DocumentHash = iota_notarization_nif:hash_data(Document),
    ct:pal("2. Document SHA-256 hash: ~s", [DocumentHash]),
    ?assert(iota_notarization_nif:is_valid_hex_string(DocumentHash)),
    
    %% 3. Create notarization payload
    Tag = <<"proof-of-existence-2026">>,
    {ok, PayloadJson} = iota_notarization_nif:create_notarization_payload(DocumentHash, Tag),
    Payload = decode_json(PayloadJson),
    PayloadHex = maps:get(<<"payload_hex">>, Payload),
    LocalTimestamp = maps:get(<<"timestamp">>, Payload),
    ct:pal("3. Notarization payload created at timestamp: ~p", [LocalTimestamp]),
    
    %% 4. Submit to IOTA Tangle (mock)
    {ok, #{block_id := BlockId, timestamp := TangleTimestamp}} = 
        iota_client_mock:send_tagged_data(Tag, PayloadHex),
    ct:pal("4. Submitted to Tangle - Block ID: ~s", [BlockId]),
    ct:pal("   Tangle confirmation timestamp: ~p", [TangleTimestamp]),
    
    %% 5. Later: retrieve from Tangle
    {ok, TangleData} = iota_client_mock:get_tagged_data(BlockId),
    RetrievedPayloadHex = maps:get(payload, TangleData),
    ct:pal("5. Retrieved from Tangle - payload matches: ~p", [RetrievedPayloadHex =:= PayloadHex]),
    ?assertEqual(PayloadHex, RetrievedPayloadHex),
    
    %% 6. Verify the notarization
    {ok, VerifyJson} = iota_notarization_nif:verify_notarization_payload(RetrievedPayloadHex),
    Verified = decode_json(VerifyJson),
    ct:pal("6. Verification result:"),
    ct:pal("   - Valid: ~p", [maps:get(<<"is_valid">>, Verified)]),
    ct:pal("   - Tag: ~s", [maps:get(<<"tag">>, Verified)]),
    ct:pal("   - Hash: ~s", [maps:get(<<"data_hash">>, Verified)]),
    ct:pal("   - Timestamp: ~p", [maps:get(<<"timestamp">>, Verified)]),
    
    ?assertEqual(true, maps:get(<<"is_valid">>, Verified)),
    ?assertEqual(Tag, maps:get(<<"tag">>, Verified)),
    ?assertEqual(DocumentHash, maps:get(<<"data_hash">>, Verified)),
    
    %% 7. Verify against original document
    RehashDocument = iota_notarization_nif:hash_data(Document),
    HashMatches = (RehashDocument =:= maps:get(<<"data_hash">>, Verified)),
    ct:pal("7. Original document hash matches Tangle record: ~p", [HashMatches]),
    ?assert(HashMatches),
    
    ct:pal("=== Lifecycle Complete: Document existence proven! ===").

%%%===================================================================
%%% Ledger Error Handling Tests
%%%===================================================================

create_empty_node_url(_Config) ->
    {error, Reason} = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<>>, <<"0x1">>, <<"some data">>),
    ?assert(binary:match(Reason, <<"node_url">>) =/= nomatch).

create_empty_secret_key(_Config) ->
    {error, Reason} = iota_notarization_nif:create_notarization(
        <<>>, <<"http://localhost:9000">>, <<"0x1">>, <<"some data">>),
    ?assert(binary:match(Reason, <<"secret_key">>) =/= nomatch).

create_empty_pkg_id(_Config) ->
    {error, Reason} = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://localhost:9000">>, <<>>, <<"some data">>),
    ?assert(binary:match(Reason, <<"notarize_pkg_id">>) =/= nomatch).

create_empty_state_data(_Config) ->
    {error, Reason} = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://localhost:9000">>, <<"0x1">>, <<>>),
    ?assert(binary:match(Reason, <<"state_data">>) =/= nomatch).

create_invalid_pkg_id_format(_Config) ->
    %% Valid state_data but invalid ObjectID format for package
    {error, Reason} = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://localhost:9000">>, <<"invalid-object-id">>,
        <<"some data to notarize">>),
    ct:pal("Error for invalid pkg_id: ~s", [Reason]),
    ?assert(is_binary(Reason)),
    ?assert(byte_size(Reason) > 0).

create_connection_refused(_Config) ->
    %% Use a port that's unlikely to have an IOTA node
    {error, Reason} = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://127.0.0.1:59999">>,
        <<"0x0000000000000000000000000000000000000000000000000000000000000001">>,
        <<"some data to notarize">>),
    ct:pal("Connection refused error: ~s", [Reason]),
    ?assert(is_binary(Reason)),
    ?assert(byte_size(Reason) > 0).

read_empty_node_url(_Config) ->
    {error, Reason} = iota_notarization_nif:read_notarization(
        <<>>, <<"0x1">>, <<"0x1">>),
    ?assert(binary:match(Reason, <<"node_url">>) =/= nomatch).

read_empty_object_id(_Config) ->
    {error, Reason} = iota_notarization_nif:read_notarization(
        <<"http://localhost:9000">>, <<>>, <<"0x1">>),
    ?assert(binary:match(Reason, <<"object_id">>) =/= nomatch).

read_empty_pkg_id(_Config) ->
    {error, Reason} = iota_notarization_nif:read_notarization(
        <<"http://localhost:9000">>, <<"0x1">>, <<>>),
    ?assert(binary:match(Reason, <<"notarize_pkg_id">>) =/= nomatch).

read_invalid_object_id(_Config) ->
    {error, Reason} = iota_notarization_nif:read_notarization(
        <<"http://localhost:9000">>, <<"not-a-valid-id!@#$">>, <<"0x1">>),
    ct:pal("Invalid object_id error: ~s", [Reason]),
    ?assert(is_binary(Reason)).

read_connection_refused(_Config) ->
    %% Valid-looking IDs but no node available
    {error, Reason} = iota_notarization_nif:read_notarization(
        <<"http://127.0.0.1:59999">>,
        <<"0x0000000000000000000000000000000000000000000000000000000000000001">>,
        <<"0x0000000000000000000000000000000000000000000000000000000000000001">>),
    ct:pal("Connection refused error: ~s", [Reason]),
    ?assert(is_binary(Reason)).

%%%===================================================================
%%% Ledger Integration Tests (requires live IOTA node)
%%%===================================================================

create_and_read_integration(Config) ->
    NodeUrl = ?config(node_url, Config),
    SecretKey = ?config(secret_key, Config),
    PkgId = ?config(notarize_pkg_id, Config),

    ct:pal("=== Ledger Integration Test ==="),
    ct:pal("Node URL: ~s", [NodeUrl]),
    ct:pal("Package ID: ~s", [PkgId]),

    %% 1. Hash some data
    Data = <<"Integration test document - notarization on IOTA ledger">>,
    DataHash = iota_notarization_nif:hash_data(Data),
    ct:pal("Data hash: ~s", [DataHash]),

    %% 2. Create a locked notarization on-chain
    ct:pal("Creating notarization on-chain..."),
    {ok, CreateJson} = iota_notarization_nif:create_notarization(
        SecretKey, NodeUrl, PkgId, DataHash, <<"integration-test">>),
    CreateResult = decode_json(CreateJson),
    ct:pal("Create result: ~p", [CreateResult]),

    ObjectId = maps:get(<<"object_id">>, CreateResult),
    TxDigest = maps:get(<<"tx_digest">>, CreateResult),
    ?assert(is_binary(ObjectId)),
    ?assert(is_binary(TxDigest)),
    ?assert(byte_size(ObjectId) > 0),
    ?assert(byte_size(TxDigest) > 0),
    ?assertEqual(DataHash, maps:get(<<"state_data">>, CreateResult)),

    ct:pal("Object ID: ~s", [ObjectId]),
    ct:pal("Transaction digest: ~s", [TxDigest]),

    %% 3. Read notarization from the ledger
    ct:pal("Reading notarization from ledger..."),
    {ok, ReadJson} = iota_notarization_nif:read_notarization(NodeUrl, ObjectId, PkgId),
    ReadResult = decode_json(ReadJson),
    ct:pal("Read result: ~p", [ReadResult]),

    ?assertEqual(ObjectId, maps:get(<<"object_id">>, ReadResult)),
    ?assertEqual(DataHash, maps:get(<<"state_data">>, ReadResult)),
    ?assertEqual(<<"Locked">>, maps:get(<<"method">>, ReadResult)),

    ct:pal("=== Ledger Integration Test Complete ===").

%%%===================================================================
%%% Helpers
%%%===================================================================

decode_json(JsonBinary) when is_binary(JsonBinary) ->
    try
        jsx:decode(JsonBinary, [return_maps])
    catch
        error:undef ->
            json:decode(JsonBinary)
    end.
