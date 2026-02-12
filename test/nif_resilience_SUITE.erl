%%%-------------------------------------------------------------------
%%% @doc NIF Resilience Test Suite
%%%
%%% Tests that NIFs handle malformed, malicious, and edge-case inputs
%%% without crashing the BEAM VM.
%%%
%%% CRITICAL: If any test in this suite causes a VM crash rather than
%%% returning an error tuple, the NIF implementation is unsafe.
%%% @end
%%%-------------------------------------------------------------------
-module(nif_resilience_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    %% Empty/Null inputs
    empty_binary_did_generation/1,
    empty_binary_document_extraction/1,
    empty_binary_did_url/1,
    empty_binary_validation/1,
    empty_binary_hash/1,
    empty_binary_notarization/1,
    
    %% Large inputs (memory stress)
    large_input_did_generation/1,
    large_input_document_extraction/1,
    large_input_hash/1,
    large_input_notarization_payload/1,
    
    %% Malformed inputs
    invalid_json_extraction/1,
    deeply_nested_json/1,
    binary_with_null_bytes/1,
    unicode_edge_cases/1,
    special_characters_in_tag/1,
    non_utf8_in_notarization/1,
    
    %% Type confusion (Rustler should reject)
    wrong_type_atom_instead_of_binary/1,
    wrong_type_integer_instead_of_binary/1,
    wrong_type_list_instead_of_binary/1,
    wrong_type_tuple_instead_of_binary/1,
    wrong_type_pid_instead_of_binary/1,
    
    %% Concurrent stress
    concurrent_did_generation/1,
    concurrent_hash_operations/1,
    rapid_sequential_calls/1,
    
    %% Boundary conditions
    max_network_name_length/1,
    single_byte_inputs/1,
    repeated_calls_same_input/1,
    
    %% Ledger NIF resilience
    ledger_empty_node_url/1,
    ledger_empty_did_resolve/1,
    ledger_non_utf8_inputs/1,
    ledger_wrong_types/1,
    
    %% Notarization Ledger NIF resilience
    notarize_ledger_empty_inputs/1,
    notarize_ledger_non_utf8_inputs/1,
    notarize_ledger_wrong_types/1,
    notarize_read_empty_inputs/1,
    notarize_read_non_utf8_inputs/1,
    notarize_read_wrong_types/1
]).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

all() ->
    [
        {group, empty_inputs},
        {group, large_inputs},
        {group, malformed_inputs},
        {group, type_confusion},
        {group, concurrent_stress},
        {group, boundary_conditions},
        {group, ledger_nif_resilience}
    ].

groups() ->
    [
        {empty_inputs, [parallel], [
            empty_binary_did_generation,
            empty_binary_document_extraction,
            empty_binary_did_url,
            empty_binary_validation,
            empty_binary_hash,
            empty_binary_notarization
        ]},
        {large_inputs, [sequence], [
            large_input_did_generation,
            large_input_document_extraction,
            large_input_hash,
            large_input_notarization_payload
        ]},
        {malformed_inputs, [parallel], [
            invalid_json_extraction,
            deeply_nested_json,
            binary_with_null_bytes,
            unicode_edge_cases,
            special_characters_in_tag,
            non_utf8_in_notarization
        ]},
        {type_confusion, [parallel], [
            wrong_type_atom_instead_of_binary,
            wrong_type_integer_instead_of_binary,
            wrong_type_list_instead_of_binary,
            wrong_type_tuple_instead_of_binary,
            wrong_type_pid_instead_of_binary
        ]},
        {concurrent_stress, [sequence], [
            concurrent_did_generation,
            concurrent_hash_operations,
            rapid_sequential_calls
        ]},
        {boundary_conditions, [parallel], [
            max_network_name_length,
            single_byte_inputs,
            repeated_calls_same_input
        ]},
        {ledger_nif_resilience, [parallel], [
            ledger_empty_node_url,
            ledger_empty_did_resolve,
            ledger_non_utf8_inputs,
            ledger_wrong_types,
            notarize_ledger_empty_inputs,
            notarize_ledger_non_utf8_inputs,
            notarize_ledger_wrong_types,
            notarize_read_empty_inputs,
            notarize_read_non_utf8_inputs,
            notarize_read_wrong_types
        ]}
    ].

init_per_suite(Config) ->
    ct:pal("=== NIF Resilience Test Suite ==="),
    ct:pal("Testing that NIFs never crash the VM, only return errors"),
    Config.

end_per_suite(_Config) ->
    ct:pal("=== All resilience tests completed without VM crash ==="),
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Testing: ~p", [TestCase]),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Empty/Null Input Tests
%%%===================================================================

empty_binary_did_generation(_Config) ->
    %% Empty network name should return error, not crash
    Result = iota_did_nif:generate_did(<<>>),
    ct:pal("generate_did(<<>>) = ~p", [Result]),
    ?assertMatch({error, _}, Result).

empty_binary_document_extraction(_Config) ->
    %% Empty document should return error, not crash
    Result = iota_did_nif:extract_did_from_document(<<>>),
    ct:pal("extract_did_from_document(<<>>) = ~p", [Result]),
    ?assertMatch({error, _}, Result).

empty_binary_did_url(_Config) ->
    %% Empty DID and fragment - should work (returns {ok, "#"})
    Result1 = iota_did_nif:create_did_url(<<>>, <<>>),
    ct:pal("create_did_url(<<>>, <<>>) = ~p", [Result1]),
    ?assertMatch({ok, _}, Result1),
    
    %% Empty DID with fragment
    Result2 = iota_did_nif:create_did_url(<<>>, <<"frag">>),
    ct:pal("create_did_url(<<>>, <<\"frag\">>) = ~p", [Result2]),
    ?assertMatch({ok, _}, Result2).

empty_binary_validation(_Config) ->
    %% Empty DID should return false, not crash
    Result = iota_did_nif:is_valid_iota_did(<<>>),
    ct:pal("is_valid_iota_did(<<>>) = ~p", [Result]),
    ?assertEqual(false, Result).

empty_binary_hash(_Config) ->
    %% Empty data hash should work (hash of empty string)
    Result = iota_notarization_nif:hash_data(<<>>),
    ct:pal("hash_data(<<>>) = ~p", [Result]),
    ?assert(is_binary(Result)),
    ?assertEqual(64, byte_size(Result)). %% SHA-256 always 64 hex chars

empty_binary_notarization(_Config) ->
    %% Empty hash should fail validation
    Result = iota_notarization_nif:create_notarization_payload(<<>>, <<"tag">>),
    ct:pal("create_notarization_payload(<<>>, <<\"tag\">>) = ~p", [Result]),
    ?assertMatch({error, _}, Result).

%%%===================================================================
%%% Large Input Tests
%%%===================================================================

large_input_did_generation(_Config) ->
    %% Very long network name
    LargeName = binary:copy(<<"x">>, 10000),
    Result = iota_did_nif:generate_did(LargeName),
    ct:pal("generate_did(10KB string) = ~p", [element(1, Result)]),
    ?assertMatch({error, _}, Result).

large_input_document_extraction(_Config) ->
    %% 1MB of invalid JSON
    LargeDoc = binary:copy(<<"x">>, 1024 * 1024),
    Result = iota_did_nif:extract_did_from_document(LargeDoc),
    ct:pal("extract_did_from_document(1MB) = ~p", [element(1, Result)]),
    ?assertMatch({error, _}, Result).

large_input_hash(_Config) ->
    %% 10MB of data - should work but may be slow
    LargeData = binary:copy(<<"abcdefghij">>, 1024 * 1024), %% 10MB
    
    {Time, Result} = timer:tc(fun() -> 
        iota_notarization_nif:hash_data(LargeData) 
    end),
    
    ct:pal("hash_data(10MB) took ~p ms", [Time / 1000]),
    ?assert(is_binary(Result)),
    ?assertEqual(64, byte_size(Result)),
    
    %% Warn if NIF took too long (scheduler concern)
    case Time > 100000 of %% > 100ms
        true -> ct:pal("WARNING: hash_data took >100ms, consider dirty scheduler");
        false -> ok
    end.

large_input_notarization_payload(_Config) ->
    %% Valid but very long tag
    LargeTag = binary:copy(<<"tag">>, 10000),
    Hash = iota_notarization_nif:hash_data(<<"test">>),
    
    Result = iota_notarization_nif:create_notarization_payload(Hash, LargeTag),
    ct:pal("create_notarization_payload with 30KB tag = ~p", [element(1, Result)]),
    %% This might succeed or fail, but must not crash
    ?assert(is_tuple(Result)).

%%%===================================================================
%%% Malformed Input Tests
%%%===================================================================

invalid_json_extraction(_Config) ->
    InvalidJsons = [
        <<"not json">>,
        <<"{incomplete">>,
        <<"[1,2,3]">>,  %% Array, not object
        <<"{\"no_id\": true}">>,  %% Missing id field
        <<"null">>,
        <<"true">>,
        <<"123">>,
        <<"{\"id\": null}">>,  %% id is null
        <<"{\"id\": 123}">>,   %% id is number
        <<"{\"id\": []}">>,    %% id is array
        <<"{\"id\": {}}">>     %% id is object
    ],
    
    lists:foreach(fun(Json) ->
        Result = iota_did_nif:extract_did_from_document(Json),
        ct:pal("extract(~p) = ~p", [Json, Result]),
        ?assertMatch({error, _}, Result)
    end, InvalidJsons).

deeply_nested_json(_Config) ->
    %% Create deeply nested JSON: {"a":{"a":{"a":...}}}
    Depth = 1000,
    DeepJson = create_nested_json(Depth),
    
    Result = iota_did_nif:extract_did_from_document(DeepJson),
    ct:pal("extract(depth=~p) = ~p", [Depth, element(1, Result)]),
    %% Should return error (no id field), not stack overflow
    ?assertMatch({error, _}, Result).

binary_with_null_bytes(_Config) ->
    %% Null bytes can cause issues in C-style string handling
    WithNulls = <<"did:iota:0x123", 0, 0, 0, "456">>,
    
    Result1 = iota_did_nif:is_valid_iota_did(WithNulls),
    ct:pal("is_valid_iota_did with nulls = ~p", [Result1]),
    ?assert(is_boolean(Result1)),
    
    Result2 = iota_did_nif:create_did_url(WithNulls, <<"frag">>),
    ct:pal("create_did_url with nulls = ~p", [Result2]),
    ?assertMatch({ok, _}, Result2).

unicode_edge_cases(_Config) ->
    UnicodeInputs = [
        <<"日本語"/utf8>>,                    %% Japanese
        <<"🎉🚀💻"/utf8>>,                    %% Emojis
        <<16#FEFF:16>>,                       %% BOM
        <<"test", 16#FFFF:16>>,               %% Invalid Unicode
        <<0:8>>,                              %% Null character
        binary:copy(<<16#E9, 16#80, 16#80>>, 100) %% Overlong encoding attempt
    ],
    
    lists:foreach(fun(Input) ->
        %% These should all complete without crash
        R1 = catch iota_did_nif:is_valid_iota_did(Input),
        R2 = catch iota_notarization_nif:hash_data(Input),
        R3 = catch iota_did_nif:generate_did(Input),
        
        ct:pal("Unicode input ~p: valid=~p, hash=~p, gen=~p", 
               [Input, R1, is_binary(R2), element(1, R3)]),
        
        %% Any result is fine, just no crash
        ?assert(R1 =:= true orelse R1 =:= false),
        ?assert(is_binary(R2)),
        ?assertMatch({error, _}, R3)
    end, UnicodeInputs).

special_characters_in_tag(_Config) ->
    SpecialTags = [
        <<"tag:with:colons">>,
        <<"tag\nwith\nnewlines">>,
        <<"tag\twith\ttabs">>,
        <<"tag with spaces">>,
        <<"tag\"with\"quotes">>,
        <<"tag\\with\\backslashes">>,
        <<"">>  %% Empty tag
    ],
    
    Hash = iota_notarization_nif:hash_data(<<"test">>),
    
    lists:foreach(fun(Tag) ->
        Result = iota_notarization_nif:create_notarization_payload(Hash, Tag),
        ct:pal("Tag ~p: ~p", [Tag, element(1, Result)]),
        %% All should succeed (tag is just data)
        ?assertMatch({ok, _}, Result)
    end, SpecialTags).

non_utf8_in_notarization(_Config) ->
    %% Test non-UTF8 bytes in notarization functions
    %% These should return errors, not crash
    
    InvalidUtf8 = <<128, 129, 130, 255>>,  %% Invalid UTF-8 bytes
    ValidHash = <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>,
    
    %% Non-UTF8 in tag - should return error
    R1 = iota_notarization_nif:create_notarization_payload(ValidHash, InvalidUtf8),
    ct:pal("create_notarization_payload with non-UTF8 tag: ~p", [R1]),
    ?assertMatch({error, _}, R1),
    
    %% Non-UTF8 in hash - should return error  
    R2 = iota_notarization_nif:create_notarization_payload(InvalidUtf8, <<"tag">>),
    ct:pal("create_notarization_payload with non-UTF8 hash: ~p", [R2]),
    ?assertMatch({error, _}, R2),
    
    %% Non-UTF8 in verify payload - should return error
    R3 = iota_notarization_nif:verify_notarization_payload(InvalidUtf8),
    ct:pal("verify_notarization_payload with non-UTF8: ~p", [R3]),
    ?assertMatch({error, _}, R3),
    
    %% is_valid_hex_string with non-UTF8 - should return false (not crash)
    R4 = iota_notarization_nif:is_valid_hex_string(InvalidUtf8),
    ct:pal("is_valid_hex_string with non-UTF8: ~p", [R4]),
    ?assertEqual(false, R4).

%%%===================================================================
%%% Type Confusion Tests (Rustler should reject gracefully)
%%%===================================================================

wrong_type_atom_instead_of_binary(_Config) ->
    %% Pass atom where binary expected
    ?assertError(badarg, iota_did_nif:generate_did(iota)),
    ?assertError(badarg, iota_did_nif:is_valid_iota_did(some_atom)),
    ?assertError(badarg, iota_notarization_nif:hash_data(test_atom)).

wrong_type_integer_instead_of_binary(_Config) ->
    %% Pass integer where binary expected
    ?assertError(badarg, iota_did_nif:generate_did(12345)),
    ?assertError(badarg, iota_did_nif:extract_did_from_document(99999)),
    ?assertError(badarg, iota_notarization_nif:hash_data(42)).

wrong_type_list_instead_of_binary(_Config) ->
    %% Pass list where binary expected
    ?assertError(badarg, iota_did_nif:generate_did("iota")),  %% String is list!
    ?assertError(badarg, iota_did_nif:generate_did([1,2,3])),
    ?assertError(badarg, iota_notarization_nif:hash_data([<<"a">>, <<"b">>])).

wrong_type_tuple_instead_of_binary(_Config) ->
    %% Pass tuple where binary expected
    ?assertError(badarg, iota_did_nif:generate_did({network, iota})),
    ?assertError(badarg, iota_did_nif:create_did_url({did}, {fragment})).

wrong_type_pid_instead_of_binary(_Config) ->
    %% Pass PID where binary expected
    ?assertError(badarg, iota_did_nif:generate_did(self())),
    ?assertError(badarg, iota_notarization_nif:hash_data(self())).

%%%===================================================================
%%% Concurrent Stress Tests
%%%===================================================================

concurrent_did_generation(_Config) ->
    %% Spawn many processes calling generate_did simultaneously
    NumProcesses = 100,
    Parent = self(),
    
    ct:pal("Spawning ~p concurrent DID generations", [NumProcesses]),
    
    Pids = [spawn_link(fun() ->
        Result = iota_did_nif:generate_did(<<"iota">>),
        Parent ! {self(), Result}
    end) || _ <- lists:seq(1, NumProcesses)],
    
    Results = [receive {Pid, R} -> R end || Pid <- Pids],
    
    Successes = length([R || {ok, _} = R <- Results]),
    Failures = length([R || {error, _} = R <- Results]),
    
    ct:pal("Concurrent DID generation: ~p successes, ~p failures", [Successes, Failures]),
    
    %% All should succeed (no crashes)
    ?assertEqual(NumProcesses, Successes + Failures),
    ?assertEqual(NumProcesses, Successes).

concurrent_hash_operations(_Config) ->
    %% Stress test hash_data with concurrent calls
    NumProcesses = 500,
    Parent = self(),
    
    ct:pal("Spawning ~p concurrent hash operations", [NumProcesses]),
    
    Pids = [spawn_link(fun() ->
        Data = integer_to_binary(rand:uniform(1000000)),
        Hash = iota_notarization_nif:hash_data(Data),
        Parent ! {self(), is_binary(Hash) andalso byte_size(Hash) =:= 64}
    end) || _ <- lists:seq(1, NumProcesses)],
    
    Results = [receive {Pid, R} -> R end || Pid <- Pids],
    
    AllValid = lists:all(fun(R) -> R =:= true end, Results),
    ct:pal("All ~p concurrent hashes valid: ~p", [NumProcesses, AllValid]),
    ?assert(AllValid).

rapid_sequential_calls(_Config) ->
    %% Rapid fire sequential calls
    NumCalls = 1000,
    
    ct:pal("Making ~p rapid sequential calls", [NumCalls]),
    
    {Time, _} = timer:tc(fun() ->
        lists:foreach(fun(N) ->
            Data = integer_to_binary(N),
            _ = iota_notarization_nif:hash_data(Data),
            _ = iota_did_nif:is_valid_iota_did(<<"did:iota:0x", Data/binary>>)
        end, lists:seq(1, NumCalls))
    end),
    
    AvgTimeUs = Time / (NumCalls * 2),  %% 2 calls per iteration
    ct:pal("~p calls completed in ~p ms (avg ~.2f µs/call)", 
           [NumCalls * 2, Time / 1000, AvgTimeUs]),
    
    %% Sanity check - should complete
    ?assert(Time < 60000000). %% < 60 seconds

%%%===================================================================
%%% Boundary Condition Tests
%%%===================================================================

max_network_name_length(_Config) ->
    %% Test various network name lengths
    %% Short valid-ish network names may succeed (IOTA SDK accepts them)
    %% Very long network names should fail
    
    %% Test short name (may succeed, SDK is permissive)
    ShortResult = iota_did_nif:generate_did(<<"x">>),
    ct:pal("Network name length 1: ~p", [element(1, ShortResult)]),
    %% Either ok or error is acceptable, just no crash
    ?assert(element(1, ShortResult) =:= ok orelse element(1, ShortResult) =:= error),
    
    %% Test very long network names - should fail
    LongLengths = [256, 1000, 10000],
    lists:foreach(fun(Len) ->
        Name = binary:copy(<<"x">>, Len),
        Result = iota_did_nif:generate_did(Name),
        ct:pal("Network name length ~p: ~p", [Len, element(1, Result)]),
        %% Very long names should fail
        ?assertMatch({error, _}, Result)
    end, LongLengths).

single_byte_inputs(_Config) ->
    %% Test all single-byte inputs (0-255) for hash_data
    lists:foreach(fun(Byte) ->
        Input = <<Byte>>,
        Result = iota_notarization_nif:hash_data(Input),
        ?assert(is_binary(Result)),
        ?assertEqual(64, byte_size(Result))
    end, lists:seq(0, 255)),
    
    ct:pal("All 256 single-byte inputs hashed successfully").

repeated_calls_same_input(_Config) ->
    %% Call the same NIF many times with identical input
    %% Tests for any state corruption
    Input = <<"test data">>,
    NumCalls = 1000,
    
    Hashes = [iota_notarization_nif:hash_data(Input) || _ <- lists:seq(1, NumCalls)],
    
    %% All results should be identical
    UniqueHashes = lists:usort(Hashes),
    ct:pal("~p calls with same input produced ~p unique results", 
           [NumCalls, length(UniqueHashes)]),
    ?assertEqual(1, length(UniqueHashes)).

%%%===================================================================
%%% Ledger NIF Resilience Tests
%%%===================================================================

ledger_empty_node_url(_Config) ->
    %% Empty node URL and key should return error, not crash
    DummyKey = base64:encode(<<0:256>>),
    Result1 = iota_did_nif:create_and_publish_did(DummyKey, <<>>, <<>>),
    ct:pal("create_and_publish_did(key, <<>>, <<>>) = ~p", [Result1]),
    ?assertMatch({error, _}, Result1),
    
    Result2 = iota_did_nif:resolve_did(<<"did:iota:0x1234">>, <<>>),
    ct:pal("resolve_did(did, <<>>) = ~p", [Result2]),
    ?assertMatch({error, _}, Result2).

ledger_empty_did_resolve(_Config) ->
    %% Empty DID string should return error, not crash
    Result = iota_did_nif:resolve_did(<<>>, <<"http://localhost">>),
    ct:pal("resolve_did(<<>>, localhost) = ~p", [Result]),
    ?assertMatch({error, _}, Result).

ledger_non_utf8_inputs(_Config) ->
    InvalidUtf8 = <<128, 129, 130, 255>>,
    DummyKey = base64:encode(<<0:256>>),
    
    %% Non-UTF8 node URL
    R1 = iota_did_nif:create_and_publish_did(DummyKey, InvalidUtf8, <<>>),
    ct:pal("create_and_publish_did(key, non-utf8, <<>>) = ~p", [R1]),
    ?assertMatch({error, _}, R1),
    
    %% Non-UTF8 key
    R2 = iota_did_nif:create_and_publish_did(InvalidUtf8, <<"http://localhost">>, <<>>),
    ct:pal("create_and_publish_did(non-utf8 key, ...) = ~p", [R2]),
    ?assertMatch({error, _}, R2),
    
    %% Non-UTF8 DID
    R3 = iota_did_nif:resolve_did(InvalidUtf8, <<"http://localhost">>),
    ct:pal("resolve_did(non-utf8, localhost) = ~p", [R3]),
    ?assertMatch({error, _}, R3).

ledger_wrong_types(_Config) ->
    %% Pass wrong types to ledger NIFs - should raise badarg
    ?assertError(badarg, iota_did_nif:create_and_publish_did(atom, atom, atom)),
    ?assertError(badarg, iota_did_nif:resolve_did(123, 456)).

%%%===================================================================
%%% Notarization Ledger NIF Resilience Tests
%%%===================================================================

notarize_ledger_empty_inputs(_Config) ->
    %% All empty inputs should return error, not crash
    R1 = iota_notarization_nif:create_notarization(<<>>, <<>>, <<>>, <<>>),
    ct:pal("create_notarization(all empty) = ~p", [R1]),
    ?assertMatch({error, _}, R1),
    
    %% Empty key with valid-looking other params
    R2 = iota_notarization_nif:create_notarization(
        <<>>, <<"http://localhost:9000">>, <<"0x1">>, <<"some data">>),
    ct:pal("create_notarization(empty key) = ~p", [R2]),
    ?assertMatch({error, _}, R2),
    
    %% Empty description is allowed (non-required field)
    R3 = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://localhost:9000">>, <<"0x1">>, <<"some data">>, <<>>),
    ct:pal("create_notarization(empty desc) = ~p", [R3]),
    %% This may return error due to invalid key/connection — but should not crash
    ?assert(is_tuple(R3)).

notarize_ledger_non_utf8_inputs(_Config) ->
    InvalidUtf8 = <<128, 129, 130, 255>>,
    
    %% Non-UTF8 in various positions — should return error, not crash
    R1 = iota_notarization_nif:create_notarization(
        InvalidUtf8, <<"http://localhost">>, <<"0x1">>, <<"some data">>),
    ct:pal("create_notarization(non-utf8 key) = ~p", [R1]),
    ?assertMatch({error, _}, R1),
    
    R2 = iota_notarization_nif:create_notarization(
        <<"dummykey">>, InvalidUtf8, <<"0x1">>, <<"some data">>),
    ct:pal("create_notarization(non-utf8 url) = ~p", [R2]),
    ?assertMatch({error, _}, R2),
    
    R3 = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://localhost">>, InvalidUtf8, <<"some data">>),
    ct:pal("create_notarization(non-utf8 pkg_id) = ~p", [R3]),
    ?assertMatch({error, _}, R3),
    
    R4 = iota_notarization_nif:create_notarization(
        <<"dummykey">>, <<"http://localhost">>, <<"0x1">>, InvalidUtf8),
    ct:pal("create_notarization(non-utf8 state_data) = ~p", [R4]),
    ?assertMatch({error, _}, R4).

notarize_ledger_wrong_types(_Config) ->
    %% Pass wrong types — should raise badarg from Rustler
    ?assertError(badarg, iota_notarization_nif:create_notarization(
        atom, atom, atom, atom)),
    ?assertError(badarg, iota_notarization_nif:create_notarization(
        123, 456, 789, 0)).

notarize_read_empty_inputs(_Config) ->
    %% Empty inputs should return error, not crash
    R1 = iota_notarization_nif:read_notarization(<<>>, <<>>, <<>>),
    ct:pal("read_notarization(all empty) = ~p", [R1]),
    ?assertMatch({error, _}, R1),
    
    R2 = iota_notarization_nif:read_notarization(
        <<>>, <<"0x1">>, <<"0x1">>),
    ct:pal("read_notarization(empty url) = ~p", [R2]),
    ?assertMatch({error, _}, R2),
    
    R3 = iota_notarization_nif:read_notarization(
        <<"http://localhost:9000">>, <<>>, <<"0x1">>),
    ct:pal("read_notarization(empty object_id) = ~p", [R3]),
    ?assertMatch({error, _}, R3).

notarize_read_non_utf8_inputs(_Config) ->
    InvalidUtf8 = <<128, 129, 130, 255>>,
    
    R1 = iota_notarization_nif:read_notarization(
        InvalidUtf8, <<"0x1">>, <<"0x1">>),
    ct:pal("read_notarization(non-utf8 url) = ~p", [R1]),
    ?assertMatch({error, _}, R1),
    
    R2 = iota_notarization_nif:read_notarization(
        <<"http://localhost">>, InvalidUtf8, <<"0x1">>),
    ct:pal("read_notarization(non-utf8 object_id) = ~p", [R2]),
    ?assertMatch({error, _}, R2).

notarize_read_wrong_types(_Config) ->
    %% Pass wrong types — should raise badarg from Rustler
    ?assertError(badarg, iota_notarization_nif:read_notarization(atom, atom, atom)),
    ?assertError(badarg, iota_notarization_nif:read_notarization(123, 456, 789)).

%%%===================================================================
%%% Helpers
%%%===================================================================

create_nested_json(0) ->
    <<"{\"id\": \"test\"}">>;
create_nested_json(Depth) ->
    Inner = create_nested_json(Depth - 1),
    <<"{\"nested\":", Inner/binary, "}">>.
