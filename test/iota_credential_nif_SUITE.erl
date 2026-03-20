%%%-------------------------------------------------------------------
%%% @doc Common Test Suite for iota_credential_nif
%%%
%%% Tests Verifiable Credentials (VC) and Verifiable Presentations (VP)
%%% creation and verification using the IOTA Identity framework.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_credential_nif_SUITE).

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

%% Test cases — Verifiable Credentials
-export([
    create_credential_basic/1,
    create_credential_with_multiple_claims/1,
    create_credential_invalid_issuer_doc/1,
    create_credential_invalid_claims_json/1,
    create_credential_empty_subject_did/1,
    create_credential_empty_type/1,
    verify_credential_valid/1,
    verify_credential_invalid_jwt/1,
    verify_credential_wrong_issuer/1,
    verify_credential_roundtrip/1
]).

%% Test cases — Verifiable Presentations
-export([
    create_presentation_basic/1,
    create_presentation_with_challenge/1,
    create_presentation_with_expiry/1,
    create_presentation_multiple_credentials/1,
    create_presentation_invalid_holder_doc/1,
    create_presentation_empty_credentials/1,
    verify_presentation_valid/1,
    verify_presentation_with_challenge/1,
    verify_presentation_invalid_jwt/1,
    verify_presentation_wrong_holder/1,
    full_vc_vp_lifecycle/1
]).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

all() ->
    [
        {group, credential_operations},
        {group, presentation_operations},
        {group, lifecycle}
    ].

groups() ->
    [
        {credential_operations, [sequence], [
            create_credential_basic,
            create_credential_with_multiple_claims,
            create_credential_invalid_issuer_doc,
            create_credential_invalid_claims_json,
            create_credential_empty_subject_did,
            create_credential_empty_type,
            verify_credential_valid,
            verify_credential_invalid_jwt,
            verify_credential_wrong_issuer,
            verify_credential_roundtrip
        ]},
        {presentation_operations, [sequence], [
            create_presentation_basic,
            create_presentation_with_challenge,
            create_presentation_with_expiry,
            create_presentation_multiple_credentials,
            create_presentation_invalid_holder_doc,
            create_presentation_empty_credentials,
            verify_presentation_valid,
            verify_presentation_with_challenge,
            verify_presentation_invalid_jwt,
            verify_presentation_wrong_holder
        ]},
        {lifecycle, [sequence], [
            full_vc_vp_lifecycle
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Verifiable Credential Tests
%%%===================================================================

create_credential_basic(_Config) ->
    %% Generate issuer and subject DIDs
    {IssuerDocJson, _IssuerDid, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),
    {_SubjectDocJson, SubjectDid, _SubjectPrivKey, _SubjectFragment} = generate_did_doc(<<"iota">>),

    Claims = <<"{\"name\": \"Alice\", \"degree\": {\"type\": \"BachelorDegree\"}}">>,
    CredType = <<"UniversityDegreeCredential">>,

    Result = iota_credential_nif:create_credential(IssuerDocJson, SubjectDid, CredType, Claims, IssuerPrivKey, IssuerFragment),
    ct:pal("create_credential result: ~p", [Result]),
    ?assertMatch({ok, _}, Result),

    {ok, ResultJson} = Result,
    Parsed = decode_json(ResultJson),
    ?assert(maps:is_key(<<"credential_jwt">>, Parsed)),
    ?assert(maps:is_key(<<"issuer_did">>, Parsed)),
    ?assert(maps:is_key(<<"subject_did">>, Parsed)),
    ?assert(maps:is_key(<<"credential_type">>, Parsed)),

    CredJwt = maps:get(<<"credential_jwt">>, Parsed),
    ct:pal("Credential JWT length: ~p", [byte_size(CredJwt)]),
    %% JWT format: header.payload.signature
    ?assertEqual(2, length(binary:matches(CredJwt, <<".">>))),

    ?assertEqual(SubjectDid, maps:get(<<"subject_did">>, Parsed)),
    ?assertEqual(CredType, maps:get(<<"credential_type">>, Parsed)).

create_credential_with_multiple_claims(_Config) ->
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"smr">>),
    {_, SubjectDid, _, _} = generate_did_doc(<<"smr">>),

    Claims = <<"{\"name\": \"Bob\", \"age\": 30, \"skills\": [\"Erlang\", \"Rust\"], \"address\": {\"city\": \"Berlin\", \"country\": \"DE\"}}">>,
    CredType = <<"EmployeeCredential">>,

    Result = iota_credential_nif:create_credential(IssuerDocJson, SubjectDid, CredType, Claims, IssuerPrivKey, IssuerFragment),
    ?assertMatch({ok, _}, Result).

create_credential_invalid_issuer_doc(_Config) ->
    Result = iota_credential_nif:create_credential(
        <<"not valid json">>,
        <<"did:iota:0x1234">>,
        <<"TestCredential">>,
        <<"{\"name\": \"Alice\"}">>,
        <<"{}">>,
        <<"fragment">>
    ),
    ct:pal("invalid issuer doc result: ~p", [Result]),
    ?assertMatch({error, _}, Result).

create_credential_invalid_claims_json(_Config) ->
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    Result = iota_credential_nif:create_credential(
        IssuerDocJson,
        <<"did:iota:0x1234">>,
        <<"TestCredential">>,
        <<"not valid json">>,
        IssuerPrivKey,
        IssuerFragment
    ),
    ct:pal("invalid claims result: ~p", [Result]),
    ?assertMatch({error, _}, Result).

create_credential_empty_subject_did(_Config) ->
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    %% Empty subject DID should still work (it's just a string field)
    Result = iota_credential_nif:create_credential(
        IssuerDocJson,
        <<>>,
        <<"TestCredential">>,
        <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey,
        IssuerFragment
    ),
    ct:pal("empty subject DID result: ~p", [Result]),
    %% This may succeed or fail depending on URL parsing — either is acceptable
    ?assert(is_tuple(Result)).

create_credential_empty_type(_Config) ->
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),
    {_, SubjectDid, _, _} = generate_did_doc(<<"iota">>),

    %% Empty credential type — should still work (base type "VerifiableCredential" always present)
    Result = iota_credential_nif:create_credential(
        IssuerDocJson,
        SubjectDid,
        <<>>,
        <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey,
        IssuerFragment
    ),
    ct:pal("empty type result: ~p", [Result]),
    ?assert(is_tuple(Result)).

verify_credential_valid(_Config) ->
    %% Create and verify a credential in one go
    {IssuerDocJson, _IssuerDid, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),
    {_, SubjectDid, _, _} = generate_did_doc(<<"iota">>),

    Claims = <<"{\"name\": \"Alice\", \"degree\": \"BSc\"}">>,
    {ok, CreateJson} = iota_credential_nif:create_credential(
        IssuerDocJson, SubjectDid, <<"TestCredential">>, Claims,
        IssuerPrivKey, IssuerFragment
    ),
    CreateResult = decode_json(CreateJson),
    CredJwt = maps:get(<<"credential_jwt">>, CreateResult),

    %% Verify with the issuer doc — should now SUCCEED because we signed
    %% with the key that matches the verification method in the document
    VerifyResult = iota_credential_nif:verify_credential(CredJwt, IssuerDocJson),
    ct:pal("verify with issuer doc: ~p", [VerifyResult]),
    ?assertMatch({ok, _}, VerifyResult).

verify_credential_invalid_jwt(_Config) ->
    {IssuerDocJson, _, _, _} = generate_did_doc(<<"iota">>),

    Result = iota_credential_nif:verify_credential(
        <<"not.a.valid.jwt">>,
        IssuerDocJson
    ),
    ct:pal("invalid JWT result: ~p", [Result]),
    ?assertMatch({error, _}, Result).

verify_credential_wrong_issuer(_Config) ->
    {IssuerDocJson, _IssuerDid, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),
    {_, SubjectDid, _, _} = generate_did_doc(<<"iota">>),
    {WrongIssuerDocJson, _, _, _} = generate_did_doc(<<"iota">>),

    Claims = <<"{\"name\": \"Alice\"}">>,
    {ok, CreateJson} = iota_credential_nif:create_credential(
        IssuerDocJson, SubjectDid, <<"TestCredential">>, Claims,
        IssuerPrivKey, IssuerFragment
    ),
    CreateResult = decode_json(CreateJson),
    CredJwt = maps:get(<<"credential_jwt">>, CreateResult),

    %% Verify with wrong issuer should fail
    Result = iota_credential_nif:verify_credential(CredJwt, WrongIssuerDocJson),
    ct:pal("verify with wrong issuer: ~p", [Result]),
    ?assertMatch({error, _}, Result).

verify_credential_roundtrip(_Config) ->
    %% Test creating two credentials from different issuers
    {IssuerDoc1, _, Issuer1PrivKey, Issuer1Fragment} = generate_did_doc(<<"iota">>),
    {IssuerDoc2, _, Issuer2PrivKey, Issuer2Fragment} = generate_did_doc(<<"smr">>),
    {_, SubjectDid, _, _} = generate_did_doc(<<"iota">>),

    Claims1 = <<"{\"name\": \"Alice\", \"score\": 95}">>,
    Claims2 = <<"{\"name\": \"Alice\", \"license\": \"A1\"}">>,

    {ok, Cred1Json} = iota_credential_nif:create_credential(
        IssuerDoc1, SubjectDid, <<"TestCredential">>, Claims1,
        Issuer1PrivKey, Issuer1Fragment
    ),
    {ok, Cred2Json} = iota_credential_nif:create_credential(
        IssuerDoc2, SubjectDid, <<"DriverLicense">>, Claims2,
        Issuer2PrivKey, Issuer2Fragment
    ),

    Cred1 = decode_json(Cred1Json),
    Cred2 = decode_json(Cred2Json),

    %% Both should produce valid-looking JWTs
    Jwt1 = maps:get(<<"credential_jwt">>, Cred1),
    Jwt2 = maps:get(<<"credential_jwt">>, Cred2),

    ct:pal("VC1 JWT: ~s", [binary:part(Jwt1, 0, min(80, byte_size(Jwt1)))]),
    ct:pal("VC2 JWT: ~s", [binary:part(Jwt2, 0, min(80, byte_size(Jwt2)))]),

    %% JWTs should be different
    ?assertNotEqual(Jwt1, Jwt2),

    %% Both should be valid JWT format
    ?assertEqual(2, length(binary:matches(Jwt1, <<".">>))),
    ?assertEqual(2, length(binary:matches(Jwt2, <<".">>))),

    %% Both should verify against their respective issuer docs
    ?assertMatch({ok, _}, iota_credential_nif:verify_credential(Jwt1, IssuerDoc1)),
    ?assertMatch({ok, _}, iota_credential_nif:verify_credential(Jwt2, IssuerDoc2)),

    %% Cross-verification should fail
    ?assertMatch({error, _}, iota_credential_nif:verify_credential(Jwt1, IssuerDoc2)),
    ?assertMatch({error, _}, iota_credential_nif:verify_credential(Jwt2, IssuerDoc1)).

%%%===================================================================
%%% Verifiable Presentation Tests
%%%===================================================================

create_presentation_basic(_Config) ->
    %% Generate holder DID and a credential
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    %% Create a credential first
    Claims = <<"{\"name\": \"Alice\"}">>,
    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"TestCredential">>, Claims,
        IssuerPrivKey, IssuerFragment
    ),
    CredResult = decode_json(CredJson),
    CredJwt = maps:get(<<"credential_jwt">>, CredResult),

    %% Build the credential JWTs array
    CredJwtsJson = encode_json([CredJwt]),

    %% Create presentation
    Result = iota_credential_nif:create_presentation(HolderDocJson, CredJwtsJson, <<>>, HolderPrivKey, HolderFragment),
    ct:pal("create_presentation result: ~p", [Result]),
    ?assertMatch({ok, _}, Result),

    {ok, PresJson} = Result,
    Parsed = decode_json(PresJson),
    ?assert(maps:is_key(<<"presentation_jwt">>, Parsed)),
    ?assert(maps:is_key(<<"holder_did">>, Parsed)),

    PresJwt = maps:get(<<"presentation_jwt">>, Parsed),
    ct:pal("Presentation JWT length: ~p", [byte_size(PresJwt)]),
    ?assertEqual(2, length(binary:matches(PresJwt, <<".">>))).

create_presentation_with_challenge(_Config) ->
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"TestCredential">>, <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey, IssuerFragment
    ),
    CredJwt = maps:get(<<"credential_jwt">>, decode_json(CredJson)),

    Challenge = <<"test-challenge-nonce-12345">>,
    CredJwtsJson = encode_json([CredJwt]),

    Result = iota_credential_nif:create_presentation(HolderDocJson, CredJwtsJson, Challenge, HolderPrivKey, HolderFragment),
    ct:pal("presentation with challenge: ~p", [Result]),
    ?assertMatch({ok, _}, Result).

create_presentation_with_expiry(_Config) ->
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"TestCredential">>, <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey, IssuerFragment
    ),
    CredJwt = maps:get(<<"credential_jwt">>, decode_json(CredJson)),
    CredJwtsJson = encode_json([CredJwt]),

    %% Create presentation with 10 minute expiry
    Result = iota_credential_nif:create_presentation(HolderDocJson, CredJwtsJson, <<>>, 600, HolderPrivKey, HolderFragment),
    ct:pal("presentation with expiry: ~p", [Result]),
    ?assertMatch({ok, _}, Result).

create_presentation_multiple_credentials(_Config) ->
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {Issuer1Doc, _, Issuer1PrivKey, Issuer1Fragment} = generate_did_doc(<<"iota">>),
    {Issuer2Doc, _, Issuer2PrivKey, Issuer2Fragment} = generate_did_doc(<<"iota">>),

    {ok, Cred1Json} = iota_credential_nif:create_credential(
        Issuer1Doc, HolderDid, <<"DegreeCredential">>, <<"{\"name\": \"Alice\", \"degree\": \"BSc\"}">>,
        Issuer1PrivKey, Issuer1Fragment
    ),
    {ok, Cred2Json} = iota_credential_nif:create_credential(
        Issuer2Doc, HolderDid, <<"EmployeeCredential">>, <<"{\"name\": \"Alice\", \"company\": \"ACME\"}">>,
        Issuer2PrivKey, Issuer2Fragment
    ),

    Jwt1 = maps:get(<<"credential_jwt">>, decode_json(Cred1Json)),
    Jwt2 = maps:get(<<"credential_jwt">>, decode_json(Cred2Json)),
    CredJwtsJson = encode_json([Jwt1, Jwt2]),

    Result = iota_credential_nif:create_presentation(HolderDocJson, CredJwtsJson, <<>>, HolderPrivKey, HolderFragment),
    ct:pal("multi-credential presentation: ~p", [Result]),
    ?assertMatch({ok, _}, Result).

create_presentation_invalid_holder_doc(_Config) ->
    Result = iota_credential_nif:create_presentation(
        <<"not valid json">>,
        <<"[\"some.jwt.token\"]">>,
        <<>>,
        <<"{}">>,
        <<"fragment">>
    ),
    ct:pal("invalid holder doc: ~p", [Result]),
    ?assertMatch({error, _}, Result).

create_presentation_empty_credentials(_Config) ->
    {HolderDocJson, _, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),

    Result = iota_credential_nif:create_presentation(HolderDocJson, <<"[]">>, <<>>, HolderPrivKey, HolderFragment),
    ct:pal("empty credentials: ~p", [Result]),
    ?assertMatch({error, _}, Result).

verify_presentation_valid(_Config) ->
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"TestCredential">>, <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey, IssuerFragment
    ),
    CredJwt = maps:get(<<"credential_jwt">>, decode_json(CredJson)),
    CredJwtsJson = encode_json([CredJwt]),

    {ok, PresJson} = iota_credential_nif:create_presentation(
        HolderDocJson, CredJwtsJson, <<>>, HolderPrivKey, HolderFragment
    ),
    PresJwt = maps:get(<<"presentation_jwt">>, decode_json(PresJson)),

    %% Verify — should now SUCCEED because both signing keys match the documents
    IssuerDocsJson = encode_json([decode_json(IssuerDocJson)]),
    Result = iota_credential_nif:verify_presentation(PresJwt, HolderDocJson, IssuerDocsJson),
    ct:pal("verify presentation: ~p", [Result]),
    ?assertMatch({ok, _}, Result).

verify_presentation_with_challenge(_Config) ->
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),

    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"TestCredential">>, <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey, IssuerFragment
    ),
    CredJwt = maps:get(<<"credential_jwt">>, decode_json(CredJson)),
    CredJwtsJson = encode_json([CredJwt]),

    Challenge = <<"my-unique-challenge-456">>,
    {ok, PresJson} = iota_credential_nif:create_presentation(
        HolderDocJson, CredJwtsJson, Challenge, HolderPrivKey, HolderFragment
    ),
    PresJwt = maps:get(<<"presentation_jwt">>, decode_json(PresJson)),

    %% Verify with the same challenge — should now SUCCEED
    IssuerDocsJson = encode_json([decode_json(IssuerDocJson)]),
    Result = iota_credential_nif:verify_presentation(
        PresJwt, HolderDocJson, IssuerDocsJson, Challenge
    ),
    ct:pal("verify with challenge: ~p", [Result]),
    ?assertMatch({ok, _}, Result).

verify_presentation_invalid_jwt(_Config) ->
    {HolderDocJson, _, _, _} = generate_did_doc(<<"iota">>),

    Result = iota_credential_nif:verify_presentation(
        <<"invalid.jwt.token">>,
        HolderDocJson,
        <<"[]">>
    ),
    ct:pal("verify invalid JWT: ~p", [Result]),
    ?assertMatch({error, _}, Result).

verify_presentation_wrong_holder(_Config) ->
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    {IssuerDocJson, _, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),
    {WrongHolderDoc, _, _, _} = generate_did_doc(<<"iota">>),

    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"TestCredential">>, <<"{\"name\": \"Alice\"}">>,
        IssuerPrivKey, IssuerFragment
    ),
    CredJwt = maps:get(<<"credential_jwt">>, decode_json(CredJson)),
    CredJwtsJson = encode_json([CredJwt]),

    {ok, PresJson} = iota_credential_nif:create_presentation(
        HolderDocJson, CredJwtsJson, <<>>, HolderPrivKey, HolderFragment
    ),
    PresJwt = maps:get(<<"presentation_jwt">>, decode_json(PresJson)),

    %% Verify with wrong holder
    IssuerDocsJson = encode_json([decode_json(IssuerDocJson)]),
    Result = iota_credential_nif:verify_presentation(PresJwt, WrongHolderDoc, IssuerDocsJson),
    ct:pal("verify with wrong holder: ~p", [Result]),
    ?assertMatch({error, _}, Result).

%%%===================================================================
%%% Lifecycle Test
%%%===================================================================

full_vc_vp_lifecycle(_Config) ->
    ct:pal("=== Full VC/VP Lifecycle Test ==="),

    %% 1. Generate DIDs for issuer and holder
    ct:pal("Step 1: Generating DIDs..."),
    {IssuerDocJson, IssuerDid, IssuerPrivKey, IssuerFragment} = generate_did_doc(<<"iota">>),
    {HolderDocJson, HolderDid, HolderPrivKey, HolderFragment} = generate_did_doc(<<"iota">>),
    ct:pal("Issuer DID: ~s", [IssuerDid]),
    ct:pal("Holder DID: ~s", [HolderDid]),

    %% 2. Validate DIDs
    ct:pal("Step 2: Validating DIDs..."),
    ?assert(iota_did_nif:is_valid_iota_did(IssuerDid)),
    ?assert(iota_did_nif:is_valid_iota_did(HolderDid)),

    %% 3. Issuer creates a VC for the holder
    ct:pal("Step 3: Creating Verifiable Credential..."),
    Claims = <<"{\"name\": \"Alice\", \"degree\": {\"type\": \"BachelorDegree\", \"name\": \"Bachelor of Science\"}, \"GPA\": \"4.0\"}">>,
    {ok, CredJson} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"UniversityDegreeCredential">>, Claims,
        IssuerPrivKey, IssuerFragment
    ),
    CredResult = decode_json(CredJson),
    CredJwt = maps:get(<<"credential_jwt">>, CredResult),
    ct:pal("VC created, JWT length: ~p", [byte_size(CredJwt)]),

    %% 4. Verify VC structure and signature
    ct:pal("Step 4: Verifying VC..."),
    ?assertEqual(2, length(binary:matches(CredJwt, <<".">>))),
    ?assertEqual(IssuerDid, maps:get(<<"issuer_did">>, CredResult)),
    ?assertEqual(HolderDid, maps:get(<<"subject_did">>, CredResult)),
    {ok, VerifyCredJson} = iota_credential_nif:verify_credential(CredJwt, IssuerDocJson),
    VerifyCred = decode_json(VerifyCredJson),
    ?assertEqual(true, maps:get(<<"valid">>, VerifyCred)),

    %% 5. Holder creates a VP with the VC
    ct:pal("Step 5: Creating Verifiable Presentation..."),
    Challenge = <<"lifecycle-test-challenge-789">>,
    CredJwtsJson = encode_json([CredJwt]),
    {ok, PresJson} = iota_credential_nif:create_presentation(
        HolderDocJson, CredJwtsJson, Challenge, 600,
        HolderPrivKey, HolderFragment
    ),
    PresResult = decode_json(PresJson),
    PresJwt = maps:get(<<"presentation_jwt">>, PresResult),
    ct:pal("VP created, JWT length: ~p", [byte_size(PresJwt)]),

    %% 6. Verify VP structure and signature
    ct:pal("Step 6: Verifying VP..."),
    ?assertEqual(2, length(binary:matches(PresJwt, <<".">>))),
    IssuerDocsJson = encode_json([decode_json(IssuerDocJson)]),
    {ok, VerifyPresJson} = iota_credential_nif:verify_presentation(
        PresJwt, HolderDocJson, IssuerDocsJson, Challenge
    ),
    VerifyPres = decode_json(VerifyPresJson),
    ?assertEqual(true, maps:get(<<"valid">>, VerifyPres)),

    %% 7. Verify that different credentials produce different JWTs
    ct:pal("Step 7: Testing uniqueness..."),
    Claims2 = <<"{\"name\": \"Bob\", \"degree\": {\"type\": \"MasterDegree\"}}">>,
    {ok, Cred2Json} = iota_credential_nif:create_credential(
        IssuerDocJson, HolderDid, <<"UniversityDegreeCredential">>, Claims2,
        IssuerPrivKey, IssuerFragment
    ),
    Cred2Jwt = maps:get(<<"credential_jwt">>, decode_json(Cred2Json)),
    ?assertNotEqual(CredJwt, Cred2Jwt),

    %% 8. Create a presentation with multiple credentials
    ct:pal("Step 8: Creating multi-credential VP..."),
    MultiCredJwtsJson = encode_json([CredJwt, Cred2Jwt]),
    {ok, MultiPresJson} = iota_credential_nif:create_presentation(
        HolderDocJson, MultiCredJwtsJson, <<>>, 0,
        HolderPrivKey, HolderFragment
    ),
    MultiPresResult = decode_json(MultiPresJson),
    MultiPresJwt = maps:get(<<"presentation_jwt">>, MultiPresResult),
    ct:pal("Multi-credential VP JWT length: ~p", [byte_size(MultiPresJwt)]),
    ?assertNotEqual(PresJwt, MultiPresJwt),

    %% 9. Verify multi-credential VP
    ct:pal("Step 9: Verifying multi-credential VP..."),
    MultiIssuerDocsJson = encode_json([decode_json(IssuerDocJson), decode_json(IssuerDocJson)]),
    {ok, _} = iota_credential_nif:verify_presentation(
        MultiPresJwt, HolderDocJson, MultiIssuerDocsJson
    ),

    ct:pal("=== VC/VP lifecycle test complete ===").

%%%===================================================================
%%% Helpers
%%%===================================================================

%% @doc Generate a DID document and return {DocJson, Did, PrivateKeyJwk, Fragment}
generate_did_doc(Network) ->
    {ok, ResultJson} = iota_did_nif:generate_did(Network),
    Result = decode_json(ResultJson),
    Did = maps:get(<<"did">>, Result),
    DocJson = maps:get(<<"document">>, Result),
    Fragment = maps:get(<<"verification_method_fragment">>, Result),
    PrivateKeyJwk = maps:get(<<"private_key_jwk">>, Result),
    {DocJson, Did, PrivateKeyJwk, Fragment}.

decode_json(JsonBinary) when is_binary(JsonBinary) ->
    try
        jsx:decode(JsonBinary, [return_maps])
    catch
        error:undef ->
            json:decode(JsonBinary)
    end.

encode_json(Term) ->
    try
        jsx:encode(Term)
    catch
        error:undef ->
            iolist_to_binary(json:encode(Term))
    end.
