%%%-------------------------------------------------------------------
%%% @doc IOTA Verifiable Credentials & Presentations NIF Module
%%%
%%% This module provides functions for creating and verifying
%%% W3C Verifiable Credentials (VCs) and Verifiable Presentations (VPs)
%%% using the IOTA Identity framework.
%%%
%%% == Concepts ==
%%%
%%% <b>Verifiable Credential (VC)</b>: A tamper-evident claim made by
%%% an issuer about a subject (holder). The issuer signs the credential
%%% as a JWT using their DID document's verification method.
%%%
%%% <b>Verifiable Presentation (VP)</b>: A container for one or more
%%% VCs that the holder signs to prove control. A challenge (nonce)
%%% can be included to prevent replay attacks.
%%%
%%% == Workflow ==
%%%
%%% 1. Issuer creates a VC about a holder using `create_credential/4'
%%% 2. Issuer or anyone can verify the VC using `verify_credential/2'
%%% 3. Holder wraps VCs into a VP using `create_presentation/3,4'
%%% 4. Verifier validates the VP using `verify_presentation/3,4'
%%%
%%% == Data Formats ==
%%%
%%% All parameters are binaries. JSON inputs/outputs use binary strings.
%%% Credential claims are provided as a JSON object binary.
%%% Credential JWTs are compact JWT strings (header.payload.signature).
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(iota_credential_nif).

-include("iota_nif.hrl").

%% API exports
-export([
    %% Verifiable Credentials
    create_credential/4,
    verify_credential/2,
    %% Verifiable Presentations
    create_presentation/3,
    create_presentation/4,
    verify_presentation/3,
    verify_presentation/4
]).

%%%===================================================================
%%% API Functions - Verifiable Credentials
%%%===================================================================

%% @doc Create a Verifiable Credential (VC) as a signed JWT.
%%
%% The issuer creates and signs a credential about a subject (holder).
%% A new Ed25519 verification method is generated in the issuer's DID
%% document for signing the JWT.
%%
%% @param IssuerDocJson The issuer's DID document as a JSON binary.
%%        This should be a full DID document, e.g., from
%%        `iota_did_nif:generate_did/0,1'.
%% @param SubjectDid The DID of the credential subject (holder)
%%        as a binary (e.g., `<<"did:iota:0xabc...">>'').
%% @param CredentialType The credential type as a binary
%%        (e.g., `<<"UniversityDegreeCredential">>'').
%% @param ClaimsJson A JSON object binary containing the credential
%%        claims/properties. The `"id"' field will be automatically
%%        set to the subject DID.
%%
%% Example claims:
%% ```
%% Claims = <<"{
%%   \"name\": \"Alice\",
%%   \"degree\": {
%%     \"type\": \"BachelorDegree\",
%%     \"name\": \"Bachelor of Science and Arts\"
%%   }
%% }">>.
%% '''
%%
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`credential_jwt' - The signed credential as a JWT string</li>
%%            <li>`issuer_did' - The issuer's DID</li>
%%            <li>`subject_did' - The subject/holder's DID</li>
%%            <li>`credential_type' - The credential type</li>
%%          </ul>
%%          `{error, Reason}' on failure.
-spec create_credential(
    IssuerDocJson :: binary(), SubjectDid :: binary(),
    CredentialType :: binary(), ClaimsJson :: binary()
) ->
    {ok, binary()} | {error, binary()}.
create_credential(IssuerDocJson, SubjectDid, CredentialType, ClaimsJson) ->
    iota_nif:create_credential(IssuerDocJson, SubjectDid, CredentialType, ClaimsJson).

%% @doc Verify a Verifiable Credential JWT.
%%
%% Validates the credential's EdDSA signature using the issuer's DID
%% document, checks the credential's semantic structure, verifies that
%% the issuance date is not in the future, and that the expiration date
%% (if present) is not in the past.
%%
%% @param CredentialJwt The credential JWT string as a binary.
%% @param IssuerDocJson The issuer's DID document as a JSON binary.
%%        This must be the document of the DID that issued (signed)
%%        the credential.
%%
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`valid' - Boolean `true' (validation passed)</li>
%%            <li>`issuer_did' - The issuer's DID from the credential</li>
%%            <li>`subject_did' - The subject/holder's DID</li>
%%            <li>`claims' - The credential claims as a JSON string</li>
%%          </ul>
%%          `{error, Reason}' on failure (invalid signature, expired, etc.).
-spec verify_credential(CredentialJwt :: binary(), IssuerDocJson :: binary()) ->
    {ok, binary()} | {error, binary()}.
verify_credential(CredentialJwt, IssuerDocJson) ->
    iota_nif:verify_credential(CredentialJwt, IssuerDocJson).

%%%===================================================================
%%% API Functions - Verifiable Presentations
%%%===================================================================

%% @doc Create a Verifiable Presentation (VP) as a signed JWT.
%%
%% The holder wraps one or more credential JWTs into a presentation
%% and signs it. No challenge or expiry is set.
%%
%% @param HolderDocJson The holder's DID document as a JSON binary.
%% @param CredentialJwtsJson A JSON array binary of credential JWT
%%        strings (e.g., `<<"[\"eyJ...\", \"eyJ...\"]">>'').
%% @param Challenge A nonce/challenge binary for replay protection.
%%        Pass `<<>>' to omit.
%%
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`presentation_jwt' - The signed presentation JWT</li>
%%            <li>`holder_did' - The holder's DID</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see create_presentation/4
-spec create_presentation(
    HolderDocJson :: binary(), CredentialJwtsJson :: binary(),
    Challenge :: binary()
) ->
    {ok, binary()} | {error, binary()}.
create_presentation(HolderDocJson, CredentialJwtsJson, Challenge) ->
    create_presentation(HolderDocJson, CredentialJwtsJson, Challenge, 0).

%% @doc Create a Verifiable Presentation with expiration.
%%
%% Same as `create_presentation/3' but with an expiration time.
%%
%% @param HolderDocJson The holder's DID document as a JSON binary.
%% @param CredentialJwtsJson A JSON array of credential JWT strings.
%% @param Challenge A nonce/challenge binary. Pass `<<>>' to omit.
%% @param ExpiresInSeconds Expiration time in seconds from now.
%%        Pass `0' for no expiration.
%%
%% @returns `{ok, JsonBinary}' on success, `{error, Reason}' on failure.
-spec create_presentation(
    HolderDocJson :: binary(), CredentialJwtsJson :: binary(),
    Challenge :: binary(), ExpiresInSeconds :: non_neg_integer()
) ->
    {ok, binary()} | {error, binary()}.
create_presentation(HolderDocJson, CredentialJwtsJson, Challenge, ExpiresInSeconds) ->
    iota_nif:create_presentation(HolderDocJson, CredentialJwtsJson, Challenge, ExpiresInSeconds).

%% @doc Verify a Verifiable Presentation JWT.
%%
%% Validates the presentation's signature and structure, then validates
%% each contained credential JWT. No challenge verification is performed.
%%
%% @param PresentationJwt The presentation JWT string as a binary.
%% @param HolderDocJson The holder's DID document as a JSON binary.
%% @param IssuerDocsJson A JSON array of issuer DID documents, one per
%%        credential in the presentation (in order).
%%
%% @returns `{ok, JsonBinary}' on success. The JSON contains:
%%          <ul>
%%            <li>`valid' - Boolean `true' (validation passed)</li>
%%            <li>`holder_did' - The holder's DID</li>
%%            <li>`credential_count' - Number of credentials</li>
%%            <li>`credentials' - Array of credential JWT strings</li>
%%          </ul>
%%          `{error, Reason}' on failure.
%% @see verify_presentation/4
-spec verify_presentation(
    PresentationJwt :: binary(), HolderDocJson :: binary(),
    IssuerDocsJson :: binary()
) ->
    {ok, binary()} | {error, binary()}.
verify_presentation(PresentationJwt, HolderDocJson, IssuerDocsJson) ->
    verify_presentation(PresentationJwt, HolderDocJson, IssuerDocsJson, <<>>).

%% @doc Verify a Verifiable Presentation JWT with challenge verification.
%%
%% Same as `verify_presentation/3' but also verifies that the presentation
%% was signed with the expected challenge (nonce) to prevent replay attacks.
%%
%% @param PresentationJwt The presentation JWT string as a binary.
%% @param HolderDocJson The holder's DID document as a JSON binary.
%% @param IssuerDocsJson A JSON array of issuer DID documents.
%% @param Challenge The expected challenge/nonce binary.
%%        Pass `<<>>' to skip challenge verification.
%%
%% @returns `{ok, JsonBinary}' on success, `{error, Reason}' on failure.
-spec verify_presentation(
    PresentationJwt :: binary(), HolderDocJson :: binary(),
    IssuerDocsJson :: binary(), Challenge :: binary()
) ->
    {ok, binary()} | {error, binary()}.
verify_presentation(PresentationJwt, HolderDocJson, IssuerDocsJson, Challenge) ->
    iota_nif:verify_presentation(PresentationJwt, HolderDocJson, IssuerDocsJson, Challenge).
