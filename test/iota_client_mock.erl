%%%-------------------------------------------------------------------
%%% @doc IOTA Client Mock
%%%
%%% This module mocks IOTA mainnet behavior for testing purposes.
%%% It simulates node connections, DID publishing/resolving, and
%%% tagged data operations.
%%% @end
%%%-------------------------------------------------------------------
-module(iota_client_mock).

-behaviour(gen_server).

%% API
-export([
    start_link/0,
    stop/0,
    %% DID operations
    publish_did/1,
    resolve_did/1,
    %% Notarization operations
    send_tagged_data/2,
    get_tagged_data/1,
    %% Test helpers
    reset/0,
    get_state/0
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-record(state, {
    published_dids = #{} :: #{binary() => map()},
    tagged_data = #{} :: #{binary() => map()},
    block_counter = 0 :: non_neg_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

%% @doc Publish a DID document to the mock Tangle.
%% Returns the finalized DID with actual block ID.
-spec publish_did(Document :: map()) -> {ok, map()} | {error, term()}.
publish_did(Document) ->
    gen_server:call(?MODULE, {publish_did, Document}).

%% @doc Resolve a DID from the mock Tangle.
-spec resolve_did(Did :: binary()) -> {ok, map()} | {error, not_found}.
resolve_did(Did) ->
    gen_server:call(?MODULE, {resolve_did, Did}).

%% @doc Send tagged data (notarization) to the mock Tangle.
-spec send_tagged_data(Tag :: binary(), Payload :: binary()) -> 
    {ok, #{block_id := binary(), timestamp := non_neg_integer()}} | {error, term()}.
send_tagged_data(Tag, Payload) ->
    gen_server:call(?MODULE, {send_tagged_data, Tag, Payload}).

%% @doc Get tagged data by block ID.
-spec get_tagged_data(BlockId :: binary()) -> {ok, map()} | {error, not_found}.
get_tagged_data(BlockId) ->
    gen_server:call(?MODULE, {get_tagged_data, BlockId}).

%% @doc Reset mock state (for test isolation).
-spec reset() -> ok.
reset() ->
    gen_server:call(?MODULE, reset).

%% @doc Get current mock state (for test assertions).
-spec get_state() -> map().
get_state() ->
    gen_server:call(?MODULE, get_state).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({publish_did, Document}, _From, State) ->
    #state{published_dids = Dids, block_counter = Counter} = State,
    
    %% Generate a realistic-looking block ID
    BlockId = generate_block_id(Counter),
    
    %% Extract the placeholder DID and create the real one
    PlaceholderDid = maps:get(<<"id">>, Document, <<>>),
    RealDid = finalize_did(PlaceholderDid, BlockId),
    
    %% Update the document with the real DID
    FinalDocument = Document#{
        <<"id">> => RealDid,
        <<"block_id">> => BlockId,
        <<"published_at">> => erlang:system_time(second)
    },
    
    NewDids = Dids#{RealDid => FinalDocument},
    NewState = State#state{
        published_dids = NewDids,
        block_counter = Counter + 1
    },
    
    Result = #{
        did => RealDid,
        document => FinalDocument,
        block_id => BlockId
    },
    {reply, {ok, Result}, NewState};

handle_call({resolve_did, Did}, _From, #state{published_dids = Dids} = State) ->
    case maps:get(Did, Dids, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Document ->
            {reply, {ok, Document}, State}
    end;

handle_call({send_tagged_data, Tag, Payload}, _From, State) ->
    #state{tagged_data = Data, block_counter = Counter} = State,
    
    BlockId = generate_block_id(Counter),
    Timestamp = erlang:system_time(second),
    
    Entry = #{
        tag => Tag,
        payload => Payload,
        block_id => BlockId,
        timestamp => Timestamp
    },
    
    NewData = Data#{BlockId => Entry},
    NewState = State#state{
        tagged_data = NewData,
        block_counter = Counter + 1
    },
    
    Result = #{
        block_id => BlockId,
        timestamp => Timestamp
    },
    {reply, {ok, Result}, NewState};

handle_call({get_tagged_data, BlockId}, _From, #state{tagged_data = Data} = State) ->
    case maps:get(BlockId, Data, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        Entry ->
            {reply, {ok, Entry}, State}
    end;

handle_call(reset, _From, _State) ->
    {reply, ok, #state{}};

handle_call(get_state, _From, State) ->
    #state{published_dids = Dids, tagged_data = Data, block_counter = Counter} = State,
    Result = #{
        published_dids => Dids,
        tagged_data => Data,
        block_counter => Counter
    },
    {reply, Result, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Generate a mock block ID (looks like real IOTA block ID).
-spec generate_block_id(Counter :: non_neg_integer()) -> binary().
generate_block_id(Counter) ->
    %% Create a deterministic but realistic-looking block ID
    Hash = crypto:hash(sha256, integer_to_binary(Counter)),
    <<"0x", (binary:encode_hex(Hash))/binary>>.

%% @doc Convert a placeholder DID to a finalized DID with block reference.
-spec finalize_did(PlaceholderDid :: binary(), BlockId :: binary()) -> binary().
finalize_did(PlaceholderDid, BlockId) ->
    %% Replace the placeholder zeros with actual block-derived ID
    %% Format: did:iota:<network>:<tag> or did:iota:<tag>
    case binary:split(PlaceholderDid, <<":">>, [global]) of
        [<<"did">>, <<"iota">>, _Network, _Placeholder] ->
            %% Network-specific DID (e.g., did:iota:smr:0x...)
            [<<"did">>, <<"iota">>, Network, _] = binary:split(PlaceholderDid, <<":">>, [global]),
            TagPart = binary:part(BlockId, {2, 16}), %% Take first 16 chars after 0x
            <<"did:iota:", Network/binary, ":0x", TagPart/binary>>;
        [<<"did">>, <<"iota">>, _Placeholder] ->
            %% Mainnet DID (e.g., did:iota:0x...)
            TagPart = binary:part(BlockId, {2, 16}),
            <<"did:iota:0x", TagPart/binary>>;
        _ ->
            %% Fallback - just use the block ID
            <<"did:iota:0x", (binary:part(BlockId, {2, 16}))/binary>>
    end.
