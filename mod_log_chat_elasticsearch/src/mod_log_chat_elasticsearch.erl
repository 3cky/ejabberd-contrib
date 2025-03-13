%%% Log chat messages to Elasticsearch

-module(mod_log_chat_elasticsearch).

-author('v.antonovich@gmail.com').

-behaviour(gen_mod).
-behaviour(gen_server).

%% gen_mod callbacks.
-export([start/2, stop/1, mod_opt_type/1, mod_options/1, depends/2, mod_status/0,
         mod_doc/0]).
%% gen_server callbacks.
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).
%% ejabberd_hooks callbacks.
-export([log_packet_send/1, log_packet_receive/1]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").

-define(DEFAULT_SERVER, <<"http://localhost:9200">>).
-define(DEFAULT_INDEX_PREFIX, <<"ejabberd-">>).
-define(DEFAULT_FLUSH_SIZE, 500).
-define(DEFAULT_FLUSH_TIMEOUT, 5000).

-define(BULK_ENDPOINT, "_bulk").

-record(state, {server :: binary(), 
                index_prefix :: binary(), 
                flush_size :: integer(),
                flush_timeout :: integer(),
                flush_timer_ref :: reference() | undefined}).

-type state() :: #state{}.
-type c2s_state() :: ejabberd_c2s:state().
-type c2s_hook_acc() :: {stanza() | drop, c2s_state()}.

%% -------------------------------------------------------------------
%% gen_mod callbacks
%% -------------------------------------------------------------------
-spec start(binary(), gen_mod:opts()) -> ok | {ok, pid()} | {error, term()}.
start(Host, Opts) ->
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE, log_packet_send, 42),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, log_packet_receive, 42),
    gen_mod:start_child(?MODULE, Host, Opts).

-spec stop(binary()) -> ok.
stop(Host) ->
    ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, log_packet_send, 42),
    ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, log_packet_receive, 42),
    gen_mod:stop_child(?MODULE, Host),
    ok.

-spec mod_opt_type(atom()) -> econf:validator().
mod_opt_type(server) ->
    econf:binary();
mod_opt_type(index_prefix) ->
    econf:binary();
mod_opt_type(flush_size) ->
    econf:int();
mod_opt_type(flush_timeout) ->
    econf:int().

-spec mod_options(binary()) -> [{atom(), any()}].
mod_options(_Host) ->
    [{server, ?DEFAULT_SERVER},
     {index_prefix, ?DEFAULT_INDEX_PREFIX},
     {flush_size, ?DEFAULT_FLUSH_SIZE},
     {flush_timeout, ?DEFAULT_FLUSH_TIMEOUT}].

-spec depends(binary(), gen_mod:opts()) -> [{module(), hard | soft}].
depends(_Host, _Opts) ->
    [].

mod_doc() ->
    #{}.

mod_status() ->
    "Logging to Elasticsearch is enabled. To stop logging, run the following command: \n"
    "ejabberdctl module_uninstall mod_log_chat_elasticsearch".

%% -------------------------------------------------------------------
%% gen_server callbacks
%% -------------------------------------------------------------------
-spec init(list()) -> {ok, state()}.
init([_Host, Opts]) ->
    process_flag(trap_exit, true),
    ssl:start(),
    ibrowse:start(),
    catch ets:new(mod_log_chat_elasticsearch, [named_table, public, {read_concurrency, true}]),
    EsServer = gen_mod:get_opt(server, Opts),
    EsIndexPrefix = gen_mod:get_opt(index_prefix, Opts),
    FlushSize = gen_mod:get_opt(flush_size, Opts),
    FlushTimeout = gen_mod:get_opt(flush_timeout, Opts),
    State = #state{server = EsServer, 
                   index_prefix = EsIndexPrefix, 
                   flush_size = FlushSize,
                   flush_timeout = FlushTimeout,
                   flush_timer_ref = undefined},
    buffer_reset(),
    {ok, State}.

-spec handle_call(_, {pid(), _}, state()) -> {noreply, state()}.
handle_call(_Request, _From, State) ->
    {noreply, State}.

-spec handle_cast(_, state()) -> {noreply, state()}.
handle_cast({index_message, Timestamp, From, To, Type, Subject, Body}, State) ->
    NewState = index_message(State, Timestamp, From, To, Type, Subject, Body),
    {noreply, NewState};
handle_cast(_Request, State) ->
    {noreply, State}.

-spec handle_info(timeout | flush_buffer | _, state()) -> {noreply, state()}.
handle_info(flush_buffer, State) ->
    NewState = buffer_flush(State), 
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(normal | shutdown | {shutdown, _} | _, _) -> any().
terminate(_Reason, State) ->
    buffer_flush(State),
    ok.

-spec code_change({down, _} | _, state(), _) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% -------------------------------------------------------------------
%% ejabberd_hooks callbacks
%% -------------------------------------------------------------------
-spec log_packet_send(c2s_hook_acc()) -> c2s_hook_acc().
log_packet_send({#message{} = Packet, _C2SState} = Acc) ->
    From = xmpp:get_from(Packet),
    To = xmpp:get_to(Packet),
    log_packet(From, To, Packet, From#jid.lserver),
    Acc;
log_packet_send({_Stanza, _C2SState} = Acc) ->
    Acc.

-spec log_packet_receive(c2s_hook_acc()) -> c2s_hook_acc().
log_packet_receive({#message{} = Packet, _C2SState} = Acc) ->
    From = xmpp:get_from(Packet),
    To = xmpp:get_to(Packet),
    %% only log at send time if the message is local to the server
    case From#jid.lserver == To#jid.lserver of
        true ->
            ok;
        false ->
            log_packet(From, To, Packet, To#jid.lserver)
        end,
    Acc;
log_packet_receive({_Stanza, _C2SState} = Acc) ->
    Acc.

%% -------------------------------------------------------------------
%% Internal functions
%% -------------------------------------------------------------------

log_packet(From, To, #message{type = Type} = Packet, Host) ->
    % ?DEBUG("log_packet: ~s", [fxml:element_to_binary(xmpp:encode(Packet))]),
    case Type of
        groupchat ->
            case is_muc_room(From#jid.luser, From#jid.lserver) of
                true ->
                    %% don't log messages from MUC room itself
                    ?DEBUG("dropping message from MUC room: ~s", 
                        [fxml:element_to_binary(xmpp:encode(Packet))]),
                    ok;
                false ->
                    index_packet(From, To, Packet, Host),
                    ok
            end;
        error -> %% we don't log errors
            ?DEBUG("dropping error: ~s", [fxml:element_to_binary(xmpp:encode(Packet))]),
            ok;
        _ ->
            index_packet(From, To, Packet, Host)
        end.

index_packet(From, To, #message{type = Type} = Packet, Host) ->
    {Subject, Body} = {case Packet#message.subject of
        [] ->
            <<>>;
        SubjEl ->
            xmpp:get_text(SubjEl)
        end,
        xmpp:get_text(Packet#message.body)},
    case Subject == <<>> andalso Body == <<>> of
        true -> %% don't log empty messages
            ?DEBUG("not logging empty message from ~s", [jid:encode(From)]),
            ok;
        false ->
            Timestamp = os:timestamp(),
            Proc = gen_mod:get_module_proc(Host, ?MODULE),
            gen_server:cast(Proc, {index_message, Timestamp, From, To, Type, Subject, Body})
    end.

index_message(State, Timestamp, From, To, Type, Subject, Body) ->
    % ?DEBUG("index_message: state: ~p~n", [State]),
    FromUser = From#jid.luser,
    FromServer = From#jid.lserver,
    ToUser = To#jid.luser,
    ToServer = To#jid.lserver,
    {MegaSecs, Secs, MicroSecs} = Timestamp,
    Seconds = MegaSecs * 1000000 + Secs,
    UTCDateTime = calendar:system_time_to_universal_time(Seconds, seconds),
    {{Y, M, D}, {Hour, Min, Sec}} = UTCDateTime,
    EsIndexPrefix = State#state.index_prefix,
    Index = io_lib:format("~s~B.~2..0B.~2..0B", [binary_to_list(EsIndexPrefix), Y, M, D]),
    MilliSecs = MicroSecs div 1000,
    Iso8601Timestamp = io_lib:format("~B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~3..0BZ",
        [Y, M, D, Hour, Min, Sec, MilliSecs]),
    Bulk = [index_metadata(Index),
            <<"\n">>,
            index_source(Iso8601Timestamp, Type, FromUser, FromServer, 
                ToUser, ToServer, Subject, Body),
            <<"\n">>],
    buffer_append(State, Bulk).

buffer_reset() ->
    buffer_store([]),
    ets:insert(mod_log_chat_elasticsearch, {buffer_length, 0}).

buffer_store(Buffer) ->
    ets:insert(mod_log_chat_elasticsearch, {buffer, Buffer}).

buffer_append(State, Bulk) ->
    [{buffer, Buffer}] = ets:lookup(mod_log_chat_elasticsearch, buffer),
    UpdatedBuffer = Buffer ++ Bulk,
    buffer_store(UpdatedBuffer),
    NewState = case {Buffer, State#state.flush_timer_ref} of
        {[], undefined} -> 
            %% first message in buffer, start timer
            TimerRef = erlang:send_after(State#state.flush_timeout, self(), flush_buffer),
            State#state{flush_timer_ref = TimerRef};
        _ ->
            %% buffer already has messages or timer is already running
            State
    end,
    case ets:update_counter(mod_log_chat_elasticsearch,
                            buffer_length, 1) >= State#state.flush_size of
        true ->
            buffer_flush(NewState);
        false ->
            NewState
    end.

buffer_flush(State) ->
    ?DEBUG("Flushing buffer to Elasticsearch", []),
    %% cancel flush timer if it's running
    case State#state.flush_timer_ref of
        undefined -> ok;
        TimerRef -> erlang:cancel_timer(TimerRef)
    end,
    %% send buffer to Elasticsearch and reset it
    [{buffer, Buffer}] = ets:lookup(mod_log_chat_elasticsearch, buffer),
    case Buffer of
        [] -> ok;
        _ -> buffer_send(State, Buffer)
    end,
    buffer_reset(),
    State#state{flush_timer_ref = undefined}.

buffer_send(State, Buffer) ->
    EsServer = State#state.server,
    EsUrl = lists:flatten(io_lib:format("~s/~s", [binary_to_list(EsServer), ?BULK_ENDPOINT])),
    Result = ibrowse:send_req(EsUrl, [], post, Buffer, []),
    case catch Result of
        {ok, "200", _, _} ->
            ok;
        Error ->
            ?ERROR_MSG("buffer send error: ~p~n", [Error])
    end.

index_metadata(Index) ->
    jsx:encode([{<<"index">>, [{<<"_index">>, list_to_binary(Index)}]}]).

index_source(Timestamp, Type, FromUser, FromServer, ToUser, ToServer, Subject, Body) ->
    jsx:encode([{<<"@timestamp">>, list_to_binary(Timestamp)},
                {<<"@version">>, <<"1">>},
                {<<"type">>, Type},
                {<<"from_user">>, FromUser},
                {<<"from_server">>, FromServer},
                {<<"to_user">>, ToUser},
                {<<"to_server">>, ToServer},
                {<<"subject">>, Subject},
                {<<"body">>, Body}]).

is_muc_room(Name, Host) ->
    case ets:lookup(muc_online_room, {Name, Host}) of
        [] -> false;
        [_R] -> true
    end.