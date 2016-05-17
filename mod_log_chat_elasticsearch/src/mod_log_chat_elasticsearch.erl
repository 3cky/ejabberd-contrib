%%%----------------------------------------------------------------------
%%% File    : mod_log_chat_elasticsearch.erl
%%%----------------------------------------------------------------------

-module(mod_log_chat_elasticsearch).
-author('victor@antonovich.me').

-behaviour(gen_mod).
-behaviour(gen_server).

%% gen_mod callbacks
-export([start_link/2,
     start/2,
	 stop/1,
	 log_packet_send/3,
	 log_packet_receive/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

%-define(ejabberd_debug, true).

-include("ejabberd.hrl").
-include("jlib.hrl").

-define(PROCNAME, ?MODULE).

-define(DEFAULT_SERVER, "http://localhost:9200").
-define(DEFAULT_INDEX_PREFIX, "ejabberd-").
-define(DEFAULT_FLUSH_SIZE, 500).

-define(BULK_ENDPOINT, "/_bulk").

-record(config, {server=?DEFAULT_SERVER, index_prefix=?DEFAULT_INDEX_PREFIX, flush_size=?DEFAULT_FLUSH_SIZE}).

%% gen_mod callbacks

start_link(Host, Opts) ->
    ?DEBUG("start_link: Host ~p, Opts ~p~n", [Host, Opts]),
    Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
    gen_server:start_link({local, Proc}, ?MODULE, [Host, Opts], []).

start(Host, Opts) ->
    ?DEBUG("starting, opts: ~p~n", [Opts]),
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE, log_packet_send, 55),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, log_packet_receive, 55),
    Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
    ChildSpec =
            {Proc,
                {?MODULE, start_link, [Host, Opts]},
                temporary,
                1000,
                worker,
                [?MODULE]},
    supervisor:start_child(ejabberd_sup, ChildSpec).

stop(Host) ->
    ?DEBUG("stopping~n", []),
    ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, log_packet_send, 55),
    ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, log_packet_receive, 55),
    Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
    gen_server:call(Proc, stop),
    supervisor:delete_child(ejabberd_sup, Proc).

%% gen_server callbacks

init([_Host, Opts]) ->
    ssl:start(),
    ibrowse:start(),
    catch ets:new(mod_log_chat_elasticsearch, [named_table, public, {read_concurrency, true}]),
    EsServer = gen_mod:get_opt(server, Opts, ?DEFAULT_SERVER),
    EsIndexPrefix = gen_mod:get_opt(index_prefix, Opts, ?DEFAULT_INDEX_PREFIX),
    FlushSize = gen_mod:get_opt(flush_size, Opts, ?DEFAULT_FLUSH_SIZE),
    Config = #config{server=EsServer, index_prefix=EsIndexPrefix, flush_size=FlushSize},
    buffer_clean(),
    {ok, Config}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.

%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast({index_message, LocalTime, From, To, Type, Subject, Body}, State) ->
    index_message(State, LocalTime, From, To, Type, Subject, Body),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% Internal functions

log_packet_send(From, To, Packet) ->
    log_packet(From, To, Packet, From#jid.lserver).

log_packet_receive(_JID, From, To, _Packet) when From#jid.lserver == To#jid.lserver->
    ok; % only log at send time if the message is local to the server
log_packet_receive(_JID, From, To, Packet) ->
    log_packet(From, To, Packet, To#jid.lserver).

log_packet(From, To = #jid{luser=ToUser, lserver=ToServer},
           Packet = {xmlelement, "message", Attrs, Els}, Host) ->
    ?DEBUG("log_packet: ~s~n", [xml:element_to_string(Packet)]),
    case xml:get_attr_s("type", Attrs) of
	"error" -> %% we don't log errors
	    ?DEBUG("dropping error: ~s", [xml:element_to_string(Packet)]),
	    ok;
    "groupchat" ->
        case is_room_exists(ToUser, ToServer) of
        false ->
           %% we don't log messages from room itself
           ?DEBUG("dropping message from room: ~s", [xml:element_to_string(Packet)]),
           ok;
        true ->
           index_packet(From, To, Packet, Host),
           ok
        end,
        ok;
	_ ->
        case is_invitation(Els) of
        false ->
	       index_packet(From, To, Packet, Host);
        true ->
           ?DEBUG("dropping invite message: ~s", [xml:element_to_string(Packet)]),
           ok
        end
    end;
log_packet(_From, _To, _Packet, _Host) ->
    ok.

index_packet(From, To, Packet = {xmlelement, _, Attrs, _}, Host) ->
    Type = xml:get_attr_s("type", Attrs),
    {Subject, Body} = {case xml:get_path_s(Packet, [{elem, "subject"}, cdata]) of
               false ->
                   "";
               Text ->
                   Text
               end,
               xml:get_path_s(Packet, [{elem, "body"}, cdata])},
    case Subject ++ Body of
        "" -> %% don't log empty messages
            ?DEBUG("not logging empty message from ~s", [jlib:jid_to_string(From)]),
            ok;
        _ ->
            LocalTime = calendar:local_time(),
            Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
            gen_server:cast(Proc, {index_message, LocalTime, From, To, Type, Subject, Body})
    end.

index_message(Config, LocalTime, From, To, Type, Subject, Body) ->
%%    ?DEBUG("index_message: config: ~p~n", [Config]),
    FromUser = From#jid.luser,
    FromServer = From#jid.lserver,
    ToUser = To#jid.luser,
    ToServer = To#jid.lserver,
    {{Yl, Ml, Dl}, _} = LocalTime,
    EsIndexPrefix = Config#config.index_prefix,
    Index = io_lib:format(EsIndexPrefix ++ "~B.~2..0B.~2..0B", [Yl, Ml, Dl]),
    {{Y, M, D}, {Hour, Min, Sec}} =
        case calendar:local_time_to_universal_time_dst(LocalTime) of
            []       -> LocalTime;
            [UTC]    -> UTC;
            [_, UTC] -> UTC
        end,
    Timestamp = io_lib:format("~B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.000Z",
                              [Y, M, D, Hour, Min, Sec]),
    Bulk = [index_metadata(Index, Type),
            <<"\n">>,
            index_source(Timestamp, FromUser, FromServer, ToUser, ToServer, Subject, Body),
            <<"\n">>],
    [{buffer, Buffer}] = ets:lookup(mod_log_chat_elasticsearch, buffer),
    UpdatedBuffer = Buffer ++ Bulk,
    case ets:update_counter(mod_log_chat_elasticsearch,
                            buffer_length, 1) >= Config#config.flush_size of
        true ->
            buffer_clean(),
            buffer_flush(Config, UpdatedBuffer);
        false ->
            buffer_store(UpdatedBuffer)
    end.

buffer_store(Buffer) ->
    ets:insert(mod_log_chat_elasticsearch, {buffer, Buffer}).

buffer_clean() ->
    buffer_store([]),
    ets:insert(mod_log_chat_elasticsearch, {buffer_length, 0}).

buffer_flush(Config, Buffer) ->
    EsServer = Config#config.server,
    Result = ibrowse:send_req(EsServer ++ ?BULK_ENDPOINT, [], post, Buffer, []),
    case catch Result of
        {ok, "200", _, _} ->
            ok;
        Error ->
            ?ERROR_MSG("buffer flush error: ~p~n", [Error])
    end.

index_metadata(Index, Type) ->
    jsx:encode([{<<"index">>, [{<<"_index">>, list_to_binary(Index)},
                               {<<"_type">>, list_to_binary(Type)}]}]).

index_source(Timestamp, FromUser, FromServer, ToUser, ToServer, Subject, Body) ->
    jsx:encode([{<<"@timestamp">>, list_to_binary(Timestamp)},
                {<<"@version">>, <<"1">>},
                {<<"from_user">>, list_to_binary(FromUser)},
                {<<"from_server">>, list_to_binary(FromServer)},
                {<<"to_user">>, list_to_binary(ToUser)},
                {<<"to_server">>, list_to_binary(ToServer)},
                {<<"subject">>, list_to_binary(Subject)},
                {<<"body">>, list_to_binary(Body)}]).

is_room_exists(Name, Service) ->
    case mnesia:dirty_read(muc_online_room, {Name, Service}) of
    [_R] ->
        true;
    [] ->
        false
    end.

%% Copied from mod_muc_room
is_invitation(Els) ->
    lists:foldl(
      fun({xmlelement, "x", Attrs, _} = El, false) ->
              case xml:get_attr_s("xmlns", Attrs) of
                  ?NS_MUC_USER ->
                      case xml:get_subtag(El, "invite") of
                          false ->
                              false;
                          _ ->
                              true
                      end;
                  _ ->
                      false
              end;
         (_, Acc) ->
              Acc
      end, false, Els).
