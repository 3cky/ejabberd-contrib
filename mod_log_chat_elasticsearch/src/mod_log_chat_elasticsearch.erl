%%%----------------------------------------------------------------------
%%% File    : mod_log_chat_elasticsearch.erl
%%%----------------------------------------------------------------------

-module(mod_log_chat_elasticsearch).
-author('victor@antonovich.me').

-behaviour(gen_mod).

-export([start/2,
	 stop/1,
	 log_packet_send/3,
	 log_packet_receive/4]).

%-define(ejabberd_debug, true).

-include("ejabberd.hrl").
-include("jlib.hrl").

-define(PROCNAME, ?MODULE).

-define(DEFAULT_SERVER, "http://localhost:9200").
-define(DEFAULT_INDEX_PREFIX, "ejabberd-").

-define(BULK_ENDPOINT, "/_bulk").

-record(config, {server=?DEFAULT_SERVER, index_prefix=?DEFAULT_INDEX_PREFIX}).

start(Host, Opts) ->
    ?DEBUG("start: host: ~p, opts: ~p~n", [Host, Opts]),
    ibrowse:start(),
    catch ets:new(mod_log_chat_elasticsearch, [named_table, public, {read_concurrency, true}]),
    EsServer = gen_mod:get_opt(server, Opts, ?DEFAULT_SERVER),
    EsIndexPrefix = gen_mod:get_opt(index_prefix, Opts, ?DEFAULT_INDEX_PREFIX),
    ets:insert(mod_log_chat_elasticsearch, {config, #config{server=EsServer, index_prefix=EsIndexPrefix}}),
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE, log_packet_send, 55),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, log_packet_receive, 55),
    ok.

stop(Host) ->
    ejabberd_hooks:delete(user_send_packet, Host,
			  ?MODULE, log_packet_send, 55),
    ejabberd_hooks:delete(user_receive_packet, Host,
			  ?MODULE, log_packet_receive, 55),
    protets:drop(mod_log_chat_elasticsearch),
    ok.

log_packet_send(From, To, Packet) ->
    log_packet(From, To, Packet, From#jid.lserver).

log_packet_receive(_JID, From, To, _Packet) when From#jid.lserver == To#jid.lserver->
    ok; % only log at send time if the message is local to the server
log_packet_receive(_JID, From, To, Packet) ->
    log_packet(From, To, Packet, To#jid.lserver).

log_packet(From, To = #jid{luser=ToUser, lserver=ToServer}, Packet = {xmlelement, "message", Attrs, Els}, _Host) ->
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
           index_packet(From, To, Packet),
           ok
        end,
        ok;
	_ ->
        case is_invitation(Els) of
        false ->
	       index_packet(From, To, Packet);
        true ->
           ?DEBUG("dropping invite message: ~s", [xml:element_to_string(Packet)]),
           ok
        end
    end;
log_packet(_From, _To, _Packet, _Host) ->
    ok.

index_packet(From, To, Packet = {xmlelement, _, Attrs, _}) ->
    [{config, Config}] = ets:lookup(mod_log_chat_elasticsearch, config),
    ?DEBUG("index_packet: config: ~p~n", [Config]),
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
	    FromUser = From#jid.luser,
        FromServer = From#jid.lserver,
	    ToUser = To#jid.luser,
        ToServer = To#jid.lserver,
        LocalTime = calendar:local_time(),
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
        Buffer = [index_metadata(Index, Type),
                <<"\n">>,
                index_source(Timestamp, FromUser, FromServer, ToUser, ToServer, Subject, Body),
                <<"\n">>],
        flush_buffer(Config, Buffer)
    end.

flush_buffer(Config, Buffer) ->
    EsServer = Config#config.server,
    Result = ibrowse:send_req(EsServer ++ ?BULK_ENDPOINT, [], post, Buffer, []),
    case catch Result of
        {ok, "200", _, _} ->
            ok;
        Error ->
            ?ERROR_MSG("indexing error: ~p~n", [Error])
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
