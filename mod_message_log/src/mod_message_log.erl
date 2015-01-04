%%%-------------------------------------------------------------------
%%% File    : mod_message_log.erl
%%% Author  : Holger Weiss <holger@zedat.fu-berlin.de>
%%% Purpose : Log one line per message transmission
%%% Created : 27 May 2014 by Holger Weiss <holger@zedat.fu-berlin.de>
%%%-------------------------------------------------------------------

-module(mod_message_log).
-author('holger@zedat.fu-berlin.de').

-behaviour(gen_mod).
-behaviour(gen_server).

%% gen_mod/supervisor callbacks.
-export([start_link/1,
	 start/2,
	 stop/1]).

%% gen_server callbacks.
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3]).

%% ejabberd_hooks callbacks.
-export([log_packet_send/3,
	 log_packet_receive/4,
	 log_packet_offline/3,
	 reopen_log/0]).

-include("ejabberd.hrl").
-include("jlib.hrl").

-define(PROCNAME, ?MODULE).
-define(DEFAULT_FILENAME, <<"message.log">>).
-define(FILE_MODES, [append, raw]).

-record(state, {filename = ?DEFAULT_FILENAME :: binary(),
		iodevice                     :: io:device()}).

%% -------------------------------------------------------------------
%% gen_mod/supervisor callbacks.
%% -------------------------------------------------------------------

start_link(Opts) ->
    gen_server:start_link({local, ?PROCNAME}, ?MODULE, Opts, []).

start(Host, Opts) ->
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE,
		       log_packet_send, 42),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE,
		       log_packet_receive, 42),
    ejabberd_hooks:add(offline_message_hook, Host, ?MODULE,
		       log_packet_offline, 42),
    Spec = {
	?PROCNAME,
	{?MODULE, start_link, [Opts]},
	permanent,
	3000,
	worker,
	[?MODULE]
    },
    supervisor:start_child(ejabberd_sup, Spec).

stop(Host) ->
    ejabberd_hooks:delete(user_send_packet, Host, ?MODULE,
			  log_packet_send, 42),
    ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE,
			  log_packet_receive, 42),
    ejabberd_hooks:delete(offline_message_hook, Host, ?MODULE,
			  log_packet_offline, 42),
    case supervisor:terminate_child(ejabberd_sup, ?PROCNAME) of
      ok ->
	  ok = supervisor:delete_child(ejabberd_sup, ?PROCNAME);
      {error, not_found} ->
	  ok % We just run one process per node.
    end.

%% -------------------------------------------------------------------
%% gen_server callbacks.
%% -------------------------------------------------------------------

init(Opts) ->
    process_flag(trap_exit, true),
    ejabberd_hooks:add(reopen_log_hook, ?MODULE, reopen_log, 42),
    Filename = gen_mod:get_opt(filename, Opts, fun(V) -> V end,
			       ?DEFAULT_FILENAME),
    {ok, IoDevice} = file:open(Filename, ?FILE_MODES),
    {ok, #state{filename = Filename, iodevice = IoDevice}}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast({message, Direction, From, To, Type}, #state{iodevice = IoDevice} =
	    State) ->
    write_log(IoDevice, Direction, From, To, Type),
    {noreply, State};
handle_cast(reopen_log, #state{filename = Filename, iodevice = IoDevice} =
	    State) ->
    ok = file:close(IoDevice),
    {ok, NewIoDevice} = file:open(Filename, ?FILE_MODES),
    {noreply, State#state{iodevice = NewIoDevice}};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    ejabberd_hooks:delete(reopen_log_hook, ?MODULE, reopen_log, 42),
    ok = file:close(State#state.iodevice).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% -------------------------------------------------------------------
%% ejabberd_hooks callbacks.
%% -------------------------------------------------------------------

log_packet_send(From, To, Packet) ->
    log_packet(outgoing, From, To, Packet).

log_packet_receive(JID, From, _To, Packet) ->
    log_packet(incoming, From, JID, Packet).

log_packet_offline(From, To, Packet) ->
    log_packet(offline, From, To, Packet).

reopen_log() ->
    gen_server:cast(?PROCNAME, reopen_log).

%% -------------------------------------------------------------------
%% Internal functions.
%% -------------------------------------------------------------------

log_packet(Direction, From, To, #xmlel{name = <<"message">>} = Packet) ->
    case xml:get_subtag(Packet, <<"body">>) of
      #xmlel{children = Body} when length(Body) > 0 ->
	  Type = get_message_type(Packet),
	  gen_server:cast(?PROCNAME, {message, Direction, From, To, Type});
      _ ->
	  case is_carbon(Packet) of
	    {true, OrigDirection} ->
		gen_server:cast(?PROCNAME, {message, OrigDirection, From, To,
					    carbon});
	    false ->
		ok
	  end
    end;
log_packet(_Direction, _From, _To, _Packet) ->
    ok.

get_message_type(#xmlel{attrs = Attrs}) ->
    case xml:get_attr_s(<<"type">>, Attrs) of
      <<"">> ->
	  <<"normal">>;
      Type ->
	  Type
    end.

is_carbon(Packet) ->
    {Direction, SubTag} = case {xml:get_subtag(Packet, <<"sent">>),
				xml:get_subtag(Packet, <<"received">>)} of
			    {false, false} ->
				{false, false};
			    {false, Tag} ->
				{incoming, Tag};
			    {Tag, _} ->
				{outgoing, Tag}
			  end,
    F = fun(_, false) ->
	       false;
	   (Name, Tag) ->
	       xml:get_subtag(Tag, Name)
	end,
    case lists:foldl(F, SubTag, [<<"forwarded">>, <<"message">>, <<"body">>]) of
      #xmlel{children = Body} when length(Body) > 0 ->
	  {true, Direction};
      _ ->
	  false
    end.

write_log(IoDevice, Direction, From, To, Type) ->
    Date = format_date(calendar:local_time()),
    Record = io_lib:format("~s [~s, ~s] ~s -> ~s~n",
			   [Date, Direction, Type,
			    jlib:jid_to_string(From),
			    jlib:jid_to_string(To)]),
    ok = file:write(IoDevice, [Record]).

format_date({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    Format = "~B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B",
    io_lib:format(Format, [Year, Month, Day, Hour, Minute, Second]).
