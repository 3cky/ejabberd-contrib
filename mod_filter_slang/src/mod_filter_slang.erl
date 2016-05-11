%% Author: avm
%% Created: 25.01.2011
%% Description: Module filter messages for slang by masking the bad words.

%% Fitered messages:
%% * outgoing private chat messages from not whitelisted to not self
%%   and to users not having sender in their rosters;
%% * outgoing MUC messages from not whitelisted and non-moderators;
%% * incoming messages from external servers.

-module(mod_filter_slang).

-behaviour(gen_mod).

-define(DEFAULT_REGEXP_FILE, "./slang_regexp.cfg").
-define(DEFAULT_SLANG_MASK, "[censored]").
-define(WHITELIST_ACL, filter_slang_whitelist).

%% Copied from mod_muc/mod_muc.erl
-record(muc_online_room, {name_host, pid}).

%%
%% Include files
%%
-include("ejabberd.hrl").
-include("jlib.hrl").
-include("mod_muc/mod_muc_room.hrl").

%%
%% Exported Functions
%%
-export([start/2,
         stop/1,
         filter_user_packet/1]).

%%
%% API Functions
%%
start(_Host, Opts) ->
    SlangFileName = gen_mod:get_opt(slang_file, Opts, ?DEFAULT_REGEXP_FILE),
    ?DEBUG("Read slang regular expression from ~p...", [SlangFileName]),
    SlangRegexpS = case read_slang_regexp_file(SlangFileName) of
        {ok, SlangRegexpRead} -> SlangRegexpRead;
        {error, ErrFileRead} ->
        ?ERROR_MSG("Can't read slang regular expression from ~p: ~p",
                   [SlangFileName, ErrFileRead]),
        ""
    end,
    ?DEBUG("Compile slang regular expression...", []),
    SlangRegexp = case re:compile(SlangRegexpS, [unicode, caseless]) of
        {ok, MP} -> MP;
        {error, ErrReCompile} ->
        ?ERROR_MSG("Can't compile slang regular expression: ~p", [ErrReCompile]),
        ""
    end,
    catch ets:new(mod_filter_slang_table, [named_table, public, {read_concurrency, true}]),
    ets:insert(mod_filter_slang_table, {slang_regexp, SlangRegexp}),
    SlangMask = gen_mod:get_opt(slang_mask, Opts, ?DEFAULT_SLANG_MASK),
    ets:insert(mod_filter_slang_table, {slang_mask, SlangMask}),
    ?DEBUG("Add filter_packet hook...", []),
    ejabberd_hooks:add(filter_packet, global, ?MODULE, filter_user_packet, 100),
    ok.

stop(_Host) ->
    ?DEBUG("Remove filter_packet hook...", []),
    ejabberd_hooks:delete(filter_packet, global, ?MODULE, filter_user_packet, 100),
    ok.

filter_user_packet({From, #jid{luser=ToUser, lserver=ToServer} = To,
                    {xmlelement, Tag, Attrs, _Els} = Packet}) ->
    if Tag == "message" ->
        case xml:get_attr_s("type", Attrs) of
            "error" -> {From, To, Packet}; %% do not filter error messages
            "groupchat" ->
            case is_whitelisted_from(From) orelse
                     case get_room_state(ToUser, ToServer) of
                         none -> true; %% MUC message _from_ room
                         RoomState -> get_role(From, RoomState) == moderator orelse
                                          is_room_persistent_private(RoomState)
                     end of
                true -> {From, To, Packet}; %% Do not filter MUC messages from room and from moderators
                false -> filter_user_message(From, To, Packet)
            end;
            _ ->
            case is_whitelisted_from(From) orelse is_presence_subscribed(To, From) of
                true -> {From, To, Packet}; %% Do not filter private messages to oneself or to subscribed
                false -> filter_user_message(From, To, Packet)
            end
        end;
        true -> {From, To, Packet} %% Do not filter non-message packets
    end.

%%
%% Local Functions
%%

%% === Slang regular expression file parser functions ===

read_slang_regexp_file(FileName) ->
    ?DEBUG("Trying to open slang regexp file: ~p", [FileName]),
    case file:open(FileName, [read, {encoding, utf8}, binary]) of
        {ok, FileDescriptor} ->
        ?DEBUG("Slang regexp file opened successfully: ~p", [FileName]),
        try
            {ok, parse_slang_regexp_file(FileDescriptor, <<>>)}
        after
            file:close(FileDescriptor)
        end;
        {error, Reason} = Error ->
        ?DEBUG("Can't open slang regexp file ~p: ~p", [FileName, Reason]),
        Error
    end.

parse_slang_regexp_file(FileDescriptor, SlangRegexpAccum) ->
    case io:get_line(FileDescriptor, "") of
        eof ->
            SlangRegexpAccum;
        Line ->
            SlangRegexpLine = parse_slang_regexp_line(Line, <<>>),
            parse_slang_regexp_file(FileDescriptor,
                                    <<SlangRegexpAccum/binary, SlangRegexpLine/binary>>)
    end.

parse_slang_regexp_line(<<"#", _Comment/binary>>, LineDataAccum) ->
    LineDataAccum;
parse_slang_regexp_line(<<"\n">>, LineDataAccum) ->
    LineDataAccum;
parse_slang_regexp_line(<<" ", Rest/binary>>, LineDataAccum) ->
    parse_slang_regexp_line(Rest, LineDataAccum);
parse_slang_regexp_line(<<"\t", Rest/binary>>, LineDataAccum) ->
    parse_slang_regexp_line(Rest, LineDataAccum);
parse_slang_regexp_line(<<Char/utf8, Rest/binary>>, LineDataAccum) ->
    parse_slang_regexp_line(Rest, <<LineDataAccum/binary, Char/utf8>>).

%% === Filtering functions ===

filter_user_message(From, To, {xmlelement, "message", Attrs, MessageEls} = Packet) ->
    ?DEBUG("filter_user_message(From=~p, To=~p, Packet=~p)", [From, To, Packet]),
    case ets:lookup(mod_filter_slang_table, slang_regexp) of
        [{slang_regexp, SlangRegexp}] ->
        FilteredPacket =
        case xml:get_path_s(Packet, [{elem, "body"}, cdata]) of
            "" -> Packet; %% do not filter empty messages
            MessageBody ->
            ?DEBUG("checking message body: ~p)", [MessageBody]),
            [{slang_mask, SlangMask}] = ets:lookup(mod_filter_slang_table, slang_mask),
            {xmlelement, "message", Attrs,
            replace_message_body(MessageEls,
                                 re:replace(MessageBody, SlangRegexp, SlangMask,
                                            [global, {return, binary}]))}
        end,
        {From, To, FilteredPacket};
        _ ->
        {From, To, Packet}
    end.

get_room_state(Name, Service) ->
    case mnesia:dirty_read(muc_online_room, {Name, Service}) of
    [R] ->
        %% Get the PID of the online room, then request its state
        Pid = R#muc_online_room.pid,
        {ok, StateData} = gen_fsm:sync_send_all_state_event(Pid, get_state),
        StateData;
    [] ->
        none
    end.

%% Copied from mod_muc_room
get_role(JID, StateData) ->
    LJID = jlib:jid_tolower(JID),
    case ?DICT:find(LJID, StateData#state.users) of
    {ok, #user{role = Role}} ->
        Role;
    _ ->
        none
    end.

is_room_persistent_private(StateData) ->
    (not (StateData#state.config)#config.public) andalso (StateData#state.config)#config.persistent.

%% Check `User` subscription to `LUser`.
%% Copied from mod_disco.
is_presence_subscribed(#jid{luser=User, lserver=Server}, #jid{luser=LUser, lserver=LServer}) ->
    lists:any(fun({roster, _, _, {TUser, TServer, _}, _, S, _, _, _, _} = RosterItem) ->
                            ?DEBUG("check roster item ~p)", [RosterItem]),
                            if
                                LUser == TUser, LServer == TServer, S/=none ->
                                    true;
                                true ->
                                    false
                            end
                    end,
                    ejabberd_hooks:run_fold(roster_get, Server, [], [{User, Server}]))
                orelse User == LUser andalso Server == LServer.

is_whitelisted_from(#jid{luser=User, lserver=Server} = From) ->
    case User of
    "" ->
        true;
    _ ->
        case acl:match_rule(Server, ?WHITELIST_ACL, From) of
        allow ->
            true;
        _ ->
            false
        end
    end.

replace_message_body({xmlelement, Tag, Attrs, _Els} = MessageEl, Body) ->
    if Tag == "body" -> {xmlelement, "body", Attrs, [{xmlcdata, Body}]};
       true -> MessageEl
    end;
replace_message_body(MessageEls, Body) ->
    ?DEBUG("replace_message_body to ~p)", [Body]),
    [replace_message_body(MessageEl, Body) || MessageEl <- MessageEls].
