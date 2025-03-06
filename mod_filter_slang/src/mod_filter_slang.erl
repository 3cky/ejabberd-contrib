%% Filter messages for slang by masking the bad words matched the given regexp.
%% Fitered messages:
%% * Outgoing private chat messages in cases the sender id not whitelisted,  
%%   the recipient is not sender itself and the recipient is not in sender's roster;
%% * Outgoing MUC messages from non-whitelisted users and non-moderators;
%% * Incoming messages from the external servers.

-module(mod_filter_slang).
-author('v.antonovich@gmail.com').

-behaviour(gen_mod).

-define(DEFAULT_REGEXP_FILE, "./slang_regexp.cfg").
-define(DEFAULT_SLANG_MASK, "[censored]").
-define(WHITELIST_ACL, filter_slang_whitelist).

%%
%% Include files
%%
-include_lib("xmpp/include/xmpp.hrl").
-include("logger.hrl").
-include("mod_roster.hrl").
-include("mod_muc_room.hrl").


%% gen_mod callbacks
-export([start/2, stop/1, depends/2, mod_opt_type/1, mod_options/1, mod_doc/0, mod_status/0]).

%% API
-export([filter_user_packet/1]).

%%
%% gen_mod callbacks
%%
start(_Host, Opts) ->
    SlangFileName = case gen_mod:get_opt(slang_file, Opts) of
        auto ->
            Package = atom_to_list(?MODULE),
            filename:join([ext_mod:modules_dir(), Package, "priv", ?DEFAULT_REGEXP_FILE]);
        SFN ->
            SFN
        end,
    ?DEBUG("Reading slang regular expression from ~p...", [SlangFileName]),
    SlangRegexpS = case read_slang_regexp_file(SlangFileName) of
        {ok, SlangRegexpRead} -> SlangRegexpRead;
        {error, ErrFileRead} ->
        ?ERROR_MSG("Error reading slang regular expression from ~p: ~p",
                   [SlangFileName, ErrFileRead]),
        ""
    end,
    ?DEBUG("Compiling slang regular expression...", []),
    SlangRegexp = case re:compile(SlangRegexpS, [unicode, caseless]) of
        {ok, MP} -> MP;
        {error, ErrReCompile} ->
        ?ERROR_MSG("Error compiling slang regular expression: ~p", [ErrReCompile]),
        ""
    end,
    Heir = {heir, whereis(ext_mod), ?MODULE},
    catch ets:new(mod_filter_slang_table, [named_table, public, Heir]),
    ets:insert(mod_filter_slang_table, {slang_regexp, SlangRegexp}),
    SlangMask = case gen_mod:get_opt(slang_mask, Opts) of
        auto ->
            ?DEFAULT_SLANG_MASK;
        SM ->
            SM
        end,
    ets:insert(mod_filter_slang_table, {slang_mask, SlangMask}),
    ?DEBUG("Add filter_packet hook...", []),
    ejabberd_hooks:add(filter_packet, global, ?MODULE, filter_user_packet, 0),
    ok.

stop(_Host) ->
    ?DEBUG("Remove filter_packet hook...", []),
    ejabberd_hooks:delete(filter_packet, global, ?MODULE, filter_user_packet, 0),
    ok.

depends(_Host, _Opts) ->
    [].

mod_opt_type(slang_file) ->
    econf:either(auto, econf:file());
mod_opt_type(slang_mask) ->
    econf:either(auto, econf:string()).

-spec mod_options(binary()) -> [{atom(), any()}].
mod_options(_Host) ->
    [{slang_file, auto},
     {slang_mask, auto}].

mod_doc() -> 
    #{}.

mod_status() ->
    "Filtering slang".

%%
%% API functions
%%

filter_user_packet(drop) ->
  drop;
filter_user_packet(Pkt) ->
    From = xmpp:get_from(Pkt),
	To = xmpp:get_to(Pkt),
    Type = xmpp:get_type(Pkt),
    case Type of
        chat ->
            case is_whitelisted(From) orelse is_subscribed(To, From) of
                true -> 
                    Pkt; %% do not filter private loopback messages or to the users with subscription
                false -> 
                    filter_user_message(From, To, Pkt)
            end;
        groupchat ->
            ToUser = To#jid.luser,
	        ToServer = To#jid.lserver,
            case is_whitelisted(From) orelse
                    case get_room_state(ToUser, ToServer) of
                        none -> 
                            true; %% do not filter messages from the MUC room itself
                        RoomState -> 
                            get_participant_role(From, RoomState) == moderator
                    end of
                true -> 
                    Pkt; %% do not filter MUC messages from the room and moderators
                false -> 
                    filter_user_message(From, To, Pkt)
            end;
        _ ->
            Pkt
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

filter_user_message(From, To, Msg) ->
    Body = xmpp:get_text(Msg#message.body),
    ?DEBUG("filter_user_message: from: ~p, to: ~p, body: ~p", [From, To, Body]),
    if (Body /= <<>>) ->
        FilteredBody = filter_user_message_body(Body),
        replace_message_body(Msg, FilteredBody);
    true ->
        Msg
    end.

filter_user_message_body(Body) ->
    case ets:lookup(mod_filter_slang_table, slang_regexp) of
        [{slang_regexp, SlangRegexp}] ->
            [{slang_mask, SlangMask}] = ets:lookup(mod_filter_slang_table, slang_mask),
            re:replace(Body, SlangRegexp, SlangMask, [global, {return, binary}]);
        _ ->
            Body
    end.

replace_message_body(Msg, NewBody) ->
    ?DEBUG("replace_message_body: ~p)", [NewBody]),
    [BodyObject|_] = Msg#message.body,
    NewBodyObject = setelement(3, BodyObject, NewBody),
    Msg#message{body = [NewBodyObject]}.

is_whitelisted(#jid{luser=LUser, lserver=LServer} = From) ->
    case LUser of
    <<"">> ->
        true;
    _ ->
        case acl:match_rule(LServer, ?WHITELIST_ACL, From) of
        allow ->
            true;
        _ ->
            false
        end
    end.

%% Check `TUser` is subscribed to `FUser`
is_subscribed(#jid{luser=TUser, lserver=TServer}, #jid{luser=FUser, lserver=FServer}) ->
    lists:any(fun({roster_item, {jid, RUser, RServer, _, _, _, _}, _, _, S, _, _} = _RosterItem) ->
                            % ?DEBUG("check roster item ~p)", [RosterItem]),
                            if FUser == RUser, FServer == RServer, S /= none ->
                                    true;
                                true ->
                                    false
                            end
                    end,
                    ejabberd_hooks:run_fold(roster_get, TServer, [], [{TUser, TServer}]))
                orelse TUser == FUser andalso TServer == FServer.

get_room_state(RoomName, MucService) ->
    case mod_muc:find_online_room(RoomName, MucService) of
        {ok, RoomPid} ->
            get_room_state(RoomPid);
        error ->
            none
    end.

get_room_state(RoomPid) ->
    case mod_muc_room:get_state(RoomPid) of
        {ok, State} -> 
            State;
        {error, _} -> 
            none
    end.

get_participant_role(JID, RoomState) ->
    try maps:get(jid:tolower(JID), RoomState#state.users) of
        #user{role = Role} ->
            Role
        catch _:{badkey, _} ->
            none
    end.
