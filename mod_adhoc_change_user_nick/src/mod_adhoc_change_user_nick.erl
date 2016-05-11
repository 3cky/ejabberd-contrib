%% "Change User Nick" custom Ad-Hoc command handler

-module(mod_adhoc_change_user_nick).
-author('victor@mobileap.ru').

-behaviour(gen_mod).

%%
%% Include files
%%

-include("ejabberd.hrl").
-include("jlib.hrl").
-include("adhoc.hrl").
-include("mod_roster.hrl").

%%
%% Exported Functions
%%

-export([start/2, stop/1,
         get_local_identity/5,
         get_local_features/5,
         get_local_items/5,
         adhoc_local_items/4,
         adhoc_local_commands/4
        ]).

%%
%% API Functions
%%

start(Host, _Opts) ->
    ejabberd_hooks:add(disco_local_items, Host, ?MODULE, get_local_items, 55),
    ejabberd_hooks:add(disco_local_features, Host, ?MODULE, get_local_features, 55),
    ejabberd_hooks:add(disco_local_identity, Host, ?MODULE, get_local_identity, 55),
    ejabberd_hooks:add(adhoc_local_items, Host, ?MODULE, adhoc_local_items, 55),
    ejabberd_hooks:add(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 55),
    ok.

stop(Host) ->
    ejabberd_hooks:delete(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 55),
    ejabberd_hooks:delete(adhoc_local_items, Host, ?MODULE, adhoc_local_items, 55),
    ejabberd_hooks:delete(disco_local_identity, Host, ?MODULE, get_local_identity, 55),
    ejabberd_hooks:delete(disco_local_features, Host, ?MODULE, get_local_features, 55),
    ejabberd_hooks:delete(disco_local_items, Host, ?MODULE, get_local_items, 55),
    gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_COMMANDS).

%%
%% Local Functions
%%

%% Copied from mod_configure.erl
-define(T(Lang, Text), translate:translate(Lang, Text)).
-define(NS_ADMINX(Sub), ?NS_ADMIN++"#"++Sub).
-define(NS_ADMINL(Sub), ["http:","jabber.org","protocol","admin", Sub]).

get_permission_level(JID) ->
    case acl:match_rule(global, configure, JID) of
    allow -> global;
    deny -> vhost
    end.

tokenize(Node) -> string:tokens(Node, "/#").

%% -- Discovery of local items --

%% Copied from mod_configure.erl
-define(NODE(Name, Node),
    {xmlelement, "item",
     [{"jid", Server},
      {"name", ?T(Lang, Name)},
      {"node", Node}], []}).
-define(ITEMS_RESULT(Allow, LNode, Fallback),
    case Allow of
        deny ->
            Fallback;
        allow ->
            PermLev = get_permission_level(From),
        case get_local_items({PermLev, LServer}, LNode,
                     jlib:jid_to_string(To), Lang) of
        {result, Res} ->
            {result, Res};
        {error, Error} ->
            {error, Error}
        end
    end).

get_local_items(Acc, From, #jid{lserver = LServer} = To, "", Lang) ->
    case gen_mod:is_loaded(LServer, mod_adhoc) of
    false ->
        Acc;
    _ ->
        Items = case Acc of
            {result, Its} -> Its;
            empty -> []
            end,
        Allow = acl:match_rule(LServer, configure, From),
        case Allow of
        deny ->
            {result, Items};
        allow ->
            PermLev = get_permission_level(From),
            case get_local_items({PermLev, LServer}, [],
                     jlib:jid_to_string(To), Lang) of
            {result, Res} ->
                {result, Items ++ Res};
            {error, _Error} ->
                {result, Items}
            end
        end
    end;

get_local_items(Acc, From, #jid{lserver = LServer} = To, Node, Lang) ->
    case gen_mod:is_loaded(LServer, mod_adhoc) of
    false ->
        Acc;
    _ ->
        LNode = tokenize(Node),
        Allow = acl:match_rule(LServer, configure, From),
        case LNode of
        ?NS_ADMINL("change-user-nick") ->
            ?ITEMS_RESULT(Allow, LNode, {error, ?ERR_FORBIDDEN});
        _ ->
            Acc
        end
    end.

get_local_items(_Host, [], Server, Lang) ->
    {result,
     [?NODE("Change User Nick", ?NS_ADMINX("change-user-nick"))
     ]};

get_local_items(_Host, ["http:" | _], _Server, _Lang) ->
    {result, []}.


%% -- Discovery of local features --

%% Copied from mod_configure.erl
-define(INFO_RESULT(Allow, Feats),
    case Allow of
        deny ->
        {error, ?ERR_FORBIDDEN};
        allow ->
        {result, Feats}
    end).

get_local_features(Acc, From, #jid{lserver = LServer} = _To, Node, _Lang) ->
    case gen_mod:is_loaded(LServer, mod_adhoc) of
    false ->
        Acc;
    _ ->
        LNode = tokenize(Node),
        Allow = acl:match_rule(LServer, configure, From),
        case LNode of
        ?NS_ADMINL("change-user-nick") ->
            ?INFO_RESULT(Allow, [?NS_COMMANDS]);
        _ ->
            Acc
        end
    end.


%% -- Discovery of local identities --

%% Copied from mod_configure.erl
-define(INFO_IDENTITY(Category, Type, Name, Lang),
    [{xmlelement, "identity",
      [{"category", Category},
       {"type", Type},
       {"name", ?T(Lang, Name)}], []}]).
-define(INFO_COMMAND(Name, Lang),
    ?INFO_IDENTITY("automation", "command-node", Name, Lang)).

get_local_identity(Acc, _From, _To, Node, Lang) ->
    LNode = tokenize(Node),
    case LNode of
    ?NS_ADMINL("change-user-nick") ->
        ?INFO_COMMAND("Change User Nick", Lang);
    _ ->
        Acc
    end.

%% -- Handling of ad-hoc commands execution --

%% Copied from mod_configure.erl
-define(TVFIELD(Type, Var, Val),
    {xmlelement, "field", [{"type", Type},
                   {"var", Var}],
     [{xmlelement, "value", [], [{xmlcdata, Val}]}]}).
-define(HFIELD(), ?TVFIELD("hidden", "FORM_TYPE", ?NS_ADMIN)).
-define(XFIELD(Type, Label, Var, Val),
    {xmlelement, "field", [{"type", Type},
                   {"label", ?T(Lang, Label)},
                   {"var", Var}],
     [{xmlelement, "value", [], [{xmlcdata, Val}]}]}).
-define(COMMANDS_RESULT(LServerOrGlobal, From, To, Request),
    case acl:match_rule(LServerOrGlobal, configure, From) of
        deny ->
            {error, ?ERR_FORBIDDEN};
        allow ->
            adhoc_local_commands(From, To, Request)
    end).
get_value(Field, XData) ->
    hd(get_values(Field, XData)).
get_values(Field, XData) ->
    {value, {_, ValueList}} = lists:keysearch(Field, 1, XData),
    ValueList.

adhoc_local_commands(Acc, From, #jid{lserver = LServer} = To,
             #adhoc_request{node = Node} = Request) ->
    LNode = tokenize(Node),
    case LNode of
    ?NS_ADMINL("change-user-nick") ->
        ?COMMANDS_RESULT(LServer, From, To, Request);
    _ ->
        Acc
    end.

adhoc_local_commands(From, #jid{lserver = LServer} = _To,
             #adhoc_request{lang = Lang,
                    node = Node,
                    sessionid = SessionID,
                    action = Action,
                    xdata = XData} = Request) ->
    %% If the "action" attribute is not present, it is
    %% understood as "execute".  If there was no <actions/>
    %% element in the first response (which there isn't in our
    %% case), "execute" and "complete" are equivalent.
    ActionIsExecute = lists:member(Action,
                   ["", "execute", "complete"]),
    if  Action == "cancel" ->
        %% User cancels request
        {stop, adhoc:produce_response(
          Request,
          #adhoc_response{status = canceled})};
    XData == false, ActionIsExecute ->
        %% User requests form
        case get_change_user_nick_form(LServer, Lang) of
        {result, Form} ->
            {stop, adhoc:produce_response(
              Request,
              #adhoc_response{status = executing,
                      elements = Form})};
        {result, Status, Form} ->
            {stop, adhoc:produce_response(
              Request,
              #adhoc_response{status = Status,
                      elements = Form})};
        {error, Error} ->
            {error, Error}
        end;
    XData /= false, ActionIsExecute ->
        %% User returns form.
        case jlib:parse_xdata_submit(XData) of
        invalid ->
            {error, ?ERR_BAD_REQUEST};
        Fields ->
            case catch set_change_user_nick_form(From, LServer, Lang, Fields) of
            {result, Res} ->
                {stop, adhoc:produce_response(
                  #adhoc_response{lang = Lang,
                                  node = Node,
                          sessionid = SessionID,
                          elements = Res,
                          status = completed})};
            {'EXIT', _} ->
                {error, ?ERR_BAD_REQUEST};
            {error, Error} ->
                {error, Error}
            end
        end;
    true ->
        {error, ?ERR_BAD_REQUEST}
    end.

get_change_user_nick_form(_Host, Lang) ->
    {result, [{xmlelement, "x", [{"xmlns", ?NS_XDATA}, {"type", "form"}],
           [?HFIELD(),
                {xmlelement, "title", [], [{xmlcdata, ?T(Lang, "Change User Nick")}]},
                {xmlelement, "field",
                 [{"type", "jid-single"},
                  {"label", ?T(Lang, "User JID")},
                  {"var", "userjid"}],
                 [{xmlelement, "required", [], []}]},
                {xmlelement, "field",
                 [{"type", "text-single"},
                  {"label", ?T(Lang, "User nick")},
                  {"var", "usernick"}],
                 [{xmlelement, "required", [], []}]}
           ]}]}.

set_change_user_nick_form(From, Host, _Lang, XData) ->
    ?DEBUG("set_change_user_nick_form: ~p", [XData]),
    UserJIDString = get_value("userjid", XData),
    UserJID = jlib:string_to_jid(UserJIDString),
    [_|_] = UserJID#jid.luser,
    User = UserJID#jid.luser,
    Server = UserJID#jid.lserver,
    Nick = get_value("usernick", XData),
    true = (Server == Host) orelse (get_permission_level(From) == global),
    case change_user_nick(User, Server, UserJID, Nick) of
    ok ->
        {result, []};
    _ ->
        ?ERROR_MSG("Can't change user ~p nick to ~p", [UserJID, Nick]),
        {error, ?ERR_BAD_REQUEST}
    end.

change_user_nick(User, Server, UserJID, Nick) ->
    LUser = jlib:nodeprep(User),
    LServer = jlib:nameprep(Server),
    DBType = gen_mod:db_type(LServer, mod_roster),
    change_user_nick(LUser, LServer, UserJID, Nick, DBType).

change_user_nick(_LU, _LS, LJID, Nick, mnesia) ->
    ?ERROR_MSG("Can't change user ~p nick to ~p: not implemented for MNESIA database", [LJID, Nick]);
change_user_nick(LU, LS, LJID, Nick, odbc) ->
    RosterItems = get_roster_entries_by_jid_with_groups(LU, LS, LJID),
    lists:foreach(fun(R) ->
                {RUser, RServer} = R#roster.us,
                update_rosteritem(RUser, RServer, LU, LS, LJID, R#roster{name = Nick})
            end,
        RosterItems).

get_roster_entries_by_jid_with_groups(_LUser, LServer, LJID) ->
    SJID = ejabberd_odbc:escape(jlib:jid_to_string(LJID)),
    case catch get_roster_entries_by_jid(LServer, SJID) of
    {selected, ["username", "jid", "nick", "subscription", "ask",
            "askmessage", "server", "subscribe", "type"],
     Items} when is_list(Items) ->
        RItems = lists:flatmap(
               fun(I) ->
                   case raw_to_record(LServer, I) of
                   %% Bad JID in database:
                   error ->
                       [];
                   R ->
                       {RUser, _RServer} = R#roster.us,
                       RGroups =
                            case get_roster_groups(LServer, RUser, SJID) of
                                {selected, ["grp"], JGrps} when is_list(JGrps) ->
                                    [JGrp || {JGrp} <- JGrps];
                                _ ->
                                    []
                            end,
                       [R#roster{groups = RGroups}]
                   end
               end, Items),
        RItems;
    _ ->
        []
    end.

get_roster_entries_by_jid(LServer, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select username, jid, nick, subscription, "
        "ask, askmessage, server, subscribe, type from rosterusers "
        "where jid='", SJID, "';"]).

get_roster_groups(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select grp from rostergroups "
       "where username='", Username, "' "
       "and jid='", SJID, "';"]).

update_rosteritem(RUser, RServer, LUser, LServer, LJID, Item) ->
    ItemVals = record_to_string(Item),
    Username = ejabberd_odbc:escape(RUser),
    SJID = ejabberd_odbc:escape(jlib:jid_to_string(LJID)),
    ejabberd_odbc:sql_transaction(
        RServer,
        fun() ->
            odbc_queries:roster_subscribe(RServer, Username, SJID, ItemVals)
        end),
    push_roster_item(RUser, RServer, LUser, LServer, {add, Item#roster.name, atom_to_list(Item#roster.subscription), Item#roster.groups}).

build_iq_roster_push(Item) ->
    {xmlelement, "iq",
     [{"type", "set"}, {"id", "push"}],
     [{xmlelement, "query",
       [{"xmlns", ?NS_ROSTER}],
       [Item]
      }
     ]
    }.

%% @spec (U::string(), S::string(), Subs::atom()) -> any()
%% Subs = both | from | to | none
build_broadcast(U, S, {add, _Nick, Subs, _Group}) ->
    build_broadcast(U, S, list_to_atom(Subs));
build_broadcast(U, S, SubsAtom) when is_atom(SubsAtom) ->
    {xmlelement, "broadcast", [],
     [{item, {U, S, ""}, SubsAtom}]
    }.

%% @spec(LU, LS, U, S, Action) -> ok
%%       Action = {add, Nick, Subs, Group} | remove
%% @doc Push to the roster of account LU@LS the contact U@S.
%% The specific action to perform is defined in Action.
push_roster_item(LU, LS, U, S, Action) ->
    lists:foreach(fun(R) ->
              push_roster_item(LU, LS, R, U, S, Action)
          end, ejabberd_sm:get_user_resources(LU, LS)).

push_roster_item(LU, LS, R, U, S, Action) ->
    LJID = jlib:make_jid(LU, LS, R),
    BJID = jlib:make_jid(LU, LS, ""),
    BroadcastEl = build_broadcast(U, S, Action),
    ejabberd_router:route(BJID, LJID, BroadcastEl),
    Item = build_roster_item(U, S, Action),
    ResIQ = build_iq_roster_push(Item),
    ejabberd_router:route(BJID, LJID, ResIQ).

build_roster_item(U, S, {add, Nick, Subs, Group}) ->
    {xmlelement, "item",
     [{"jid", jlib:jid_to_string(jlib:make_jid(U, S, ""))},
      {"name", Nick},
      {"subscription", Subs}],
     [{xmlelement, "group", [], [{xmlcdata, Group}]}]
    };
build_roster_item(U, S, remove) ->
    {xmlelement, "item",
     [{"jid", jlib:jid_to_string(jlib:make_jid(U, S, ""))},
      {"subscription", "remove"}],
     []
    }.

%% Copied from mod_roster.erl

record_to_string(#roster{us = {User, _Server},
             jid = JID,
             name = Name,
             subscription = Subscription,
             ask = Ask,
             askmessage = AskMessage}) ->
    Username = ejabberd_odbc:escape(User),
    SJID = ejabberd_odbc:escape(jlib:jid_to_string(jlib:jid_tolower(JID))),
    Nick = ejabberd_odbc:escape(Name),
    SSubscription = case Subscription of
            both -> "B";
            to   -> "T";
            from -> "F";
            none -> "N"
            end,
    SAsk = case Ask of
           subscribe   -> "S";
           unsubscribe -> "U";
           both    -> "B";
           out     -> "O";
           in      -> "I";
           none    -> "N"
       end,
    SAskMessage = ejabberd_odbc:escape(AskMessage),
    [Username, SJID, Nick, SSubscription, SAsk, SAskMessage, "N", "", "item"].

raw_to_record(LServer, {User, SJID, Nick, SSubscription, SAsk, SAskMessage,
            _SServer, _SSubscribe, _SType}) ->
    case jlib:string_to_jid(SJID) of
    error ->
        error;
    JID ->
        LJID = jlib:jid_tolower(JID),
        Subscription = case SSubscription of
                   "B" -> both;
                   "T" -> to;
                   "F" -> from;
                   _ -> none
               end,
        Ask = case SAsk of
              "S" -> subscribe;
              "U" -> unsubscribe;
              "B" -> both;
              "O" -> out;
              "I" -> in;
              _ -> none
          end,
        #roster{usj = {User, LServer, LJID},
            us = {User, LServer},
            jid = LJID,
            name = Nick,
            subscription = Subscription,
            ask = Ask,
            askmessage = SAskMessage}
    end.

%% -- Handling of ad-hoc commands enumeration --

%% Copied from mod_configure.erl
adhoc_local_items(Acc, From, #jid{lserver = LServer, server = Server} = To,
          Lang) ->
    case acl:match_rule(LServer, configure, From) of
    allow ->
        Items = case Acc of
            {result, Its} -> Its;
            empty -> []
            end,
        PermLev = get_permission_level(From),
        %% Recursively get all configure commands
        Nodes = recursively_get_local_items(PermLev, LServer, "", Server,
                        Lang),
        Nodes1 = lists:filter(
               fun(N) ->
                   Nd = xml:get_tag_attr_s("node", N),
                   F = get_local_features([], From, To, Nd, Lang),
                   case F of
                   {result, [?NS_COMMANDS]} ->
                       true;
                   _ ->
                       false
                   end
               end, Nodes),
        {result, Items ++ Nodes1};
    _ ->
        Acc
    end.

recursively_get_local_items(PermLev, LServer, Node, Server, Lang) ->
    LNode = tokenize(Node),
    Items = case get_local_items({PermLev, LServer}, LNode, Server, Lang) of
        {result, Res} ->
            Res;
        {error, _Error} ->
            []
        end,
    Nodes = lists:flatten(
          lists:map(
        fun(N) ->
            S = xml:get_tag_attr_s("jid", N),
            Nd = xml:get_tag_attr_s("node", N),
            if (S /= Server) or (Nd == "") ->
                [];
               true ->
                [N, recursively_get_local_items(
                      PermLev, LServer, Nd, Server, Lang)]
            end
        end, Items)),
    Nodes.
