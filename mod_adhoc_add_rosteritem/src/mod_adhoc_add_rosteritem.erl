%% "Add Roster Item" custom Ad-Hoc command handler

-module(mod_adhoc_add_rosteritem).
-author('victor@mobileap.ru').

-behaviour(gen_mod).

%%
%% Include files
%%

-include("ejabberd.hrl").
-include("jlib.hrl").
-include("adhoc.hrl").

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
        ?NS_ADMINL("add-rosteritem") ->
            ?ITEMS_RESULT(Allow, LNode, {error, ?ERR_FORBIDDEN});
        _ ->
            Acc
        end
    end.

get_local_items(_Host, [], Server, Lang) ->
    {result,
     [?NODE("Add Roster Item", ?NS_ADMINX("add-rosteritem"))
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
        ?NS_ADMINL("add-rosteritem") ->
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
    ?NS_ADMINL("add-rosteritem") ->
        ?INFO_COMMAND("Add Roster Item", Lang);
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
    ?NS_ADMINL("add-rosteritem") ->
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
        case get_add_rosteritem_form(LServer, Lang) of
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
            case catch set_add_rosteritem_form(From, LServer, Lang, Fields) of
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

get_add_rosteritem_form(_Host, Lang) ->
    {result, [{xmlelement, "x", [{"xmlns", ?NS_XDATA}, {"type", "form"}],
           [?HFIELD(),
                {xmlelement, "title", [], [{xmlcdata, ?T(Lang, "Add Roster Item")}]},
                {xmlelement, "field",
                 [{"type", "jid-single"},
                  {"label", ?T(Lang, "Roster JID")},
                  {"var", "rosterjid"}],
                 [{xmlelement, "required", [], []}]},
                {xmlelement, "field",
                 [{"type", "jid-single"},
                  {"label", ?T(Lang, "Item JID")},
                  {"var", "itemjid"}],
                 [{xmlelement, "required", [], []}]},
                {xmlelement, "field",
                 [{"type", "text-single"},
                  {"label", ?T(Lang, "Item nick")},
                  {"var", "itemnick"}],
                 []},
                {xmlelement, "field",
                 [{"type", "text-single"},
                  {"label", ?T(Lang, "Item group")},
                  {"var", "itemgroup"}],
                 []},
                {xmlelement, "field", [{"type", "list-single"},
                           {"label", ?T(Lang, "Items subscription type")},
                           {"var", "itemsubs"}],
                 [{xmlelement, "value", [], [{xmlcdata, "both"}]},
                  {xmlelement, "option", [{"label", "from"}],
                   [{xmlelement, "value", [], [{xmlcdata, "from"}]}]},
                  {xmlelement, "option", [{"label", "to"}],
                   [{xmlelement, "value", [], [{xmlcdata, "to"}]}]},
                  {xmlelement, "option", [{"label", "both"}],
                   [{xmlelement, "value", [], [{xmlcdata, "both"}]}]}
                 ]}
           ]}]}.

set_add_rosteritem_form(From, Host, Lang, XData) ->
    ?DEBUG("set_add_rosteritem_form: ~p", [XData]),
    RosterJIDString = get_value("rosterjid", XData),
    RosterJID = jlib:string_to_jid(RosterJIDString),
    [_|_] = RosterJID#jid.luser,
    RosterUser = RosterJID#jid.luser,
    RosterServer = RosterJID#jid.lserver,
    ItemJIDString = get_value("itemjid", XData),
    ItemJID = jlib:string_to_jid(ItemJIDString),
    [_|_] = ItemJID#jid.luser,
    ItemUser = ItemJID#jid.luser,
    ItemServer = ItemJID#jid.lserver,
    ItemNick = get_value("itemnick", XData),
    ItemGroup = get_value("itemgroup", XData),
    ItemSubs = get_value("itemsubs", XData),
    true = (RosterServer == Host) orelse (get_permission_level(From) == global),
    ?DEBUG("set_add_rosteritem_form: adding item ~p to ~p roster", [ItemUser, RosterUser]),
    case add_rosteritem(RosterUser, RosterServer, ItemUser, ItemServer, ItemNick, ItemGroup, ItemSubs) of
    ok ->
        {result, []};
    _ ->
        ?ERROR_MSG("Can't add item ~p to ~p roster", [ItemUser, RosterUser]),
        {error, ?ERR_BAD_REQUEST}
    end.

%% Copied from mod_admin_extra.erl

add_rosteritem(LocalUser, LocalServer, User, Server, Nick, Group, Subs) ->
    case add_rosteritem(LocalUser, LocalServer, User, Server, Nick, Group, list_to_atom(Subs), []) of
    {atomic, ok} ->
        push_roster_item(LocalUser, LocalServer, User, Server, {add, Nick, Subs, Group}),
        ok;
    _ ->
        error
    end.

add_rosteritem(LU, LS, User, Server, Nick, Group, Subscription, Xattrs) ->
    subscribe(LU, LS, User, Server, Nick, Group, Subscription, Xattrs).

subscribe(LU, LS, User, Server, Nick, Group, Subscription, _Xattrs) ->
    SubscriptionS = case is_atom(Subscription) of
    true -> atom_to_list(Subscription);
    false -> Subscription
    end,
    ItemEl = build_roster_item(User, Server, {add, Nick, SubscriptionS, Group}),
    {ok, M} = loaded_module(LS,[mod_roster_odbc,mod_roster]),
    M:set_items(
    LU, LS,
    {xmlelement,"query",
            [{"xmlns","jabber:iq:roster"}],
            [ItemEl]}).

loaded_module(Domain,Options) ->
    LoadedModules = gen_mod:loaded_modules(Domain),
    case lists:filter(fun(Module) ->
                              lists:member(Module, LoadedModules)
                      end, Options) of
        [M|_] -> {ok, M};
        [] -> {error,not_found}
    end.

build_iq_roster_push(Item) ->
    {xmlelement, "iq",
     [{"type", "set"}, {"id", "push"}],
     [{xmlelement, "query",
       [{"xmlns", ?NS_ROSTER}],
       [Item]
      }
     ]
    }.

build_broadcast(U, S, {add, _Nick, Subs, _Group}) ->
    build_broadcast(U, S, list_to_atom(Subs));
build_broadcast(U, S, remove) ->
    build_broadcast(U, S, none);
%% @spec (U::string(), S::string(), Subs::atom()) -> any()
%% Subs = both | from | to | none
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
    BroadcastEl = build_broadcast(U, S, Action),
    ejabberd_router:route(LJID, LJID, BroadcastEl),
    Item = build_roster_item(U, S, Action),
    ResIQ = build_iq_roster_push(Item),
    ejabberd_router:route(LJID, LJID, ResIQ).

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
