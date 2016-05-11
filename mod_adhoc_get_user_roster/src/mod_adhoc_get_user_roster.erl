%% XEP-0133 "Get User Roster" Ad-Hoc command handler
%% (http://xmpp.org/extensions/xep-0133.html#get-user-roster)

-module(mod_adhoc_get_user_roster).
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
        ?NS_ADMINL("get-user-roster") ->
            ?ITEMS_RESULT(Allow, LNode, {error, ?ERR_FORBIDDEN});
        _ ->
            Acc
        end
    end.

get_local_items(_Host, [], Server, Lang) ->
    {result,
     [?NODE("Get User Roster", ?NS_ADMINX("get-user-roster"))
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
        ?NS_ADMINL("get-user-roster") ->
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
    ?NS_ADMINL("get-user-roster") ->
        ?INFO_COMMAND("Get User Roster", Lang);
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
    ?NS_ADMINL("get-user-roster") ->
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
        case get_user_roster_form(LServer, Lang) of
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
            case catch set_user_roster_form(From, LServer, Lang, Fields) of
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

get_user_roster_form(_Host, Lang) ->
    {result, [{xmlelement, "x", [{"xmlns", ?NS_XDATA}, {"type", "form"}],
           [?HFIELD(),
        {xmlelement, "title", [], [{xmlcdata, ?T(Lang, "Get User Roster")}]},
        {xmlelement, "field",
         [{"type", "jid-single"},
          {"label", ?T(Lang, "Jabber ID")},
          {"var", "accountjid"}],
         [{xmlelement, "required", [], []}]}
           ]}]}.

set_user_roster_form(From, Host, Lang, XData) ->
    AccountString = get_value("accountjid", XData),
    JID = jlib:string_to_jid(AccountString),
    [_|_] = JID#jid.luser,
    User = JID#jid.luser,
    Server = JID#jid.lserver,
    true = (Server == Host) orelse (get_permission_level(From) == global),
    Items = ejabberd_hooks:run_fold(roster_get, Server, [], [{User, Server}]),
    {result, [{xmlelement, "x", [{"xmlns", ?NS_XDATA}],
           [?HFIELD(),
            ?XFIELD("jid-single", "Jabber ID", "accountjid", AccountString),
            {xmlelement, "query",
               [{"xmlns", ?NS_ROSTER}],
               lists:map(fun mod_roster:item_to_xml/1, Items)}
           ]}]}.


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
