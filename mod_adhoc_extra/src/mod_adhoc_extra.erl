%% Custom Ad-Hoc commands:
%% * Add Roster Item
%% * Change User Nick
%% * Get Roster Item

-module(mod_adhoc_extra).
-author('v.antonovich@gmail.com').

-behaviour(gen_mod).

%%
%% Include files
%%

-include("logger.hrl").
-include("mod_roster.hrl").
-include("translate.hrl").
-include_lib("xmpp/include/xmpp.hrl").

%%
%% Exported Functions
%%

-export([start/2, stop/1, reload/3,
         mod_options/1, depends/2, mod_doc/0,
         get_local_identity/5,
         get_local_features/5,
         get_local_items/5,
         adhoc_local_items/4,
         adhoc_local_commands/4
        ]).

%%
%% API Functions
%%

start(_Host, _Opts) ->
    {ok, [{hook, disco_local_items, get_local_items, 55},
          {hook, disco_local_features, get_local_features, 55},
          {hook, disco_local_identity, get_local_identity, 55},
          {hook, adhoc_local_items, adhoc_local_items, 55},
          {hook, adhoc_local_commands, adhoc_local_commands, 55}]}.

stop(_Host) ->
    ok.

reload(_Host, _NewOpts, _OldOpts) ->
    ok.

depends(_Host, _Opts) ->
    [{mod_adhoc, hard}].

mod_options(_) ->
    [].

mod_doc() -> 
    #{}.

%%
%% Local Functions
%%

%% Copied from mod_configure.erl
-define(INFO_IDENTITY(Category, Type, Name, Lang),
	[#identity{category = Category, type = Type, name = tr(Lang, Name)}]).

-define(INFO_COMMAND(Name, Lang),
	?INFO_IDENTITY(<<"automation">>, <<"command-node">>,
		       Name, Lang)).

-define(NODEJID(To, Name, Node),
	#disco_item{jid = To, name = tr(Lang, Name), node = Node}).

-define(NODE(Name, Node),
	#disco_item{jid = jid:make(Server),
		    node = Node,
		    name = tr(Lang, Name)}).

-define(NS_ADMINX(Sub),
	<<(?NS_ADMIN)/binary, "#", Sub/binary>>).

-define(NS_ADMINL(Sub),
	[<<"http:">>, <<"jabber.org">>, <<"protocol">>,
	 <<"admin">>, Sub]).

-spec tokenize(binary()) -> [binary()].
tokenize(Node) -> str:tokens(Node, <<"/#">>).

-spec tr(binary(), binary()) -> binary().
tr(Lang, Text) ->
    translate:translate(Lang, Text).

-spec get_value(binary(), xdata()) -> binary().
get_value(Field, XData) ->
    hd(get_values(Field, XData)).

-spec get_values(binary(), xdata()) -> [binary()].
get_values(Field, XData) ->
    xmpp_util:get_xdata_values(Field, XData).

%% -- Discovery of local items --

%% Copied from mod_configure.erl
-define(ITEMS_RESULT(Allow, LNode, Fallback),
	case Allow of
	  deny -> Fallback;
	  allow ->
	      PermLev = get_permission_level(From),
	      case get_local_items({PermLev, LServer}, LNode,
				   jid:encode(To), Lang)
		  of
		{result, Res} -> {result, Res};
		{error, Error} -> {error, Error}
	      end
	end).

-spec get_local_items(mod_disco:items_acc(), jid(), jid(),
		      binary(), binary()) -> mod_disco:items_acc().
get_local_items(Acc, From, #jid{lserver = LServer} = To,
		<<"">>, Lang) ->
    case gen_mod:is_loaded(LServer, mod_adhoc) of
      false -> Acc;
      _ ->
	  Items = case Acc of
		    {result, Its} -> Its;
		    empty -> []
		  end,
	  Allow = acl:match_rule(LServer, configure, From),
	  case Allow of
	    deny -> {result, Items};
	    allow ->
		PermLev = get_permission_level(From),
		case get_local_items({PermLev, LServer}, [],
				     jid:encode(To), Lang)
		    of
		  {result, Res} -> {result, Items ++ Res};
		  {error, _Error} -> {result, Items}
		end
	  end
    end;
get_local_items(Acc, From, #jid{lserver = LServer} = To,
		Node, Lang) ->
    case gen_mod:is_loaded(LServer, mod_adhoc) of
      false -> Acc;
      _ ->
	  LNode = tokenize(Node),
	  Allow = acl:match_rule(LServer, configure, From),
	  Err = xmpp:err_forbidden(?T("Access denied by service policy"), Lang),
	  case LNode of
	    ?NS_ADMINL(<<"add-rosteritem">>) ->
		    ?ITEMS_RESULT(Allow, LNode, {error, Err});
	    ?NS_ADMINL(<<"change-user-nick">>) ->
		    ?ITEMS_RESULT(Allow, LNode, {error, Err});
	    ?NS_ADMINL(<<"get-user-roster">>) ->
		    ?ITEMS_RESULT(Allow, LNode, {error, Err});
	    _ -> Acc
	  end
    end.

-spec get_local_items({global | vhost, binary()}, [binary()],
		      binary(), binary()) -> {result, [disco_item()]} | {error, stanza_error()}.
get_local_items(_Host, [], Server, Lang) ->
    {result, 
	[?NODE(?T("Add Roster Item"), 
		(?NS_ADMINX(<<"add-rosteritem">>))),
	 ?NODE(?T("Change User Nick"), 
		(?NS_ADMINX(<<"change-user-nick">>))),
	 ?NODE(?T("Get User Roster"), 
		(?NS_ADMINX(<<"get-user-roster">>)))]};
get_local_items(_Host, _, _Server, _Lang) ->
    {error, xmpp:err_item_not_found()}.

%% -- Discovery of local features --

%% Copied from mod_configure.erl
-define(INFO_RESULT(Allow, Feats, Lang),
	case Allow of
	  deny -> {error, xmpp:err_forbidden(?T("Access denied by service policy"), Lang)};
	  allow -> {result, Feats}
	end).

-spec get_local_features(mod_disco:features_acc(), jid(), jid(),
			 binary(), binary()) -> mod_disco:features_acc().
get_local_features(Acc, From,
		   #jid{lserver = LServer} = _To, Node, Lang) ->
    case gen_mod:is_loaded(LServer, mod_adhoc) of
      false -> Acc;
      _ ->
	  LNode = tokenize(Node),
	  Allow = acl:match_rule(LServer, configure, From),
	  case LNode of
	    ?NS_ADMINL(<<"add-rosteritem">>) ->
		    ?INFO_RESULT(Allow, [?NS_COMMANDS], Lang);
	    ?NS_ADMINL(<<"change-user-nick">>) ->
		    ?INFO_RESULT(Allow, [?NS_COMMANDS], Lang);
	    ?NS_ADMINL(<<"get-user-roster">>) ->
		    ?INFO_RESULT(Allow, [?NS_COMMANDS], Lang);
	    _ -> Acc
	  end
    end.

%% -- Discovery of local identities --

%% Copied from mod_configure.erl
-spec get_local_identity([identity()], jid(), jid(), binary(), binary()) -> [identity()].
get_local_identity(Acc, _From, _To, Node, Lang) ->
    LNode = tokenize(Node),
    case LNode of
      ?NS_ADMINL(<<"add-rosteritem">>) ->
	    ?INFO_COMMAND(?T("Add Roster Item"), Lang);
      ?NS_ADMINL(<<"change-user-nick">>) ->
	    ?INFO_COMMAND(?T("Change User Nick"), Lang);
      ?NS_ADMINL(<<"get-user-roster">>) ->
	    ?INFO_COMMAND(?T("Get User Roster"), Lang);
      _ -> Acc
    end.

%% -- Handling of ad-hoc commands execution --

%% Copied from mod_configure.erl
-define(COMMANDS_RESULT(LServerOrGlobal, From, To,
			Request, Lang),
	case acl:match_rule(LServerOrGlobal, configure, From) of
	  deny -> {error, xmpp:err_forbidden(?T("Access denied by service policy"), Lang)};
	  allow -> adhoc_local_commands(From, To, Request)
	end).

-spec adhoc_local_commands(adhoc_command(), jid(), jid(), adhoc_command()) ->
				  adhoc_command() | {error, stanza_error()}.
adhoc_local_commands(Acc, From,
		     #jid{lserver = LServer} = To,
		     #adhoc_command{node = Node, lang = Lang} = Request) ->
    LNode = tokenize(Node),
    case LNode of
      ?NS_ADMINL(_) ->
	    ?COMMANDS_RESULT(LServer, From, To, Request, Lang);
      _ -> Acc
    end.

-spec adhoc_local_commands(jid(), jid(), adhoc_command()) -> adhoc_command() | {error, stanza_error()}.
adhoc_local_commands(From,
		     #jid{lserver = LServer} = _To,
		     #adhoc_command{lang = Lang, node = Node,
				    sid = SessionID, action = Action,
				    xdata = XData} = Request) ->
    LNode = tokenize(Node),
    ActionIsExecute = Action == execute orelse Action == complete,
    if Action == cancel ->
	    #adhoc_command{status = canceled, lang = Lang,
			   node = Node, sid = SessionID};
       XData == undefined, ActionIsExecute ->
	   case get_form(LServer, LNode, Lang) of
	     {result, Form} ->
		 xmpp_util:make_adhoc_response(
		   Request,
		   #adhoc_command{status = executing, xdata = Form});
	     {result, Status, Form} ->
		 xmpp_util:make_adhoc_response(
		   Request,
		   #adhoc_command{status = Status, xdata = Form});
	     {error, Error} -> {error, Error}
	   end;
       XData /= undefined, ActionIsExecute ->
	    case set_form(From, LServer, LNode, Lang, XData) of
		{result, Res} ->
		    xmpp_util:make_adhoc_response(
		      Request,
		      #adhoc_command{xdata = Res, status = completed});
		%%{'EXIT', _} -> {error, xmpp:err_bad_request()};
		{error, Error} -> {error, Error}
	    end;
       true ->
	  {error, xmpp:err_bad_request(?T("Unexpected action"), Lang)}
    end.

-define(TVFIELD(Type, Var, Val),
	#xdata_field{type = Type, var = Var, values = [Val]}).

-define(HFIELD(),
	?TVFIELD(hidden, <<"FORM_TYPE">>, (?NS_ADMIN))).

-define(TLFIELD(Type, Label, Var),
	#xdata_field{type = Type, label = tr(Lang, Label), var = Var}).

-define(XFIELD(Type, Label, Var, Val),
	#xdata_field{type = Type, label = tr(Lang, Label),
		     var = Var, values = [Val]}).

-define(XMFIELD(Type, Label, Var, Vals),
	#xdata_field{type = Type, label = tr(Lang, Label),
		     var = Var, values = Vals}).

-spec get_form(binary(), [binary()], binary()) -> {result, xdata()} |
						  {result, completed, xdata()} |
						  {error, stanza_error()}.
get_form(_Host, ?NS_ADMINL(<<"add-rosteritem">>), Lang) ->
    {result,
     #xdata{title = tr(Lang, ?T("Add Roster Item")),
	    type = form,
	    fields = [?HFIELD(),
		      #xdata_field{type = 'jid-single',
				   label = tr(Lang, ?T("Roster JID")),
				   required = true,
				   var = <<"rosterjid">>},
		      #xdata_field{type = 'jid-single',
				   label = tr(Lang, ?T("Item JID")),
				   required = true,
				   var = <<"itemjid">>},
		      #xdata_field{type = 'text-single',
				   label = tr(Lang, ?T("Item nick")),
				   required = true,
				   var = <<"itemnick">>},
		      #xdata_field{type = 'text-single',
				   label = tr(Lang, ?T("Item group")),
				   required = false,
				   var = <<"itemgroup">>},
              #xdata_field{
                    type = 'list-single',
                    label = tr(Lang, ?T("Items subscription type")),
                    var = <<"itemsubs">>,
                    required = true,
                    options = [#xdata_option{label = tr(Lang, ?T("Both")),
                                    value = <<"both">>},
                               #xdata_option{label = tr(Lang, ?T("From")),
                                    value = <<"from">>},
                               #xdata_option{label = tr(Lang, ?T("To")),
                                    value =  <<"to">>}]}]}};
get_form(_Host, ?NS_ADMINL(<<"change-user-nick">>), Lang) ->
    {result,
     #xdata{title = tr(Lang, ?T("Change User Nick")),
	    type = form,
	    fields = [?HFIELD(),
		      #xdata_field{type = 'jid-single',
				   label = tr(Lang, ?T("User JID")),
				   required = true,
				   var = <<"userjid">>},
		      #xdata_field{type = 'text-single',
				   label = tr(Lang, ?T("User nick")),
				   required = true,
				   var = <<"usernick">>}]}};
get_form(_Host, ?NS_ADMINL(<<"get-user-roster">>), Lang) ->
    {result,
     #xdata{title = tr(Lang, ?T("Get User Roster")),
	    type = form,
	    fields = [?HFIELD(),
		      #xdata_field{type = 'jid-single',
				   label = tr(Lang, ?T("User JID")),
				   required = true,
				   var = <<"accountjid">>}]}}.                                       

-spec set_form(jid(), binary(), [binary()], binary(), xdata()) -> {result, xdata() | undefined} |
								  {error, stanza_error()}.                                                
set_form(From, Host, ?NS_ADMINL(<<"add-rosteritem">>), Lang, XData) ->
    ?DEBUG("set_form: add rosteritem: ~p", [XData]),
    RosterJIDString = get_value(<<"rosterjid">>, XData),
    RosterJID = jid:decode(RosterJIDString),
    RosterUser = RosterJID#jid.luser,
    RosterServer = RosterJID#jid.lserver,
    ItemJIDString = get_value(<<"itemjid">>, XData),
    ItemJID = jid:decode(ItemJIDString),
    ItemUser = ItemJID#jid.luser,
    ItemServer = ItemJID#jid.lserver,
    ItemNick = get_value(<<"itemnick">>, XData),
    ItemGroup = case get_values(<<"itemgroup">>, XData) of
        [] ->
            [];
        [S|_] ->
            [#xdata_field{var = <<"itemgroup">>, values = [S]}]
        end,
    ItemSubs = get_value(<<"itemsubs">>, XData),
    true = lists:member(RosterServer, ejabberd_option:hosts()),
    true = (RosterServer == Host) orelse (get_permission_level(From) == global),
    ?DEBUG("set_form: add rosteritem: adding item ~p to ~p roster with nickname ~p, group ~p and subscription ~p", 
        [ItemJID, RosterJID, ItemNick, ItemGroup, ItemSubs]),
    case add_rosteritem(RosterUser, RosterServer, ItemUser, ItemServer, ItemNick, ItemGroup, ItemSubs) of
    ok ->
        {result, undefined};
    _ ->
        ?ERROR_MSG("Can't add item ~p to ~p roster", [ItemJID, RosterJID]),
        {error, xmpp:err_bad_request(?T("Can't add roster item"), Lang)}
    end;
set_form(From, Host, ?NS_ADMINL(<<"change-user-nick">>), Lang, XData) ->
    ?DEBUG("set_form: change user nick: ~p", [XData]),
    UserJIDString = get_value(<<"userjid">>, XData),
    UserJID = jid:decode(UserJIDString),
	UserServer = UserJID#jid.lserver,
    Nick = get_value(<<"usernick">>, XData),
	true = lists:member(UserServer, ejabberd_option:hosts()),
    true = (UserServer == Host) orelse (get_permission_level(From) == global),
    case change_user_nick(Nick, UserJID) of
    ok ->
        {result, undefined};
    _ ->
        ?ERROR_MSG("Can't change user ~p nickname to ~p", [UserJID, Nick]),
        {error, xmpp:err_bad_request(?T("Can't change user nickname"), Lang)}
    end;
set_form(From, Host, ?NS_ADMINL(<<"get-user-roster">>), _Lang, XData) ->
    ?DEBUG("set_form: get user roster: ~p", [XData]),
    UserJIDString = get_value(<<"accountjid">>, XData),
    UserJID = jid:decode(UserJIDString),
	User = UserJID#jid.luser,
	Server = UserJID#jid.lserver,
	true = lists:member(Server, ejabberd_option:hosts()),
    true = (Server == Host) orelse (get_permission_level(From) == global),
	Roster = ejabberd_hooks:run_fold(roster_get, Server, [], [{User, Server}]),
	{result,
	#xdata{type = result,
		fields = [?HFIELD(),
			#xdata_field{var = <<"accountjid">>, 
				values = [UserJIDString], 
				sub_els = [#roster_query{items = make_roster_xmlrpc(Roster)}]}]}}.

change_user_nick(Nick, UserJID) ->
	?DEBUG("change user nick: user ~p, new nickname ~p", [UserJID, Nick]),
	UserRosterItems = mod_roster:process_rosteritems("list", "any", "any", "any", 
		binary_to_list(jid:encode(UserJID))),
	lists:foreach(fun(UserRosterItem) -> 
		change_roster_nick(UserRosterItem, Nick) end, UserRosterItems).

change_roster_nick({UserRosterJIDString, UserRosterContactJIDString}, Nick) ->
	UserRosterJID = jid:decode(UserRosterJIDString),
	UserRosterContactJID = jid:decode(UserRosterContactJIDString),
	RosterItem = #roster_item{jid = UserRosterContactJID, name = Nick},
	case mod_roster:set_item_and_notify_clients(UserRosterJID, RosterItem, false) of
	ok -> ok;
	_ -> error
	end.

%% Copied from mod_admin_extra.erl
add_rosteritem(LocalUser, LocalServer, User, Server, Nick, Group, Subs) when is_binary(Group) ->
    add_rosteritem(LocalUser, LocalServer, User, Server, Nick, [Group], Subs);
add_rosteritem(LocalUser, LocalServer, User, Server, Nick, Groups, Subs) ->
    case {jid:make(LocalUser, LocalServer), jid:make(User, Server)} of
	{error, _} ->
	    throw({error, "Invalid 'localuser'/'localserver'"});
	{_, error} ->
	    throw({error, "Invalid 'user'/'server'"});
	{Jid, _Jid2} ->
	    RosterItem = build_roster_item(User, Server, {add, Nick, Subs, Groups}),
	    case mod_roster:set_item_and_notify_clients(Jid, RosterItem, true) of
		ok -> ok;
		_ -> error
	    end
    end.

build_roster_item(U, S, {add, Nick, Subs, Groups}) when is_list(Groups) ->
    #roster_item{jid = jid:make(U, S),
		 name = Nick,
		 subscription = misc:binary_to_atom(Subs),
		 groups = Groups};
build_roster_item(U, S, {add, Nick, Subs, Group}) ->
    Groups = binary:split(Group,<<";">>, [global, trim]),
    #roster_item{jid = jid:make(U, S),
		 name = Nick,
		 subscription = misc:binary_to_atom(Subs),
		 groups = Groups};
build_roster_item(U, S, remove) ->
    #roster_item{jid = jid:make(U, S), subscription = remove}.

make_roster_xmlrpc(Roster) ->
    lists:map(
      fun(#roster_item{jid = JID, name = Nick, groups = Groups, subscription = Sub, ask = Ask}) ->
	    %   JIDS = jid:encode(JID),
		%   NickS = binary_to_list(Nick),
	    %   Subs = atom_to_list(Sub),
	    %   Asks = atom_to_list(Ask),
	      {roster_item, JID, Nick, Groups, Sub, Ask, undefined}
      end,
      Roster).

%% -- Handling of ad-hoc commands enumeration --

%% Copied from mod_configure.erl
-spec adhoc_local_items(mod_disco:items_acc(),
			jid(), jid(), binary()) -> mod_disco:items_acc().
adhoc_local_items(Acc, From,
		  #jid{lserver = LServer, server = Server} = To, Lang) ->
    case acl:match_rule(LServer, configure, From) of
      allow ->
	  Items = case Acc of
		    {result, Its} -> Its;
		    empty -> []
		  end,
	  PermLev = get_permission_level(From),
	  Nodes = recursively_get_local_items(PermLev, LServer,
					      <<"">>, Server, Lang),
	  Nodes1 = lists:filter(
		     fun (#disco_item{node = Nd}) ->
			     F = get_local_features(empty, From, To, Nd, Lang),
			     case F of
				 {result, [?NS_COMMANDS]} -> true;
				 _ -> false
			     end
		     end,
		     Nodes),
	  {result, Items ++ Nodes1};
      _ -> Acc
    end.

-spec recursively_get_local_items(global | vhost, binary(), binary(),
				  binary(), binary()) -> [disco_item()].
recursively_get_local_items(PermLev, LServer, Node,
			    Server, Lang) ->
    LNode = tokenize(Node),
    Items = case get_local_items({PermLev, LServer}, LNode,
				 Server, Lang)
		of
	      {result, Res} -> Res;
	      {error, _Error} -> []
	    end,
    lists:flatten(
      lists:map(
	fun(#disco_item{jid = #jid{server = S}, node = Nd} = Item) ->
		if (S /= Server) or
		   (Nd == <<"">>) ->
			[];
		   true ->
			[Item,
			 recursively_get_local_items(
			   PermLev, LServer, Nd, Server, Lang)]
		end
	end,
	Items)).

-spec get_permission_level(jid()) -> global | vhost.
get_permission_level(JID) ->
    case acl:match_rule(global, configure, JID) of
      allow -> global;
      deny -> vhost
    end.
