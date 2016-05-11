%% Author: avm
%% Created: 17.01.2011
%% Description: TODO: Add description to mod_privacy_web
-module(mod_privacy_web).

-behavior(gen_mod).

%%
%% Include files
%%
-include("ejabberd.hrl").
-include("jlib.hrl").
-include("web/ejabberd_http.hrl").
-include("mod_privacy.hrl").

%%
%% Exported Functions
%%
-export([start/2,
     stop/1,
     process/2
    ]).

%%
%% API Functions
%%
start(_Host, _Opts) ->
    ?DEBUG("Starting: ~p ~p", [_Host, _Opts]),
    ok.

stop(_Host) ->
    ok.

process([JidS, Action], #request{method = 'POST',
             data = Data,
             host = _Host,
             ip = _ClientIp
            }) ->
    try
    From = jlib:string_to_jid(JidS),
    #jid{user = _User, server = Server, resource = _Resource} = From,
    To = jlib:string_to_jid(Server),
    DataEl = xml_stream:parse_element(Data),
    QueryEl = {xmlelement, "query", [{"xmlns", "jabber:iq:privacy"}], [DataEl]},
    Stanza = {xmlelement, "iq", [{"type", Action}], [QueryEl]},
    process_post_request(Server, From, To, Stanza)
    catch
    error:{badmatch, _} = Error ->
        ?DEBUG("Error request processing: ~nData: ~p~nError: ~p", [Data, Error]),
        {406, [], "Error: request is rejected by service."};
    error:{Reason, _} = Error ->
        ?DEBUG("Error request processing: ~nData: ~p~nError: ~p~nStacktrace:~n~p",
               [Data, Error, erlang:get_stacktrace()]),
        {500, [], "Error: " ++ atom_to_list(Reason)};
    Error ->
        ?DEBUG("Error request processing: ~nData: ~p~nError: ~p", [Data, Error]),
        {500, [], "Error"}
    end;

process([], #request{method = 'POST',
             data = Data,
             host = Host,
             ip = _ClientIp
            }) ->
    try
    Stanza = xml_stream:parse_element(Data),
    From = jlib:string_to_jid(xml:get_tag_attr_s("from", Stanza)),
    To = jlib:string_to_jid(xml:get_tag_attr_s("to", Stanza)),
    process_post_request(Host, From, To, Stanza)
    catch
    error:{badmatch, _} = Error ->
        ?DEBUG("Error request processing: ~nData: ~p~nError: ~p", [Data, Error]),
        {406, [], "Error: request is rejected by service."};
    error:{Reason, _} = Error ->
        ?DEBUG("Error request processing: ~nData: ~p~nError: ~p~nStacktrace:~n~p",
               [Data, Error, erlang:get_stacktrace()]),
        {500, [], "Error: " ++ atom_to_list(Reason)};
    Error ->
        ?DEBUG("Error request processing: ~nData: ~p~nError: ~p", [Data, Error]),
        {500, [], "Error"}
    end;

process(Path, Request) ->
    ?DEBUG("Got request to ~p: ~p", [Path, Request]),
    {200, [], "Try POSTing a stanza."}.

%%
%% Local Functions
%%
process_post_request(Host, From, To, Stanza) ->
    {xmlelement, Name, _Attrs, _Els} = Stanza,
    ?DEBUG("Process stanza: ~p", [Stanza]),
    case Name of
        "iq" ->
            case jlib:iq_query_info(Stanza) of
                #iq{xmlns = ?NS_PRIVACY} = IQ ->
                process_privacy_iq(Host, From, To, IQ);
                _ ->
                {400, [], lists:concat(["Invalid IQ: ",  Stanza])}
            end;
        _ ->
            {400, [], lists:concat(["Invalid stanza: ",  Stanza])}
    end.

process_privacy_iq(Host, From, To, #iq{type = Type, sub_el = SubEl} = IQ) ->
    ?DEBUG("Process IQ stanza of type '~p', host ~p, from ~p, to ~p",
           [Type, Host, From, To]),
    Res =
    case Type of
        get ->
        ejabberd_hooks:run_fold(privacy_iq_get,
                                Host,
                                {error, ?ERR_FEATURE_NOT_IMPLEMENTED},
                                [From, To, IQ, #userlist{}]);
        set ->
        {xmlelement, "query", _QueryAttrs, [QueryEl | _]} = SubEl,
        {xmlelement, DataTag, _DataAttrs, _DataEls} = QueryEl,
        case DataTag of
            "active" ->
            ?DEBUG("Set active list for all resources of ~p", [From]),
            send_resources_iq(From, IQ),
            {result, ""};
            _ ->
            case ejabberd_hooks:run_fold(privacy_iq_set,
                                          Host,
                                          {error, ?ERR_FEATURE_NOT_IMPLEMENTED},
                                          [From, To, IQ]) of
                {result, R, _} -> {result, R};
                R -> R
            end
        end
    end,
    IQRes =
    case Res of
        {result, Result} ->
        IQ#iq{type = result, sub_el = Result};
        {error, Error} ->
        IQ#iq{type = error, sub_el = [SubEl, Error]}
    end,
    {200, [], jlib:iq_to_xml(IQRes)}.

send_resources_iq(#jid{luser = User, lserver = Server},
                  #iq{type = Type, sub_el = SubEl}) ->
    Fun = fun(Resource) ->
        Pid = ejabberd_sm:get_session_pid(User, Server, Resource),
        IQEl = {xmlelement, "iq",
                [{"xmlns", "jabber:client"}, {"type", atom_to_list(Type)}],
                [SubEl]},
        p1_fsm:send_event(Pid, {xmlstreamelement, IQEl})
    end,
    lists:foreach(Fun, ejabberd_sm:get_user_resources(User, Server)).