-module(rebar3_hex_key).

-export([init/1,
         do/1,
         format_error/1]).

-include("rebar3_hex.hrl").

-define(PROVIDER, key).
-define(DEPS, []).

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([{name, ?PROVIDER},
                                 {module, ?MODULE},
                                 {namespace, hex},
                                 {bare, true},
                                 {deps, ?DEPS},
                                 {example, "rebar3 hex key [generate -k <key> | list | revoke -k <key> | revoke --all]"},
                                 {short_desc, "Remove or list API keys associated with your account"},
                                 {desc, ""},
                                 {opts, [
                                         {all, $a, "all", boolean, "all."},
                                         {keyname, $k, "key-name", string, "key-name"},
                                         {permission, $p, "permission", list, "perms."},
                                         rebar3_hex:repo_opt()
                                        ]
                                 }]),
    State1 = rebar_state:add_provider(State, Provider),
    {ok, State1}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, term()}.
do(State) ->
    case rebar3_hex_config:repo(State) of
        {ok, Repo} ->
            TaskArgs = rebar3_hex:task_args(State),
            handle_command(TaskArgs, State, Repo);
        {error, Reason} ->
            ?PRV_ERROR(Reason)
    end.

handle_command({"generate", Params}, State, Repo) ->
    case rebar3_hex_config:hex_config_write(Repo) of
        {ok, Config} ->
            generate(State, Config, Params);
        Err ->
            ?PRV_ERROR(Err)
    end;

handle_command({"fetch", Params}, State, Repo) ->
    case rebar3_hex_config:hex_config_read(Repo) of
        {ok, Config} ->
            case Params of
                [{keyname, KeyName}] ->
                    fetch(State, Config, KeyName);
                [] ->
                    ?PRV_ERROR({fetch, missing_required_params})
            end;
        Err ->
            ?PRV_ERROR(Err)
    end;

handle_command({"list", _Params},  State, Repo) ->
    case rebar3_hex_config:hex_config_read(Repo) of
        {ok, Config} ->
            list(State, Config);
        Err ->
            ?PRV_ERROR(Err)
    end;

handle_command({"revoke", Params}, State, Repo) ->
    case rebar3_hex_config:hex_config_write(Repo) of
        {ok, Config} ->
            case Params of
               [{all,true}]  ->
                    revoke_all(State, Config);
               [{keyname, KeyName}] ->
                    revoke(State, Config, KeyName);
               _ ->
                 ?PRV_ERROR({revoke, unsupported_params})
            end;
        Err ->
            ?PRV_ERROR(Err)
    end;

handle_command(_, _, _) ->
    ?PRV_ERROR(bad_command).

generate(State, HexConfig, Params) ->
    Perms = gather_permissions(proplists:get_all_values(permission, Params)),
    KeyName =  proplists:get_value(keyname, Params, undefined),
    case rebar3_hex_client:key_add(HexConfig, KeyName, Perms) of
        {ok, _Res} ->
            rebar3_hex_io:say("Key successfully created", []),
            {ok, State};
        Error ->
            ?PRV_ERROR({generate, Error})
    end.

fetch(State, HexConfig, KeyName) ->
    case rebar3_hex_client:key_get(HexConfig, KeyName) of
        {ok, Res} ->
            ok = print_key_details(Res),
            {ok, State};
        Error ->
            ?PRV_ERROR({fetch, Error})
    end.

revoke(State, HexConfig, KeyName) ->
    case rebar3_hex_client:key_delete(HexConfig, KeyName) of
        {ok, _Res} ->
             rebar3_hex_io:say("Key successfully revoked", []),
            {ok, State};
        Error ->
            ?PRV_ERROR({revoke, Error})
    end.

revoke_all(State, HexConfig) ->
    case rebar3_hex_client:key_delete_all(HexConfig) of
        {ok, _Res} ->
            rebar3_hex_io:say("All keys successfully revoked", []),
            {ok, State};
        Error ->
            ?PRV_ERROR({revoke_all, Error})
    end.

list(State, HexConfig) ->
    case rebar3_hex_client:key_list(HexConfig) of
        {ok, Res} ->
            ok = print_results(Res),
            {ok, State};
        Error ->
            ?PRV_ERROR({list, Error})
    end.

gather_permissions([]) ->
    [];
gather_permissions(Perms) ->
    lists:foldl(fun(Name, Acc) ->
                [Domain, Resource] = binary:split(rebar_utils:to_binary(Name), <<":">>),
                [#{<<"domain">> => Domain, <<"resource">> => Resource}] ++ Acc
                end, [], Perms).

print_results(Res) ->
    Header = ["Name", "Created"],
    Rows = lists:map(fun(#{<<"name">> := Name, <<"inserted_at">> := Created}) ->
                                [binary_to_list(Name), binary_to_list(Created)]
                     end, Res),
    ok = rebar3_hex_results:print_table([Header] ++ Rows),
    ok.
print_key_details(#{<<"name">> := Name,
                    <<"inserted_at">> := Created,
                    <<"updated_at">> := Updated,
                    <<"last_use">> := #{
                        <<"ip">> := Addr,
                        <<"used_at">> := Used,
                        <<"user_agent">> := _Agent
                       }
                   }
                 ) ->
    Header = ["Name", "Created", "Updated", "LastUsed", "LastUsedBy"],
    Row = [binary_to_list(Name),
           binary_to_list(Created),
           binary_to_list(Updated),
           binary_to_list(Used),
           binary_to_list(Addr)],
    ok = rebar3_hex_results:print_table([Header] ++ [Row]),
    ok.

-spec format_error(any()) -> iolist().
format_error({list, {unauthorized, _Res}}) ->
    "Error while attempting to perform list : Not authorized";
format_error({list,{error,#{<<"message">> := Msg}}}) ->
   "Error while attempting to perform list : " ++ Msg;
format_error({revoke, {not_found, _Res}}) ->
    "Error while revoking key : key not found";
format_error({generate, {validation_errors, #{<<"errors">> := Errors, <<"message">> := Message}}}) ->
    ErrorString = rebar3_hex_results:errors_to_string(Errors),
    io_lib:format("~ts~n\t~ts", [Message, ErrorString]);
format_error(bad_command) ->
    "Unknown command. Command must be fetch, generate, list, or revoke";
format_error(Reason) ->
    rebar3_hex_error:format_error(Reason).
