-module(rebar3_hex).

-export([ init/1
        , get_args/1
        , gather_opts/2
        , get_required/2
        , task_args/1
        , task_state/1
        , repo_opt/0
        , help_opt/0
        ]).

-type task() :: #{args := map(), 
                  repo := map(), 
                  apps := [rebar_app_info:t()], 
                  state := rebar_state:t(), 
                  multi_app := boolean()
                 }.

-export_type([task/0]).

init(State) ->
    lists:foldl(fun provider_init/2, {ok, State}, [rebar3_hex_user,
                                                   rebar3_hex_cut,
                                                   rebar3_hex_key,
                                                   rebar3_hex_owner,
                                                   rebar3_hex_repo,
                                                   rebar3_hex_search,
                                                   rebar3_hex_retire,
                                                   rebar3_hex_publish]).

provider_init(Module, {ok, State}) ->
    Module:init(State).

gather_opts(Targets, State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    lists:foldl(fun(T, Acc) ->
                        case proplists:get_value(T, Args, undefined) of
                            undefined ->
                                Acc;
                            V ->
                                maps:put(T, V, Acc)
                        end
                end, #{}, Targets).

get_required(Key, Args) ->
    case proplists:get_value(Key, Args) of
        undefined ->
            {error, {required, Key}};
        Value ->
            Value
    end.

task_args(State) ->
    {Opts, _Args} = rebar_state:command_parsed_args(State),
    case proplists:get_value(task, Opts, undefined) of
        undefined ->
            {undefined, Opts};
        Task ->
            {Task, proplists:delete(task, Opts)}
    end.

-spec task_state(rebar_state:t()) -> {ok, task()} | {error, term()}.
task_state(State) ->
     case rebar3_hex_config:repo(State) of
         {ok, Repo} -> 
             Opts = get_args(State),
             case rebar_state:project_apps(State) of 
                 [_App] = Apps ->
                    {ok, #{args => Opts, repo => Repo, state => State, multi_app => false, apps => Apps}};
                 [_|_] = Apps ->
                    {ok, #{args => Opts, repo => Repo, state => State, multi_app => true, apps => Apps}}
             end;
         Err -> 
            Err
     end.

-spec get_args(rebar_state:t()) -> map().
get_args(State) -> 
    {Opts, Args} = rebar_state:command_parsed_args(State),
    Opts1 = lists:foldl(fun (Arg, Acc) ->
                                case is_atom(Arg) of
                                    true ->
                                        [{Arg, true} | Acc];
                                    _ ->
                                        case Arg of
                                            {task, Task} ->
                                                [{task, list_to_atom(Task)} | Acc];
                                             _ -> 
                                              [Arg | Acc]
                                        end
                                end
                        end,
                        [],
                        Opts),
    
    Opts2 = lists:foldl(fun (Arg, Acc) ->
                                case is_atom(Arg) of
                                    true ->
                                        [{Arg, true} | Acc];
                                    _ ->
                                     [{list_to_atom(Arg), true} | Acc]
                                end
                        end,
                        Opts1,
                        Args),
    maps:from_list(Opts2).

repo_opt() ->
  {repo, $r, "repo", string, "Repository to use for this command."}.

help_opt() ->
  {help, $h, "help", undefined, "Help"}.
