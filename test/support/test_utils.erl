-module(test_utils).

-export([stub_project/2, stub_project/3, mock_command/4, repo_config/0, repo_config/1]).

-define(REPO_CONFIG, maps:merge(hex_core:default_config(), #{
                                  name        => <<"hexpm">>,
                                  repo        => <<"hexpm">>,
                                  api_url     => <<"http://127.0.0.1:3000">>,
                                  repo_url    => <<"http://127.0.0.1:3000">>,
                                  repo_verify => false,
                                  read_key                 => <<"123">>,
                                  repo_public_key          => <<0>>,
                                  repo_key                => <<"repo_key">>,
                                  username                 => <<"mr_pockets">>,

                                  write_key               => rebar3_hex_user:encrypt_write_key(<<"mr_pockets">>,
                                  <<"special_shoes">>, <<"key">>)
                                 }
                               )).

stub_project(AppName, DataDir) ->
    stub_project(AppName, DataDir, repo_config()).

stub_project(AppName, DataDir, Repo) ->
    AppsDir = filename:join([DataDir, "test_apps/" ++ AppName]),
    State = rebar_state(AppsDir, Repo),
    LibDirs = rebar_dir:lib_dirs(State),
    State1 = rebar_app_discover:do(State, LibDirs),
    {ok, State1}.

mock_command(ProviderName, Command, RepoConfig, State0) ->
    State1 = rebar_state:add_resource(State0, {pkg, rebar_pkg_resource}),
    State2 = rebar_state:create_resources([{pkg, rebar_pkg_resource}], State1),
    State3 = rebar_state:set(State2, hex, RepoConfig),
    State4 = rebar_state:command_args(State3, Command),
    {ok, State5} = ProviderName:init(State4),

    [Provider] = rebar_state:providers(State5),

    {ok, State6} = rebar_prv_edoc:init(State5),

    Opts = providers:opts(Provider) ++ rebar3:global_option_spec_list(),
    {ok, Args} = getopt:parse(Opts, rebar_state:command_args(State6)),
    {ok, rebar_state:command_parsed_args(State6, Args)}.

rebar_state(AppsDir, Repo) -> 
    State = rebar_state:new([{root_dir, AppsDir}, 
                             {base_dir, filename:join([AppsDir, "_build"])}, 
                             {command_parsed_args, []}, 
                             {resources, []},
                             {hex, [{repos, [Repo]}]}
                            ]),
    rebar_state:dir(State, AppsDir).

repo_config() ->
    ?REPO_CONFIG.
repo_config(Cfg) ->
    maps:merge(?REPO_CONFIG, Cfg).
