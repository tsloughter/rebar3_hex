-module(rebar3_hex_publish_SUITE).

-compile(export_all).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [format_error_test].

format_error_test(_Config) ->
    ReqTimeErrs = [
        <<"Status Code: Validation failed (422)\nHex Error: your app is bad!\n\t">>,
        <<"Inserted At: can only modify a release up to one hour after creation\n">>,
        <<"Requirements could not be computed\nnil\n--------------------\nno bueno\n">>
    ],

    ErrMap = [
        {
            {invalid_semver, {myapp, "-1.2.3"}},
            <<"myapp.app.src : non-semantic version number \"-1.2.3\" found">>
        },
        { 
         {invalid_semver_arg, <<"1.0">>},
          <<"The version argument provided \"1.0\" is not a valid semantic version.">>
        },
        {{no_description, myapp}, <<"myapp.app.src : missing or empty description property">>},
        {{no_license, myapp}, <<"myapp.app.src : missing or empty licenses property">>},
        {{has_maintainers, myapp}, <<"myapp.app.src : deprecated field maintainers found">>},
        {{has_contributors, myapp}, <<"myapp.app.src : deprecated field contributors found">>},
        {no_write_key,
            <<"No write key found for user. Be sure to authenticate first with: rebar3 hex user auth">>},
        {
            {publish,
                {error, #{
                    <<"message">> => <<"eh?">>,
                    <<"errors">> => [<<"Bad things">>, {<<"More bad">>, <<"things">>}]
                }}},
            <<"Failed to publish package: eh?\n\tBad thingsMore bad: things">>
        },
        {
            {publish, {error, #{<<"message">> => "non sequitur"}}},
            <<"Failed to publish package: non sequitur">>
        },
        {
            {publish_package, app_switch_required},
            <<"--app required when publishing with the package argument in a umbrella">>
        },
        {
            {publish_docs, app_switch_required},
            <<"--app required when publishing with the docs argument in a umbrella">>
        },
        {
            {revert, app_switch_required},
            <<"--app required when reverting in a umbrella with multiple apps">>
        },
        {
            {non_hex_deps, ["dep1", "dep2", "dep3"]},
            <<"Can not publish package because the following deps are not available in hex: dep1, dep2, dep3">>
        },
        {undefined_server_error, <<"Unknown server error">>},
        {{status, 403}, <<"Forbidden (403)">>},
        {{status, 500, undefined_server_error}, <<"Unknown server error: HTTP status code: 500">>},
        {
            {status, 422, #{
                <<"message">> => <<"your app is bad!">>,
                <<"errors">> => #{
                    <<"requirements">> => #{nil => <<"no bueno">>},
                    <<"inserted_at">> =>
                        <<"can only modify a release up to one hour after creation">>
                }
            }},
            list_to_binary(ReqTimeErrs)
        }
    ],

    ErrList = lists:map(fun({Args, _Exp}) -> Args end, ErrMap),

    BigStr = lists:foldl(
        fun({_Args, Exp}, Acc) ->
            <<Acc/binary, Exp/binary, <<"\n     ">>/binary>>
        end,
        <<"Validator Errors:\n     ">>,
        ErrMap
    ),

    lists:foreach(
        fun({Args, Exp}) ->
            ?assertEqual(Exp, list_to_bitstring(rebar3_hex_publish:format_error(Args)))
        end,
        ErrMap
    ),

    TrimStr = re:replace(BigStr, "^\\s+|\\s+$", "", [{return, binary}, global]),

    Info = <<"Please see https://hex.pm/docs/rebar3_publish for more info.\n">>,

    ?assertEqual(
        <<TrimStr/binary, <<"\n\n\n     ">>/binary, Info/binary>>,
        list_to_bitstring(rebar3_hex_publish:format_error(ErrList))
    ),

    ?assertEqual("bad command", rebar3_hex_publish:format_error(bad_command)),
    ?assertEqual(
        "App foo specified with --app switch not found in project",
        rebar3_hex_publish:format_error({app_not_found, foo})
    ),
    ?assertEqual(
        "publish requires a repo name argument to identify the repo to publish to",
        rebar3_hex_publish:format_error({required, repo})
    ),
    ?assertEqual(
        "No configuration for repository foo found.",
        rebar3_hex_publish:format_error({not_valid_repo, foo})
    ),

    Msg = "--app required when publishing with the package argument in a umbrella",
    ?assertEqual(Msg, rebar3_hex_publish:format_error({publish_package, app_switch_required})),

    Msg1 = io_lib:format(
        "Can not publish package because the following deps are not available in hex: ~s", ["eh"]
    ),
    ?assertEqual(Msg1, rebar3_hex_publish:format_error({non_hex_deps, ["eh"]})),

    Msg2 = io_lib:format("~ts.app.src : non-semantic version number \"~ts\" found", ["eh", "42"]),
    ?assertEqual(
        [Msg2],
        rebar3_hex_publish:format_error({validation_errors, [{invalid_semver, {"eh", "42"}}]})
    ),

    ?assertEqual(
        "empty tarball", rebar3_hex_publish:format_error({publish, {error, {tarball, empty}}})
    ),
    ?assertEqual(
        "An unknown error was encountered. Run with DEBUG=1 for more details.",
        rebar3_hex_publish:format_error(unknown)
    ),

    ExpErr = [
        "The following pre-release dependencies were found : ",
        10,
        10,
        [["verl", 32, 45, 32, "42", 32]],
        10,
        10,
        [
            "In the future packages with pre-release dependencies will be considered unstable ",
            "and will be prevented from being published. ",
            "We recommend you upgrade your these dependencies as soon as possible"
        ],
        10
    ],
    ?assertEqual(ExpErr, rebar3_hex_publish:format_error({has_unstable_deps, [{"verl", "42"}]})).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%
