-module(rebar3_hex_build). 

-export([create_package/3, create_docs/3]).

-include("rebar3_hex.hrl").

-define(DEFAULT_FILES, ["src", "c_src", "include", "rebar.config.script"
                       ,"priv", "rebar.config", "rebar.lock"
                       ,"CHANGELOG*", "changelog*"
                       ,"README*", "readme*"
                       ,"LICENSE*", "license*"
                       ,"NOTICE"]).

-define(DEFAULT_DOC_DIR, "doc").

create_package(State, #{name := RepoName} = _Repo, App) ->
    Name = rebar_app_info:name(App),

    Version = rebar3_hex_app:vcs_vsn(State, App),

    %% Note we should not implicitly do this IMO
    {application, _, AppDetails} = rebar3_hex_file:update_app_src(App, Version),

    Deps = rebar_state:get(State, {locks, default}, []),
    TopLevel = gather_deps(Deps),
    AppDir = rebar_app_info:dir(App),
    Config = rebar_config:consult(AppDir),
    ConfigDeps = proplists:get_value(deps, Config, []),
    Deps1 = update_versions(ConfigDeps, TopLevel),
    Description = proplists:get_value(description, AppDetails, ""),
    PackageFiles = include_files(Name, AppDir, AppDetails),
    Licenses = proplists:get_value(licenses, AppDetails, []),
    Links = proplists:get_value(links, AppDetails, []),
    BuildTools = proplists:get_value(build_tools, AppDetails, [<<"rebar3">>]),

    %% We check the app file for the 'pkg' key which allows us to select
    %% a package name other then the app name, if it is not set we default
    %% back to the app name.
    PkgName = rebar_utils:to_binary(proplists:get_value(pkg_name, AppDetails, Name)),

    Optional = [{<<"app">>, Name},
                {<<"parameters">>, []},
                {<<"description">>, rebar_utils:to_binary(Description)},
                {<<"files">>, [binarify(File) || {File, _} <- PackageFiles]},
                {<<"licenses">>, binarify(Licenses)},
                {<<"links">>, to_map(binarify(Links))},
                {<<"build_tools">>, binarify(BuildTools)}],
    OptionalFiltered = [{Key, Value} || {Key, Value} <- Optional, Value =/= []],
    Metadata = maps:from_list([{<<"name">>, PkgName}, {<<"version">>, binarify(Version)},
                               {<<"requirements">>, maps:from_list(Deps1)} | OptionalFiltered]),
    
    Tarball = create_package_tarball(Metadata, PackageFiles),

    #{name => PkgName,
      repo_name => RepoName,
      deps => Deps1,
      version => Version,
      metadata => Metadata,
      files => PackageFiles,
      tarball => Tarball,
      has_checkouts => has_checkouts_for(AppDir)}.

gather_deps(Deps) ->
    case rebar3_hex_app:get_deps(Deps) of
        {ok, Top} ->
            Top;
        {error, Reason} ->
             ?RAISE(Reason)
    end.

update_versions(ConfigDeps, Deps) ->
    [begin
         case lists:keyfind(binary_to_atom(N, utf8), 1, ConfigDeps) of
             {_, V} when is_binary(V) ->
                 Req =  {<<"requirement">>, V},
                 {N, maps:from_list(lists:keyreplace(<<"requirement">>, 1, M, Req))};
             {_, V} when is_list(V) ->
                 Req = {<<"requirement">>, rebar_utils:to_binary(V)},
                 {N, maps:from_list(lists:keyreplace(<<"requirement">>, 1, M, Req))};
             _ ->
                 %% using version from lock. prepend ~> to make it looser
                 {_, Version} = lists:keyfind(<<"requirement">>, 1, M),
                 Req = {<<"requirement">>, <<"~>", Version/binary>>},
                 {N, maps:from_list(lists:keyreplace(<<"requirement">>, 1, M, Req))}
         end
     end || {N, M} <- Deps].

include_files(Name, AppDir, AppDetails) ->
    AppSrc = {application, to_atom(Name), AppDetails},
    FilePaths = proplists:get_value(files, AppDetails, ?DEFAULT_FILES),
    IncludeFilePaths = proplists:get_value(include_files, AppDetails, []),
    ExcludeFilePaths = proplists:get_value(exclude_files, AppDetails, []),
    ExcludeRes = proplists:get_value(exclude_regexps, AppDetails, []),

    AllFiles = lists:ukeysort(2, rebar3_hex_file:expand_paths(FilePaths, AppDir)),
    IncludeFiles = lists:ukeysort(2, rebar3_hex_file:expand_paths(IncludeFilePaths, AppDir)),
    ExcludeFiles = lists:ukeysort(2, rebar3_hex_file:expand_paths(ExcludeFilePaths, AppDir)),

    %% We filter first and then include, that way glob excludes can be
    %% overwritten be explict includes
    FilterExcluded = lists:filter(fun ({_, Path}) ->
                                      not exclude_file(Path, ExcludeFiles, ExcludeRes)
                                  end, AllFiles),
    WithIncludes = lists:ukeymerge(2, FilterExcluded, IncludeFiles),

    AppFileSrc = filename:join("src", rebar_utils:to_list(Name)++".app.src"),
    AppSrcBinary = rebar_utils:to_binary(lists:flatten(io_lib:format("~tp.\n", [AppSrc]))),
    lists:keystore(AppFileSrc, 1, WithIncludes, {AppFileSrc, AppSrcBinary}).

exclude_file(Path, ExcludeFiles, ExcludeRe) ->
    lists:keymember(Path, 2, ExcludeFiles) orelse
        known_exclude_file(Path, ExcludeRe).

known_exclude_file(Path, ExcludeRe) ->
    KnownExcludes = [
                     "~$",        %% emacs temp files
                     "\\.o$",     %% c object files
                     "\\.so$",    %% compiled nif libraries
                     "\\.swp$"    %% vim swap files
                    ],
    lists:foldl(fun(_, true) -> true;
                   (RE, false) ->
                        re:run(Path, RE) =/= nomatch
                end, false, KnownExcludes ++ ExcludeRe).

%% Note that we return a list 
has_checkouts_for(AppDir) ->
    Checkouts = filename:join(AppDir, "_checkouts"),
    filelib:is_dir(Checkouts).

create_docs(State, Repo, App) -> 
    maybe_gen_docs(State, Repo),
    AppDir = rebar_app_info:dir(App),
    AppOpts = rebar_app_info:opts(App),
    EdocOpts = rebar_opts:get(AppOpts, edoc_opts, []),
    AppDetails = rebar_app_info:app_details(App),
    Dir = proplists:get_value(dir, EdocOpts, ?DEFAULT_DOC_DIR),
    DocDir = proplists:get_value(doc, AppDetails, Dir),
    IndexFile = filename:join(AppDir, DocDir) ++ "/index.html",

    filelib:is_file(IndexFile) orelse ?RAISE({publish, {missing_doc_dir, DocDir}}),

    Files = rebar3_hex_file:expand_paths([DocDir], AppDir),
    Name = rebar_utils:to_list(rebar_app_info:name(App)),
    PkgName = rebar_utils:to_list(proplists:get_value(pkg_name, AppDetails, Name)),
    OriginalVsn = rebar_app_info:original_vsn(App),
    Vsn = rebar_utils:vcs_vsn(App, OriginalVsn, State),

    FileList = [{filename:join(filename:split(ShortName) -- [DocDir]), FullName} || {ShortName, FullName} <- Files],
    {ok, Tarball} = create_docs_tarball(FileList),   
    #{tarball => Tarball, name => binarify(PkgName), vsn => binarify(Vsn)}.
 
maybe_gen_docs(State, Repo) ->
    case doc_opts(State, Repo) of
        {ok, #{provider := PrvName}} ->
            case providers:get_provider(PrvName, rebar_state:providers(State)) of
                not_found ->
                    rebar_api:error("No provider found for ~ts", [PrvName]);
                Prv ->
                    case providers:do(Prv, State) of
                        {ok, State1} ->
                            {ok, State1};
                        Err ->
                            ?RAISE({publish, Err})
                    end
            end;
        _ ->
            Msg = "No valid hex docs configuration found. Docs will will not be generated",
            rebar_api:error(Msg, [])
    end.

doc_opts(State, Repo) ->
    case Repo of
      #{doc := DocOpts} when is_map(DocOpts) ->
            {ok, DocOpts};
      _ ->
        Opts = rebar_state:opts(State),
        case proplists:get_value(doc, rebar_opts:get(Opts, hex, []), undefined) of
            DocOpts when is_map(DocOpts) -> {ok, DocOpts};
            _ -> undefined
        end
    end.
binarify(Term) when is_boolean(Term) ->
    Term;
binarify(Term) when is_atom(Term) ->
    atom_to_binary(Term, utf8);
binarify([]) ->
    [];
binarify(Map) when is_map(Map) ->
    maps:from_list(binarify(maps:to_list(Map)));
binarify(Term) when is_list(Term) ->
    case io_lib:printable_unicode_list(Term) of
        true ->
            rebar_utils:to_binary(Term);
        false ->
            [binarify(X) || X <- Term]
    end;
binarify({Key, Value}) ->
    {binarify(Key), binarify(Value)};
binarify(Term) ->
    Term.

create_package_tarball(Metadata, Files) ->
     case hex_tarball:create(Metadata, Files) of
         {ok, #{tarball := Tarball, inner_checksum := _Checksum}} ->
             Tarball;
         Error ->
             Error
     end.

-dialyzer({nowarn_function, create_docs_tarball/1}).
create_docs_tarball(Files) ->
    case hex_tarball:create_docs(Files) of
        {ok, Tarball} ->
            {ok, Tarball};
        Error ->
            Error
    end.

-spec to_atom(atom() | string() | binary() | integer() | float()) ->
                     atom().
to_atom(X) when erlang:is_atom(X) ->
    X;
to_atom(X) when erlang:is_list(X) ->
    list_to_existing_atom(X);
to_atom(X) ->
    to_atom(rebar_utils:to_list(X)).

to_map(Map) when is_map(Map) ->
    Map;
to_map(List) when is_list(List) ->
    maps:from_list(List).
