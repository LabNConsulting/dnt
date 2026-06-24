
-module(receiver).
-moduledoc """
Sample notification receiver application to demonstrate how to use the `notification_receiver` module.
It receives the fragments with an UDP socket, and prints the received notifications to stdout.
""".

-compile([debug_info]).
-behavior(notification_receiver).

%% public API
-export([start/0, start/1, start_link/0, start_link/1, stop/1]).

%% notification_receiver callbacks
-export([notification/4]).

-define(DEFAULT_IP, "::").
-define(DEFAULT_PORT, 5678).

-spec start() -> pid().
start() -> start([]).

-spec start(list()) -> pid().
start(Params) ->
    {IP, Port} = get_ip_port(Params),
    io:format("Starting ~p with IP ~s port ~p~n", [?MODULE, IP, Port]),
    spawn(fun() -> init(IP, Port) end).

-spec start_link() -> pid().
start_link() -> start_link([]).

-spec start_link(list()) -> pid().
start_link(Params) ->
    {IP, Port} = get_ip_port(Params),
    io:format("Starting ~p with IP ~s port ~p~n", [?MODULE, IP, Port]),
    spawn_link(fun() -> init(IP, Port) end).

-spec stop(pid()) -> true.
stop(Receiver) ->
    exit(Receiver, "Stop"). % must be drastic, the process is not reading its mailbox

% note: if started as `erl -s receiver start ....` the arguments are received as atoms

-spec get_ip_port(list()) -> {term(), term()}.
get_ip_port([]) ->
    io:format("Using default IP ~s default port ~p~n", [?DEFAULT_IP, ?DEFAULT_PORT]),
    {?DEFAULT_IP, ?DEFAULT_PORT};
get_ip_port([Port]) ->
    io:format("Using default IP ~s~n", [?DEFAULT_IP]),
    {?DEFAULT_IP, Port};
get_ip_port([IP, Port]) ->
    {IP, Port}.

-spec get_addr(atom() | string()) ->
    {inet:ip4_address(), inet} | {inet:ip6_address(), inet6}.
get_addr(IPStr) when is_atom(IPStr) ->
    get_addr(atom_to_list(IPStr));
get_addr(IPStr) ->
    case inet:getaddr(IPStr, inet6) of
        {error, _} ->
            case inet:getaddr(IPStr, inet) of
                {error, _} ->
                    error("Invalid address");
                {ok, Addr} -> {Addr, inet}
            end;
        {ok, Addr6} -> {Addr6, inet6}
    end.

-spec get_port(atom() | string() | inet:port_number()) -> inet:port_number().
get_port(PortStr) when is_atom(PortStr) ->
    get_port(atom_to_list(PortStr));
get_port(PortStr) when is_list(PortStr) ->
    try get_port(list_to_integer(PortStr))
    catch
        error:badarg -> error("Port must be a number between 0 and 65535")
    end;
get_port(Port) when is_integer(Port) andalso Port >= 0 andalso Port =< 65535 ->
    Port;
get_port(_Port) ->
    error("Port must be a number between 0 and 65535").

init(IP, Port) ->
    %io:format("init receiver ~p ~s ~p~n", [Family, inet:ntoa(IP), Port]),
    {Address, Family} = get_addr(IP),
    Portnum = get_port(Port),
    {ok, Socket} = gen_udp:open(Portnum, [binary, Family, {ip, Address}, {active, false}]),
    {ok, Recv} = notification_receiver:start_link(?MODULE, []),
    loop(Socket, Recv).

loop(Socket, Recv) ->
    case gen_udp:recv(Socket, 0) of
        {ok, {_Host, _Port, Bin}} ->
            %io:format("UDP received ~p ~p from ~s : ~p~n", [byte_size(Bin), Bin, inet:ntoa(_Host), _Port]),
            notification_receiver:fragment(Recv, Bin),
            loop(Socket, Recv);
        {error, Reason} ->
            io:format("receive error ~p~n", [Reason]),
            loop(Socket, Recv)
    end.


notification({Hostname, Session, Seq} = _Key, _Tstamp, Msg, State) ->
    Chars = json:format(json:decode(Msg)),
    io:format("~nReceived from ~p session ~p seq ~p~n========== JSON data begin ==========~n",
              [Hostname, Session, Seq]),
    io:format("~s........... JSON data end ...........~n", [Chars]),
    {ok, State}.
