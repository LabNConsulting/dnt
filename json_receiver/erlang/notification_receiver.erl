
-module(notification_receiver).
-moduledoc """
Notification receiver module.

It receives notification fragments, and calls the `notificaiton/X` callback with reassembled notifications.

Use `start/2` or `start_link/2` to start the service, `terminate/1` to stop.
The incoming notification fragments should be submitted with `fragment/2`.
The reassembled notification messages are handled by the `notification/4` callback.
""".

-compile([debug_info]).
-behaviour(gen_server).

%% need this for ets:fun2ms()
-include_lib("stdlib/include/ms_transform.hrl").

-define(MAX_FRAGMENTS, 20).
-define(GC_INTERVAL, 10).
-define(GC_AGELIMIT, 20).

%% public API
-export([start/2, start_link/2, terminate/1, fragment/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-doc """
Called when a notification message has been successfully reassembled from its fragments.
Key is the unique identifier of this message {hostname, session, seq}.
Tstamp is the timestamp from the last received fragment.
Message is the reassembled notification message (usually a serialized JSON).
State is the internal state of the callback.
The callback should return its updated state.
""".
-callback notification(Key :: {string(), integer(), integer()},
                       Tstamp :: number(),
                       Message :: binary(),
                       State :: term()) -> {ok, NewState :: term()}.
-type notification_callback() :: fun((Key :: {string(), integer(), integer()},
                                      Tstamp :: number(),
                                      Message :: binary(),
                                      State :: term())
                                     -> {ok, NewState :: term()}).


-doc """
Key for the reassembly buffer database.
""".
-record(notification_key, {
          hostname :: binary(),
          session :: integer(),
          seq :: integer()
         }).

-type notification_key() :: #notification_key{}.

-doc """
Storage record in the reassembly buffer.
""".
-record(notification, {
          key :: notification_key(),
          recv = 1 :: integer(), % unique fragments received
          total = 1 :: integer(), % total fragments expected
          arrived :: integer(), % our timestamp, not the received one
          msg :: array:array(binary()) % fragment collector for reassembly
         }).

-type notification() :: #notification{}.

-record(mod_state, {
          notification :: notification_callback(),
          notif_state :: term(), % state of the callback
          reassembly :: ets:table(), % stores notification() records
          inserts = 0 :: integer()
         }).

-type state() :: #mod_state{}.


%%% public API

-doc """
Start the service.
""".
-spec start(Module :: module(), State :: term()) -> {ok, pid()}.
start(Module, State) ->
    gen_server:start(?MODULE, {Module, State}, []).

-doc """
Start the service, and link the process.
""".
-spec start_link(Module :: module(), State :: term()) -> {ok, pid()}.
start_link(Module, State) ->
    gen_server:start_link(?MODULE, {Module, State}, []).

-doc """
Stop the service.
""".
-spec terminate(Recv :: pid()) -> ok.
terminate(Recv) ->
    gen_server:cast(Recv, terminate).

-doc """
Submit a received notification fragment.
The reassembled notification messages are handled by the `notification/4` callback.
""".
-spec fragment(Recv :: pid(), Bin :: binary()) -> ok.
fragment(Recv, Bin) ->
    gen_server:cast(Recv, {fragment, Bin}).


%%% gen_server callbacks

init({Module, CbState}) ->
    {ok, #mod_state{
            notification = fun Module:notification/4,
            notif_state = CbState,
            reassembly = ets:new(reassembly, [set, private, {keypos, #notification.key}])
           }}.

handle_call(_Req, _From, State) ->
    {noreply, State}.

handle_cast({fragment, Bin}, State) ->
    try
        {ok, Fragment} = decode_fragment(Bin),
        {noreply, store(Fragment, State)}
    catch
        _Err:_Reason -> {noreply, State}
    end;
handle_cast(terminate, State) ->
    {stop, normal, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    % the ETS table is automatically deleted when the owner process is gone
    % we just make sure
    ets:delete(State#mod_state.reassembly),
    ok.

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.


%%% private functions

-spec decode_fragment(Bin :: binary()) ->
    {ok, {notification_key(), {integer(), integer()}, number(), binary()}}.
decode_fragment(Bin) ->
    Json = json:decode(Bin),
    #{
      <<"notif_hostname">> := Hostname,
      <<"notif_session">> := Session,
      <<"notif_seq">> := Seq,
      <<"notif_tstamp">> := Tstamp,
      <<"notif_msg">> := Msg
     } = Json,
    Fragcount = maps:get(<<"notif_fragment">>, Json, <<"1/1">>),
    NumTotal = fragment_num_total(Fragcount),
    {ok, {#notification_key{hostname = Hostname, session = Session, seq = Seq},
          NumTotal, Tstamp, Msg}}.

-spec fragment_num_total(Fragcount :: binary() | string()) -> {integer(), integer()}.
fragment_num_total(Fragcount) when is_binary(Fragcount) ->
    fragment_num_total(binary_to_list(Fragcount));
fragment_num_total(Fragcount) ->
    [Num, Total] = [list_to_integer(X) || X <- string:split(Fragcount, "/")],
    fragment_num_total(Num, Total).
fragment_num_total(Num, Total) when Total > 0 andalso Total =< ?MAX_FRAGMENTS
                                    andalso Num > 0 andalso Num =< Total ->
    {Num, Total}.

-spec notify(Key :: notification_key(), Tstamp :: number(), Msg :: binary(), State :: state()) -> state().
notify(Key, Tstamp, Msg, State) ->
    #mod_state{notification = Callback, notif_state = CbState} = State,
    #notification_key{hostname = H, session = S, seq = Q} = Key,
    try Callback({binary_to_list(H), S, Q}, Tstamp, Msg, CbState) of
        {ok, NewCbState} -> State#mod_state{notif_state = NewCbState}
    catch _:_ -> State
    end.

-spec store({notification_key(), {integer(), integer()}, number(), binary()},
            State :: state()) -> state().
store({Key, {_Num, _Total}, _Tstamp, _Msg} = Incoming, State) ->
    store(ets:lookup(State#mod_state.reassembly, Key), Incoming, State).
store([Fragment], {_Key, {_Num, Total}, _Tstamp, _Msg} = Incoming, State) when
      Fragment#notification.total =:= Total andalso Fragment#notification.recv < Total ->
    update_fragments(Fragment, Incoming, State);
store([_Fragment], {_Key, {_Num, _Total}, _Tstamp, _Msg} = _Incoming, State) ->
    State; % ignore Incoming: invalid or already completed
store([], {Key, {_Num, Total}, Tstamp, Msg} = _Incoming, State) when Total =:= 1 ->
    NewState = notify(Key, Tstamp, Msg, State),
    ets:insert(NewState#mod_state.reassembly,
               #notification{
                  key = Key,
                  arrived = erlang:system_time(second),
                  msg = array:new()}),
    purge_old(NewState#mod_state{inserts = NewState#mod_state.inserts + 1});
store([], {Key, {Num, Total}, _Tstamp, Msg} = _Incoming, State) ->
    Array = array:set(Num-1, Msg, array:new(Total)), % fix size, index starts at 0
    ets:insert(State#mod_state.reassembly,
               #notification{
                  key = Key,
                  total = Total,
                  arrived = erlang:system_time(second),
                  msg = Array}),
    purge_old(State#mod_state{inserts = State#mod_state.inserts + 1}).

-spec update_fragments(Fragment :: notification(),
                       {notification_key(), {integer(), integer()}, number(), binary()},
                       State :: state()) -> state().
update_fragments(Fragment, {_Key, {Num, _Total}, _Tstamp, _Msg} = Incoming, State) ->
    % the array index starts at 0
    update_fragments(Fragment, Incoming, array:get(Num - 1, Fragment#notification.msg), State).
update_fragments(Fragment, {Key, {Num, Total}, Tstamp, Msg} = _Incoming,
                 Stored, State) when Stored =:= undefined ->
    Array = array:set(Num-1, Msg, Fragment#notification.msg), % store the incoming fragment
    case Fragment#notification.recv + 1 of
        Total ->
            Reassembled = list_to_binary(array:to_list(Array)),
            NewState = notify(Key, Tstamp, Reassembled, State),
            ets:insert(NewState#mod_state.reassembly,
                       Fragment#notification{
                         arrived = erlang:system_time(second),
                         msg = array:new(), % we no longer need the fragments
                         recv = Total}),
            NewState;
        _ ->
            ets:insert(State#mod_state.reassembly,
                       Fragment#notification{
                         arrived = erlang:system_time(second),
                         msg = Array,
                         recv = Fragment#notification.recv + 1}),
            State
    end;
update_fragments(_Fragment, _Incoming, _Stored, State) ->
    State. % fragment already received, ignore Incoming

-spec purge_old(State :: state()) -> state().
purge_old(State) when State#mod_state.inserts >= ?GC_INTERVAL ->
    Now = erlang:system_time(second),
    _Removed = ets:select_delete(State#mod_state.reassembly,
                                 ets:fun2ms(fun(N = #notification{arrived=Arrived})
                                                  when Now - Arrived > ?GC_AGELIMIT -> true end)),
    %io:format("purge_old removed ~p kept ~p~n", [_Removed, ets:info(State#mod_state.reassembly, size)]),
    State#mod_state{inserts = 0};
purge_old(State) -> State.
