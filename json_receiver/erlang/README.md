# Notification receiver implemented in Erlang

It does mostly the same thing as the Python implementation: receive notifications with an UDP socket, and print the JSON message.

To compile:

```
erlc -pa "$PWD" *.erl
```

The receiver can be started in multiple ways:

```
$ erl -S receiver start <IP> <Port>
$ erl -S receiver start <Port>
$ erl -S receiver start
$ erl -S receiver
```

If `<IP>` is not given, it defaults to `::`, if `<Port>` is not given, it defaults to `5678`.
If `<IP>` is IPv6, it can also receive IPv4 packets.

The code can also be compiled and started from the Erlang shell:

```
$ erl
1> c(notification_receiver).
{ok,notification_receiver}
2> c(receiver).
{ok,receiver}
3> Rec = receiver:start(["fd10::2", 8998]).
4> receiver:stop(Rec).
```

## Using the Module

The notification message processing is handled by the `notification_receiver` module.
The `receiver` module is a simple example of using this module, a proper application would also use supervision.

When using the `notification_receiver` module the code must implement its behavior:

```erlang
-behavior(notification_receiver).
```

This behavior prescribes a `notification/4` callback function that will get the reassembled notifications.
The four parameters are the following:

* `Key = {Hostname, Session, Seq}` identifies the notification message
* `Tstamp` of the last received fragment
* `Msg` is the reassembled notification (usually a serialized JSON)
* `State` is the state of the callback

The callback should return `{ok, NewState}` or crash.
In case of a crash the previous state of the callback is preserved.

The module should be started as

```erlang
{ok, Receiver} = notification_receiver:start_link(?MODULE, CallbackState)
```

Once the module is running, the received fragments must be handed over as a binary to the `fragment` method:

```erlang
ok = notification_receiver:fragment(Receiver, Binary)
```

If this received fragment completes a notification message, the `notification/4` callback function will be called.

