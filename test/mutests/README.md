# munet mutests

These tests are built on munet and its `mutest` framework rather than the mininet harness
used by the rest of `test/`. Each directory holds a topology (`munet.yaml`), the DNT and FRR
configuration for its nodes, and one test. `mutest` brings the topology up, runs the test
against it, and tears it down. Directory names follow the objective numbering of the work
they came from.

Run from inside a test's directory, with `mutest` on your path or invoked from the
virtualenv it is installed in:

```
cd obj2_frer
sudo mutest mutest_obj2_frer.py
```

`obj4_ospf` additionally needs FRR (`zebra`, `ospfd`) available on the node images.

All three share the same eight-node shape: a talker and a listener either side of two DNT
edge nodes, with two disjoint three-hop paths between them. Path-facing links run at MTU
1600 to carry the encapsulation overhead.

## obj2_frer

FRER (IEEE 802.1CB) over four transparent Layer 2 bridges, with no IP addressing and no
routing daemon in the core. The two paths are separated by VLAN 100 and VLAN 200, and every
replicated frame carries an R-TAG behind its VLAN tag. Checks replication, path separation,
an R-TAG on every frame, and elimination at the listener, then takes each path down in turn
and confirms traffic continues on the survivor before both resume.

## obj3_preof

PREOF over an MPLS-over-UDP data plane with static routes and no routing daemon. The two
members are separated by MPLS labels 100 and 200, and neither label appears on the other
path. A path failure is survived by the second copy, but the route must be repaired by hand
before that path returns.

## obj4_ospf

The same data plane over OSPF. Both DNT tunnel senders are bound to a fixed interface
(`nni1_out` to eth1, `nni2_out` to eth2), which is what the two failure cases below have in
common: when the routing table and the interface pin disagree, that member is discarded
inside the sending edge node and never reaches the wire at all.

The test first establishes the healthy case — both paths carrying equally, labels
separated, elimination at the listener.

**A link failure on Path 1.** OSPF withdraws the route and reinstalls it out eth2 on its
own, with no manual repair. But member 1 is still pinned to eth1, so it never uses the new
route: zero packets reach the next hop, and delivery continues entirely on member 2 at 0%
loss. The reroute is real in the routing table and invisible on the wire.

**Path 2 re-costed from 10 to 50**, on the six interfaces along it, while the test runs.
OSPF has no notion of keeping two flows disjoint, so it routes both tunnel endpoints over
the now-cheaper Path 1. Path 2 goes silent, label 200 disappears from the network entirely,
and the listener still receives everything at 0% loss — the redundancy is gone while every
health signal stays green. The same link failure that cost nothing in the healthy case now
costs 20%.

Costs are restored to 10 at the end and both paths resume carrying equally, which
establishes that the cost change caused the collapse rather than something else about the
topology. The change is made through vtysh only; the `.conf` files are untouched, so a
re-run starts from the equal-cost state.

## Conventions

`mutest` reports FAIL for an *unexpected* result, so a step expecting a negative result
passes when that result is observed. Known-broken behaviour is asserted as a negative rather
than left as a red step, and every such assertion is guarded on a positive measurement from
the same run — Path 2 being empty only counts as a result when Path 1 is demonstrably busy.

Step descriptions state what was verified rather than what was intended. Where a step claims
a cause, a capture in the same section measures it.
