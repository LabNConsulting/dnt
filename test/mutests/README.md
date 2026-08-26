# munet mutests

These tests are built on munet and its `mutest` framework rather than the mininet harness
used by the rest of `test/`. Each directory holds a topology (`munet.yaml`), the DNT and FRR
configuration for its nodes, and one test. `mutest` brings the topology up, runs the test
against it, and tears it down.

Run from inside a test's directory, with `mutest` on your path or invoked from the
virtualenv it is installed in:

```
cd frer
sudo mutest mutest_frer.py
```

`preof_ospf` additionally needs FRR (`zebra`, `ospfd`) available on the node images.

All three share the same eight-node shape: a talker and a listener either side of two DNT
edge nodes, with two disjoint three-hop paths between them. Path-facing links run at MTU
1600 to carry the encapsulation overhead.

## frer

FRER (IEEE 802.1CB) over four transparent Layer 2 bridges, with no IP addressing and no
routing daemon in the core. The two paths are separated by VLAN 100 and VLAN 200, and every
replicated frame carries an R-TAG behind its VLAN tag. Checks replication, path separation,
an R-TAG on every frame, and elimination at the listener, then takes each path down in turn
and confirms traffic continues on the survivor before both resume.

## preof

PREOF over an MPLS-over-UDP data plane with static routes and no routing daemon. The two
members are separated by MPLS labels 100 and 200, and neither label appears on the other
path. A path failure is survived by the second copy, but the route must be repaired by hand
before that path returns.

## preof_ospf

The same data plane over OSPF, in two halves.

The first establishes the working case: both paths carrying equally, labels separated, and a
link failure that OSPF reroutes with no packet loss and no manual repair.

The second raises Path 2's OSPF cost from 10 to 50 on the six interfaces along it, while the
test is running. OSPF has no notion of keeping two flows disjoint, so it routes both tunnel
endpoints over the now-cheaper Path 1. Path 2 goes silent, label 200 disappears from the
network entirely, and the listener still receives everything at 0% loss — the redundancy is
gone while every health signal stays green. The same link failure that cost nothing in the
first half then costs 20%.

Costs are restored to 10 at the end and both paths resume carrying equally, which
establishes that the cost change caused the collapse rather than something else about the
topology. The change is made through vtysh only; the `.conf` files are untouched, so a
re-run starts from the equal-cost state.

## Conventions

`mutest` reports FAIL for an *unexpected* result, so a step expecting a negative result
passes when that result is observed. Known-broken behaviour is asserted as a negative rather
than left as a red step, and every such assertion is guarded on a positive measurement from
the same run — Path 2 being empty only counts as a result when Path 1 is demonstrably busy.
