"""Objective 4: PREOF over OSPF, equal cost then Path 2 re-costed."""

import re

from munet.mutest.userapi import log
from munet.mutest.userapi import match_step
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import step_json
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step


def pkt_count(target, pcap, pfilter="", what="packets"):
    out = step(target, f"tcpdump -nr {pcap} {pfilter} 2>/dev/null | wc -l")
    m = re.search(r"(\d+)", out)
    n = int(m.group(1)) if m else 0
    log("%s: %s", what, n)
    return n


NO_LOSS = r"\b0% packet loss"


def no_loss(output):
    return bool(re.search(NO_LOSS, output))


def loss_pct(output):
    m = re.search(r"(\d+)% packet loss", output)
    return int(m.group(1)) if m else -1


ROUTERS = ("bridgeA", "bridge1A", "bridge1B", "bridge2A", "bridge2B", "bridgeB")
EDGES = ("bridgeA", "bridgeB")

CAPTURES = [
    ("bridge1A", "eth1", "path1", "'udp port 6635'"),
    ("bridge2A", "eth1", "path2", "'udp port 6635'"),
    ("h2", "eth0", "listener", "'icmp or (vlan and icmp)'"),
]


def start_capture(target, iface, tag, pfilter):
    step(target, f"rm -f /tmp/obj4_{tag}.pcap /tmp/obj4_{tag}.pid")
    step(
        target,
        f"nohup tcpdump -U -Z root -ni {iface} -w /tmp/obj4_{tag}.pcap {pfilter} "
        f">/tmp/obj4_{tag}.log 2>&1 & echo $! > /tmp/obj4_{tag}.pid",
    )
    wait_step(
        target,
        f"cat /tmp/obj4_{tag}.log",
        match=f"listening on {iface}",
        desc=f"tcpdump listening on {iface} for the {tag} capture",
        timeout=15,
    )


def stop_capture(target, tag):
    step(target, f"kill -INT $(cat /tmp/obj4_{tag}.pid)")
    wait_step(
        target,
        f"kill -0 $(cat /tmp/obj4_{tag}.pid) 2>/dev/null; echo rc=$?",
        match="rc=1",
        desc=f"The {tag} capture flushed to disk and stopped",
        timeout=15,
    )


PATH2_LINKS = (
    ("bridgeA", "eth2"),
    ("bridge2A", "eth0"),
    ("bridge2A", "eth1"),
    ("bridge2B", "eth0"),
    ("bridge2B", "eth1"),
    ("bridgeB", "eth2"),
)


def set_path2_cost(cost):
    for node, iface in PATH2_LINKS:
        step(
            node,
            f"vtysh -N {node} -c 'configure terminal' -c 'interface {iface}' "
            f"-c 'ip ospf cost {cost}'",
        )
    for node, iface in PATH2_LINKS:
        wait_step(
            node,
            f"vtysh -N {node} -c 'show ip ospf interface {iface}'",
            match=rf"Cost: {cost}\b",
            desc=f"{iface} now advertises OSPF cost {cost}",
            timeout=30,
        )


section("The DNT replication engine is running on both edge nodes")

for edge in EDGES:
    wait_step(
        edge,
        f"ps -eo comm,args | awk '$1==\"dnt\" && /{edge}.ini/' | wc -l",
        match=r"^1$",
        flags=re.MULTILINE,
        desc=f"A dnt process is running with {edge}.ini",
        timeout=30,
    )


section("OSPF is running on all six routers and every adjacency is Full")

for node in ROUTERS:
    wait_step(
        node,
        f"ps -eo comm,args | awk '$1==\"zebra\" && /-N {node}/' | wc -l",
        match=r"^1$",
        flags=re.MULTILINE,
        desc="The zebra routing daemon is running",
        timeout=30,
    )
    wait_step(
        node,
        f"ps -eo comm,args | awk '$1==\"ospfd\" && /-N {node}/' | wc -l",
        match=r"^1$",
        flags=re.MULTILINE,
        desc="The ospfd OSPF daemon is running",
        timeout=30,
    )

for node in ROUTERS:
    wait_step(
        node,
        f"vtysh -N {node} -c 'show ip ospf neighbor' | grep -c Full",
        match=r"^2$",
        flags=re.MULTILINE,
        desc="Both OSPF neighbours have reached Full state",
        timeout=90,
    )


section("Every path-facing link is at MTU 1600 to fit the tunnel headers")

for node, iface in [
    ("bridgeA", "eth1"),
    ("bridgeA", "eth2"),
    ("bridge1A", "eth0"),
    ("bridge1A", "eth1"),
    ("bridge1B", "eth0"),
    ("bridge1B", "eth1"),
    ("bridge2A", "eth0"),
    ("bridge2A", "eth1"),
    ("bridge2B", "eth0"),
    ("bridge2B", "eth1"),
    ("bridgeB", "eth1"),
    ("bridgeB", "eth2"),
]:
    match_step(
        node,
        f"ip link show {iface}",
        match="mtu 1600",
        desc=f"{iface} is set to MTU 1600",
    )


section("Both tunnel paths are learned from OSPF, with nothing configured by hand")

for edge in EDGES:
    match_step(
        edge,
        "ip route show proto static",
        match=r"\d",
        expect_fail=True,
        desc="No static routes exist, all forwarding comes from OSPF",
    )

wait_step(
    "bridgeA",
    "ip route show proto ospf",
    match=r"10\.1\.3\.0/30",
    desc="Path 1 far-side subnet 10.1.3.0/30 was learned from OSPF",
    timeout=90,
)
wait_step(
    "bridgeA",
    "ip route show proto ospf",
    match=r"10\.2\.3\.0/30",
    desc="Path 2 far-side subnet 10.2.3.0/30 was learned from OSPF",
    timeout=90,
)

wait_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="Tunnel endpoint 10.1.3.2 routes out eth1, over Path 1",
    timeout=90,
)
wait_step(
    "bridgeA",
    "ip route get 10.2.3.2",
    match=r"via 10\.2\.1\.2 dev eth2",
    desc="Tunnel endpoint 10.2.3.2 routes out eth2, over Path 2",
    timeout=90,
)
wait_step(
    "bridgeB",
    "ip route get 10.1.1.1",
    match=r"via 10\.1\.3\.1 dev eth1",
    desc="The return route to 10.1.1.1 leaves bridgeB on eth1",
    timeout=90,
)
wait_step(
    "bridgeB",
    "ip route get 10.2.1.1",
    match=r"via 10\.2\.3\.1 dev eth2",
    desc="The return route to 10.2.1.1 leaves bridgeB on eth2",
    timeout=90,
)


section("Both paths are reachable end to end before any tunnelling is involved")

wait_step(
    "bridgeA",
    "ping -c 2 -W 1 10.1.3.2",
    match=NO_LOSS,
    desc="Ping to 10.1.3.2 succeeds across Path 1",
    timeout=30,
)
wait_step(
    "bridgeA",
    "ping -c 2 -W 1 10.2.3.2",
    match=NO_LOSS,
    desc="Ping to 10.2.3.2 succeeds across Path 2",
    timeout=30,
)
match_step(
    "bridgeA",
    "traceroute -n -w 1 -q 1 -m 5 10.1.3.2",
    match=r"10\.1\.1\.2.*10\.1\.3\.2",
    desc="Traceroute to 10.1.3.2 goes through bridge1A, as expected",
)
match_step(
    "bridgeA",
    "traceroute -n -w 1 -q 1 -m 5 10.2.3.2",
    match=r"10\.2\.1\.2.*10\.2\.3\.2",
    desc="Traceroute to 10.2.3.2 goes through bridge2A, as expected",
)


section("Host ARP entries are pinned so replicated ARP stays out of the captures")

h1_mac = step_json("h1", "ip -j link show eth0")[0]["address"]
h2_mac = step_json("h2", "ip -j link show eth0")[0]["address"]
log("h1 eth0 %s, h2 eth0 %s", h1_mac, h2_mac)

step("h1", f"ip neigh replace 10.0.0.2 lladdr {h2_mac} dev eth0 nud permanent")
step("h2", f"ip neigh replace 10.0.0.1 lladdr {h1_mac} dev eth0 nud permanent")

warm = step("h1", "ping -c 2 -W 1 10.0.0.2")
test_step(no_loss(warm), "Warm-up ping from h1 to h2 got 2 of 2 replies", "h1")
test_step("DUP!" not in warm, "The warm-up ping produced no duplicate replies", "h1")


section("EQUAL COST. Captures are running on both paths and h1 sends 10 pings")

for target, iface, tag, pfilter in CAPTURES:
    start_capture(target, iface, tag, pfilter)

sent = step("h1", "ping -c 10 -W 1 10.0.0.2")
log("ping output:\n%s", sent)

test_step("10 received" in sent, "h1 received all 10 ICMP replies", "h1")
test_step(no_loss(sent), "h1 reported 0% packet loss", "h1")
test_step("DUP!" not in sent, "h1 saw no duplicates, so elimination worked", "h1")

step("h1", "sleep 2")

for target, _, tag, _ in CAPTURES:
    stop_capture(target, tag)


section("REPLICATION. Both paths carry their own copy of every packet")

p1 = pkt_count(
    "bridge1A",
    "/tmp/obj4_path1.pcap",
    "'dst host 10.1.3.2'",
    "Path 1 packets travelling toward bridgeB",
)
p2 = pkt_count(
    "bridge2A",
    "/tmp/obj4_path2.pcap",
    "'dst host 10.2.3.2'",
    "Path 2 packets travelling toward bridgeB",
)
log("Path 1 carried %s, Path 2 carried %s", p1, p2)

test_step(p1 >= 10, f"Path 1 carried {p1} packets toward bridgeB", "bridge1A")
test_step(p2 >= 10, f"Path 2 carried {p2} packets toward bridgeB", "bridge2A")
test_step(
    abs(p1 - p2) <= 2,
    f"Both paths carried the same number of copies, {p1} and {p2}",
)


section("SEPARATION. Each path carries only its own MPLS label, never the other")

l100 = pkt_count(
    "bridge1A",
    "/tmp/obj4_path1.pcap",
    "'udp[8:2] = 0x0006 and udp[10] & 0xf0 = 0x40'",
    "Path 1 packets carrying MPLS label 100",
)
l200 = pkt_count(
    "bridge2A",
    "/tmp/obj4_path2.pcap",
    "'udp[8:2] = 0x000c and udp[10] & 0xf0 = 0x80'",
    "Path 2 packets carrying MPLS label 200",
)

test_step(
    l100 >= 10,
    f"Path 1 carried {l100} label 100 packets, counting both directions",
    "bridge1A",
)
test_step(
    l200 >= 10,
    f"Path 2 carried {l200} label 200 packets, counting both directions",
    "bridge2A",
)

match_step(
    "bridge1A",
    "tcpdump -nr /tmp/obj4_path1.pcap 'udp[8:2] = 0x000c' 2>/dev/null",
    match=r"IP ",
    expect_fail=True,
    desc="No label 200 packet ever appeared on Path 1",
)
match_step(
    "bridge2A",
    "tcpdump -nr /tmp/obj4_path2.pcap 'udp[8:2] = 0x0006' 2>/dev/null",
    match=r"IP ",
    expect_fail=True,
    desc="No label 100 packet ever appeared on Path 2",
)


section("ELIMINATION. The listener receives one copy of each packet, not two")

requests = pkt_count(
    "h2",
    "/tmp/obj4_listener.pcap",
    "'icmp[icmptype] = 8 or (vlan and icmp[icmptype] = 8)'",
    "ICMP echo requests arriving at the listener",
)
replies = pkt_count(
    "h2",
    "/tmp/obj4_listener.pcap",
    "'icmp[icmptype] = 0 or (vlan and icmp[icmptype] = 0)'",
    "ICMP echo replies sent back by the listener",
)
log("listener saw %s requests and %s replies", requests, replies)

test_step(requests == 10, f"h2 received 10 requests, one per ping ({requests})", "h2")
test_step(replies == 10, f"h2 sent 10 replies, one per request ({replies})", "h2")
test_step(
    requests < p1 + p2,
    f"{p1 + p2} packets crossed the core but only {requests} reached h2",
    "h2",
)


section("PATH 1 FAILS. Delivery survives on member 2, not on the OSPF reroute")

step("bridge1A", "ip link set eth1 down")

wait_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.2\.1\.2 dev eth2",
    desc="OSPF moved the route for 10.1.3.2 onto eth2 by itself",
    timeout=120,
)

FAIL_CAPTURES = [
    ("bridge1A", "eth0", "fail-path1", "'udp port 6635'"),
    ("bridge2A", "eth1", "fail-path2", "'udp port 6635'"),
]

for target, iface, tag, pfilter in FAIL_CAPTURES:
    start_capture(target, iface, tag, pfilter)

failover = step("h1", "ping -c 5 -W 1 10.0.0.2")
step("h1", "sleep 2")

for target, _, tag, _ in FAIL_CAPTURES:
    stop_capture(target, tag)

f1 = pkt_count(
    "bridge1A",
    "/tmp/obj4_fail-path1.pcap",
    "",
    "packets still arriving at bridge1A from bridgeA",
)
f2 = pkt_count(
    "bridge2A",
    "/tmp/obj4_fail-path2.pcap",
    "'udp[8:2] = 0x000c and udp[10] & 0xf0 = 0x80'",
    "label 200 packets still crossing Path 2",
)
log("into bridge1A %s, label200 on path2 %s", f1, f2)

test_step(no_loss(failover), "0% loss with Path 1 down", "h1")
test_step("DUP!" not in failover, "No duplicate replies while Path 1 is down", "h1")
test_step(f2 > 0, f"Path 2 still carried {f2} label 200 packets", "bridge2A")
test_step(
    f2 > 0 and f1 == 0,
    f"Member 1 never left bridgeA, {f1} packets reached bridge1A",
    "bridgeA",
)

route_moved = step("bridgeA", "ip route get 10.1.3.2; ip route get 10.2.3.2")
both_out_eth2 = len(re.findall(r"dev eth2", route_moved)) == 2
test_step(
    both_out_eth2 and f1 == 0,
    "Both routes now point out eth2, but member 1 stays pinned to eth1",
    "bridgeA",
)

step("bridge1A", "ip link set eth1 up")

wait_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="OSPF restored the route for 10.1.3.2 with no manual repair",
    timeout=120,
)

restored = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(no_loss(restored), "0% loss with both paths healthy again", "h1")
test_step("DUP!" not in restored, "No duplicate replies with both paths up", "h1")


section("UNEQUAL COST. Path 2 is re-costed from 10 to 50 while the lab runs")

set_path2_cost(50)

wait_step(
    "bridgeA",
    "ip route get 10.2.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="Tunnel endpoint 10.2.3.2 has moved off eth2 and onto eth1",
    timeout=120,
)
wait_step(
    "bridgeB",
    "ip route get 10.2.1.1",
    match=r"via 10\.1\.3\.1 dev eth1",
    desc="The return route to 10.2.1.1 has also moved onto eth1",
    timeout=120,
)
match_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="Tunnel endpoint 10.1.3.2 is unchanged, still out eth1",
)


section("Both endpoints now point down Path 1 and h1 sends 10 more pings")

COST_CAPTURES = [
    ("bridge1A", "eth1", "cost-path1", "'udp port 6635'"),
    ("bridge2A", "eth1", "cost-path2", "'udp port 6635'"),
    ("h2", "eth0", "cost-listener", "'icmp or (vlan and icmp)'"),
]

for target, iface, tag, pfilter in COST_CAPTURES:
    start_capture(target, iface, tag, pfilter)

recost = step("h1", "ping -c 10 -W 1 10.0.0.2")
log("ping output:\n%s", recost)

test_step("10 received" in recost, "h1 still received all 10 ICMP replies", "h1")
test_step(no_loss(recost), "h1 still reported 0% packet loss", "h1")

step("h1", "sleep 2")

for target, _, tag, _ in COST_CAPTURES:
    stop_capture(target, tag)


section("REDUNDANCY IS GONE. Only one copy now reaches the wire at all")

c1 = pkt_count(
    "bridge1A",
    "/tmp/obj4_cost-path1.pcap",
    "",
    "Path 1 packets after the cost change",
)
c2 = pkt_count(
    "bridge2A",
    "/tmp/obj4_cost-path2.pcap",
    "",
    "Path 2 packets after the cost change",
)
c100 = pkt_count(
    "bridge1A",
    "/tmp/obj4_cost-path1.pcap",
    "'udp[8:2] = 0x0006 and udp[10] & 0xf0 = 0x40'",
    "label 100 packets on Path 1 after the cost change",
)
c200 = pkt_count(
    "bridge1A",
    "/tmp/obj4_cost-path1.pcap",
    "'udp[8:2] = 0x000c and udp[10] & 0xf0 = 0x80'",
    "label 200 packets on Path 1 after the cost change",
)
log("path1 %s, path2 %s, label100 %s, label200 on path1 %s", c1, c2, c100, c200)

test_step(
    c1 > 0,
    f"Path 1 still carried {c1} packets, counting both directions",
    "bridge1A",
)
test_step(
    c100 > 0,
    f"Path 1 still carried {c100} label 100 packets, both directions",
    "bridge1A",
)
test_step(
    c1 > 0 and c2 == 0,
    f"Path 2 carried nothing at all, {c2} packets, the second copy is gone",
    "bridge2A",
)
test_step(
    c1 > 0 and c200 == 0,
    f"Label 200 appears nowhere, {c200} of them even on Path 1",
    "bridge1A",
)


section("Delivery still succeeds, on the single surviving copy")

c_req = pkt_count(
    "h2",
    "/tmp/obj4_cost-listener.pcap",
    "'icmp[icmptype] = 8 or (vlan and icmp[icmptype] = 8)'",
    "ICMP echo requests still arriving at the listener",
)
c_rep = pkt_count(
    "h2",
    "/tmp/obj4_cost-listener.pcap",
    "'icmp[icmptype] = 0 or (vlan and icmp[icmptype] = 0)'",
    "ICMP echo replies still sent by the listener",
)
test_step(c_req == 10, f"h2 still received all 10 requests ({c_req})", "h2")
test_step(c_rep == 10, f"h2 still sent all 10 replies ({c_rep})", "h2")


section("THE COST OF THAT. The same link failure now loses traffic")

step("bridge1A", "ip link set eth1 down")

during = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(
    loss_pct(during) > 0,
    f"Traffic was lost while OSPF reconverged, {loss_pct(during)}% of it",
    "h1",
)

wait_step(
    "bridgeA",
    "ip route get 10.2.3.2",
    match=r"dev eth2",
    desc="OSPF pushed 10.2.3.2 back onto eth2 after the failure",
    timeout=120,
)

after = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(no_loss(after), "0% loss once OSPF had finished reconverging", "h1")

step("bridge1A", "ip link set eth1 up")


section("CONTROL. Costs go back to 10 and the redundancy returns")

set_path2_cost(10)

wait_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="Tunnel endpoint 10.1.3.2 is back out eth1",
    timeout=120,
)
wait_step(
    "bridgeA",
    "ip route get 10.2.3.2",
    match=r"via 10\.2\.1\.2 dev eth2",
    desc="Tunnel endpoint 10.2.3.2 is back out eth2, where it started",
    timeout=120,
)

BACK_CAPTURES = [
    ("bridge1A", "eth1", "back-path1", "'udp port 6635'"),
    ("bridge2A", "eth1", "back-path2", "'udp port 6635'"),
]

for target, iface, tag, pfilter in BACK_CAPTURES:
    start_capture(target, iface, tag, pfilter)

back = step("h1", "ping -c 10 -W 1 10.0.0.2")
step("h1", "sleep 2")

for target, _, tag, _ in BACK_CAPTURES:
    stop_capture(target, tag)

b1 = pkt_count(
    "bridge1A",
    "/tmp/obj4_back-path1.pcap",
    "",
    "Path 1 packets once the costs were restored",
)
b2 = pkt_count(
    "bridge2A",
    "/tmp/obj4_back-path2.pcap",
    "",
    "Path 2 packets once the costs were restored",
)
log("path1 %s, path2 %s", b1, b2)

test_step(no_loss(back), "h1 reported 0% packet loss with costs back at 10", "h1")
test_step(b1 > 0, f"Path 1 is carrying {b1} packets again, both directions", "bridge1A")
test_step(b2 > 0, f"Path 2 is carrying {b2} packets again, both directions", "bridge2A")
test_step(
    abs(b1 - b2) <= 2,
    f"Both paths are carrying equally again, {b1} and {b2}",
)
