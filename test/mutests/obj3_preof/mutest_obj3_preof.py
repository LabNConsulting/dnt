"""Objective 3: PREOF over static routes, no FRR."""

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


CAPTURES = [
    ("bridge1A", "eth1", "path1", "'udp port 6635'"),
    ("bridge2A", "eth1", "path2", "'udp port 6635'"),
    ("h2", "eth0", "listener", "'icmp or (vlan and icmp)'"),
]


def start_capture(target, iface, tag, pfilter):
    step(target, f"rm -f /tmp/obj3_{tag}.pcap /tmp/obj3_{tag}.pid")
    step(
        target,
        f"nohup tcpdump -U -Z root -ni {iface} -w /tmp/obj3_{tag}.pcap {pfilter} "
        f">/tmp/obj3_{tag}.log 2>&1 & echo $! > /tmp/obj3_{tag}.pid",
    )
    wait_step(
        target,
        f"cat /tmp/obj3_{tag}.log",
        match=f"listening on {iface}",
        desc=f"tcpdump listening on {iface} for the {tag} capture",
        timeout=15,
    )


def stop_capture(target, tag):
    step(target, f"kill -INT $(cat /tmp/obj3_{tag}.pid)")
    wait_step(
        target,
        f"kill -0 $(cat /tmp/obj3_{tag}.pid) 2>/dev/null; echo rc=$?",
        match="rc=1",
        desc=f"The {tag} capture flushed to disk and stopped",
        timeout=15,
    )


section("The DNT replication engine is running on both edge nodes")

for edge in ("bridgeA", "bridgeB"):
    wait_step(
        edge,
        f"ps -eo comm,args | awk '$1==\"dnt\" && /{edge}.ini/' | wc -l",
        match=r"^1$",
        flags=re.MULTILINE,
        desc=f"A dnt process is running with {edge}.ini",
        timeout=30,
    )


section("No FRR or any other routing daemon exists anywhere in the lab")

match_step(
    "bridgeA",
    "ps -ef | grep -E '[z]ebra|[o]spfd|[f]rr'",
    match=r"zebra|ospfd|frr",
    expect_fail=True,
    desc="No zebra, ospfd or frr process is running",
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


section("STATIC ROUTES. Both tunnel paths are pinned by hand, not learned")

match_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="Tunnel endpoint 10.1.3.2 routes out eth1, over Path 1",
)
match_step(
    "bridgeA",
    "ip route get 10.2.3.2",
    match=r"via 10\.2\.1\.2 dev eth2",
    desc="Tunnel endpoint 10.2.3.2 routes out eth2, over Path 2",
)
match_step(
    "bridgeB",
    "ip route get 10.1.1.1",
    match=r"via 10\.1\.3\.1 dev eth1",
    desc="The return route to 10.1.1.1 leaves bridgeB on eth1",
)
match_step(
    "bridgeB",
    "ip route get 10.2.1.1",
    match=r"via 10\.2\.3\.1 dev eth2",
    desc="The return route to 10.2.1.1 leaves bridgeB on eth2",
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


section("Captures are running on both paths and h1 sends 10 pings")

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
    "/tmp/obj3_path1.pcap",
    "'dst host 10.1.3.2'",
    "Path 1 packets travelling toward bridgeB",
)
p2 = pkt_count(
    "bridge2A",
    "/tmp/obj3_path2.pcap",
    "'dst host 10.2.3.2'",
    "Path 2 packets travelling toward bridgeB",
)
log("Path 1 carried %s copies, Path 2 carried %s copies", p1, p2)

test_step(p1 >= 10, f"Path 1 carried {p1} packets toward bridgeB", "bridge1A")
test_step(p2 >= 10, f"Path 2 carried {p2} packets toward bridgeB", "bridge2A")
test_step(
    abs(p1 - p2) <= 2,
    f"Both paths carried the same number of copies, {p1} and {p2}",
)


section("SEPARATION. Each path carries only its own MPLS label, never the other")

l100 = pkt_count(
    "bridge1A",
    "/tmp/obj3_path1.pcap",
    "'udp[8:2] = 0x0006 and udp[10] & 0xf0 = 0x40'",
    "Path 1 packets carrying MPLS label 100",
)
l200 = pkt_count(
    "bridge2A",
    "/tmp/obj3_path2.pcap",
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
    "tcpdump -nr /tmp/obj3_path1.pcap 'udp[8:2] = 0x000c' 2>/dev/null",
    match=r"IP ",
    expect_fail=True,
    desc="No label 200 packet ever appeared on Path 1",
)
match_step(
    "bridge2A",
    "tcpdump -nr /tmp/obj3_path2.pcap 'udp[8:2] = 0x0006' 2>/dev/null",
    match=r"IP ",
    expect_fail=True,
    desc="No label 100 packet ever appeared on Path 2",
)


section("ELIMINATION. The listener receives one copy of each packet, not two")

requests = pkt_count(
    "h2",
    "/tmp/obj3_listener.pcap",
    "'icmp[icmptype] = 8 or (vlan and icmp[icmptype] = 8)'",
    "ICMP echo requests arriving at the listener",
)
replies = pkt_count(
    "h2",
    "/tmp/obj3_listener.pcap",
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


section("PATH 1 DOWN. Delivery survives, but the route needs repairing by hand")

step("bridge1A", "ip link set eth1 down")

match_step(
    "bridgeA",
    "ping -c 2 -W 1 10.1.3.2",
    match=NO_LOSS,
    expect_fail=True,
    desc="Path 1 is genuinely broken, 10.1.3.2 no longer answers",
)

failover = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(no_loss(failover), "0% loss with Path 1 down, the second copy carries it", "h1")
test_step("DUP!" not in failover, "No duplicate replies while Path 1 is down", "h1")

step("bridge1A", "ip link set eth1 up")
step("bridge1A", "ip route replace 10.1.3.2/32 via 10.1.2.2 dev eth1")

wait_step(
    "bridgeA",
    "ping -c 2 -W 1 10.1.3.2",
    match=NO_LOSS,
    desc="Path 1 works again, but only after the route was re-added by hand",
    timeout=30,
)

restored = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(no_loss(restored), "0% loss with both paths healthy again", "h1")
test_step("DUP!" not in restored, "No duplicate replies with both paths up", "h1")
