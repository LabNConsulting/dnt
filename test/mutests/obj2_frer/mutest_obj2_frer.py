"""Objective 2: FRER (802.1CB) over transparent Layer 2 bridges."""

import re

from munet.mutest.userapi import log
from munet.mutest.userapi import match_step
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import step_json
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step


def pkt_count(target, pcap, pfilter="", what="frames"):
    out = step(target, f"tcpdump -nr {pcap} {pfilter} 2>/dev/null | wc -l")
    m = re.search(r"(\d+)", out)
    n = int(m.group(1)) if m else 0
    log("%s: %s", what, n)
    return n


def first_frame(target, pcap, what):
    ok, g = match_step(
        target,
        f"tcpdump -ner {pcap} -c 1 2>/dev/null | head -1",
        match=r"(\S.*)",
        desc=f"Read the first {what} frame off the capture",
    )
    return g[0].strip() if ok and g else "(empty capture)"


NO_LOSS = r"\b0% packet loss"


def no_loss(output):
    return bool(re.search(NO_LOSS, output))


EDGES = ("bridgeA", "bridgeB")
RELAYS = ("bridge1A", "bridge1B", "bridge2A", "bridge2B")

V1 = "ether[14:2] & 0x0fff = 100"
V2 = "ether[14:2] & 0x0fff = 200"
VID1 = f"'{V1}'"
VID2 = f"'{V2}'"
RTAG = "'ether[16:2] = 0xf1c1'"
ICMP_ANY = "'icmp or (vlan and icmp)'"
ECHO_REQ = "'icmp[icmptype] = 8 or (vlan and icmp[icmptype] = 8)'"
ECHO_REP = "'icmp[icmptype] = 0 or (vlan and icmp[icmptype] = 0)'"

CAPTURES = [
    ("bridge1A", "eth1", "path1", ""),
    ("bridge2A", "eth1", "path2", ""),
    ("h2", "eth0", "listener", ICMP_ANY),
]


def start_capture(target, iface, tag, pfilter):
    step(target, f"rm -f /tmp/obj2_{tag}.pcap /tmp/obj2_{tag}.pid")
    step(
        target,
        f"nohup tcpdump -U -Z root -ni {iface} -w /tmp/obj2_{tag}.pcap {pfilter} "
        f">/tmp/obj2_{tag}.log 2>&1 & echo $! > /tmp/obj2_{tag}.pid",
    )
    wait_step(
        target,
        f"cat /tmp/obj2_{tag}.log",
        match=f"listening on {iface}",
        desc=f"tcpdump listening on {iface} for the {tag} capture",
        timeout=15,
    )


def stop_capture(target, tag):
    step(target, f"kill -INT $(cat /tmp/obj2_{tag}.pid)")
    wait_step(
        target,
        f"kill -0 $(cat /tmp/obj2_{tag}.pid) 2>/dev/null; echo rc=$?",
        match="rc=1",
        desc=f"The {tag} capture flushed to disk and stopped",
        timeout=15,
    )


section("The DNT replication engine is running on both edge nodes")

for edge in EDGES:
    wait_step(
        edge,
        "ps -eo comm,args | awk '$1==\"dnt\" && /dnt.ini/' | wc -l",
        match=r"^[1-9]",
        flags=re.MULTILINE,
        desc="At least one dnt process is running with dnt.ini",
        timeout=30,
    )


section("The four relay nodes are plain Linux bridges, nothing more")

for node in RELAYS:
    match_step(
        node,
        "ip -d link show br0",
        match=r"bridge",
        desc="br0 exists and is a real bridge device",
    )
    match_step(
        node,
        "ip link show br0",
        match=r"state UP|UP>",
        desc="br0 is administratively up",
    )
    for iface in ("eth0", "eth1"):
        match_step(
            node,
            f"ip link show {iface}",
            match=r"master br0",
            desc=f"{iface} is enslaved to br0",
        )


section("The core has no IP addresses and no routing daemon anywhere")

for node in RELAYS:
    match_step(
        node,
        "ip -4 addr show eth0; ip -4 addr show eth1",
        match=r"inet ",
        expect_fail=True,
        desc="Neither relay port carries an IPv4 address",
    )

match_step(
    "bridge1A",
    "ps -ef | grep -E '[z]ebra|[o]spfd|[f]rr'",
    match=r"zebra|ospfd|frr",
    expect_fail=True,
    desc="No zebra, ospfd or frr process is running",
)

match_step(
    "h1",
    "ip route get 10.0.0.2",
    match=r"10\.0\.0\.2 dev eth0",
    desc="h1 and h2 share one subnet, with no router between them",
)


section("Host ARP entries are pinned so replicated ARP stays out of the captures")

h1_mac = step_json("h1", "ip -j link show eth0")[0]["address"]
h2_mac = step_json("h2", "ip -j link show eth0")[0]["address"]
log("h1 eth0 %s, h2 eth0 %s", h1_mac, h2_mac)

step("h1", f"ip neigh replace 10.0.0.2 lladdr {h2_mac} dev eth0 nud permanent")
step("h2", f"ip neigh replace 10.0.0.1 lladdr {h1_mac} dev eth0 nud permanent")

warm = step("h1", "ping -c 2 -W 1 10.0.0.2")
test_step(no_loss(warm), "Warm-up ping from h1 to h2 got 2 of 2 replies", "h1")
test_step(
    no_loss(warm) and "DUP!" not in warm,
    "The warm-up ping had no loss and no duplicate replies",
    "h1",
)


section("Captures are running on both paths and h1 sends 10 pings")

for target, iface, tag, pfilter in CAPTURES:
    start_capture(target, iface, tag, pfilter)

sent = step("h1", "ping -c 10 -W 1 10.0.0.2")
log("ping output:\n%s", sent)

test_step("10 received" in sent, "h1 received all 10 ICMP replies", "h1")
test_step(no_loss(sent), "h1 reported 0% packet loss", "h1")
test_step(
    no_loss(sent) and "DUP!" not in sent,
    "h1 had no loss and saw no duplicates, so elimination worked",
    "h1",
)

step("h1", "sleep 2")

for target, _, tag, _ in CAPTURES:
    stop_capture(target, tag)


section("What is actually on the wire, surveyed before anything is asserted")

total1 = pkt_count(
    "bridge1A", "/tmp/obj2_path1.pcap", "", "every frame captured on Path 1"
)
total2 = pkt_count(
    "bridge2A", "/tmp/obj2_path2.pcap", "", "every frame captured on Path 2"
)
test_step(total1 > 0, f"Path 1 carried {total1} frames of any kind", "bridge1A")
test_step(total2 > 0, f"Path 2 carried {total2} frames of any kind", "bridge2A")

f1 = first_frame("bridge1A", "/tmp/obj2_path1.pcap", "Path 1")
f2 = first_frame("bridge2A", "/tmp/obj2_path2.pcap", "Path 2")
log("Path 1 frame 1: %s", f1[:110])
log("Path 2 frame 1: %s", f2[:110])

for tpid, off in (("0x8100", 12), ("0xf1c1", 12), ("0xf1c1", 16), ("0x88a8", 12)):
    n = pkt_count(
        "bridge1A",
        "/tmp/obj2_path1.pcap",
        f"'ether[{off}:2] = {tpid}'",
        f"Path 1 frames with ethertype {tpid} at byte offset {off}",
    )
    log("Path 1: %s frames with %s at offset %s", n, tpid, off)


section("REPLICATION. Both paths carry their own copy of every frame")

p1 = pkt_count("bridge1A", "/tmp/obj2_path1.pcap", VID1, "Path 1 frames on VLAN 100")
p2 = pkt_count("bridge2A", "/tmp/obj2_path2.pcap", VID2, "Path 2 frames on VLAN 200")
log("Path 1 carried %s, Path 2 carried %s", p1, p2)

test_step(p1 >= 10, f"Path 1 carried {p1} frames tagged VLAN 100", "bridge1A")
test_step(p2 >= 10, f"Path 2 carried {p2} frames tagged VLAN 200", "bridge2A")
test_step(
    abs(p1 - p2) <= 2,
    f"Both paths carried the same number of copies, {p1} and {p2}",
)


section("SEPARATION. Each path carries only its own VLAN, never the other's")

x1 = pkt_count(
    "bridge1A", "/tmp/obj2_path1.pcap", VID2,
    "Path 1 frames on VLAN 200, which belongs to Path 2",
)
x2 = pkt_count(
    "bridge2A", "/tmp/obj2_path2.pcap", VID1,
    "Path 2 frames on VLAN 100, which belongs to Path 1",
)

test_step(
    p1 > 0 and x1 == 0,
    f"Path 1 carried VLAN 100 only, {x1} frames on VLAN 200",
    "bridge1A",
)
test_step(
    p2 > 0 and x2 == 0,
    f"Path 2 carried VLAN 200 only, {x2} frames on VLAN 100",
    "bridge2A",
)


section("R-TAG. Every replicated frame carries an 802.1CB sequence tag")

r1 = pkt_count(
    "bridge1A", "/tmp/obj2_path1.pcap", RTAG, "Path 1 frames carrying an 802.1CB R-TAG"
)
r2 = pkt_count(
    "bridge2A", "/tmp/obj2_path2.pcap", RTAG, "Path 2 frames carrying an 802.1CB R-TAG"
)

test_step(r1 >= 10, f"Path 1 carried {r1} R-TAGged frames", "bridge1A")
test_step(r2 >= 10, f"Path 2 carried {r2} R-TAGged frames", "bridge2A")
test_step(
    p1 > 0 and r1 == p1,
    f"Every one of Path 1's frames was R-TAGged, {r1} of {p1}",
    "bridge1A",
)
test_step(
    p2 > 0 and r2 == p2,
    f"Every one of Path 2's frames was R-TAGged, {r2} of {p2}",
    "bridge2A",
)


section("ELIMINATION. The listener receives one copy of each frame, not two")

requests = pkt_count(
    "h2", "/tmp/obj2_listener.pcap", ECHO_REQ,
    "ICMP echo requests arriving at the listener",
)
replies = pkt_count(
    "h2", "/tmp/obj2_listener.pcap", ECHO_REP,
    "ICMP echo replies sent back by the listener",
)
log("listener saw %s requests and %s replies", requests, replies)

test_step(requests == 10, f"h2 received 10 requests, one per ping ({requests})", "h2")
test_step(replies == 10, f"h2 sent 10 replies, one per request ({replies})", "h2")
test_step(
    requests < p1 + p2,
    f"{p1 + p2} frames crossed the core but only {requests} reached h2",
    "h2",
)

tagged_at_listener = pkt_count(
    "h2", "/tmp/obj2_listener.pcap", "'ether[12:2] = 0x8100'",
    "still-tagged frames arriving at the listener",
)
test_step(
    requests > 0 and tagged_at_listener == 0,
    f"h2 sees plain untagged frames, {tagged_at_listener} still tagged",
    "h2",
)


def send_and_count(phase, label):
    caps = [
        ("bridge1A", "eth1", f"{phase}-path1", ""),
        ("bridge2A", "eth1", f"{phase}-path2", ""),
        ("h2", "eth0", f"{phase}-listener", ICMP_ANY),
    ]
    for t, i, tag, f in caps:
        start_capture(t, i, tag, f)
    out = step("h1", "ping -c 10 -W 1 10.0.0.2")
    step("h1", "sleep 2")
    for t, _, tag, _ in caps:
        stop_capture(t, tag)

    fwd1 = pkt_count(
        "bridge1A", f"/tmp/obj2_{phase}-path1.pcap",
        f"'{V1} and ether src {h1_mac}'",
        f"Path 1 frames sent by h1, {label}",
    )
    rev1 = pkt_count(
        "bridge1A", f"/tmp/obj2_{phase}-path1.pcap",
        f"'{V1} and ether src {h2_mac}'",
        f"Path 1 frames sent back by h2, {label}",
    )
    fwd2 = pkt_count(
        "bridge2A", f"/tmp/obj2_{phase}-path2.pcap",
        f"'{V2} and ether src {h1_mac}'",
        f"Path 2 frames sent by h1, {label}",
    )
    rev2 = pkt_count(
        "bridge2A", f"/tmp/obj2_{phase}-path2.pcap",
        f"'{V2} and ether src {h2_mac}'",
        f"Path 2 frames sent back by h2, {label}",
    )
    delivered = pkt_count(
        "h2", f"/tmp/obj2_{phase}-listener.pcap", ECHO_REQ,
        f"requests delivered to the listener, {label}",
    )
    log("%s: path1 fwd %s rev %s, path2 fwd %s rev %s, delivered %s",
        phase, fwd1, rev1, fwd2, rev2, delivered)
    return out, fwd1, rev1, fwd2, rev2, delivered


section("PATH 1 DOWN. Traffic keeps flowing on Path 2 alone")

step("bridgeA", "ip link set eth1 down")
out, fwd1, rev1, fwd2, rev2, delivered = send_and_count("p1down", "with Path 1 down")

test_step(fwd1 == 0, f"Path 1 sent nothing from h1, {fwd1} frames", "bridge1A")
test_step(fwd2 >= 10, f"Path 2 kept sending from h1, {fwd2} frames", "bridge2A")
test_step(rev1 >= 10, f"h2's replies still came back down Path 1, {rev1}", "bridge1A")
test_step(rev2 >= 10, f"h2's replies also came down Path 2, {rev2}", "bridge2A")
test_step(delivered == 10, f"h2 still received all 10 requests ({delivered})", "h2")
test_step(no_loss(out), "0% loss with Path 1 down", "h1")
test_step(
    no_loss(out) and "DUP!" not in out,
    "No loss and no duplicates with Path 1 down",
    "h1",
)


section("PATH 2 DOWN. Traffic keeps flowing on Path 1 alone")

step("bridgeA", "ip link set eth1 up")
wait_step(
    "bridgeA",
    "ip link show eth1",
    match=r"LOWER_UP",
    desc="The Path 1 port came back up",
    timeout=30,
)
step("bridgeA", "ip link set eth2 down")
out, fwd1, rev1, fwd2, rev2, delivered = send_and_count("p2down", "with Path 2 down")

test_step(fwd2 == 0, f"Path 2 sent nothing from h1, {fwd2} frames", "bridge2A")
test_step(fwd1 >= 10, f"Path 1 kept sending from h1, {fwd1} frames", "bridge1A")
test_step(rev2 >= 10, f"h2's replies still came back down Path 2, {rev2}", "bridge2A")
test_step(rev1 >= 10, f"h2's replies also came down Path 1, {rev1}", "bridge1A")
test_step(delivered == 10, f"h2 still received all 10 requests ({delivered})", "h2")
test_step(no_loss(out), "0% loss with Path 2 down", "h1")
test_step(
    no_loss(out) and "DUP!" not in out,
    "No loss and no duplicates with Path 2 down",
    "h1",
)


section("BOTH PATHS BACK. Replication resumes on both at once")

step("bridgeA", "ip link set eth2 up")
wait_step(
    "bridgeA",
    "ip link show eth2",
    match=r"LOWER_UP",
    desc="The Path 2 port came back up",
    timeout=30,
)
out, fwd1, rev1, fwd2, rev2, delivered = send_and_count("bothup", "with both paths up")

test_step(fwd1 >= 10, f"Path 1 is sending from h1 again, {fwd1} frames", "bridge1A")
test_step(fwd2 >= 10, f"Path 2 is sending from h1 again, {fwd2} frames", "bridge2A")
test_step(
    abs(fwd1 - fwd2) <= 2,
    f"Both paths are carrying equally again, {fwd1} and {fwd2}",
)
test_step(
    rev1 >= 10 and rev2 >= 10,
    f"Both paths carry h2's replies too, {rev1} and {rev2}",
)
test_step(delivered == 10, f"h2 received all 10 requests ({delivered})", "h2")
test_step(no_loss(out), "0% loss with both paths up", "h1")
test_step(
    no_loss(out) and "DUP!" not in out,
    "No loss and no duplicates with both paths up",
    "h1",
)
