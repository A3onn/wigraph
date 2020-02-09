#!/usr/bin/env python
# -*- coding: utf-8 -*-

# colors used when displaying text
ACTION = "\033[34m[.]\033[0m"
FINISHED = "\033[92m[O]\033[0m"
INFO = "\033[93m[i]\033[0m"
FAIL = "\033[91m[X]\033[0m"

# IMPORTS
try:
    from dpkt.ieee80211 import * # avoid typing: dpkt.ieee802.11.M_BEACON, etc
    import dpkt
except ModuleNotFoundError:
    print(f"{FAIL} This program require dpkt. Please install it.")
    exit(1)
try:
    import networkx as nx
except ModuleNotFoundError:
    print(f"{FAIL} This program require networkx. Please install it.")
    exit(1)
import argparse
import os
import time
from functools import lru_cache
import textwrap


# CONSTANTS

G = nx.MultiDiGraph()

ignore_probe_resp = False
no_probe_graph = False
verbose = False
only_mac = tuple()
only_bssid = tuple()
no_oui_lookup = True
oui_content = {}

# cannot get any idea who's sending and who's receiving, so we have to wait
# the parsing to finish to add the edges
delayed_frames = {
        "deauth": [],
        "disassoc": [],
        "action": [],
        "data": []}

# types of node
AP_T = 0
CLIENT_T = 1
REPEATER_T = 2
UNKNOWN_T = 3

# COLORS
# nodes
AP_C = "#FF7777"
CLIENT_C = "#7777FF"
REPEATER_C = "#77FF77"

# edges
ASSOC_C = "#0000FF"  # blue
AUTH_C = "#FF8C00"  # dark orange
REASSOC_C = "#FF69B4"  # hot pink
PROBE_RESP_C = "#009B9F" # blue ice
DEAUTH_C = "#800000"  # maroon
DISASSOC_C = "#32CD32"  # lime green
ACTION_C = "#556B2F"  # dark olive green
DATA_C = "#000000"


# CLASSES
class AP:
    def __init__(self, ts, bssid="", ssid="", ch=-1, rates=[]):
        self.bssid = bssid
        self.ssid = ssid
        self.ch = ch
        self.rates = rates
        self.beacons = 0
        self.first_seen = ts
        self.last_seen = ts

    def __str__(self):
        ret = ""
        if self.bssid:
            ret += f"bssid: {self.bssid}\n"

        if self.ssid:
            ret += f"ssid: {self.ssid}\n"

        if self.ch != -1:
            ret += f"channel: {self.ch}\n"

        if len(self.rates) != 0:  # if we know its rates
            # [int] -> [str] with map
            mandatory_rates = ",".join(map(str, self.rates[0]))
            if mandatory_rates:
                ret += f"mandatory rates Mbit/s: {mandatory_rates}\n"
            optional_rates = ",".join(map(str, self.rates[1]))
            if optional_rates:
                ret += f"optional rates Mbit/s: {optional_rates}\n"

        ret += f"# of beacons: {self.beacons}\n" \
            f"First seen: {time.asctime(time.localtime(self.first_seen))}\n" \
            f"Last seen: {time.asctime(time.localtime(self.last_seen))}"
        return ret

    def __mod__(self, other):
        """
        Can now use the % operator to add missing parts of an instance
        by creating another instance with some attirbutes set (= other)
        and getting these attributes and add them into this instance:
        a = AP(ts, ssid="ap 1", bssid="11:22:33:44:55:66")
        ...
        some code
        ...
        a % AP(ts, ch=5) # This will change the ch attribute to 5

        Mind you that Ap(ts, ch=5) is "disposable", it is only used when
        modifying another existing AP instance.

        I use this weird method because it is simple to implement and
        relatively efficient. You can see it as a replacement for dict
        and spaghetti code to change values in these dicts
        """

        if not isinstance(other, AP):
            raise TypeError()

        if not self.bssid and other.bssid:
            self.bssid = other.bssid

        if not self.ssid and other.ssid:
            self.ssid = other.ssid

        if self.ch == -1 and other.ch != -1:
            self.ch = other.ch

        if not self.rates and other.rates:
            self.rates = other.rates

        self.last_seen = other.first_seen
        # could be other.last_seen, as other is "disposable"


class Client:
    def __init__(self, ts, probe=""):
        # might add more attributes later
        self.probes = [probe] if probe else []
        self.first_seen = ts
        self.last_seen = ts
        self.data_frames = 0

    def __str__(self):
        ret = ""
        if self.probes:
            probed = textwrap.fill(",".join(self.probes))
            ret += f"probed: {probed}\n"

        if self.data_frames > 0:
            ret += f"# of data frame: {self.data_frames}\n"

        ret += f"First seen: {time.asctime(time.localtime(self.first_seen))}\n"
        ret += f"Last seen: {time.asctime(time.localtime(self.last_seen))}"
        return ret

    def __mod__(self, other):
        if not isinstance(other, Client):
            raise TypeError()

        if other.probes:
            if other.probes[0] not in self.probes:
                self.probes.append(other.probes[0])

        self.last_seen = other.first_seen
        # could be other.last_seen, it's the same as 'other' is "disposable"
        # and other.first_seen == other.last_seen


# FUNCTIONS

@lru_cache(maxsize=512)
def toRates(raw):
    rates = {2: 1, 4: 2, 11: 5.5, 12: 6, 18: 9, 22: 11, 24: 12, 36: 18, 44: 22,
            48: 24, 66: 33, 72: 36, 96: 48, 108: 54}
    optional = []
    mandatory = []
    for b in raw:
        if b > 127:
            if b - 127 in rates:
                mandatory.append(rates[b-127])
        else:
            if b in rates:
                optional.append(rates[b])
    return mandatory, optional


def generateNodesLabel(G):
    # this is used to avoid generating the label of each node each time there
    # is a modification
    for mac in G.nodes:
        if G.nodes[mac]["type"] == AP_T:
            nx.set_node_attributes(
                G, {mac: {"label": f"{mac} {OUILookup(mac) if not no_oui_lookup else ''}\n" \
                    f"{str(G.nodes[mac]['value'])}", "style": "filled",
                    "fillcolor": AP_C}})
        elif G.nodes[mac]["type"] == CLIENT_T:
            nx.set_node_attributes(
                G, {mac: {"label": f"{mac} {OUILookup(mac) if not no_oui_lookup else ''}\n" \
                    f"{str(G.nodes[mac]['value'])}",
                    "style": "filled", "fillcolor": CLIENT_C}})
        elif G.nodes[mac]["type"] == REPEATER_T:
            nx.set_node_attributes(G, {mac: {"label": f"{mac} {OUILookup(mac) if not no_oui_lookup else ''}\nRepeater",
                    "style": "filled", "fillcolor": REPEATER_C}})


def whatIs(mac):
    if mac in G.nodes:
        return G.nodes[mac]["type"]
    return UNKNOWN_T


def addEdge(src, dst, color):
    if not G.has_edge(src, dst, key=color):
        G.add_edge(src, dst, color=color, key=color)


def addAP(mac, ap):
    if mac not in G.nodes:  # if first time seeing ap
        if verbose:
            print(f"{INFO} Added new AP: {mac}")
        G.add_node(mac, type=AP_T, value=ap)
    else:  # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T:
            # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"] % ap
        except TypeError:
            if verbose:
                print(f"{INFO} Marked {mac} as a repeater")
            nx.set_node_attributes(G, {mac: {'type': REPEATER_T}})


def addClient(mac, client):
    if mac not in G.nodes:  # if first time seeing client
        if verbose:
            print(f"{INFO} Added new Client: {mac}")
        G.add_node(mac, type=CLIENT_T, value=client)
    else:  # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T:
            # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"] % client
        except TypeError:
            if verbose:
                print(f"{INFO} Marked {mac} as a repeater")
            nx.set_node_attributes(G, {mac: {'type': REPEATER_T}})


def processManagementFrame(frame, ts):
    # some frames are delayed because either we cannot guess what is sending
    # it or what is receiving it
    src = frame.mgmt.src.hex(":").upper()
    dst = frame.mgmt.dst.hex(":").upper()
    bssid = frame.mgmt.bssid.hex(":").upper()

    if len(only_mac) > 0:  # if there is a filter for mac
        if (src not in only_mac) and (dst not in only_mac):
            # doesn't pass filter
            return
    if len(only_bssid) > 0:  # if there is a filter for bssid
        if bssid not in only_bssid:
            # doesn't pass filter
            return

    if frame.subtype == M_BEACON:
        addAP(src, AP(ts, bssid=bssid, ssid=frame.ssid.data.decode(
            "utf-8", "ignore"), ch=frame.ds.ch,
            rates=toRates(frame.rate.data)))
        if whatIs(src) == AP_T:
            # check if src hasn't been put as a repeater and
            # add a beacon manually
            G.nodes[src]["value"].beacons += 1
    elif frame.subtype == M_PROBE_REQ:
        addClient(src, Client(ts,
            probe=frame.ssid.data.decode("utf-8", "ignore")))
    elif frame.subtype == M_PROBE_RESP and not ignore_probe_resp:
        addClient(dst, Client(ts))
        addAP(src, AP(ts, bssid=bssid,
                      ssid=frame.ssid.data.decode("utf-8", "ignore"),
                      ch=frame.ds.ch, rates=toRates(frame.rate.data)))
        if not no_probe_graph:
            addEdge(src, dst, color=PROBE_RESP_C)
    elif frame.subtype == M_ASSOC_REQ:
        addAP(dst, AP(ts, ssid=frame.ssid.data.decode("utf-8", "ignore"),
                      bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client(ts))

        addEdge(src, dst, color=ASSOC_C)
    elif frame.subtype == M_ASSOC_RESP:
        addAP(src, AP(ts, rates=toRates(frame.rate.data), bssid=bssid))
        addClient(dst, Client(ts))

        addEdge(src, dst, color=ASSOC_C)
    elif frame.subtype == M_REASSOC_REQ:
        current_ap = frame.reassoc_req.current_ap.hex(":")
        if current_ap != bssid:  # meaning the client wants to reconnect
            addAP(dst, AP(ts, bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client(ts))

        addEdge(src, dst, color=REASSOC_C)
    elif frame.subtype == M_REASSOC_RESP:
        addAP(src, AP(ts, bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(dst, Client(ts))

        addEdge(src, dst, color=REASSOC_C)
    elif frame.subtype == M_AUTH:
        if frame.auth.auth_seq == 256:  # CLIENT -> AP
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))

            addEdge(src, dst, color=AUTH_C)
        elif frame.auth.auth_seq == 512:  # AP -> CLIENT
            addAP(src, AP(ts, bssid=bssid))
            addClient(dst, Client(ts))

            addEdge(src, dst, color=AUTH_C)

    elif frame.subtype == M_DEAUTH:
        delayed_frames["deauth"].append((ts, src, dst))
    elif frame.subtype == M_DISASSOC:
        delayed_frames["disassoc"].append((ts, src, dst))
    elif frame.subtype == M_ACTION:
        delayed_frames["action"].append((ts, src, dst))


def processDataFrame(frame, ts):
    src = frame.data_frame.src.hex(":").upper()
    dst = frame.data_frame.dst.hex(":").upper()
    delayed_frames["data"].append((ts, src, dst))


def parseDelayedFrames():
    if verbose:
        print(f"{INFO} Handling delayed deauthentification frames.")
    for probe in delayed_frames["deauth"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(probe[1], probe[2], color=DEAUTH_C)
            else:
                addEdge(probe[1], probe[2], color=DEAUTH_C)
    if verbose:
        print(f"{INFO} Handling delayed disassociation frames.")
    for probe in delayed_frames["disassoc"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(probe[1], probe[2], color=DISASSOC_C)
            else:
                addEdge(probe[1], probe[2], color=DISASSOC_C)
    if verbose:
        print(f"{INFO} Handling delayed action frames.")
    for probe in delayed_frames["action"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(probe[1], probe[2], color=ACTION_C)
            else:
                addEdge(probe[1], probe[2], color=ACTION_C)
    if verbose:
        print(f"{INFO} Handling delayed data frames.")
    for probe in delayed_frames["data"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            addEdge(probe[1], probe[2], color=DATA_C)


def parseWithRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            radio_tap = dpkt.radiotap.Radiotap(buf)
            dot11 = radio_tap.data
        except Exception:
            continue

        if not isinstance(dot11, IEEE80211):
            # check if the frame is a 802.11 packet
            continue

        if dot11.type == MGMT_TYPE:  # management frames
            processManagementFrame(dot11, ts)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11, ts)
            c += 1

    if verbose:
        print(f"{INFO} Parsing delayed probe requests...")
    parseDelayedFrames()

    return c


def parseWithoutRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            dot11 = IEEE80211(buf)
        except Exception:
            continue

        if dot11.type == MGMT_TYPE:  # management frames
            processManagementFrame(dot11, ts)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11, ts)
            c += 1
    if verbose:
        print(f"{INFO} Parsing delayed probe requests...")
    parseDelayedFrames()

    return c


@lru_cache(maxsize=None)
def OUILookup(mac):
    for mac_o in oui_content:
        if mac.startswith(mac_o):
            return oui_content[mac_o]
    return "Unknown"


def addLegend(g):
    g.add_node("AP", style="filled", fillcolor=AP_C)
    g.add_node("CLIENT", style="filled", fillcolor=CLIENT_C)
    g.add_edge("AP", "CLIENT",
            color=DISASSOC_C, fontcolor=DISASSOC_C,headlabel="disassoc")
    g.add_edge("AP", "CLIENT",
            color=DEAUTH_C, fontcolor=DEAUTH_C,taillabel="deauth")
    g.add_edge("AP", "CLIENT",
            color=AUTH_C, fontcolor=AUTH_C,headlabel="auth")
    g.add_edge("AP", "CLIENT",
            color=REASSOC_C, fontcolor=REASSOC_C,taillabel="reassoc")
    g.add_edge("AP", "CLIENT",
            color=ASSOC_C, fontcolor=ASSOC_C,headlabel="assoc")
    g.add_edge("AP", "CLIENT",
            color=DATA_C, fontcolor=DATA_C,taillabel="data")
    g.add_edge("AP", "CLIENT",
            color=ACTION_C, fontcolor=ACTION_C, headlabel="action")
    g.add_edge("AP", "CLIENT",
            color=PROBE_RESP_C, fontcolor=PROBE_RESP_C, taillabel="probe resp")

def generateGraph(args):
    print(f"{ACTION} Generating {args.output}.{args.format} file...")
    generateNodesLabel(G)

    if not args.no_legend:
        addLegend(G)

    graph = nx.nx_agraph.to_agraph(G)
    graph.draw(f"{args.output}.{args.format}", prog=args.graph)

    print(f"{FINISHED} {args.output}.{args.format} generated!")


def generateMultipleGraphs(args):
    if args.verbose:
        print(f"{INFO} Removing nodes without any edge...")
    G_null = nx.Graph()  # nodes without edges, don't need a fancy graph
    # need a copy because some nodes in the original graph will be removed
    nodes = list(G.nodes)
    for node in nodes:
        if len(G.in_edges(node)) == 0 and len(G.out_edges(
                node)) == 0:  # if this node doesn't have any edge
            G_null.add_node(
                node,
                value=G.nodes[node]["value"],
                type=G.nodes[node]["type"])
            G.remove_node(node)
    if not args.no_alone:  # if generating alone_nodes graph
        if len(G_null.nodes) > 0:
            print(f"{ACTION} Generating {args.output}_alone_nodes.dot file...")
            generateNodesLabel(G_null)

            graph = nx.nx_agraph.to_agraph(G_null)
            graph.draw(f"{args.output}_alone_nodes.{args.format}",
                    prog=args.graph)

            print(f"{FINISHED} {args.output}_alone_nodes.{args.format}"
                "generated!")

        else:
            print(
                f"{ACTION} All nodes have an edge at least, don't generate " \
                        f"{args.output}.{args.format} because it's empty.")

    print(f"{ACTION} Generating all subgraphs...")
    for i, g in enumerate(list(nx.weakly_connected_components(G))):
        # there is no alone nodes as they were removed

        sub = nx.MultiDiGraph(G.subgraph(g))
        generateNodesLabel(sub)

        if not args.no_legend:
            addLegend(sub)
        print(f"{ACTION} Generating {args.output}_{i}.dot file...")
        graph = nx.nx_agraph.to_agraph(sub)
        graph.draw(f"{args.output}_{i}.{args.format}", prog=args.graph)

        print(f"{FINISHED} {args.output}_{i}.{args.format} generated!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create wifi graph from PCAP containing IEEE802.11 frames.")
    parser.add_argument("--pcap", "-p", help="PCAP to parse.", required=True,
            metavar="PCAP")
    parser.add_argument(
        "--output", "-o", help="Name without extension of the output file.",
        dest="output", required=True, metavar="name")
    parser.add_argument(
        "--ignore-probe-graph", "-e", help="Don't draw probe responses,"
        "but don't ignore them.",
        dest="no_probe_graph", action="store_true")
    parser.add_argument(
        "--ignore-probe", "-i", help="Ignore probe responses.",
        dest="no_probe", action="store_true")
    parser.add_argument(
        "--format", "-f", help="Output file's format.", dest="format",
        choices=["pdf", "jpg", "png", "dot", "ps", "svg", "svgz", "fig", "gif",
                 "json", "imap", "cmapx"], default="png", metavar="format")
    parser.add_argument("--only-mac", "-m", help="Filter for mac.",
                        dest="only_mac", nargs='+', action="store",
                        metavar="MACs")
    parser.add_argument("--no-legend", "-l", help="Don't draw the legend.",
                        dest="no_legend", action="store_true")
    parser.add_argument("--only-bssid", "-b", help="Filter for bssid.",
                        dest="only_bssid", nargs='+', action="store",
                        metavar="BSSIDs")
    parser.add_argument(
        "--no-alone-graph", "-a",
        help="Don't generate graph holding nodes without edges. Works with -s.",
        dest="no_alone", action="store_true")
    parser.add_argument(
        "--split-graph", "-s", help="Split graph into multiple " \
        "files. This is useful when there is a lot of nodes.",
        dest="split_graph", action="store_true")
    parser.add_argument(
        "--verbose", "-v", help="Verbose mode.",
        dest="verbose", action="store_true")
    parser.add_argument(
        "--no-oui-lookup", "-k", help="Don't resolve MACs addresses.",
        dest="no_oui_lookup", action="store_true")
    parser.add_argument(
        "--graph", "-g", help="Graphviz filter to use", dest="graph",
        choices=["dot", "neato", "twopi", "circo", "fdp", "sfdp"],
        default="sfdp", metavar="prog")
    args = parser.parse_args()

    ignore_probe_resp = args.no_probe
    no_probe_graph = args.no_probe_graph
    verbose = args.verbose

    if not args.no_oui_lookup:
        try:
            with open("oui.txt", "r") as f:
                for line in f:
                    elements = line.strip().split("\t")
                    # MAC: NAME
                    oui_content.update({elements[0]: elements[1]})
                    no_oui_lookup = False
        except FileNotFoundError:
            print(f"{FAIL} Impossible to open oui.txt, please put this file "
                    "in the same directory as this file: "
                    f"{os.path.dirname(os.path.realpath(__file__))}. "
                    "Quitting.")
            exit(1)
    else:
        no_oui_lookup = True

    no_oui_lookup = args.no_oui_lookup
    if args.only_mac:
        only_mac = tuple(args.only_mac)
    if args.only_bssid:
        only_bssid = tuple(args.only_bssid)

    try:
        raw_pcap = open(args.pcap, "rb")
    except FileNotFoundError:
        print(f"{FAIL} No file found: {args.pcap}")
        exit(1)
    try:
        if args.pcap.endswith(".pcapng") or args.pcap.endswith(".pcap-ng"):
            pcap = dpkt.pcapng.Reader(raw_pcap)
        else:
            pcap = dpkt.pcap.Reader(raw_pcap)
    except BaseException:
        print(f"{FAIL} An error occured while reading {args.pcap}.")
        exit(1)

    if verbose:
        print(f"{INFO} Loading {args.pcap} in memory")
    packets = pcap.readpkts()
    raw_pcap.close()

    if pcap.datalink() == dpkt.pcap.DLT_IEEE802_11_RADIO:
        print(f"{ACTION} Begining of parsing!")
        count = parseWithRadio(packets)
        print(f"{FINISHED} Parsed {count} frames!")
    elif pcap.datalink() == dpkt.pcap.DLT_IEEE802_11:
        print(f"{ACTION} Begining of parsing!")
        count = parseWithoutRadio(packets)
        print(f"{FINISHED} Parsed {count} frames!")
    else:
        raw_pcap.close()
        print(f"{FAIL} Wrong link-layer header type. It should either be " \
                "LINKTYPE_IEEE802_11 or LINKTYPE_IEEE802_11_RADIOTAP.")
        exit(1)
    raw_pcap.close()

    # generate dot file and image file
    if args.split_graph:
        generateMultipleGraphs(args)
    else:
        generateGraph(args)