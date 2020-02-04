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
except BaseException:
    print(f"{FAIL} This program require dpkt. Please install it.")
    exit(1)
try:
    import networkx as nx
except BaseException:
    print(f"{FAIL} This program require networkx. Please install it.")
    exit(1)
from subprocess import call, PIPE
import argparse
import time


# CONSTANTS

G = nx.MultiDiGraph()

ignore_probe_resp = False
no_probe_graph = False
verbose = False
only_mac = tuple()
only_bssid = tuple()

# cannot get any idea who's sending and who's receiving, so we have to wait
# the parsing to finish to add the edges
delayed_frames = {
        "probe_req": [],
        "probe_resp": [],
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
ASSOC_REQ = "#0000FF"  # blue
ASSOC_RESP = "#0000AA"
AUTH_REQ = "#FF8C00"  # dark orange
AUTH_RESP = "#AA4700"
REASSOC_REQ = "#FF69B4"  # hot pink
REASSOC_RESP = "#AA2560"
PROBE_RESP = "#123456"
DEAUTH_FROM_AP = "#800000"  # maroon
DEAUTH_FROM_CLIENT = "#400000"
DISASSOC_FROM_CLIENT = "#32CD32"  # lime green
DISASSOC_FROM_AP = "#007800"
ACTION_FROM_AP = "#556B2F"  # dark olive green
ACTION_FROM_CLIENT = "#11460A"
DATA = "#000000"


# CLASSES
class AP:
    def __init__(self, ts, bssid="", ssid="", ch=-1, rates=[], probe=""):
        self.probes = [probe] if probe else []
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

        if self.probes:
            probed = ",".join(self.probes)
            ret += f"probed: {probed}\n"

        if len(self.rates) != 0:  # if we know its rates
            # [int] -> [str] with map
            supported_rates = ",".join(map(str, self.rates[0]))
            if supported_rates:
                ret += f"supported rates: {supported_rates}\n"
            basic_rates = ",".join(map(str, self.rates[1]))
            if basic_rates:
                ret += f"basic rates: {basic_rates}\n"

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

        if other.probes:
            if other.probes[0] not in self.probes:
                self.probes.append(other.probes[0])

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
            probed = ",".join(self.probes)
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
def toRates(raw):
    # supported, basics
    return [500 * x for x in raw if x > 127], [500 * x for x in raw if x > 127]


def generateNodesColors(G):
    # this is used to avoid generating the label of each node each time there
    # is a modification
    for mac in G.nodes:
        if G.nodes[mac]["type"] == AP_T:
            nx.set_node_attributes(
                G, {mac: {"label": f"{mac}\n" \
                    f"{str(G.nodes[mac]['value'])}", "style": "filled",
                    "fillcolor": AP_C}})
        elif G.nodes[mac]["type"] == CLIENT_T:
            nx.set_node_attributes(
                G, {mac: {"label": f"{mac}\n" \
                    f"{str(G.nodes[mac]['value'])}",
                    "style": "filled", "fillcolor": CLIENT_C}})
        elif G.nodes[mac]["type"] == REPEATER_T:
            nx.set_node_attributes(G, {mac: {"label": f"{mac}\nRepeater",
                    "style": "filled", "fillcolor": REPEATER_C}})


def whatIs(mac):
    if mac in G.nodes:
        return G.nodes[mac]["type"]
    return UNKNOWN_T


def addEdge(src, dst, color, style="solid"):
    if not G.has_edge(src, dst, key=color):
        G.add_edge(src, dst, color=color, style=style, key=color)


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
    src = frame.mgmt.src.hex(":")
    dst = frame.mgmt.dst.hex(":")
    bssid = frame.mgmt.bssid.hex(":")

    if len(only_mac) > 0:  # if there is a filter for mac
        if (src not in only_mac) and (dst not in only_mac):
            # doesn't pass filter
            return
    if len(only_bssid) > 0:  # if there is a filter for bssid
        if bssid not in only_bssid:
            # doesn't pass filter
            return

    if frame.subtype in FRAMES_WITH_CAPABILITY:
        ibss = frame.capability.ibss

    if frame.subtype == M_BEACON:
        addAP(src, AP(ts, bssid=bssid, ssid=frame.ssid.data.decode(
            "utf-8", "ignore"), ch=frame.ds.ch,
            rates=toRates(frame.rate.data)))
        if whatIs(src) == AP_T:
            # check if src hasn't been put as a repeater and
            # add a beacon manually
            G.nodes[src]["value"].beacons += 1
    elif frame.subtype == M_PROBE_REQ:
        delayed_frames["probe_req"].append(
            (ts, src, frame.ssid.data.decode("utf-8", "ignore")))
    elif frame.subtype == M_PROBE_RESP and not ignore_probe_resp:
        # cannot guess what has sent a request, so we cannot guess
        # what is the destination (AP or client)
        delayed_frames["probe_resp"].append(
            (ts, src, dst, frame.ssid.data.decode("utf-8", "ignore")))
        # but only APs send reponses
        addAP(src, AP(ts, bssid=bssid,
                      ssid=frame.ssid.data.decode("utf-8", "ignore"),
                      ch=frame.ds.ch, rates=toRates(frame.rate.data)))
    elif frame.subtype == M_ASSOC_REQ:
        addAP(dst, AP(ts, ssid=frame.ssid.data.decode("utf-8", "ignore"),
                      bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client(ts))

        addEdge(src, dst, color=ASSOC_REQ, style="box" if ibss else "solid")
    elif frame.subtype == M_ASSOC_RESP:
        addAP(src, AP(ts, rates=toRates(frame.rate.data), bssid=bssid))
        addClient(dst, Client(ts))

        addEdge(src, dst, color=ASSOC_RESP, style="box" if ibss else "solid")
    elif frame.subtype == M_REASSOC_REQ:
        current_ap = frame.reassoc_req.current_ap.hex(":")
        if current_ap != bssid:  # meaning the client wants to reconnect
            addAP(dst, AP(ts, bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client(ts))

        addEdge(src, dst, color=REASSOC_REQ, style="box" if ibss else "solid")
    elif frame.subtype == M_REASSOC_RESP:
        addAP(src, AP(ts, bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(dst, Client(ts))

        addEdge(src, dst, color=REASSOC_RESP)
    elif frame.subtype == M_AUTH:
        if frame.auth.auth_seq == 256:  # CLIENT -> AP
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))

            addEdge(src, dst, color=AUTH_REQ)
        elif frame.auth.auth_seq == 512:  # AP -> CLIENT
            addAP(src, AP(ts, bssid=bssid))
            addClient(dst, Client(ts))

            addEdge(src, dst, color=AUTH_RESP)

    elif frame.subtype == M_DEAUTH:
        delayed_frames["deauth"].append((ts, src, dst))
    elif frame.subtype == M_DISASSOC:
        delayed_frames["disassoc"].append((ts, src, dst))
    elif frame.subtype == M_ACTION:
        delayed_frames["action"].append((ts, src, dst))


def processDataFrame(frame, ts):
    src = frame.data_frame.src.hex(":")
    dst = frame.data_frame.dst.hex(":")
    delayed_frames["data"].append((ts, src, dst))

def parseDelayedFrames():
    if verbose:
        print(f"{INFO} Handling delayed probe requests.")
    for probe in delayed_frames["probe_req"]:
        src = whatIs(probe[1])
        ssid = probe[2]
        ts = probe[0]
        if src == AP_T:
            addAP(probe[1], AP(ts, probe=ssid if ssid else "<broadcast>"))
        elif src == CLIENT_T:
            addClient(
                probe[1], Client(
                    ts, probe=ssid if ssid else "<broadcast>"))
    if verbose:
        print(f"{INFO} Handling delayed probe responses.")
    for probe in delayed_frames["probe_resp"]:
        # sender is an AP and addAP has been called directly
        # in processManagementFrame
        dst = whatIs(probe[2])
        ssid = probe[3]
        ts = probe[0]
        if dst == AP_T:
            addAP(probe[2], AP(ts, probe=ssid if ssid else "<broadcast>"))
            if not no_probe_graph:
                addEdge(probe[1], probe[2], color=PROBE_RESP, style="dotted")
        elif dst == CLIENT_T:
            addClient(
                probe[2], Client(
                    ts, probe=ssid if ssid else "<broadcast>"))
            if not no_probe_graph:
                addEdge(probe[1], probe[2], color=PROBE_RESP, style="dotted")

    if verbose:
        print(f"{INFO} Handling delayed deauthentification frames.")
    for probe in delayed_frames["deauth"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(probe[1], probe[2], color=DEAUTH_FROM_AP)
            else:
                addEdge(probe[1], probe[2], color=DEAUTH_FROM_CLIENT)
    if verbose:
        print(f"{INFO} Handling delayed disassociation frames.")
    for probe in delayed_frames["disassoc"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(probe[1], probe[2], color=DISASSOC_FROM_AP)
            else:
                addEdge(probe[1], probe[2], color=DISASSOC_FROM_CLIENT)
    if verbose:
        print(f"{INFO} Handling delayed action frames.")
    for probe in delayed_frames["action"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(probe[1], probe[2], color=ACTION_FROM_AP)
            else:
                addEdge(probe[1], probe[2], color=ACTION_FROM_CLIENT)
    if verbose:
        print(f"{INFO} Handling delayed data frames.")
    for probe in delayed_frames["data"]:
        src = whatIs(probe[1])
        dst = whatIs(probe[2])
        ts = probe[0]
        if src != UNKNOWN_T and dst != UNKNOWN_T:
            addEdge(probe[1], probe[2], color=DATA)


def parseWithRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            radio_tap = dpkt.radiotap.Radiotap(buf)
            dot11 = radio_tap.data
        except Exception:
            continue

        if not isinstance(
                dot11, IEEE80211):  # check if the frame is a 802.11 packet
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


def createImageGraph(name_without_extension, format, graph_type, keep_dot):
    try:
        print(
            f"{ACTION} Generating {name_without_extension}.{format}. " \
                    "It may take awhile.")
        cmd = [  # graphviz command to execute
            graph_type,
            f"{name_without_extension}.dot",
            "-Goverlap=scale",
            "-T",
            format,
            "-o",
            f"{name_without_extension}.{format}"]
        if verbose:
            print(f"{INFO} Calling: {' '.join(cmd)}")
        r = call(cmd, stdout=PIPE, stderr=PIPE)
        if r != 0:
            print(
                f"{FAIL} An error occured while generating the image! " \
                        f"Left {name_without_extension}.dot intact.")
            exit(1)
        else:
            print(f"{FINISHED} {name_without_extension}.{format} generated!")
            if not keep_dot:
                if verbose:
                    print(f"{INFO} Calling: rm {name_without_extension}.dot")
                call(["rm", f"{name_without_extension}.dot"],
                     stdout=PIPE, stderr=PIPE)
    except FileNotFoundError: # generated if graphviz prog used is not found
        print(
            f"{FAIL} Impossible to generate the image! Maybe Graphviz isn't " \
                    "installed properly.")
        exit(1)


def generateGraph(args):
    print(f"{ACTION} Generating {args.output}.dot file...")
    generateNodesColors(G)
    try:
        nx.nx_agraph.write_dot(G, f"{args.output}.dot")
    except ImportError:
        print(f"{FAIL} Cannot generate {args.output}.dot. Verify that you " \
                "have Graphviz installed! Quitting.")
        exit(1)
    print(f"{FINISHED} {args.output}.dot generated!")
    if args.format != "dot":
        createImageGraph(args.output, args.format, args.graph, args.keep_dot)


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
            generateNodesColors(G_null)
            try:
                nx.nx_agraph.write_dot(G_null, f"{args.output}_alone_nodes.dot")
            except ImportError:
                print(f"{FAIL} Cannot generate {args.output}.dot. Verify that " \
                        "you have Graphviz installed! Quitting.")
                exit(1)
            print(f"{FINISHED} {args.output}_alone_nodes.dot generated!")
            if args.format != "dot":
                createImageGraph(
                    f"{args.output}_alone_nodes",
                    args.format,
                    args.graph,
                    args.keep_dot)
        else:
            print(
                f"{ACTION} All nodes have an edge at least, don't generate " \
                        f"{args.output}.{args.format} because it's empty.")

    print(f"{ACTION} Generating all subgraphs...")
    for i, g in enumerate(list(nx.weakly_connected_components(
            G))):  # there is no alone nodes as they were removed
        sub = G.subgraph(g)
        generateNodesColors(sub)
        print(f"{ACTION} Generating {args.output}_{i}.dot file...")
        try:
            nx.nx_agraph.write_dot(sub, f"{args.output}_{i}.dot")
        except ImportError:
            print(f"{FAIL} Cannot generate {args.output}.dot. Verify that " \
                    "you have Graphviz installed! Quitting.")
            exit(1)
        print(f"{FINISHED} {args.output}_{i}.dot generated!")
        if args.format != "dot":
            createImageGraph(
                f"{args.output}_{i}",
                args.format,
                args.graph,
                args.keep_dot)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create map from pcap containing IEEE802.11 frames.")
    parser.add_argument("--pcap", "-p", help="PCAP to parse.", required=True)
    parser.add_argument(
        "--output", "-o", help="Name without extension of the output file.",
        dest="output", required=True)
    parser.add_argument(
        "--ignore-probe-graph", "-e", help="Don't draw probe responses, but don't ignore them.",
        dest="no_probe_graph", action="store_true")
    parser.add_argument(
        "--ignore-probe", "-i", help="Ignore probe responses.",
        dest="no_probe", action="store_true")
    parser.add_argument(
        "--format", "-f", help="Output file's format.", dest="format",
        choices=["pdf", "jpg", "png", "dot", "ps", "svg", "svgz", "fig", "gif",
                 "json", "imap", "cmapx"], default="png")
    parser.add_argument(
        "--keep-dot", "-k", help="Keep .dot file.",
        dest="keep_dot", action="store_true")
    parser.add_argument("--only-mac", "-m", help="Filter for mac.",
                        dest="only_mac", nargs='+', action="store")
    parser.add_argument("--only-bssid", "-b", help="Filter for bssid.",
                        dest="only_bssid", nargs='+', action="store")
    parser.add_argument(
        "--no-alone-graph", "-a",
        help="Don't generate graph holding nodes without edges.",
        dest="no_alone", action="store_true")
    parser.add_argument(
        "--split-graph", "-s", help="Split graph into multiple " \
        "files. This is useful when there is a lot of nodes.",
        dest="split_graph", action="store_true")
    parser.add_argument(
        "--verbose", "-v", help="Verbose mode.",
        dest="verbose", action="store_true")
    parser.add_argument(
        "--graph", "-g", help="Graphviz filter to use", dest="graph",
        choices=["dot", "neato", "twopi", "circo", "fdp", "sfdp",
                 "osage", "patchwork"], default="dot")
    args = parser.parse_args()

    if args.no_probe:
        ignore_probe_resp = True
    if args.no_probe_graph:
        no_probe_graph = True
    if args.verbose:
        verbose = True
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
