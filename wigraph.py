#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# colors used when displaying text
ACTION = "\033[34m[.]\033[0m"
FINISHED = "\033[92m[O]\033[0m"
INFO = "\033[93m[i]\033[0m"
FAIL = "\033[91m[X]\033[0m"

# IMPORTS
try:
    from dpkt.ieee80211 import *
    from dpkt.radiotap import Radiotap
    from dpkt.dpkt import UnpackError
    from dpkt.pcapng import Reader as pcapng_Reader
    from dpkt.pcap import DLT_IEEE802_11_RADIO,DLT_IEEE802_11, Reader as pcap_Reader
except ModuleNotFoundError:
    print("{} This program require dpkt. Please install it.".format(FAIL))
    exit(1)
try:
    import networkx as nx
except ModuleNotFoundError:
    print("{} This program require networkx. Please install it.".format(FAIL))
    exit(1)
try:
    import pygraphviz # used by networkx to output the graph
except ModuleNotFoundError:
    print("{} This program require pygraphviz. Please install it.".format(FAIL))
    exit(1)

from argparse import ArgumentParser
from functools import lru_cache
import os
import re
import time
import textwrap


# CONSTANTS
G = nx.MultiDiGraph() # graph containing all nodes during the parsing

# settings
ignore_probe_resp = False
no_probe_graph = False
verbose = False
only_mac = tuple()
only_bssid = tuple()
no_oui_lookup = True
oui_table = {}

# cannot get, with these frames, if the source is an AP or a client and same thing for the destination,
# so we have to wait the parsing to finish to add the edges
delayed_frames = {
        "deauth": [],
        "disassoc": [],
        "action": [],
        "data": [],
        "ctl": []}

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
    def __init__(self, ts, bssid="", ssid="", ch=-1, rates=[], enc="", auth=[], cipher=[]):
        self.bssid = bssid
        self.ssid = ssid
        self.ch = ch
        self.rates = rates
        self.beacons = 0
        self.first_seen = ts
        self.last_seen = ts
        self.enc = enc
        self.auth = auth
        self.cipher = cipher

    def __str__(self):
        # this function will be used when adding text in nodes when generating
        # the graph

        ret = ""
        if self.bssid:
            ret += "bssid: {}\n".format(self.bssid)

        if self.ssid:
            ret += "ssid: {}\n".format(self.ssid)

        if self.ch != -1:
            ret += "channel: {}\n".format(self.ch)
        
        if self.enc:
            ret += "enc: {}\n".format(self.enc)
            
        if self.auth:
            ret += "auth: {}\n".format(', '.join(self.auth))
            
        if self.cipher:
            ret += "cipher: {}\n".format(', '.join(self.cipher))

        if len(self.rates) != 0:  # if we know its rates
            # [int] -> [str] with map
            mandatory_rates = ",".join(map(str, self.rates[0]))
            if mandatory_rates:
                ret += "mandatory rates Mbit/s: {}\n".format(mandatory_rates)
            optional_rates = ",".join(map(str, self.rates[1]))
            if optional_rates:
                ret += "optional rates Mbit/s: {}\n".format(optional_rates)

        ret += "# of beacons: {}\n".format(self.beacons) + \
            "First seen: {}\n".format(time.asctime(time.localtime(self.first_seen))) + \
            "Last seen: {}\n".format(time.asctime(time.localtime(self.last_seen)))
        return ret

    def update(self, other):
        if not isinstance(other, AP):
            raise TypeError()

        if not self.bssid and other.bssid:
            self.bssid = other.bssid

        if not self.ssid and other.ssid:
            self.ssid = other.ssid
            
        if not self.enc and other.enc:
            self.enc = other.enc
        
        for a in other.auth:
            if a not in self.auth:
                self.auth.append(a)
            
        for c in other.cipher:
            if c not in self.cipher:
                self.cipher.append(c)
            
        if self.ch == -1 and other.ch != -1:
            self.ch = other.ch

        if not self.rates and other.rates:
            self.rates = other.rates

        self.last_seen = other.first_seen
        # could be other.last_seen, as other is juste used here


class Client:
    def __init__(self, ts, probe="", probed=False):
        # might add more attributes later
        self.probes = [probe if probe else "<Broadcast>"] if probed else [] # list of probes
        self.first_seen = ts
        self.last_seen = ts
        self.data_frames = 0

    def __str__(self):
        ret = ""
        if self.probes:
            probed = textwrap.fill(",".join(self.probes))
            ret += "probed: {}\n".format(probed)

        if self.data_frames > 0:
            ret += "# of data frame: {}\n".format(self.data_frames)

        ret += "First seen: {}\n".format(time.asctime(time.localtime(self.first_seen)))
        ret += "Last seen: {}\n".format(time.asctime(time.localtime(self.last_seen)))
        return ret

    def update(self, other):
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
        if b & (1 << 7) == (1 << 7):
            if b - (1 << 7)  in rates:
                mandatory.append(rates[b-(1 << 7)])
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
                    G, {mac: {"label": "{} {}\n".format(mac, OUILookup(mac[:8]) if not no_oui_lookup else '') +
                    str(G.nodes[mac]['value']), "style": "filled", "fillcolor": AP_C}})
        elif G.nodes[mac]["type"] == CLIENT_T:
            nx.set_node_attributes(
                    G, {mac: {"label": "{} {}\n".format(mac, OUILookup(mac[:8]) if not no_oui_lookup else '') +
                    str(G.nodes[mac]['value']), "style": "filled", "fillcolor": CLIENT_C}})
        elif G.nodes[mac]["type"] == REPEATER_T:
            nx.set_node_attributes(G, {mac: {"label": "{} {}\nRepeater".format(mac, OUILookup(mac[:8]) if not no_oui_lookup else ''),
                    "style": "filled", "fillcolor": REPEATER_C}})


def whatIs(mac):
    if mac in G.nodes:
        return G.nodes[mac]["type"]
    return UNKNOWN_T


def getSecurity(frame):
    # taken from: https://github.com/aircrack-ng/aircrack-ng/blob/master/src/airodump-ng/airodump-ng.c#L2093
    # note that in airodump-ng, the data contains the tag and the length of the ie, here not so each value
    # used as a padding had -2.
    # returns (enc, auth, cipher)
    enc = ""
    cipher = []
    auth = []
    for ie in frame.ies:
        if (ie.id == 0x30 or ie.id == 0xDD) and ie.len >= 8: # RSN or WPA
            offset = 0

            if ie.id == 0x30: # RNS tag
                enc = "WPA2"
            elif ie.id == 0xDD and ie.data[0:6] == b"\x00\x50\xF2\x01\x01\x00": # vendor tag for WPA
                enc = "WPA"
                offset = 4
            else: # if not RSN not vendor tag with WPA
                break
                    
            if ie.len < 16 + offset:
                break
            if 7 + offset > ie.len:
                break
                
            count_cipher_suites = ie.data[6 + offset] + (ie.data[7 + offset] << 8)

            if (11 + offset) + (4 * count_cipher_suites) > ie.len:
                break
            count_AKM_suites = ie.data[(8 + offset) + 4 * count_cipher_suites] + (ie.data[(9 + offset) + 4 * count_cipher_suites] << 8)
                
            if ie.id != 0x30:
                if (4 * count_cipher_suites) + (4 * count_AKM_suites) > ie.len:
                    break
            else:
                if (4 * count_cipher_suites) + (4 * count_AKM_suites) + 2 > ie.len:
                    break

            base = 8 + offset
            for i in range(count_cipher_suites): # list of cipher suites
                cip = ie.data[i * 4 + 3 + base]
                if cip == 0x01:
                    cipher.append("WEP")
                elif cip == 0x02:
                    cipher.append("TKIP")
                elif cip == 0x03:
                    cipher.append("WRAP")
                elif cip == 0x0A or cip == 0x4:
                    cipher.append("CCMP")
                    enc = "WPA2"
                elif cip == 0x05:
                    cipher.append("WEP104")
                elif cip == 0x08 or cip == 0x9:
                    cipher.append("GCMP")
                    enc = "WPA2"
                elif cip == 0x0B or cip == 0xC:
                    cipher.append("GMAC")
                    enc = "WPA2"


            base += 2 + 4 * count_cipher_suites;
            for i in range(count_AKM_suites): # list of akm suites
                akm = ie.data[i * 4 + 3 + base]

                if akm == 0x1:
                    auth.append("MGT")
                elif akm == 0x2:
                    auth.append("PSK")
                elif akm == 0x6 or akm == 0xd:
                    auth.append("CMAC")
                elif akm == 0x8:
                    auth.append("SAE")
                elif akm == 0x12:
                    auth.append("OWE")
    if not enc and frame.subtype in FRAMES_WITH_CAPABILITY:
        if frame.capability.privacy:
            enc = "WEP"
        else:
            enc = "OPEN"
    # remove duplicates
    auth = list(dict.fromkeys(auth))
    cipher = list(dict.fromkeys(cipher))
    return (enc, auth, cipher)


def addEdge(src, dst, color):
    if not G.has_edge(src, dst, key=color):
        G.add_edge(src, dst, color=color, key=color)


def addAP(mac, ap):
    if mac not in G.nodes:  # if first time seeing ap
        if verbose:
            print("{} Added new AP: {}".format(INFO, mac))
        G.add_node(mac, type=AP_T, value=ap)
    else:  # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T:
            # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"].update(ap)
        except TypeError:
            if verbose:
                print("{} Marked {} as a repeater".format(INFO, mac))
            nx.set_node_attributes(G, {mac: {'type': REPEATER_T}})


def addClient(mac, client):
    if mac not in G.nodes:  # if first time seeing client
        if verbose:
            print("{} Added new Client: {}".format(INFO, mac))
        G.add_node(mac, type=CLIENT_T, value=client)
    else:  # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T:
            # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"].update(client)
        except TypeError:
            if verbose:
                print("{} Marked {} as a repeater".format(INFO, mac))
            nx.set_node_attributes(G, {mac: {'type': REPEATER_T}})


def processManagementFrame(frame, ts):
    # some frames are delayed because it is not possible to know
    # what sent it or what is the receiver, but it might be possible
    # after going through all the frames in the pcap
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
        sec = getSecurity(frame)
        addAP(src, AP(ts, bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"),
            ch=frame.ds.ch, rates=toRates(frame.rate.data), enc=sec[0], auth=sec[1], cipher=sec[2]))

        if whatIs(src) == AP_T:
            # check if src hasn't been put as a repeater and
            # add a beacon manually
            G.nodes[src]["value"].beacons += 1

    elif frame.subtype == M_PROBE_REQ:
        addClient(src, Client(ts, probe=frame.ssid.data.decode("utf-8", "ignore"), probed=True))

    elif frame.subtype == M_PROBE_RESP and not ignore_probe_resp:
        sec = getSecurity(frame)
        addClient(dst, Client(ts))
        addAP(src, AP(ts, bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"),
                      ch=frame.ds.ch, rates=toRates(frame.rate.data), enc=sec[0], auth=sec[1], cipher=sec[2]))

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
        # for some reason, auth_seq are in little endian instead of big
        if frame.auth.auth_seq == (1 << 8):  # CLIENT -> AP
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))

            addEdge(src, dst, color=AUTH_C)
        elif frame.auth.auth_seq == (1 << 9):  # AP -> CLIENT
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
    if len(only_mac) > 0:  # if there is a filter for mac
        if (src not in only_mac) and (dst not in only_mac):
            # doesn't pass filter
            return
    delayed_frames["data"].append((ts, src, dst))


def processControlFrame(frame, ts):
    # cannot guess anything from control frames, so delay them
    if frame.subtype == C_RTS:
        delayed_frames["ctl"].append((ts, frame.rts.src.hex(":").upper()))
    elif frame.subtype == C_BLOCK_ACK:
        delayed_frames["ctl"].append((ts, frame.back.src.hex(":").upper()))
    elif frame.subtype == C_BLOCK_ACK_REQ:
        delayed_frames["ctl"].append((ts, frame.bar.src.hex(":").upper()))


def parseDelayedFrames():
    if verbose:
        print("{} Handling delayed control frames.".format(INFO))
    for frame in delayed_frames["ctl"]:
        src = whatIs(frame[1])
        ts = frame[0]

        # update 'last seen' and 'first seen' of the src
        if src == CLIENT_T:
            addClient(frame[1], Client(ts))
        elif src == AP_T:
            addAP(frame[1], AP(ts))

    if verbose:
        print("{} Handling delayed deauthentification frames.".format(INFO))
    for frame in delayed_frames["deauth"]:
        src = whatIs(frame[1])
        dst = whatIs(frame[2])
        ts = frame[0]

        # update 'last seen' and 'first seen' of the src
        if src == CLIENT_T:
            addClient(frame[1], Client(ts))
        elif src == AP_T:
            addAP(frame[1], AP(ts))

        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(frame[1], frame[2], color=DEAUTH_C)
            else:
                addEdge(frame[1], frame[2], color=DEAUTH_C)
    if verbose:
        print("{} Handling delayed disassociation frames.".format(INFO))

    for frame in delayed_frames["disassoc"]:
        src = whatIs(frame[1])
        dst = whatIs(frame[2])
        ts = frame[0]

        # update 'last seen' and 'first seen' of the src
        if src == CLIENT_T:
            addClient(frame[1], Client(ts))
        elif src == AP_T:
            addAP(frame[1], AP(ts))

        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(frame[1], frame[2], color=DISASSOC_C)
            else:
                addEdge(frame[1], frame[2], color=DISASSOC_C)
    if verbose:
        print("{} Handling delayed action frames.".format(INFO))

    for frame in delayed_frames["action"]:
        src = whatIs(frame[1])
        dst = whatIs(frame[2])
        ts = frame[0]

        # update 'last seen' and 'first seen' of the src
        if src == CLIENT_T:
            addClient(frame[1], Client(ts))
        elif src == AP_T:
            addAP(frame[1], AP(ts))

        if src != UNKNOWN_T and dst != UNKNOWN_T:
            if src == AP_T:
                addEdge(frame[1], frame[2], color=ACTION_C)
            else:
                addEdge(frame[1], frame[2], color=ACTION_C)
    if verbose:
        print("{} Handling delayed data frames...".format(INFO))

    for frame in delayed_frames["data"]:
        src = whatIs(frame[1])
        dst = whatIs(frame[2])
        ts = frame[0]

        # update 'last seen' and 'first seen' of the src
        if src == CLIENT_T:
            addClient(frame[1], Client(ts))
        elif src == AP_T:
            addAP(frame[1], AP(ts))

        if src != UNKNOWN_T and dst != UNKNOWN_T:
            addEdge(frame[1], frame[2], color=DATA_C)


def parseWithRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            radio_tap = Radiotap(buf)
            dot11 = radio_tap.data
        except UnpackError:
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
        elif dot11.type == CTL_TYPE:
            processControlFrame(dot11, ts)
            c += 1

    if verbose:
        print("{} Parsing delayed frames...".format(INFO))
    parseDelayedFrames()
    if verbose:
        print("{} Finished parsing delayed frames...".format(INFO))

    return c


def parseWithoutRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            dot11 = IEEE80211(buf)
        except UnpackError:
            continue

        if dot11.type == MGMT_TYPE:
            processManagementFrame(dot11, ts)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11, ts)
            c += 1
        elif dot11.type == CTL_TYPE:
            processControlFrame(dot11, ts)
            c += 1

    if verbose:
        print("{INFO} Parsing delayed probe requests...".format(INFO))
    parseDelayedFrames()

    return c


@lru_cache(maxsize=None)
def OUILookup(mac):
    for mac_o in oui_table:
        if mac == mac_o:
            return oui_table[mac_o]
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
    if len(G.nodes) == 0:
        print("{} The graph is empty... Cannot generate anything.".format(FINISHED))
        exit(0)

    if args.no_alone_nodes: # remove nodes without edges
        # need a copy because some nodes in the original graph will be removed, act like as an iterator
        nodes = list(G.nodes)

        for node in nodes:
            if len(G.in_edges(node)) == 0 and len(G.out_edges(node)) == 0:  # if this node doesn't have any edge
                G.remove_node(node)

    print("{} Generating {}.{} file...".format(ACTION, args.output, args.format))
    generateNodesLabel(G)

    if not args.no_legend:
        addLegend(G)

    graph = nx.nx_agraph.to_agraph(G)
    graph.draw(args.output + "." + args.format, prog=args.graph)

    print("{} {}.{} generated!".format(FINISHED, args.output, args.format))


def generateMultipleGraphs(args):
    if len(G.nodes) == 0:
        print("{} The graph is empty... Cannot generate anything.".format(FINISHED))
        exit(0)

    if verbose:
        print("{} Removing nodes without any edge...".format(INFO))

    G_null = nx.Graph()  # nodes without edges, don't need a fancy graph

    # need a copy because some nodes in the original graph will be removed, act like as an iterator
    nodes = list(G.nodes)

    for node in nodes:
        if len(G.in_edges(node)) == 0 and len(G.out_edges(node)) == 0:  # if this node doesn't have any edge
            G_null.add_node(node, value=G.nodes[node]["value"], type=G.nodes[node]["type"])
            G.remove_node(node)

    if not args.no_alone:  # if generating alone_nodes graph
        if len(G_null.nodes) > 0:
            print("{} Generating {}_alone_nodes.{} file...".format(ACTION, args.output, args.format))
            generateNodesLabel(G_null)

            graph = nx.nx_agraph.to_agraph(G_null)
            graph.draw("{}_alone_nodes.{}".format(args.output, args.format), prog=args.graph)

            print("{} {}_alone_nodes.{} generated!".format(FINISHED, args.output, args.format))

        else:
            print("{} All nodes have an edge at least, don't generate ".format(ACTION) + \
                        "{}.{} because it's empty.".format(args.output, args.format))

    print("{} Generating all subgraphs...".format(ACTION))
    for num_graph, g in enumerate(list(nx.weakly_connected_components(G))):
        # there is no alone nodes as they were removed

        sub = nx.MultiDiGraph(G.subgraph(g))
        generateNodesLabel(sub)

        if not args.no_legend:
            addLegend(sub)
        print("{} Generating {}_{}.{} file...".format(ACTION, args.output, num_graph, args.format))
        graph = nx.nx_agraph.to_agraph(sub)
        graph.draw("{}_{}.{}".format(args.output, num_graph, args.format), prog=args.graph)

        print("{} {}_{}.{} generated!".format(FINISHED, args.output, num_graph, args.format))


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Create graphs from pcaps containing IEEE802.11 frames.")
    parser.add_argument("--pcap", "-p", help="pcap/pcapng to parse.", required=True,
            metavar="pcap")
    parser.add_argument(
        "--output", "-o", help="Name without extension of the output file(s)."
        "This can used be used as a path to put the file(s) too (e.g. "
        "../../test).", dest="output", required=True, metavar="name")
    parser.add_argument(
        "--no-probe-graph", "-e", help="Don't draw probe responses,"
        "but don't ignore them.",
        dest="no_probe_graph", action="store_true")
    parser.add_argument(
        "--ignore-probe", "-i", help="Ignore probe responses.",
        dest="no_probe", action="store_true")
    parser.add_argument(
        "--format", "-f", help="Output file's format.", dest="format",
        choices=["pdf", "jpg", "png", "dot", "ps", "svg", "svgz", "gif"],
        default="png", metavar="format")
    parser.add_argument("--only-mac", "-m", help="Filter for MAC address. Separate them with space.",
        dest="only_mac", nargs='+', action="store",
        metavar="MACs")
    parser.add_argument("--no-legend", "-l", help="Don't add a legend.",
        dest="no_legend", action="store_true")
    parser.add_argument("--only-bssid", "-b", help="Filter for BSSIDs. Separate them with space.",
        dest="only_bssid", nargs='+', action="store",
        metavar="BSSIDs")
    parser.add_argument(
        "--no-alone-graph", "-a",
        help="Don't generate image containing nodes without edges. Works with -s.",
        dest="no_alone", action="store_true")
    parser.add_argument(
        "--no-alone-nodes", "-n",
        help="Remove nodes without edges. Works without --split-graph, otherwise use --no-alone-graph.",
        dest="no_alone_nodes", action="store_true")
    parser.add_argument(
        "--split-graph", "-s", help="Split graph into multiple " \
        "files. This is useful when there is a lot of nodes.",
        dest="split_graph", action="store_true")
    parser.add_argument(
        "--verbose", "-v", help="Be verbose.",
        dest="verbose", action="store_true")
    parser.add_argument(
        "--no-oui-lookup", "-k", help="Don't make OUI lookup for MAC addresses.",
        dest="no_oui_lookup", action="store_true")
    parser.add_argument(
        "--graph", "-g", help="Graphviz program to use", dest="graph",
        choices=["dot", "neato", "twopi", "circo", "fdp", "sfdp"],
        default="sfdp", metavar="prog")
    args = parser.parse_args()

    ignore_probe_resp = args.no_probe
    no_probe_graph = args.no_probe_graph
    verbose = args.verbose
    no_oui_lookup = args.no_oui_lookup
    
    # OUI
    if not no_oui_lookup: # if the --no-oui-lookup is not present
        try:
            oui_file_path = os.path.dirname(os.path.realpath(__file__)) + "/oui.txt"
            with open(oui_file_path, "r") as f:
                if verbose:
                    print("{} Loading OUI file lookup: {}".format(INFO, oui_file_path))

                for line in f:
                    elements = line.strip().split("\t")
                    # MAC: NAME
                    oui_table.update({elements[0]: elements[1]})
        except FileNotFoundError:
            print("{} Impossible to open oui.txt, please put this file ".format(FAIL) + \
                    "in this directory: " + 
                    os.path.dirname(os.path.realpath(__file__)) + \
                    ". Quitting...")
            exit(1)

    # FILTERS
    if args.only_mac:
        only_mac = tuple(args.only_mac)
    if args.only_bssid:
        only_bssid = tuple(args.only_bssid)


    mac_p = re.compile(r"^([0-9A-Fa-f][0-9A-Fa-f]:){5}[0-9A-Fa-f][0-9A-Fa-f]$")
    for bssid in only_bssid:
        if not mac_p.match(bssid):
            print("{} {} is not a valid BSSID!".format(FAIL, bssid))
            exit(1)
    for mac in only_mac:
        if not mac_p.match(mac):
            print("{} {} is not a valid MAC address!".format(FAIL, mac))
            exit(1)
    only_mac = list(map(str.upper, only_mac)) # upper all MACs
    only_bssid = list(map(str.upper, only_bssid)) # upper all bssids


    # PCAP
    try:
        raw_pcap = open(args.pcap, "rb")
    except FileNotFoundError:
        print("{} File not found: {}".format(FAIL, args.pcap))
        exit(1)
    try:
        if args.pcap.endswith(".pcapng") or args.pcap.endswith(".pcap-ng"):
            pcap = pcapng_Reader(raw_pcap)
        else:
            pcap = pcap_Reader(raw_pcap)
    except ValueError as e:
        print("{} An error occured while reading {} : {}".format(FAIL, args.pcap, e))
        raw_pcap.close()
        exit(1)

    if verbose:
        print("{} Loading {} in memory".format(INFO, args.pcap))
    packets = pcap.readpkts()
    raw_pcap.close()

    if pcap.datalink() == DLT_IEEE802_11_RADIO:
        print("{} Begining of parsing!".format(ACTION))
        count = parseWithRadio(packets)
        print("{} Parsed {} frames!".format(FINISHED, count))
    elif pcap.datalink() == DLT_IEEE802_11:
        print("{} Begining of parsing!".format(ACTION))
        count = parseWithoutRadio(packets)
        print("{} Parsed {} frames!".format(FINISHED, count))
    else:
        print("{} Wrong link-layer header type. It should either be ".format(FAIL) + \
                "LINKTYPE_IEEE802_11 or LINKTYPE_IEEE802_11_RADIOTAP.")
        exit(1)
    del packets  # free some space

    # generate dot file and image file
    if args.split_graph:
        generateMultipleGraphs(args)
    else:
        generateGraph(args)
