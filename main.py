#!/usr/bin/env python
# -*- coding: utf-8 -*-
from dpkt.ieee80211 import *
from subprocess import call, PIPE
import dpkt, argparse, time
import networkx as nx

# CONSTANTS

G = nx.MultiDiGraph()

ignore_probe_resp = False
verbose = False

# colors
ACTION = "\033[92m[o]\033[0m"
INFO = "\033[93m[i]\033[0m"
FAIL = "\033[91m[X]\033[0m"

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
ASSOC_REQ = "#0000FF" # blue
ASSOC_RESP = "#0000AA"
AUTH_REQ = "#FF8C00" # dark orange
AUTH_RESP = "#AA4700"
REASSOC_REQ = "#FF69B4" # hot pink
REASSOC_RESP = "#AA2560"
PROBE_RESP = "#123456"
DEAUTH_FROM_AP = "#800000" # maroon
DEAUTH_FROM_CLIENT = "#400000"
DISASSOC_FROM_CLIENT = "#32CD32" # lime green
DISASSOC_FROM_AP = "#007800"
ACTION_FROM_AP = "#556B2F" # dark olive green
ACTION_FROM_CLIENT = "#11460A"
DATA = "#000000"
DATA_INTER_DS = "#A0A0A0"

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
        if len(self.rates) == 0: # add empty lists
            supported_rates = "<unknown>"
            basic_rates = "<unknown>"
        else:
            supported_rates = ",".join(map(str, self.rates[0])) # [int] -> [str] with map
            basic_rates = ",".join(map(str, self.rates[1])) # same here
        return f"bssid: {self.bssid if self.bssid else '<unknown>'}\nssid: {self.ssid if self.ssid else '<unknown>'}\nchannel: {self.ch if self.ch >= 1 else '<unknown>'}\nsupported rates: {supported_rates}\nbasic rates: {basic_rates}\nbeacons: {self.beacons}\nFirst seen: {time.asctime(time.localtime(self.first_seen))}\nLast seen: {time.asctime(time.localtime(self.last_seen))}"

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

        Mind you that Ap(ts, ch=5) is "disposable", it is only used when modifying
        another existing AP instance.

        I use this weird method because it is simple to implement and relatively efficient.
        You can see it as a replacement for dict and spaghetti code to change values in these dicts
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

        self.last_seen = other.first_seen # could be other.last_seen, as other is "disposable"

class Client:
    def __init__(self, ts, probe=""):
        # might add more attributes later
        self.probes = [probe if probe else "<broadcast>"]
        self.first_seen = ts
        self.last_seen = ts

    def __str__(self):
        if self.probes:
            probed = ",".join(self.probes)
            return f"probed: {probed}\nFirst seen: {time.asctime(time.localtime(self.first_seen))}\nLast seen: {time.asctime(time.localtime(self.last_seen))}"
        else:
            return ""

    def __mod__(self, other):
        if not isinstance(other, Client):
            raise TypeError()

        if other.probes:
            if not other.probes[0] in self.probes:
                self.probes.append(other.probes[0])
        
        self.last_seen = other.first_seen # could be other.last_seen, as other is "disposable"

# FUNCTIONS
def toRates(raw):
    # supported, basics
    return [500*x for x in raw if x > 127],[500*x for x in raw if x > 127]

def generateNodesColors():
    # this is used to avoid generating the label of each node each time there is a modification
    for mac in G.nodes:
        if G.nodes[mac]["type"] == AP_T:
            nx.set_node_attributes(G, {mac: {"label": mac + "\n" + str(G.nodes[mac]["value"]), "style": "filled", "fillcolor": AP_C}})
        elif G.nodes[mac]["type"] == CLIENT_T:
            nx.set_node_attributes(G, {mac: {"label": mac + "\n" + str(G.nodes[mac]["value"]), "style": "filled", "fillcolor": CLIENT_C}})
        elif G.nodes[mac]["type"] == REPEATER_T:
            nx.set_node_attributes(G, {mac: {"label": mac + "\n" + "Repeater", "style": "filled", "fillcolor": REPEATER_C}})

def whatIs(mac):
    if mac in G.nodes:
        return G.nodes[mac]["type"]
    return UNKNOWN_T

def addEdge(src, dst, color, style="solid"):
    if not G.has_edge(src, dst, key=color):
        G.add_edge(src, dst, color=color, style=style, key=color)

def addAP(mac, ap):
    if not mac in G.nodes: # if first time seeing ap
        if verbose:
            print(f"{INFO} Added new AP: {mac}")
        G.add_node(mac, type=AP_T, value=ap)
    else: # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"] % ap
        except TypeError:
            if verbose:
                print(f"{INFO} Marked {mac} as a repeater")
            nx.set_node_attributes(G, {mac:{'type': REPEATER_T}})

def addClient(mac, client):
    if not mac in G.nodes: # if first time seeing client
        if verbose:
            print(f"{INFO} Added new Client: {mac}")
        G.add_node(mac, type=CLIENT_T, value=client)
    else: # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"] % client
        except TypeError:
            if verbose:
                print(f"{INFO} Marked {mac} as a repeater")
            nx.set_node_attributes(G, {mac:{'type': REPEATER_T}})

def processManagementFrame(frame, ts):
    src = frame.mgmt.src.hex(":")
    dst = frame.mgmt.dst.hex(":")
    bssid  = frame.mgmt.bssid.hex(":")

    if frame.subtype in FRAMES_WITH_CAPABILITY:
        ibss = frame.capability.ibss

    if frame.subtype == M_BEACON:
        addAP(src, AP(ts, bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"), ch=frame.ds.ch,\
            rates=toRates(frame.rate.data)))
        if whatIs(src) == AP_T: # check if src hasn't been put as a repeater
            G.nodes[src]["value"].beacons += 1
    elif frame.subtype == M_PROBE_REQ:
        addClient(src, Client(ts, probe=frame.ssid.data.decode("utf-8", "ignore")))
    elif frame.subtype == M_PROBE_RESP and not ignore_probe_resp:
        addAP(src, AP(ts, bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"), ch=frame.ds.ch,\
                rates=toRates(frame.rate.data)))
        addClient(dst, Client(ts, frame.ssid.data.decode("utf-8", "ignore")))

        addEdge(src, dst, color=PROBE_RESP, style="dotted")
    elif frame.subtype == M_ASSOC_REQ:
        addAP(dst, AP(ts, ssid=frame.ssid.data.decode("utf-8", "ignore"), bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client(ts))

        addEdge(src, dst, color=ASSOC_REQ, style="box" if ibss else "solid")
    elif frame.subtype == M_ASSOC_RESP:
        addAP(src, AP(ts, rates=toRates(frame.rate.data), bssid=bssid))
        addClient(dst, Client(ts))
        
        addEdge(src, dst, color=ASSOC_RESP, style="box" if ibss else "solid")
    elif frame.subtype == M_REASSOC_REQ:
        current_ap = frame.reassoc_req.current_ap.hex(":")
        if current_ap != bssid: # meaning the client wants to reconnect
            addAP(dst, AP(ts, bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client(ts))

        addEdge(src, dst, color=REASSOC_REQ, style="box" if ibss else "solid")
    elif frame.subtype == M_REASSOC_RESP:
        addAP(src, AP(ts, bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(dst, Client(ts))

        addEdge(src, dst, color=REASSOC_RESP)
    elif frame.subtype == M_AUTH:
        if frame.auth.auth_seq == 256: # CLIENT -> AP
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))

            addEdge(src, dst, color=AUTH_REQ)
        elif frame.auth.auth_seq == 512: # AP -> CLIENT
            addAP(src, AP(ts, bssid=bssid))
            addClient(dst, Client(ts))

            addEdge(src, dst, color=AUTH_RESP)

    elif frame.subtype == M_DEAUTH:
        who = whatIs(src)
        if who == AP_T:
            addAP(src, AP(ts, bssid=bssid))
            addClient(dst, Client(ts))
            
            addEdge(src, dst, color=DEAUTH_FROM_AP)
        elif who == CLIENT_T:
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))
            
            addEdge(src, dst, color=DEAUTH_FROM_CLIENT)
        elif who == UNKNOWN_T:
            pass
    elif frame.subtype == M_DISASSOC:
        who = whatIs(src)
        if who == AP_T:
            addAP(src, AP(ts, bssid=bssid))
            addClient(dst, Client(ts))
            
            addEdge(src, dst, color=DISASSOC_FROM_AP)
        elif who == CLIENT_T:
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))
            
            addEdge(src, dst, color=DISASSOC_FROM_CLIENT)
        elif who == UNKNOWN_T:
            pass
    elif frame.subtype == M_ACTION:
        who = whatIs(src)
        if who == AP_T:
            addAP(src, AP(ts, bssid=bssid))
            addClient(dst, Client(ts))
            
            addEdge(src, dst, color=ACTION_FROM_AP)
        elif who == CLIENT_T:
            addAP(dst, AP(ts, bssid=bssid))
            addClient(src, Client(ts))
            
            addEdge(src, dst, color=ACTION_FROM_CLIENT)
        elif who == UNKNOWN_T:
            pass

def processDataFrame(frame, ts):
    src = frame.data_frame.src.hex(":")
    dst = frame.data_frame.dst.hex(":")

    if frame.to_ds == 1 and frame.from_ds == 0:
        if dst != "ff:ff:ff:ff:ff:ff":
            addAP(dst, AP(ts, bssid=frame.data_frame.bssid.hex(":")))
        if src != "ff:ff:ff:ff:ff:ff":
            addClient(src, Client(ts))
        
        if dst != "ff:ff:ff:ff:ff:ff" and src != "ff:ff:ff:ff:ff:ff":
            addEdge(src, dst, color=DATA)

    elif frame.to_ds == 0 and frame.to_ds == 1:
        if src != "ff:ff:ff:ff:ff:ff":
            addAP(src, AP(ts, bssid=frame.data_frame.bssid.hex(":")))
        if dst != "ff:ff:ff:ff:ff:ff":
            addClient(dst, Client(ts))
        
        if dst != "ff:ff:ff:ff:ff:ff" and src != "ff:ff:ff:ff:ff:ff":
            addEdge(src, dst, color=DATA)
    elif frame.to_ds == 1 and frame.from_ds == 1:
        addAP(frame.data_frame.da.hex(":"), AP(ts))
        addAP(frame.data_frame.sa.hex(":"), AP(ts))

        addEdge(frame.data_frame.sa.hex(":"), frame.data_frame.da.hex(":"), color=DATA_INTER_DS)


def parseWithRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            radio_tap = dpkt.radiotap.Radiotap(buf)
            dot11 = radio_tap.data
        except Exception as e:
            continue

        if not isinstance(dot11, IEEE80211): # check if the frame is a 802.11 packet
            continue

        if dot11.type == MGMT_TYPE: # management frames
            processManagementFrame(dot11, ts)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11, ts)
            c += 1
    return c

def parseWithoutRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            dot11 = IEEE80211(buf)
        except Exception as e:
            continue

        if dot11.type == MGMT_TYPE: # management frames
            processManagementFrame(dot11, ts)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11, ts)
            c += 1
    return c


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create map from pcap containing IEEE802.11 frames")
    parser.add_argument("--pcap", "-p", help="PCAP to parse", required=True)
    parser.add_argument("--output", "-o", help="Name without extension of the output file", required=True)
    parser.add_argument("--no-probe-resp", "-r", help="Ignore probe responses", dest="no_probe", action="store_true")
    parser.add_argument("--format", "-f", help="Output file's format", choices=["pdf", "jpg", "png", "dot"], default="png")
    parser.add_argument("--keep-dot", "-k", help="Keep .dot file.", dest="keep", action="store_true")
    parser.add_argument("--verbose", "-v", help="Verbose mode.", dest="verbose", action="store_true")
    parser.add_argument("--graph", "-g", help="Graphviz filter to use", choices=["dot", "neato", "twopi", "circo", "fdp", "sfdp", "osage", "patchwork"], default="dot")
    args = parser.parse_args()

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
    except:
        raw_pcap.close()
        print(f"{FAIL} An error occured while reading {args.pcap}.")
        exit(1)

    if args.no_probe:
        ignore_probe_resp = True
    if args.verbose:
        verbose = True

    if pcap.datalink() == dpkt.pcap.DLT_IEEE802_11_RADIO:
        print(f"{ACTION} Begining of parsing!")
        count = parseWithRadio(pcap)
        print(f"{ACTION} Parsed {count} frames!")
    elif pcap.datalink() == dpkt.pcap.DLT_IEEE802_11:
        print(f"{ACTION} Begining of parsing!")
        count = parseWithoutRadio(pcap)
        print(f"{ACTION} Parsed {count} frames!")
    else:
        raw_pcap.close()
        print(f"{FAIL} Wrong link-layer header type. It should either be LINKTYPE_IEEE802_11 or LINKTYPE_IEEE802_11_RADIOTAP.")
        exit(1)


    raw_pcap.close()

    print(f"{ACTION} Generating {args.output}.dot file...")
    generateNodesColors()
    nx.nx_agraph.write_dot(G, args.output + ".dot")
    print(f"{ACTION} {args.output}.dot generated!")

    if args.format != "dot":
        try:
            print(f"{ACTION} Generating {args.output}.{args.format}. It may take awhile.")
            cmd = [args.graph, args.output + ".dot", "-Goverlap=scale", "-T", args.format, "-o", args.output + "." + args.format] # graphviz command to execute
            if verbose:
                print(f"{INFO} Calling: {' '.join(cmd)}")
            r = call(cmd, stdout=PIPE, stderr=PIPE)
            if r != 0:
                print(f"{FAIL} An error occured while generating the image! Left {args.output_name}.dot intact.")
                exit(1)
            else:
                print(f"{ACTION} {args.output}.{args.format} generated!")
                if not args.keep:
                    if verbose:
                        print(f"{INFO} Calling: rm {args.output}.dot")
                    call(["rm", args.output + ".dot"], stdout=PIPE, stderr=PIPE)
        except FileNotFoundError:
            print(f"{FAIL} Impossible to generate the image! Maybe Graphviz isn't installed properly.")
            exit(1)
