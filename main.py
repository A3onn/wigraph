#!/usr/bin/env python
# -*- coding: utf-8 -*-
from dpkt.ieee80211 import *
import dpkt, argparse, subprocess
import networkx as nx


# CONSTANTS

G = nx.MultiDiGraph()

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
AP_C = "#ff0000"
CLIENT_C = "#0000ff"
REPEATER_C = "#00ff00"

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
    def __init__(self, bssid="", ssid="", ch=-1, rates=[]):
        self.bssid = bssid
        self.ssid = ssid
        self.ch = ch
        self.rates = rates

    def __str__(self):
        if len(self.rates) == 0: # add empty lists
            supported_rates = "<unknown>"
            basic_rates = "<unknown>"
        else:
            supported_rates = ",".join(map(str, self.rates[0])) # [int] -> [str] with map
            basic_rates = ",".join(map(str, self.rates[1])) # same here
        return f"bssid: {self.bssid if self.bssid else '<unknown>'}\nssid: {self.ssid if self.ssid else '<unknown>'}\nchannel: {self.ch if self.ch >= 1 else '<unknown>'}\nsupported rates: {supported_rates}\nbasic rates: {basic_rates}"

    def __mod__(self, other):
        """
        Can now use the % operator to add missing parts of an instance
        by creating another instance with some attirbutes set (= other)
        and getting these attributes and add them into this instance:
        a = AP(ssid="ap 1", bssid="11:22:33:44:55:66")
        ...
        some code
        ...
        a % AP(ch=5) # This will change the ch attribute to 5 from a
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

class Client:
    def __init__(self, probe=""):
        # might add more attributes later
        self.probes = [probe if probe else "<broadcast>"]

    def __str__(self):
        if self.probes:
            probed = ",".join(self.probes)
            return f"probed: {probed}"
        else:
            return ""

    def __mod__(self, other):
        if not isinstance(other, Client):
            raise TypeError()

        if other.probes:
            if not other.probes[0] in self.probes:
                self.probes.append(other.probes[0])

# FUNCTIONS
def toRates(raw):
    # supported, basics
    return [500*x for x in raw if x > 127],[500*x for x in raw if x > 127]

def generateNodesColors():
    # this is used to avoid generating the label of each node each time there is a modification
    for mac in G.nodes:
        if G.nodes[mac]["type"] == AP_T:
            nx.set_node_attributes(G, {mac: {"label": mac + "\n" + str(G.nodes[mac]["value"]), "color": AP_C}})
        elif G.nodes[mac]["type"] == CLIENT_T:
            nx.set_node_attributes(G, {mac: {"label": mac + "\n" + str(G.nodes[mac]["value"]), "color": CLIENT_C}})
        elif G.nodes[mac]["type"] == REPEATER_T:
            nx.set_node_attributes(G, {mac: {"label": mac + "\n" + "Repeater", "color": REPEATER_C}})

def whatIs(mac):
    if mac in G.nodes:
        return G.nodes[mac]["type"]
    return UNKNOWN_T

def addEdge(src, dst, color):
    if not G.has_edge(src, dst, key=color):
        G.add_edge(src, dst, color=color, key=color)

def addAP(mac, ap):
    if not mac in G.nodes: # if first time seeing ap
        G.add_node(mac, type=AP_T, value=ap)
    else: # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"] % ap
        except TypeError:
            nx.set_node_attributes(G, {mac:{'type': REPEATER_T}})

def addClient(mac, client):
    if not mac in G.nodes: # if first time seeing client
        G.add_node(mac, type=CLIENT_T, value=client)
    else: # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's already been marked as a repeater
            return
        try:
            G.nodes[mac]["value"] % client
        except TypeError:
            nx.set_node_attributes(G, {mac:{'type': REPEATER_T}})

def processManagementFrame(frame):
    src = frame.mgmt.src.hex(":")
    dst = frame.mgmt.dst.hex(":")
    bssid  = frame.mgmt.bssid.hex(":")

    if frame.subtype in FRAMES_WITH_CAPABILITY:
        ibss = frame.capability.ibss

    if frame.subtype == M_BEACON:
        addAP(src, AP(bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"), ch=frame.ds.ch,\
            rates=toRates(frame.rate.data)))
    elif frame.subtype == M_PROBE_REQ:
        addClient(src, Client(probe=frame.ssid.data.decode("utf-8", "ignore")))
    elif frame.subtype == M_PROBE_RESP:
        addAP(src, AP(bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"), ch=frame.ds.ch,\
                rates=toRates(frame.rate.data)))
        addClient(dst, Client(frame.ssid.data.decode("utf-8", "ignore")))

        addEdge(src, dst, color=PROBE_RESP)
    elif frame.subtype == M_ASSOC_REQ:
        addAP(dst, AP(ssid=frame.ssid.data.decode("utf-8", "ignore"), bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client())

        addEdge(src, dst, color=ASSOC_REQ)
    elif frame.subtype == M_ASSOC_RESP:
        addAP(src, AP(rates=toRates(frame.rate.data), bssid=bssid))
        addClient(dst, Client())
        
        addEdge(src, dst, color=ASSOC_RESP)
    elif frame.subtype == M_REASSOC_REQ:
        current_ap = frame.reassoc_req.current_ap.hex(":")
        if current_ap != bssid: # meaning the client wants to reconnect
            addAP(dst, AP(bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(src, Client())

        addEdge(src, dst, color=REASSOC_REQ)
    elif frame.subtype == M_REASSOC_RESP:
        addAP(src, AP(bssid=bssid, rates=toRates(frame.rate.data)))
        addClient(dst, Client())

        addEdge(src, dst, color=REASSOC_RESP)
    elif frame.subtype == M_AUTH:
        if frame.auth.auth_seq == 256: # CLIENT -> AP
            addAP(dst, AP(bssid=bssid))
            addClient(src, Client())

            addEdge(src, dst, color=AUTH_REQ)
        elif frame.auth.auth_seq == 512: # AP -> CLIENT
            addAP(src, AP(bssid=bssid))
            addClient(dst, Client())

            addEdge(src, dst, color=AUTH_RESP)

    elif frame.subtype == M_DEAUTH:
        who = whatIs(src)
        if who == AP_T:
            addAP(src, AP(bssid=bssid))
            addClient(dst, Client())
            
            addEdge(src, dst, color=DEAUTH_FROM_AP)
        elif who == CLIENT_T:
            addAP(dst, AP(bssid=bssid))
            addClient(src, Client())
            
            addEdge(src, dst, color=DEAUTH_FROM_CLIENT)
        elif who == UNKNOWN_T:
            pass
    elif frame.subtype == M_DISASSOC:
        who = whatIs(src)
        if who == AP_T:
            addAP(src, AP(bssid=bssid))
            addClient(dst, Client())
            
            addEdge(src, dst, color=DISASSOC_FROM_AP)
        elif who == CLIENT_T:
            addAP(dst, AP(bssid=bssid))
            addClient(src, Client())
            
            addEdge(src, dst, color=DISASSOC_FROM_CLIENT)
        elif who == UNKNOWN_T:
            pass
    elif frame.subtype == M_ACTION:
        who = whatIs(src)
        if who == AP_T:
            addAP(src, AP(bssid=bssid))
            addClient(dst, Client())
            
            addEdge(src, dst, color=ACTION_FROM_AP)
        elif who == CLIENT_T:
            addAP(dst, AP(bssid=bssid))
            addClient(src, Client())
            
            addEdge(src, dst, color=ACTION_FROM_CLIENT)
        elif who == UNKNOWN_T:
            pass

def processDataFrame(frame):
    src = frame.data_frame.src.hex(":")
    dst = frame.data_frame.dst.hex(":")

    if frame.to_ds == 1 and frame.from_ds == 0:
        addClient(src, Client())
        addAP(dst, AP(bssid=frame.data_frame.bssid.hex(":")))

        addEdge(src, dst, color=DATA)

    elif frame.to_ds == 0 and frame.to_ds == 1:
        addAP(src, AP(bssid=frame.data_frame.bssid.hex(":")))
        addClient(dst, Client())

        addEdge(src, dst, color=DATA)
    elif frame.to_ds == 1 and frame.from_ds == 1:
        addAP(frame.data_frame.da.hex(":"), AP())
        addAP(frame.data_frame.sa.hex(":"), AP())

        addEdge(frame.data_frame.sa.hex(":"), frame.data_frame.da.hex(":"), color=DATA_INTER_DS)


def parseWithRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            radio_tap = dpkt.radiotap.Radiotap(buf)
            dot11 = radio_tap.data
        except Exception as e:
            continue

        if not isinstance(dot11, dpkt.ieee80211.IEEE80211): # check if the frame is a 802.11 packet
            continue

        if dot11.type == MGMT_TYPE: # management frames
            processManagementFrame(dot11)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11)
            c += 1
    return c

def parseWithoutRadio(pcap):
    c = 0
    for ts, buf in pcap:
        try:
            dot11 = dpkt.ieee80211.IEEE80211(buf)
        except Exception as e:
            continue

        if dot11.type == MGMT_TYPE: # management frames
            processManagementFrame(dot11)
            c += 1
        elif dot11.type == DATA_TYPE:
            processDataFrame(dot11)
            c += 1
    return c


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create map from pcap containing IEEE802.11 frames")
    parser.add_argument("--pcap", "-p", help="pcap to parse", required=True)
    parser.add_argument("--output", "-o", help="name without extension of the output file", required=True)
    parser.add_argument("--format", "-f", help="output file's format", choices=["pdf", "jpg", "png", "dot"], default="png")
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
            r = subprocess.call([args.graph, args.output + ".dot", "-Goverlap=scale", "-T", args.format, "-o", args.output + "." + args.format], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if r != 0:
                print(f"{FAIL} An error occured while generating the image! Left {args.output_name}.dot intact.")
                exit(1)
            else:
                print(f"{ACTION} {args.output}.{args.format} generated!")
                subprocess.call(["rm", args.output + ".dot"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            print(f"{FAIL} Impossible to generate the image! Maybe Graphviz isn't installed properly.")
            exit(1)
