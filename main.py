#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from dpkt.ieee80211 import *
import dpkt, pprint
import networkx as nx
import matplotlib.pyplot as plt

# ------- DEBUGGING ----------
pp = pprint.PrettyPrinter()
def dbgPrint(p):
    pp.pprint(p.__dict__)
    exit(0)
#----------------------------

# CONSTANTS
G=nx.Graph()

INFRASTRUCTURE = "Infrastructure"
AD_HOC = "AD-HOC"

AP_T = 0
CLIENT_T = 1

# CLASSES
class AP:
    def __init__(self, bssid="", ssid="", ch=-1, enc="", type="", rates=[]):
        self.bssid = bssid
        self.ssid = ssid
        self.ch = ch
        self.enc = enc
        self.type = type
        self.rates = rates

    def __str__(self):
        return f"bssid = {self.bssid}, ssid = {self.ssid}, channel = {self.ch}, enc = {self.enc}, type = {self.type}, rates = {self.rates}"

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
            raise TypeError(f"{other} is not an AP")

        if not self.bssid and other.bssid:
            self.bssid = other.bssid

        if not self.ssid and other.ssid:
            self.ssid = other.ssid

        if self.ch == -1 and other.ch != -1:
            self.ch = other.ch

        if not self.enc and other.enc:
            self.enc = other.enc

        if not self.type and other.type:
            self.type = other.type

        if not self.rates and other.rates:
            self.rates = other.rates

class Client:
    def __init__(self, probe=""):
        # might add more attributes later
        self.probes = [probe if probe else "<wildcard"]

    def __mod__(self, other):
        if not isinstance(other, Client):
            raise TypeError(f"{other} is not a Client")
        if other.probes:
            probe = other.probes[0] if other.probes[0] else "<wildcard>" # other has only one probe
            if not probe in self.probes:
                self.probes.append(probe)

    def __str__(self):
        return f"probed = {self.probes}"


# FUNCTIONS
def toRates(raw):
    # supported, basics
    return [500*x for x in raw if x > 127],[500*x for x in raw if x > 127]

def addAP(mac, ap):
    if not mac in G.nodes: # if first time seeing ap
        G.add_node(mac, type=AP_T, value=ap)
    else: # if not, updating its attributes
        G.nodes[mac]["value"] % ap

def addClient(mac, client):
    if not mac in G.nodes: # if first time seeing client
        G.add_node(mac, type=CLIENT_T, value=client)
    else: # if not, updating its attributes
        G.nodes[mac]["value"] % client




raw_pcap = open("dump_test.pcap", "rb")
pcap = dpkt.pcap.Reader(raw_pcap)

if pcap.datalink() != dpkt.pcap.DLT_IEEE802_11_RADIO:
    print("Wrong link type")
    exit(1)

c = 0
for ts, buf in pcap:
    c += 1
    radio_tap = dpkt.radiotap.Radiotap(buf)
    dot11 = radio_tap.data

    if not isinstance(dot11, dpkt.ieee80211.IEEE80211): # check if the packet is a 802.11 packet
        print(f"Wrong packet number {c}")
        continue

    if dot11.type == MGMT_TYPE: # management frames
        src = dot11.mgmt.src.hex(":")
        dst = dot11.mgmt.dst.hex(":")
        bssid  = dot11.mgmt.bssid.hex(":")

        if dot11.subtype in FRAMES_WITH_CAPABILITY:
            ibss = dot11.capability.ibss

        if dot11.subtype == M_BEACON:
            addAP(src, AP(bssid=bssid, ssid=dot11.ssid.data.decode("utf-8"), ch=dot11.ds.ch, type=INFRASTRUCTURE if ibss == 0 else AD_HOC, rates=toRates(dot11.rate.data)))
        elif dot11.subtype == M_PROBE_RESP:
            addAP(src, AP(bssid=bssid, ssid=dot11.ssid.data.decode("utf-8"), ch=dot11.ds.ch, type=INFRASTRUCTURE if ibss == 0 else AD_HOC, rates=toRates(dot11.rate.data)))
            addClient(dst, Client(dot11.ssid.data.decode("utf-8")))

            G.add_edge(src, dst)
        elif dot11.subtype == M_PROBE_REQ:
            addClient(src, Client(dot11.ssid.data.decode("utf-8")))

raw_pcap.close()

nx.draw_shell(G, with_labels=True, font_weight='bold')
plt.show()
