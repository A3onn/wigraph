#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from dpkt.ieee80211 import *
import dpkt, pprint, logging
import networkx as nx
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.DEBUG)

# ------- DEBUGGING ----------
pp = pprint.PrettyPrinter()
def dbgPrint(p):
    pp.pprint(p.__dict__)
    exit(0)
#----------------------------

# CONSTANTS
G = nx.MultiDiGraph()

INFRASTRUCTURE = "Infrastructure"
AD_HOC = "AD-HOC"

AP_T = 0
CLIENT_T = 1
REPEATER_T = 2

# CLASSES
class AP:
    def __init__(self, bssid="", ssid="", ch=-1, rates=[]):
        self.bssid = bssid
        self.ssid = ssid if ssid else "<none>"
        self.ch = ch
        self.rates = rates

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
            logging.error(f"Wrong type, {other} is not an AP")
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
    def __init__(self, probe="", rates=[]):
        # might add more attributes later
        self.probes = [probe if probe else "<wildcard>"]
        self.rates = rates

    def __mod__(self, other):
        if not isinstance(other, Client):
            logging.error(f"Wrong type, {other} is not a Client")
            raise TypeError()

        if other.probes:
            probe = other.probes[0] if other.probes[0] else "<wildcard>" # other has only one probe
            if not probe in self.probes:
                self.probes.append(probe)
        if other.rates and not self.rates:
            self.rates = other.rates


# FUNCTIONS
def toRates(raw):
    # supported, basics
    return [500*x for x in raw if x > 127],[500*x for x in raw if x > 127]

def addAP(mac, ap):
    if not mac in G.nodes: # if first time seeing ap
        logging.debug(f"Adding new AP: {mac}")
        G.add_node(mac, type=AP_T, value=ap)
    else: # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's alread marked as a repeater
            return
        try:
            logging.debug(f"Updating client: {mac}")
            G.nodes[mac]["value"] % ap
        except TypeError:
            G.nodes[mac]["type"] = REPEATER_T
            logging.info(f"Put {mac} as a repeater")

def addClient(mac, client):
    if not mac in G.nodes: # if first time seeing client
        logging.debug(f"Adding new Client: {mac}")
        G.add_node(mac, type=CLIENT_T, value=client)
    else: # if not, updating its attributes
        if G.nodes[mac]["type"] == REPEATER_T:
            return
        try:
            logging.debug(f"Updating client: {mac}")
            G.nodes[mac]["value"] % client
        except TypeError:
            G.nodes[mac]["type"] = REPEATER_T
            logging.info(f"Put {mac} as a repeater")

# DEV

raw_pcap = open("home.pcap", "rb")
pcap = dpkt.pcap.Reader(raw_pcap)

if pcap.datalink() != dpkt.pcap.DLT_IEEE802_11_RADIO:
    logging.critical("Wrong link type")
    exit(1)

c = 0
for ts, buf in pcap:
    c += 1
    try:
        radio_tap = dpkt.radiotap.Radiotap(buf)
        dot11 = radio_tap.data
    except Exception as e:
        logging.error(f"Exception occurred with frame #{c}:", exc_info=True)
        continue

    if not isinstance(dot11, dpkt.ieee80211.IEEE80211): # check if the frame is a 802.11 packet
        logging.error(f"#{c} is not an IEEE802.11 frame")
        continue

    if dot11.type == MGMT_TYPE: # management frames
        src = dot11.mgmt.src.hex(":")
        dst = dot11.mgmt.dst.hex(":")
        bssid  = dot11.mgmt.bssid.hex(":")

        if dot11.subtype in FRAMES_WITH_CAPABILITY:
            ibss = dot11.capability.ibss

        if dot11.subtype == M_BEACON: # DONE
            logging.info(f"Got beacon from {src}")
            addAP(src, AP(bssid=bssid, ssid=dot11.ssid.data.decode("utf-8", "ignore"), ch=dot11.ds.ch,\
                rates=toRates(dot11.rate.data)))
        elif dot11.subtype == M_PROBE_REQ: # DONE
            logging.info(f"Got probe request from {src}")
            addClient(src, Client(probe=dot11.ssid.data.decode("utf-8", "ignore"), rates=toRates(dot11.rate.data)))
        elif dot11.subtype == M_PROBE_RESP: # DONE
            logging.info(f"Got probe response from {src}")
            addAP(src, AP(bssid=bssid, ssid=dot11.ssid.data.decode("utf-8", "ignore"), ch=dot11.ds.ch,\
                    rates=toRates(dot11.rate.data)))
            addClient(dst, Client(dot11.ssid.data.decode("utf-8", "ignore")))

            G.add_edge(src, dst, type=M_PROBE_RESP, ts=ts)
        elif dot11.subtype == M_ASSOC_REQ: # DONE
            logging.info(f"Got association request from {src}")
            addAP(dst, AP(ssid=dot11.ssid.data.decode("utf-8", "ignore"), bssid=bssid))
            addClient(src, Client(rates=toRates(dot11.rate.data)))

            G.add_edge(src, dst, type=M_ASSOC_REQ, ts=ts)
        elif dot11.subtype == M_ASSOC_RESP: # DONE
            logging.info(f"Got association response from {src}")
            addAP(src, AP(rates=toRates(dot11.rate.data), bssid=bssid))
            addClient(dst, Client())
            
            G.add_edge(src, dst, type=M_ASSOC_RESP, ts=ts)
        elif dot11.subtype == M_REASSOC_REQ: # DONE
            logging.info(f"Got reassociation request from {src}")
            current_ap = dot11.reassoc_req.current_ap.hex(":")
            if current_ap != bssid: # meaning the client wants to reconnect
                addAP(dst, AP(bssid=bssid, ssid=dot11.ssid.data.decode("utf-8", "ignore")))
            addClient(src, Client(rates=toRates(dot11.rate.data)))

            G.add_edge(src, dst, type=M_REASSOC_REQ, ts=ts)
        elif dot11.subtype == M_REASSOC_REQ: # DONE
            logging.info(f"Got reassociation response from {src}")
            addAP(src, AP(bssid=bssid, rates=toRates(dot11.rate.data), ssid=dot11.ssid.data.decode("utf-8", "ignore")))
            addClient(dst, Client())

            G.add_edge(src, dst, type=M_REASSOC_RESP, ts=ts)


raw_pcap.close()

#nx.draw_circular(G, with_labels=True, font_weight='bold')
#plt.show()
