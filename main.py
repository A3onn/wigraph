#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from dpkt.ieee80211 import *
import dpkt, pprint, logging
import networkx as nx
import matplotlib.pyplot as plt

#logging.basicConfig(level=logging.DEBUG)

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


ASSOC_REQ = 0
ASSOC_RESP = 1
AUTH_REQ = 2
AUTH_RESP = 3
REASSOC_REQ = 4
REASSOC_RESP = 5
PROBE_RESP = 6


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
            logging.warning(f"Wrong type, {other} is not an AP")
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
            logging.warning(f"Wrong type, {other} is not a Client")
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
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's already been marked as a repeater
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
        if G.nodes[mac]["type"] == REPEATER_T: # check if it's already been marked as a repeater
            return
        try:
            logging.debug(f"Updating client: {mac}")
            G.nodes[mac]["value"] % client
        except TypeError:
            G.nodes[mac]["type"] = REPEATER_T
            logging.info(f"Put {mac} as a repeater")

def processManagementFrame(frame):
    src = frame.mgmt.src.hex(":")
    dst = frame.mgmt.dst.hex(":")
    bssid  = frame.mgmt.bssid.hex(":")

    if frame.subtype in FRAMES_WITH_CAPABILITY:
        ibss = frame.capability.ibss

    if frame.subtype == M_BEACON: # DONE
        logging.info(f"Got beacon from {src}")
        addAP(src, AP(bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"), ch=frame.ds.ch,\
            rates=toRates(frame.rate.data)))
    elif frame.subtype == M_PROBE_REQ: # DONE
        logging.info(f"Got probe request from {src}")
        addClient(src, Client(probe=frame.ssid.data.decode("utf-8", "ignore"), rates=toRates(frame.rate.data)))
    elif frame.subtype == M_PROBE_RESP: # DONE
        logging.info(f"Got probe response from {src}")
        addAP(src, AP(bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore"), ch=frame.ds.ch,\
                rates=toRates(frame.rate.data)))
        addClient(dst, Client(frame.ssid.data.decode("utf-8", "ignore")))

        G.add_edge(src, dst, type=PROBE_RESP, ts=ts)
    elif frame.subtype == M_ASSOC_REQ: # DONE
        logging.info(f"Got association request from {src}")
        addAP(dst, AP(ssid=frame.ssid.data.decode("utf-8", "ignore"), bssid=bssid))
        addClient(src, Client(rates=toRates(frame.rate.data)))

        G.add_edge(src, dst, type=ASSOC_REQ, ts=ts)
    elif frame.subtype == M_ASSOC_RESP: # DONE
        logging.info(f"Got association response from {src}")
        addAP(src, AP(rates=toRates(frame.rate.data), bssid=bssid))
        addClient(dst, Client())
        
        G.add_edge(src, dst, type=ASSOC_RESP, ts=ts)
    elif frame.subtype == M_REASSOC_REQ: # DONE
        logging.info(f"Got reassociation request from {src}")
        current_ap = frame.reassoc_req.current_ap.hex(":")
        if current_ap != bssid: # meaning the client wants to reconnect
            addAP(dst, AP(bssid=bssid, ssid=frame.ssid.data.decode("utf-8", "ignore")))
        addClient(src, Client(rates=toRates(frame.rate.data)))

        G.add_edge(src, dst, type=REASSOC_REQ, ts=ts)
    elif frame.subtype == M_REASSOC_RESP: # DONE
        logging.info(f"Got reassociation response from {src}")
        addAP(src, AP(bssid=bssid, rates=toRates(frame.rate.data), ssid=frame.ssid.data.decode("utf-8", "ignore")))
        addClient(dst, Client())

        G.add_edge(src, dst, type=REASSOC_RESP, ts=ts)
    elif frame.subtype == M_AUTH:
        if frame.auth.auth_seq == 256: # CLIENT -> AP
            addAP(dst, AP(bssid=bssid))
            addClient(src, Client())

            G.add_edge(src, dst, type=AUTH_REQ)
        elif frame.auth.auth_seq == 512: # AP -> CLIENT
            addAP(src, AP(bssid=bssid))
            addClient(dst, Client())

            G.add_edge(src, dst, type=AUTH_RESP)

# DEV
raw_pcap = open("dump_test.pcap", "rb")
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
        logging.error(f"#{c} frame is not an IEEE802.11 frame")
        continue

    if dot11.type == MGMT_TYPE: # management frames
        processManagementFrame(dot11)

raw_pcap.close()

#nx.draw_circular(G, with_labels=True, font_weight='bold')
#plt.show()
