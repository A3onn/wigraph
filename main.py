#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from dpkt.ieee80211 import *
import dpkt, pprint

# ------- DEBUGGING ----------
pp = pprint.PrettyPrinter()
def dbgPrint(p):
    pp.pprint(p.__dict__)
    exit(0)
#----------------------------

# CONSTANTS
INFRASTRUCTURE = "Infrastructure"
AD_HOC = "AD-HOC"


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

def toRates(raw):
    # supported, basics
    return [500*x for x in raw if x > 127],[500*x for x in raw if x > 127]



aps = {} # mac as key and AP instance as value
def addAP(mac, ap):
    if not mac in aps: # if first time seeing ap
        aps.update({mac: ap})
    else: # if not, updating its attributes
        aps[mac] % ap


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
        if dot11.subtype == M_PROBE_RESP:
            addAP(src, AP(bssid=bssid, ssid=dot11.ssid.data.decode("utf-8"), ch=dot11.ds.ch, type=INFRASTRUCTURE if ibss == 0 else AD_HOC, rates=toRates(dot11.rate.data)))

raw_pcap.close()
