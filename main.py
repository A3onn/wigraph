#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import dpkt

class AP:
    def __init__(self, bssid="", essid="", ch=-1, enc="", type="", rates=[]):
        self.bssid = bssid
        self.essid = essid
        self.ch = ch
        self.enc = enc
        self.type = type
        self.rates = rates

    def __imod__(self, other):
        """
        Can now use the %= operator to add missing parts of an instance
        by creating another instance with some attirbutes set (= other)
        and getting these attributes and add them into this instance:
        a = AP(essid="ap 1", bssid="11:22:33:44:55:66")
        ...
        some code
        ...
        a %= AP(ch=5) # This will change the ch attribute to 5 from a
        """

        if not isinstance(other, AP):
            raise TypeError(f"{other} is not an AP")

        if not self.bssid and other.bssid:
            self.bssid = other.bssid

        if not self.essid and other.essid:
            self.essid = other.essid

        if self.ch == -1 and other.ch != -1:
            self.ch = other.ch

        if not self.enc and other.enc:
            self.enc = other.enc

        if not self.type and other.type:
            self.type = other.type

        if not self.rates and other.rates:
            self.rates = other.rates

