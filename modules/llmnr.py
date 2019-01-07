#!/usr/bin/python2

import sys
import os
import glob
import random
import struct
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.utils import *

class LLMNR:

    def __init__(self, keys, packet):

        self.keys = keys
        self.packet = packet

    def search(self):

        if self.packet.getlayer(Ether) and self.packet.getlayer(LLMNRResponse):

            mac = self.packet[Ether].src
            ipv4 = None
            ipv6 = None
            domain = None
            dns = None
            router = None
            hostname = None
            os = None
            notes = 'Potential remote segment host (LLMNR)'
            sport = self.packet[UDP].sport
            dport = self.packet[UDP].dport
            protocol = 'LLMNR'

            qname = self.packet[LLMNRResponse].qd.qname
            qtype = self.packet[LLMNRResponse].qd.qtype
            qclass = self.packet[LLMNRResponse].qd.qclass

            rrname = self.packet[LLMNRResponse].an.rrname
            rtype = self.packet[LLMNRResponse].an.type
            rclass = self.packet[LLMNRResponse].an.rclass
            rdata = self.packet[LLMNRResponse].an.rdata
            r_ns = self.packet[LLMNRResponse].ns
            r_ar = self.packet[LLMNRResponse].ar

            if protocol not in self.keys['protocols']:
                self.keys['protocols'].append(protocol)

            if domain not in self.keys['domains']:
                self.keys['domains'].append(domain)

            if rrname not in self.keys['hosts'].keys() and rrname != None:
                self.keys['hosts'].update({'*{}'.format(rrname): {'ipv4': rdata, 'mac': mac, 'domain': 'Unknown', 'ipv6': ipv6, 'os': os, 'protocol': protocol}})

        return self.keys
