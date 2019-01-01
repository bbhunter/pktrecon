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

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(Ether) and packet.getlayer(LLMNRResponse):

                    mac = packet[Ether].src
                    ipv4 = None
                    ipv6 = None
                    domain = None
                    dns = None
                    router = None
                    hostname = None
#                    os = None
                    os = 'LLMNR Foreign Host'
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    protocol = 'LLMNR'

                    qname = packet[LLMNRResponse].qd.qname
                    qtype = packet[LLMNRResponse].qd.qtype
                    qclass = packet[LLMNRResponse].qd.qclass

                    rrname = packet[LLMNRResponse].an.rrname
                    rtype = packet[LLMNRResponse].an.type
                    rclass = packet[LLMNRResponse].an.rclass
                    rdata = packet[LLMNRResponse].an.rdata
                    r_ns = packet[LLMNRResponse].ns
                    r_ar = packet[LLMNRResponse].ar

                    if protocol not in self.keys['protocols']:
                        self.keys['protocols'].append(protocol)

                    if domain not in self.keys['domains']:
                        self.keys['domains'].append(domain)

                    if rrname not in self.keys['hosts'].keys() and rrname != None:
                        self.keys['hosts'].update({'*{}'.format(rrname): {'ipv4': rdata, 'mac': mac, 'domain': 'Unknown', 'ipv6': ipv6, 'os': os, 'protocol': protocol}})

        return self.keys
