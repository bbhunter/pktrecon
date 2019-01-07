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

def decode_nbns_name(nbn):
    """Return the NetBIOS first-level decoded nbname."""
    if len(nbn) != 32:
        return nbn

    l = []

    for i in range(0, 32, 2):
        l.append(chr(((ord(nbn[i]) - 0x41) << 4) |
             ((ord(nbn[i+1]) - 0x41) & 0xf)))

    return ''.join(l).split('\x00', 1)[0]

class NBNS:

    def __init__(self, keys, packet):

        self.keys = keys
        self.packet = packet

    def search(self):
        if self.packet.getlayer(Ether) and self.packet.getlayer(UDP) and self.packet.getlayer(NBNSQueryRequest) and self.packet[UDP].dport == 137 and self.packet[Ether].dst == 'ff:ff:ff:ff:ff:ff':

            raw_packet = list(str(self.packet[NBNSQueryRequest]))

            mac = self.packet[Ether].src
            sport = self.packet[IP].sport
            dport = self.packet[IP].dport
            ipv4 = self.packet[IP].src
            question = self.packet[NBNSQueryRequest].QUESTION_NAME.strip()
            suffix = self.packet[NBNSQueryRequest].SUFFIX

            ipv6 = None
            domain = None
            dns = None
            router = None
            hostname = None
            os = None
            suffix_type = None
            notes = None

            segment = '{}.0/24'.format('.'.join(ipv4.split('.')[0:3]))
            protocol = 'NBNS'

            if str(suffix) == '16705':
                suffix_type = 'workstation'

            if str(suffix) == '16973':
                suffix_type = 'domain controller'

            if str(suffix) == '17217':
                suffix_type = 'file server service'

            if str(suffix) == '16970':
                suffix_type = 'unknown'

            if dport not in self.keys['ports']:
                self.keys['ports'].append(dport)

            if domain not in self.keys['domains'] and domain != None and '__MSBROWSE__' not in domain:
                self.keys['domains'].append(domain)

            if protocol not in self.keys['protocols']:
                self.keys['protocols'].append(protocol)

            if 'WPAD' in question and 'WPAD' not in self.keys['protocols']:
                self.keys['protocols'].append('WPAD')
                notes = 'WPAD client'

            if router not in self.keys['routers'] and router != None:
                self.keys['routers'].append(router)

            if dns not in self.keys['dns'] and dns != None:
                self.keys['dns'].append(dns)

            if hostname not in self.keys['hosts'].keys():
                if hostname != None:
                    self.keys['hosts'].update({hostname: {'mac': mac, 'ipv4': ipv4, 'ipv6': ipv6, 'domain': domain, 'lookup': question, 'suffix_type': suffix_type, 'os': os, 'protocol': protocol, 'notes': notes}})

            else:

                if self.keys['hosts'][hostname]['os'] == None or self.keys['hosts'][hostname]['os'] == 'Unknown':
                    engine.UpdateReconKeys(self.keys, hostname, os=os).operating_system()

        return self.keys
