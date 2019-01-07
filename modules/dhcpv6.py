#!/usr/bin/python2

import sys
import os
import glob
import random
import logging
import engine

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.utils import *

class DHCPV6:

    def __init__(self, keys, packet):

        self.keys = keys
        self.packet = packet

    def search(self):

        if self.packet.getlayer(IPv6) and self.packet.getlayer(DHCP6_Solicit):

           mac = self.packet[Ether].src
           fqdn = self.packet[DHCP6_Solicit].fqdn
           hostname = fqdn.split('.')[0]
           ipv6 = self.packet[IPv6].src
           ipv4 = None
           domain = '.'.join(fqdn.split('.')[1:]).rstrip('.').upper()
           dns = None
           router = None
           segment = None
           os = None
           notes = None
           enterprisenum = self.packet[DHCP6_Solicit].enterprisenum
           protocol = 'DHCPv6'

           if str(enterprisenum) == '311':
               enterprise = 'Microsoft'
               notes = 'Microsoft Windows'

           if protocol not in self.keys['protocols']:
                self.keys['protocols'].append(protocol)

           if domain not in self.keys['domains'] and domain != None and '__MSBROWSE__' not in domain:
                self.keys['domains'].append(domain)

           if router not in self.keys['routers'] and router != None:
                self.keys['routers'].append(router)

           if dns not in self.keys['dns'] and dns != None:
                self.keys['dns'].append(dns)

           if hostname not in self.keys['hosts'].keys() and hostname != None:
                self.keys['hosts'].update({hostname: {'mac': mac, 'ipv4': ipv4, 'domain': domain, 'ipv6': ipv6, 'enterprisenum': enterprisenum, 'enterprise': enterprise, 'os': os, 'protocol': protocol, 'notes': notes}})

           else:

                if self.keys['hosts'][hostname]['os'] == None or self.keys['hosts'][hostname]['os'] == 'Unknown':
                    engine.UpdateReconKeys(self.keys, hostname, os=os).operating_system()

        return self.keys
