#!/usr/bin/python2

import sys
import os
import glob
import random
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.utils import *

class DHCPV4:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        datasets = ['server_id','client_id','router','name_server','hostname','vendor_class_id','lease_time','broadcast_address','domain','NetBIOS_server']
        sessions = self.data.sessions()

        for session in sessions:
            for packet in sessions[session]:

                if packet.getlayer(IP) and packet.getlayer(BOOTP):
                    raw_packet = list(str(packet[BOOTP]))
                    ipv4 = None
                    mac = packet[Ether].src
                    ipv6 = None
                    domain = None
                    os = None
                    hostname = None
                    cipv4 = None
                    dns = None
                    fqdn = None
                    subnet_mask = None
                    nbt_server = None
                    protocol = 'DHCPv4'
                    sport = packet[IP].sport
                    dport = packet[IP].dport
                    boot_type = packet[BOOTP].op
                    bootp_data = packet[DHCP].options
                    broadcast_address = None
                    testkeys = {}

                    for obj in bootp_data:
                        objlen = len(list(obj))
                        if objlen == 3 and str(list(obj)[0]).strip() in datasets:
                            objkeys = dict([(list(obj)[0], str(', '.join(list(obj)[1:3])))])
                            testkeys.update(objkeys)

                        if objlen == 2 and str(list(obj)[0]).strip() in datasets:
                            objkeys = dict([obj])
                            testkeys.update(objkeys)

                    if boot_type == 1:
                        ipv4 = packet[IP].src
                        testkeys.update({'mac': mac, 'domain': domain, 'ipv4': ipv4, 'ipv6': ipv6, 'os': os})

                        if 'hostname' in testkeys.keys() and testkeys['hostname'] not in self.keys['hosts'].keys() and testkeys['hostname'] != None:
                            self.keys['hosts'].update({hostname: testkeys})

                    if boot_type == 2:

                        if 'router' in testkeys.keys() and testkeys['router'] not in self.keys['routers'].keys() and testkeys['router'] != None:
                            self.keys['routers'].update({testkeys['router']:testkeys})

                        if 'name_server' in testkeys.keys() and testkeys['name_server'] not in self.keys['dns'] and testkeys['name_server'] != None:
                            self.keys['dns'].append(testkeys['name_server'])

        return self.keys
