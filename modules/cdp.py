#!/usr/bin/python2

import sys
import os
import glob
import random
import logging
import binascii
import struct
import more_itertools

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.utils import *

class CDP:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(Dot3) and packet[Dot3].dst == '01:00:0c:cc:cc:cc':
                    raw_packet = list(str(packet[Raw]))
                    mac = packet[Dot3].src
                    ipv4 = None
                    ipv6 = None
                    domain = None
                    os = None
                    dns = None
                    router = None
                    segment = None
                    protocol = 'CDP'
                    notes = None

                    cdp_version = str(int(str(raw_packet[0]).encode('hex'), 16)).strip()
                    cdp_ttl = str(int(str(raw_packet[1]).encode('hex'), 16)).strip()
                    cdp_checksum = ''.join(raw_packet[2:4]).encode('hex').strip()

                    cdp_device_id_type = ''.join(raw_packet[4:6]).encode('hex')
                    cdp_device_id_length = int(''.join(list(raw_packet[6:8])).encode('hex'), 16)
                    cdp_device_id = ''.join(raw_packet[8:(8 + (cdp_device_id_length - 4))])

                    cdp_addr_type = int(''.join(raw_packet[(8 + (cdp_device_id_length - 4)):(8 + (cdp_device_id_length - 4)) + 2]).encode('hex'), 16)
                    cdp_addr_length = int(''.join(raw_packet[(8 + (cdp_device_id_length - 4)) + 2:(8 + (cdp_device_id_length - 4)) + 4]).encode('hex'), 16)
                    cdp_address_count = int(''.join(raw_packet[(12 + (cdp_device_id_length - 4)):(12 + (cdp_device_id_length - 4)) + 4]).encode('hex'), 16)

                    cdp_addr_proto_type = int(''.join(raw_packet[(12 + (cdp_device_id_length - 4)) + 4:(13 + (cdp_device_id_length - 4)) + 4]).encode('hex'), 16)
                    cdp_addr_proto_length = int(''.join(raw_packet[(13 + (cdp_device_id_length - 4)) + 4:(13 + (cdp_device_id_length - 4)) + 5]).encode('hex'), 16)
                    cdp_addr_proto = ''.join(raw_packet[(13 + (cdp_device_id_length - 4)) + 5:(13 + (cdp_device_id_length - 4)) + 6]).encode('hex')

                    cdp_address_length = int(''.join(raw_packet[(13 + (cdp_device_id_length - 4)) + 6:(13 + (cdp_device_id_length - 4)) + 8]).encode('hex'), 16)
                    cdp_address = raw_packet[(13 + (cdp_device_id_length - 4)) + 8:(13 + (cdp_device_id_length - 4)) + 12]
                    cdp_addr_list = []

                    for c in cdp_address:
                        octet = int(c.encode('hex'), 16)
                        cdp_addr_list.append(str(octet))

                    ipv4 = '.'.join(cdp_addr_list)

                    cdp_port_id_type = str(''.join(raw_packet[(13 + (cdp_device_id_length - 4)) + 12:(13 + (cdp_device_id_length - 4)) + 14]).encode('hex'))
                    cdp_port_id_length = int(''.join(raw_packet[(13 + (cdp_device_id_length - 4)) + 14:(13 + (cdp_device_id_length - 4)) + 16]).encode('hex'), 16)
                    cdp_port_id = str(''.join(raw_packet[(13 + (cdp_device_id_length - 4)) + 16:(13 + (cdp_device_id_length - 4)) + (16 - 4) + cdp_port_id_length])).strip()

                    cdp_platform_list = raw_packet[(17 + (cdp_device_id_length - 4)) + 19 + 8 + 5:(17 + (cdp_device_id_length - 4)) + 19 + 8 + 5 + 14]

                    cdp_cap = raw_packet[(17 + (cdp_device_id_length - 4)) + 19:(17 + (cdp_device_id_length - 4)) + 19 + 8]
                    cap = cdp_cap[4:]

                    cdp_software_type = str(''.join(raw_packet[(19 + (cdp_device_id_length - 4)) + 19 + 8:(17 + (cdp_device_id_length - 4)) + 19 + 8 + 2]).encode('hex')).strip()
                    cdp_software_length = int(''.join(raw_packet[(19 + (cdp_device_id_length - 4)) + 19 + 8 + 2:(19 + (cdp_device_id_length - 4)) + 19 + 8 + 4]).encode('hex'), 16)
                    cdp_software_version = str(''.join(raw_packet[(19 + (cdp_device_id_length - 4)) + 19 + 8 + 4: cdp_software_length])).strip()

                    cdp_platform_type = ''.join(cdp_platform_list[0:2]).encode('hex')
                    cdp_platform_length = int(''.join(list(cdp_platform_list[2:4])).encode('hex'), 16)
                    cdp_platform_name = str(''.join(cdp_platform_list[4:cdp_platform_length]))

                    cdp_vlan_list = raw_packet[(17 + (cdp_device_id_length - 4)) + 19 + 8 + 5 + 14:(17 + (cdp_device_id_length - 4)) + 19 + 8 + 5 + 14 + 6]
                    cdp_vlan = str(int(''.join(cdp_vlan_list[5:6]).encode('hex'), 16)).strip()

                    cdp_powerlist = raw_packet[(17 + (cdp_device_id_length - 4)) + 19 + 8 + 5 + 14 + 6:]
                    cdp_power_type = ''.join(cdp_powerlist[0:2]).encode('hex')
                    cdp_power_length = int(''.join(cdp_powerlist[2:4]).encode('hex'), 16)
                    cdp_power_req_id = str(int(''.join(cdp_powerlist[4:6]).encode('hex'), 16)).strip()
                    cdp_power_mgt_id = str(int(''.join(cdp_powerlist[6:8]).encode('hex'), 16)).strip()
                    cdp_power_avail_min = str(int(''.join(cdp_powerlist[8:12]).encode('hex'), 16)).strip()
                    cdp_power_avail_max = str(int(''.join(cdp_powerlist[12:16]).encode('hex'), 16)).strip()

                    cdp_power = {'cdp_power_mgt_id': cdp_power_mgt_id, 'cdp_power_available': cdp_power_avail_min, 'cdp_power_max': cdp_power_avail_max}

                    hostname = cdp_device_id

                    if domain not in self.keys['domains'] and domain != None:
                        self.keys['domains'].append(domain)

                    if protocol not in self.keys['protocols']:
                        self.keys['protocols'].append(protocol)

                    if cdp_platform_name not in self.keys['fingerprints'] and cdp_platform_name not in ' '.join(self.keys['fingerprints']) and cdp_platform_name != None and cdp_platform_name != 'Unknown':
                        self.keys['fingerprints'].append(cdp_platform_name)

                    if hostname not in self.keys['gateways'].keys() and hostname != None:
                        self.keys['gateways'].update({hostname:{'ipv4': ipv4, 'ipv6': ipv6, 'domain': domain, 'protocol': protocol, 'cdp_version': cdp_version, 'cdp_port_id': cdp_port_id, 'cdp_ttl': cdp_ttl, 'cdp_checksum': cdp_checksum, 'cdp_software_version': 'v{}'.format(cdp_software_version), 'cdp_platform_name': cdp_platform_name, 'cdp_vlan': cdp_vlan, 'notes': notes, 'power': cdp_power}})


        return self.keys

