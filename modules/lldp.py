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

class LLDP:

    def __init__(self, keys, packet):

        self.keys = keys
        self.packet = packet

    def search(self):

        if self.packet.getlayer(Ether) and (self.packet[Ether].dst == "01:80:c2:00:00:0e" or self.packet[Ether].dst == "01:80:c2:00:00:03" or self.packet[Ether].dst == "01:80:c2:00:00:00"):

            mac = self.packet[Ether].src
            raw_packet = list(str(self.packet[Raw]))

            hostname = '{}'.format(mac)
            domain = None
            os = None
            ipv6 = None
            protocol = 'LLDP'
            system_name = hostname
            system_description = None
            mgt_ipv4 = None
            mgt_802 = None
            mgt_address_type = None
            address = None
            segment = None
            dns = None
            router = None
            notes = None

            # Get Chassis ID
            chassis_id = ''
            chassis_id_bytes = list(str(self.packet))[17:23]

            for chassis_obj in chassis_id_bytes:
                chassis_byte = str(chassis_obj.encode('hex'))
                chassis_id += '{}:'.format(str(chassis_obj.encode('hex')))

            chassis_id_mac = chassis_id.rstrip(':')

            # Get LLDP System Name
            if '\x0a' in raw_packet:

                system_name_start = int(raw_packet.index('\x0a'))
                system_name_type = raw_packet[system_name_start].encode('hex')
                system_name_length = int(raw_packet[system_name_start + 1].encode('hex'), 16)

                system_name = ''.join(raw_packet[system_name_start + 2:system_name_start + system_name_length + 2])

            if '\x0c' in raw_packet:
            # Get LLDP System Description

                system_description_start = raw_packet.index('\x0c')
                system_description_list = raw_packet[(system_description_start + 2):]
                system_description = str(''.join(system_description_list).rsplit('\x0e')[0].rsplit('\x08')[0]).strip()


            # Get LLDP Port ID
            # Get LLDP VLAN
            # Get LLDP Power


            if '\x0e' in raw_packet:
            # Get LLDP Management Address
                mgt_addr_type_index = None
                mgt_addr_type = None

                if '\x10' in raw_packet:
                    mgt_addr_type_index = raw_packet.index('\x10')
                    mgt_addr_type = raw_packet[(mgt_addr_type_index + 3)]

                if mgt_addr_type == '\x06':

                    mgt_address_type = '802 Media'
                    mgt_addr_start = list(''.join(system_description_list).rsplit('\x0e')[-1:][0][2:8])
                    mgt_802_addr = ''

                    for mgt in mgt_addr_start:

                        mgt_obj = mgt.encode('hex')
                        mgt_802_addr += '{}.'.format(mgt_obj)
                        mgt_802 = mgt_802_addr.rstrip('.')

                if mgt_addr_type == '\x01':

                    mgt_address_type = 'IPv4'
                    mgt_addr_start = raw_packet[(mgt_addr_type_index + 4):(mgt_addr_type_index + 8)]
                    mgt_addr_list = []

                    for mgt in mgt_addr_start:
                        octet = int(mgt.encode('hex'), 16)
                        mgt_addr_list.append(str(octet))

                        mgt_ipv4 = '.'.join(mgt_addr_list)

                if '\xfe' in raw_packet and mgt_addr_type == '\x01':

                    teledata_start = raw_packet.index('\xfe')
                    teledata_list = ''.join(raw_packet[teledata_start:]).lstrip('\xfe').split('\xfe')[1::]

                    if len(teledata_list) == 4:

                        media_capabilities = teledata_list[0]
                        #print list(media_capabilities)

                        network_policy = teledata_list[1]
                        #print network_policy

                        location_identification = teledata_list[2]
                        #print location_identification

                        extended_power = teledata_list[3]
                        #print extended_power

                        country = location_identification[8:10]
                        state = location_identification[12:14]
                        city = str(''.join(location_identification[16:]).rsplit('\x06')[0]).strip()
                        street = str(''.join(location_identification[16:]).rsplit('\x06')[1].rsplit('\x13')[0]).strip()
                        number = str(''.join(location_identification[16:]).rsplit('\x06')[1].split('\x13')[1][1:5]).strip()
                        unit = location_identification[-3:]

                        address = '{} {} {} - {}, {} - {}'.format(number, street, unit, city, state, country)

            if domain not in self.keys['domains'] and domain != None:
                self.keys['domains'].append(domain)

            if system_description not in self.keys['fingerprints'] and system_description != None:
                self.keys['fingerprints'].append(system_description)

            if protocol not in self.keys['protocols']:
                self.keys['protocols'].append(protocol)

            if router not in self.keys['routers'] and router != None:
                self.keys['routers'].append(router)

            if dns not in self.keys['dns'] and dns != None:
                self.keys['dns'].append(dns)

            hostname = system_name
            if hostname not in self.keys['gateways'].keys() and hostname != None:
                self.keys['gateways'].update({hostname: {'mac': mac, 'ipv6': ipv6, 'domain': domain, 'sysinfo': system_description, 'ipv4': mgt_ipv4, 'mgt_802': mgt_802, 'mgt_addr_type': mgt_address_type, 'address': address, 'chassis_id_mac': chassis_id_mac, 'os': os, 'protocol': protocol, 'notes': notes}})


        return self.keys
