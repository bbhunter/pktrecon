#!/usr/bin/python2

import sys
import os
import glob
import random
import logging
import engine
import re

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.utils import *

class WINBROWSER:

    def __init__(self, keys, packet):

        self.keys = keys
        self.packet = packet

    def search(self):

        username = None
        broadcast = None

        if self.packet.getlayer(IP):
            broadcast = '{}.255'.format('.'.join(self.packet[IP].src.split('.')[0:3]))

        if broadcast and self.packet.getlayer(UDP) and self.packet[IP].dst == broadcast and self.packet[UDP].sport == 138 and self.packet[UDP].dport == 138:

                raw_packet = list(str(self.packet[Raw]))
                if '\x12' in raw_packet:
                    logon_index = raw_packet.index('\x12')
                    check_logon = raw_packet[logon_index + 1]
                    if check_logon == '\x00':
                        username = ''.join(raw_packet[logon_index + 4 + 10: logon_index + 4 + 10 + 26])

        if self.packet.getlayer(UDP) and self.packet.getlayer(NBTDatagram) and self.packet[UDP].sport == 138 and self.packet[UDP].dport == 138:

            mac = self.packet[Ether].src
            ipv4 = self.packet[IP].src
            segment = '{}.0/24'.format('.'.join(ipv4.split('.')[0:3]))
            ipv6 = None
            domain = None
            domain_controller = False
            os = None
            sport = self.packet[IP].sport
            dport = self.packet[IP].dport
            dns = None
            router = None
            raw_packet = list(str(self.packet[Raw]))
            browser_cmd = raw_packet[85:87]
            notes = None
            attack = None
            protocol = 'Windows Browser Datagram'

            server_type = ''.join(list(raw_packet[110:114])).encode('hex')
            little_endian_server_type = ''.join(list(raw_packet[110:114])[::-1]).encode('hex')

            if browser_cmd[1] == '\x01':
                announcement = "Host Announcement"

            elif browser_cmd[1] == '\x02':
                announcement = "Request Announcement"

            elif browser_cmd[1] == '\x0b':
                announcement = "Become Backup Browser"

            elif browser_cmd[1] == '\x0c':
                announcement = "Domain/Workgroup Announcement"

            elif browser_cmd[1] == '\x0f':
                announcement = "Local Master Announcement"

                if raw_packet[118:] != ['\x00']:
                    host_comment = ''.join(raw_packet[118:]).strip()

            else:
                announcement = None

            if announcement != "Request Announcement" and announcement != "Become Backup Browser" and len(list(raw_packet)) > 108:

                if list(raw_packet[108:110])[0] == '\x0a' and list(raw_packet[108:110])[1] == '\x00':
                    os = 'Windows 10 / Server 2016 (NT 10.0)'

                elif list(raw_packet[108:110])[0] == '\x06' and list(raw_packet[108:110])[1] == '\x00':
                    os = 'Windows Vista / Server 2008 (NT 6.0)'

                elif list(raw_packet[108:110])[0] == '\x06' and list(raw_packet[108:110])[1] == '\x01':
                    os = 'Windows 7 / Server 2008 R2 (NT 6.1)'

                elif list(raw_packet[108:110])[0] == '\x06' and list(raw_packet[108:110])[1] == '\x02':
                    os = 'Windows 8 / Server 2012 (NT 6.2)'

                elif list(raw_packet[108:110])[0] == '\x06' and list(raw_packet[108:110])[1] == '\x03':
                    os = 'Windows 8.1 / Server 2012 R2 (NT 6.3)'



                elif list(raw_packet[108:110])[0] == '\x05' and list(raw_packet[108:110])[1] == '\x00':
                    os = 'Windows 2000 (NT 5.0)'

                elif list(raw_packet[108:110])[0] == '\x05' and list(raw_packet[108:110])[1] == '\x01':
                    os = 'Windows XP (NT 5.1)'

                elif list(raw_packet[108:110])[0] == '\x05' and list(raw_packet[108:110])[1] == '\x02':
                    os = 'Windows XP Pro x64 / Server 2003 / Server 2003 R2 (NT 5.2)'

                else:
                    os = None

            else:
                os = None

            type = self.packet[NBTDatagram].Type
            hostname = self.packet[NBTDatagram].SourceName.strip()
            host_ipv4 = str(self.packet[NBTDatagram].SourceIP)
            host_type = str(self.packet[NBTDatagram].SUFFIX1)
            domain = str(self.packet[NBTDatagram].DestinationName).strip()
            sid_keys = {}

            if little_endian_server_type and announcement == "Host Announcement":

                byte_list = re.findall('..', little_endian_server_type)
                server_type_binary = []

                for b in byte_list:
                    bin_byte = bin(int(b, 16))[2:].zfill(8)
                    server_type_binary.append(bin_byte)

                little_end_srv_bin_list = server_type_binary[::-1]
                server_type_binary_string = ''.join(little_end_srv_bin_list).strip()

                server_type_keys_1 = ['novell','apple','time_source','backup_controller','domain_controller','sql_server','server','workstation']
                server_type_keys_2 = ['nt_server_1','nt_server_2','wfw','nt_workstation','xenix','dialin','print','member']
                server_type_keys_3 = ['dfs','windows_95_plus','vms','osf','domain_master_browser','master_browser','backup_browser','potential_browser']

                server_type_values_1 = list(server_type_binary_string)[0:8]
                server_type_values_2 = list(server_type_binary_string)[8:16]
                server_type_values_3 = list(server_type_binary_string)[16:24]

                server_type_keys = server_type_keys_1 + server_type_keys_2 + server_type_keys_3
                server_type_values = server_type_values_1 + server_type_values_2 + server_type_values_3

                sid_keys = dict(zip(server_type_keys,server_type_values))

            if username not in self.keys['usernames'] and username != None:
                self.keys['usernames'].append(username)

            if 'MSBROWSE' in domain:
                domain = 'MSBROWSE'

            if domain not in self.keys['domains'] and domain != None and 'MSBROWSE' not in domain:
                self.keys['domains'].append(domain)

            if dport not in self.keys['ports']:
                self.keys['ports'].append(dport)

            if protocol not in self.keys['protocols']:
                self.keys['protocols'].append(protocol)

            if os not in self.keys['fingerprints'] and os != None and os != 'Unknown':
                self.keys['fingerprints'].append(os)

            if notes not in self.keys['fingerprints'] and notes != None and not notes.startswith('Performed'):
                self.keys['fingerprints'].append(notes)

            if router not in self.keys['routers'] and router != None:
                self.keys['routers'].append(router)

            if dns not in self.keys['dns'] and dns != None:
                self.keys['dns'].append(dns)

            if hostname not in self.keys['hosts'].keys() and hostname != None:
                self.keys['hosts'].update({hostname: {'mac': mac, 'domain': domain, 'ipv4': host_ipv4, 'ipv6': ipv6, 'os': os, 'notes': notes, 'protocol': protocol, 'segment': segment, 'server_keys': sid_keys}})

            else:

                if self.keys['hosts'][hostname]['os'] == None or self.keys['hosts'][hostname]['os'] == 'Unknown':
                    engine.UpdateReconKeys(self.keys, hostname, os=os).operating_system()

        return self.keys
