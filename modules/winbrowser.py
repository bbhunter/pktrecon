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

class WINBROWSER:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:
            for packet in sessions[session]:

                if packet.getlayer(UDP) and packet.getlayer(NBTDatagram) and packet[UDP].sport == 138 and packet[UDP].dport == 138:

                    mac = packet[Ether].src
                    ipv4 = packet[IP].src
                    segment = '{}.0/24'.format('.'.join(ipv4.split('.')[0:3]))
                    ipv6 = None
                    domain = None
                    os = None
                    sport = packet[IP].sport
                    dport = packet[IP].dport
                    dns = None
                    router = None
                    raw_packet = list(str(packet[Raw]))
                    browser_cmd = raw_packet[85:87]
                    notes = None
                    attack = None
                    protocol = 'Windows Browser Datagram'

                    if browser_cmd[1] == '\x01':
                        announcement = "Host Announcement"
                        notes = 'Performed {}'.format(announcement.lower())

                    elif browser_cmd[1] == '\x02':
                        announcement = "Request Announcement"
                        notes = 'Performed {}'.format(announcement.lower())

                    elif browser_cmd[1] == '\x0b':
                        announcement = "Become Backup Browser"
                        notes = 'Performed {}'.format(announcement.lower())

                    elif browser_cmd[1] == '\x0c':
                        announcement = "Domain/Workgroup Announcement"
                        notes = 'Performed {}'.format(announcement.lower())

                    elif browser_cmd[1] == '\x0f':
                        announcement = "Local Master Announcement"
                        notes = 'Performed {}'.format(announcement.lower())

                        if raw_packet[118:] != ['\x00']:
                            notes = ''.join(raw_packet[118:]).strip()

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

                    type = packet[NBTDatagram].Type
                    hostname = packet[NBTDatagram].SourceName.strip()
                    host_ipv4 = str(packet[NBTDatagram].SourceIP)
                    host_type = str(packet[NBTDatagram].SUFFIX1)
                    domain = str(packet[NBTDatagram].DestinationName).strip()

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
                        self.keys['hosts'].update({hostname: {'mac': mac, 'domain': domain, 'ipv4': host_ipv4, 'ipv6': ipv6, 'os': os, 'notes': notes, 'protocol': protocol, 'segment': segment}})

                    else:

                        if self.keys['hosts'][hostname]['os'] == None or self.keys['hosts'][hostname]['os'] == 'Unknown':
                            engine.UpdateReconKeys(self.keys, hostname, os=os).operating_system()

        return self.keys
