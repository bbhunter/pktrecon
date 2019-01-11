#!/usr/bin/python2

import sys
import os
import importlib
import console
import netaddr
import logging
import blessings

from glob import glob

logging.getLogger("scapy").setLevel(1)

from scapy.all import *

def sort_ips(iplist):

    return sorted(iplist, key=lambda ip: long(''.join(["%02X" % long(i) for i in ip.split('.')]), 16))

def index_module_names():

    mlist = []
    modules = glob('{}/modules/*'.format(os.getcwd()))

    for mod in modules:
        if mod.rsplit('.')[1].strip() != 'pyc' and mod.rsplit('.')[1].strip() == 'py':
            modulename = mod.split('/').pop().split('.')[0].strip()

            if modulename != '__init__' and modulename != 'console' and modulename != "engine":
                mlist.append(modulename)

    return mlist

class PktReconSniffer:

    def __init__(self, interface):

        self.interface = interface

    def run(self):

        sniff(iface=self.interface, prn=pkt_bridge, store=0)

def pkt_bridge(p):

    module_list = index_module_names()
    recon_keys = create_recon_keys()

    for mod in module_list:

        i = importlib.import_module('modules.{}'.format(mod))
        sniff_engine = getattr(i, '{}'.format(mod.upper()))

        sniff_engine(recon_keys, p).search()

def create_recon_keys():

    recon_keys = {'hosts': {},
                  'servers': {'dc': [], 'backup_dc': [], 'sql': []},
                  'usernames': [],
                  'fingerprints': [],
                  'ports': [],
                  'protocols': [],
                  'gateways': {},
                  'routers': {},
                  'dns':[],
                  'domains': []
                  }

    return recon_keys

class RunModule:

    def __init__(self, data, keys, module):

        self.data = data
        self.keys = keys
        self.module = module

    def run(self):

        i = importlib.import_module('modules.{}'.format(self.module))
        run_engine = getattr(i, '{}'.format(self.module.upper()))
        sessions = self.data.sessions()

        for session in sessions:
            loaded_session = sessions[session]

            for packet in loaded_session:
                runkeys = run_engine(self.keys, packet).search()

        return runkeys

class LoadModules:

    def __init__(self, data, keys, modules, rpath, c):

        self.data = data
        self.keys = keys
        self.modules = modules
        self.rpath = rpath
        self.c = c

        for module in self.modules:

            print '  . {}'.format(module.upper())
            self.keys = RunModule(self.data, self.keys, module).run()

        print ''
        console.pktrecon_console_output(self.keys, self.rpath, self.c)

class UpdateReconKeys:

    def __init__(self, keys, host, os=None, port=None):

        self.keys = keys
        self.host = host
        self.os = os
        self.port = port

    def operating_system(self):

        self.keys['hosts'][self.host].update({'os': self.os})

        return self.keys

    def ports(self):

        self.keys['hosts'][self.host]['ports'].append(self.port)

        return self.keys

class ReconOpsOutput:

    def __init__(self, tcolor, hosts=None, ports=None, domains=None, protocols=None, dns=None, creds=None, fprints=None, attacks=None, gateways=None, routers=None, users=None):

        self.tcolor = tcolor
        self.hosts = hosts
        self.ports = ports
        self.domains = domains
        self.protocols = protocols
        self.dns = dns
        self.fprints = fprints
        self.gateways = gateways
        self.routers = routers
        self.usernames = users
        self.color = getattr(self, self.tcolor)

    def hostname_output(self):

        host_title = '| {0:16} | {1:16} | {2:20} | {3:18} | {4:14} | {5:20} | {6:1}'.format('Host', 'IPv4', 'IPv6', 'MAC', 'Domain', 'Server Type', 'Windows OS (Server Fingerprint)')

        print '-' * blessings.Terminal().width
        print self.color(host_title, char='')
        print '-' * blessings.Terminal().width

        server_type = ''

        for host in sorted(self.hosts):

            ipv4 = self.hosts[host]['ipv4']
            ipv6 = self.hosts[host]['ipv6']
            mac = self.hosts[host]['mac']

            if host != None and '*' not in host:

                if 'fqdn' in self.hosts[host].keys():
                    print self.hosts[host]['fqdn']

                mac = self.hosts[host]['mac']
                os = self.hosts[host]['os']
                nt_version = None
                os_version = os
                serverlist = {'domain_controller': 'DC', 'backup_controller': 'Backup DC', 'sql_server': 'SQL', 'print': 'Printer'}
                host_comment = None

                if 'comment' in self.hosts[host].keys():
                    host_comment = self.hosts[host]['comment']

                if os != None and not os.startswith('Microsoft'):
                    nt_version = os.split('(')[1].split(')')[0].strip()
                    os_version = os.split('(')[0].strip()

                if host_comment != None and list(host_comment)[0] != '\x00':
                    os_version += ' ({})'.format(host_comment.capitalize())

                domain = self.hosts[host]['domain']
                notes = self.hosts[host]['notes']

                if 'server_keys' in self.hosts[host].keys():
                    servers = []
                    server_types = self.hosts[host]['server_keys']

                    for server in server_types:

                        if server_types[server] == '1' and server in serverlist.keys():
                            servers.append(serverlist[server])

                    host_output = '| {0:16} | {1:16} | {2:20} | {3:18} | {4:14} | {5:20} | {6:1}'.format(host.upper(), ipv4, ipv6, mac, domain, ','.join(servers).strip(), os_version)

                    print self.color(host_output, char='')

        print '-' * blessings.Terminal().width
        print ''


    def domains_output(self):

        domains_title = '| Domains'

        print '-' * blessings.Terminal().width
        print self.color(domains_title, char='')
        print '-' * blessings.Terminal().width

        if self.domains != []:

            for domain in self.domains:
                if domain != None:
                    print self.color('{}'.format(domain), char='| ')

        print self.color('-' * blessings.Terminal().width, char='')
        print ''

    def protos_output(self):

        protos_title = '| Protocols'

        print '-' * blessings.Terminal().width
        print self.color(protos_title, char='')
        print '-' * blessings.Terminal().width

        for proto in self.protocols:

            print self.color('{}'.format(proto), char='| ')

        print self.color('-' * blessings.Terminal().width, char='')
        print ''


    def gateways_output(self):

        gateways_title = '| {0:28} | {1:18} | {2:10} | {3:14} | {4:44} | {5:1}'.format('Device', 'MgtIPv4', 'VLAN', 'Port', 'Platform', 'Power')

        print self.color('-' * blessings.Terminal().width, char='')
        print self.color(gateways_title, char='')
        print self.color('-' * blessings.Terminal().width, char='')

        for device in sorted(list(set(self.gateways.keys()))):
            gatekeys = self.gateways[device].keys()

            if self.gateways[device] != None:

                protocol = self.gateways[device]['protocol']
                mgt_ipv4 = self.gateways[device]['ipv4']

                if protocol.upper() == 'CDP':

                    vlan = self.gateways[device]['cdp_vlan']
                    port_id = self.gateways[device]['cdp_port_id']
                    platform = self.gateways[device]['cdp_platform_name'].split(',')[0]
                    protocol_version = self.gateways[device]['cdp_version']
                    power = self.gateways[device]['power']
                    software_version= self.gateways[device]['cdp_software_version']
                    mgt_802 = ''
                    address = ''

                    if power != None:
                        power = '{} ({}, {})'.format(power['cdp_power_mgt_id'], power['cdp_power_available'], power['cdp_power_max'])

                    cdp_output = '| {0:28} | {1:18} | {2:10} | {3:14} | {4:44} | {5:1}'.format(device, mgt_ipv4, vlan, port_id, platform, power)

                    print self.color(cdp_output, char='')

                if protocol.upper() == 'LLDP':

                    protocol_version = ''
                    power = None

                    port_id = self.gateways[device]['lldp_port_id']
                    mgt_802 = self.gateways[device]['mgt_802']
                    vlan = self.gateways[device]['lldp_vlan']
                    address = self.gateways[device]['address']
                    platform = self.gateways[device]['sysinfo'].split(',')[0]

                    lldp_output = '| {0:28} | {1:18} | {2:10} | {3:14} | {4:44} | {5:1}'.format(device, mgt_ipv4, vlan, port_id, platform, power)

                    print self.color(lldp_output, char='')

                    if address != None:
                        print ''
                        print self.color('LLDP TR-41 Address: {}'.format(address), char=' . ')

        print '-' * blessings.Terminal().width
        print ''

    def dns_output(self):

        dns_title = '| DNS Name Servers'

        print '-' * blessings.Terminal().width
        print self.color(dns_title, char='')
        print '-' * blessings.Terminal().width

        for d in sort_ips(self.dns[0].split(',')):

            print self.color(d.strip(), char='| ')

        print '-' * blessings.Terminal().width
        print ''

    def routers_output(self):

        routers_title = '{0:18} | {1:18} | {2:16} | {3:20} | {4:1}'.format('Router', 'Server ID', 'Domain', 'Client ID', 'Name Servers')

        print self.color('-' * blessings.Terminal().width, char='')
        print self.color(routers_title, char='| ')
        print self.color('-' * blessings.Terminal().width, char='')

        for router in sorted(list(set(self.routers.keys()))):

            routerkeys = self.routers[router].keys()

            if 'router' in routerkeys:
                router = self.routers[router]['router']

            else:
                router = 'Unknown'


            if 'server_id' in routerkeys:
                server_id = self.routers[router]['server_id']

            else:
                server_id = 'Unknown'


            if 'name_server' in routerkeys:
                name_servers = self.routers[router]['name_server']

            else:
                name_servers = 'Unknown'

            if 'client_id' in routerkeys:
                client_id = self.routers[router]['client_id']

            else:
                client_id = 'Unknown'

            if 'domain' in routerkeys:
                domain = self.routers[router]['domain']

            else:
                domain = 'Unknown'

            if type(name_servers) == 'list':
                name_servers = str(','.join(name_servers)).strip()

            else:
                name_servers = name_servers

            router_output = '{0:18} | {1:18} | {2:16} | {3:20} | {4:1}'.format(router, server_id, domain, client_id, name_servers)

            print self.color(router_output, char='| ')

        print '-' * blessings.Terminal().width
        print ''

    def fingerprints_output(self):

        fingerprints_title = '| {0:30}'.format('Fingerprints')

        print '-' * blessings.Terminal().width
        print self.color(fingerprints_title, char='')
        print '-' * blessings.Terminal().width

        for fingerprint in sorted(list(set(self.fprints))):
            fprint_output = '{0:30}'.format(fingerprint)

            print self.color(fprint_output, char='| ')

        print '-' * blessings.Terminal().width
        print ''

    def username_output(self):

        if len(self.usernames) > 0:
            usernames_title = '| {0:16} | {1:10} | {2:16} | {3:1}'.format('Username', 'Host', 'Domain', 'Win2k Format')

            print '-' * blessings.Terminal().width
            print self.color(usernames_title, char='')
            print '-' * blessings.Terminal().width

            for userpair in self.usernames:

                for username in userpair.keys():

                    hostname = userpair[username]
                    domain = None
                    win2k = None

                    if hostname in self.hosts.keys():
                        domain = self.hosts[hostname]['domain']
                        win2k = '{}\{}'.format(domain, username)

                    username_output = '| {0:16} | {1:10} | {2:16} | {3:1}'.format(username, hostname, domain, win2k)

                    print self.color(username_output, char='')

        print '-' * blessings.Terminal().width
        print ''

    def summary_output(self):

        summary_title = '| Summary |\n'
        print self.color(summary_title, char='')

        print 'Hosts:        {}'.format(len(self.hosts.keys()))
        print 'Domains:      {}'.format(len(self.domains))
        print 'Fingerprints: {}'.format(len(self.fprints))
        print 'Protocols:    {}'.format(len(self.protocols))
        print 'Gateways:     {}'.format(len(self.gateways.keys()))
        print 'Routers:      {}'.format(len(self.routers.keys()))
        print 'DNS Servers:  {}'.format(len(self.dns))

        print ''

    def red(self, out, char='-'):

        return '\033[1;31m{}\033[1;m{}'.format(char, out)

    def blue(self, out, char='-'):

        return '\033[1;34m{}\033[1;m{}'.format(char, out)

    def white(self, out, char='-'):

        return '\033[1;37m{}\033[1;m{}'.format(char, out)

    def purple(self, out, char='-'):

        return '\033[1;35m{}\033[1;m{}'.format(char, out)

    def nocolor(self, out, char='-'):
        return '{}{}'.format(char, out)
