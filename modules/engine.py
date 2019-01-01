#!/usr/bin/python2

import sys
import os
import importlib
import console
import netaddr

from glob import glob

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

class RunModule:

    def __init__(self, data, keys, module):

        self.data = data
        self.keys = keys
        self.module = module

    def run(self):

        i = importlib.import_module('modules.{}'.format(self.module))
        run_engine = getattr(i, '{}'.format(self.module.upper()))

        runkeys = run_engine(self.data, self.keys).search()

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

    def __init__(self, tcolor, hosts=None, ports=None, domains=None, protocols=None, dns=None, creds=None, fprints=None, attacks=None, gateways=None, routers=None):

        self.tcolor = tcolor
        self.hosts = hosts
        self.ports = ports
        self.domains = domains
        self.protocols = protocols
        self.dns = dns
        self.fprints = fprints
        self.gateways = gateways
        self.routers = routers

        self.color = getattr(self, self.tcolor)

    def hostname_output(self):

        host_title = '{0:20} {1:16} {2:18} {3:18} {4:30} {5:1}\n'.format('[ Host ]', '[ IPv4 ]', '[ MAC ]', '[ Domain ]', '[ Windows NT ]', '[ Notes ]')
        print self.color(host_title, char='')

        for host in sorted(self.hosts):

            ipv4 = self.hosts[host]['ipv4']
            mac = self.hosts[host]['mac']

            if host != None and ipv4 != '0.0.0.0' and '*' not in host:

                mac = self.hosts[host]['mac']
                os = self.hosts[host]['os']
                domain = self.hosts[host]['domain']
                notes = self.hosts[host]['notes']

                host_output = '{0:20} {1:16} {2:18} {3:18} {4:30} {5:1}'.format(host, ipv4, mac, domain, os.split('(')[1].split(')')[0].strip(), notes)

                print self.color(host_output, char='')

        print '\n'


    def domains_output(self):

        domains_title = '[ Domains ]\n'
        print self.color(domains_title, char='')

        for domain in self.domains:
            if domain != None:
                print self.color(domain)

        print '\n'

    def ports_output(self):

        ports_title = '[ Ports ]\n'
        print self.color(ports_title, char='')
        print 'nmap -Pn -sS -p{} -sV --open <targets>'.format(','.join(self.ports))
        for port in self.ports:

            print self.color(port)

        print '\n'

    def protos_output(self):

        protos_title = '[ Protocols ]\n'
        print self.color(protos_title, char='')

        for proto in self.protocols:

            print self.color(proto)

        print '\n'

    def gateways_output(self):

        gateways_title = '[ Gateways ]\n'
        print self.color(gateways_title, char='')

        for gateway in sorted(list(set(self.gateways.keys()))):

            print self.color(' {}\n'.format(gateway.upper()), char='-')
            gatekeys = self.gateways[gateway].keys()

            for g in sorted(list(set(gatekeys))):
                if self.gateways[gateway][g] != None:
                    print self.color('{0:20} - {1:10}'.format(g.upper().replace('_', ' '), self.gateways[gateway][g]), char='  . ')

            if len(self.gateways.keys()) > 1:
                print ''

        print '\n'

    def dns_output(self):

        dns_title = '[ DNS Servers ]\n'
        print self.color(dns_title, char='')

        for d in sorted(list(set(self.dns))):

            print self.color(d)

        print '\n'

    def routers_output(self):

        routers_title = '[ Routers ]\n'
        print self.color(routers_title, char='')

        for router in sorted(list(set(self.routers))):

            print self.color(router)

        print '\n'

    def ports_output(self):

        ports_title = '[ Ports ]\n'
        print self.color(ports_title, char='')

        for port in sorted(list(set(self.ports))):

            print self.color(port)

        print '\n'

    def fingerprints_output(self):

        fingerprints_title = '[ Fingerprints ]\n'
        print self.color(fingerprints_title, char='')

        for fingerprint in self.fprints:

            print self.color(fingerprint)

        print '\n'

    def summary_output(self):

        summary_title = '[ Summary ]\n'
        print self.color(summary_title, char='')

        print 'Hosts:        {}'.format(len(self.hosts.keys()))
        print 'Domains:      {}'.format(len(self.domains))
        print 'Fingerprints: {}'.format(len(self.fprints))
        print 'Ports:        {}'.format(len(self.ports))
        print 'Protocols:    {}'.format(len(self.protocols))
        print 'Gateways:     {}'.format(len(self.gateways.keys()))
        print 'Routers:      {}'.format(len(self.routers.keys()))
        print 'DNS Servers:  {}'.format(len(self.dns))

        print '\n'

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
