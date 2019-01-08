#!/usr/bin/python2

import sys
import os
import glob
import random
import json
import readline
import subprocess
import logging
import importlib
import engine

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.utils import *

from datetime import date

def console_banner():

    with open('{}/banners/pktrecon.banner'.format(os.getcwd()), 'r') as banner:
        print banner.read()


class ColorOut:

    def __init__(self, str, char='-'):

        self.str = str
        self.char = char

    def red(self):
        return '\033[1;31m{}\033[1;m{}'.format(self.char,self.str)

    def blue(self):
        return '\033[1;34m{}\033[1;m{}'.format(self.char,self.str)

    def green(self):
        return '\033[1;32m{}\033[1;m{}'.format(self.char,self.str)

    def white(self):
        return '\033[1;37m{}\033[1;m{}'.format(self.char,self.str)

    def purple(self):
        return '\033[1;35m{}\033[1;m{}'.format(self.char,self.str)

    def nocolor(self):
        return '{}{}'.format(self.char,self.str)

class PktReconHelp:

    def __init__(self, cmdstr):

        self.cmdstr = cmdstr
        self.parselen = len(cmdstr.split())

        if self.parselen > 1:
            try:
                runcmd = getattr(self, self.cmdstr.split()[1].strip())
                runcmd()

            except AttributeError, err:

                pass

        else:

            try:
                runcmd = getattr(self, self.cmdstr)
                runcmd()

            except AttributeError, err:

                pass

    def capture(self):

        capture_help = '''
Usage : capture <iface>
E.X.  : capture eth0

About: Capture network packets on a specified interface

    '''

    def show(self):

        show_help = '''
Usage : show <all, hosts, ipv4, protocols, fqdn, fingerprints, ports>
E.X.  : show hosts WINADCOMPUTER1337
        show domains

About: Use this command to show available session infrastructure data

    '''

        print show_help

    def search(self):

        search_help = '''
----------------------------------------------------------
{} Command Help
----------------------------------------------------------
Usage: search <hosts, ipv4, protocols, fqdn, fingerprints, ports>
E.X. : search hosts WINADCOMPUTER321
       search ipv4 192.168.1.1
       search protocols dhcp
       search fqdns WINADCOMPUTER321.WINAD.LOCAL
       search fingerprints Windows Server 2008

About: Use this command to find saved targets
       and/or recon data using search queries.
       For example, a "search protocol lldp"
       command would search for any hosts
       discovered via LLDP and display the hosts
       information.

    '''.format(self.cmdstr)

        print search_help

    def shell(self):

        shell_help = '''
----------------------------------------------------------
{} Command Help
----------------------------------------------------------
Usage: shell <cmd>
E.X. : shell ls -la
       shell whoami && id

About: Execute local shell command

'''

class PktReconConsole:

    def __init__(self, cmdstr, keys, rpath):

        self.cmdstr = cmdstr
        self.keys = keys
        self.rpath = rpath
        self.parselen = len(self.cmdstr.split())

        if self.parselen == 3:

            try:
                runcmd = getattr(self, self.cmdstr.split()[0].strip())
                runcmd(self.keys)

            except AttributeError, err:

                print ColorOut('PktRecon command not found: {}'.format(self.cmdstr.split()[0])).red()

        elif self.parselen == 2:

            try:
                runcmd = getattr(self, self.cmdstr.split()[0].strip())
                runcmd(self.keys)

            except AttributeError, err:

                print ColorOut('PktRecon command not found: {}'.format(self.cmdstr)).red()

        elif self.parselen == 1:

            try:
                runcmd = getattr(self, self.cmdstr.split()[0].strip())
                runcmd(self.keys)

            except AttributeError, err:

                print ColorOut('PktRecon command not found: {}'.format(self.cmdstr)).red()

    def help(self, keys):

        if self.parselen == 2:
            PktReconHelp(self.cmdstr)

        else:
            print '''
===========================================
             PktRecon Commands
-------------------------------------------
- help
- show
- search
- history
- capture
- shell
- exit

Type "help <command>" for more help.

===========================================
            '''

    def show(self, keys):

        if self.parselen == 3:

            if self.cmdstr.split()[1] in keys.keys():

                if keys[self.cmdstr.split()[1]] != {}:
                    subkeylist = keys[self.cmdstr.split()[1]].keys()

                    if self.cmdstr.split()[2].upper() in sorted(list(set(subkeylist))):

                        hostname = self.cmdstr.split()[2].strip()
                        hostdata = keys[self.cmdstr.split()[1]][self.cmdstr.split()[2].upper()].keys()

                        print hostname

                        for dataname in hostdata:
                            datavalue = keys[self.cmdstr.split()[1]][self.cmdstr.split()[2].upper()][dataname]

                            if type(datavalue) == 'list':
                                datavalue = ', '.join(datavalue)

                            else:
                                datavalue = datavalue

                            print '{0:20} {1:2} {2:1}'.format(dataname.upper(), '-', datavalue)

                    if self.cmdstr.split()[2] in sorted(list(set(subkeylist))):

                        hostname = self.cmdstr.split()[2].strip()
                        hostdata = keys[self.cmdstr.split()[1]][self.cmdstr.split()[2]].keys()

                        print hostname

                        for dataname in hostdata:
                            datavalue = keys[self.cmdstr.split()[1]][self.cmdstr.split()[2]][dataname]

                            if type(datavalue) == 'list':
                                datavalue = ', '.join(datavalue)

                            else:
                                datavalue = datavalue

                            print '{0:20} {1:2} {2:1}'.format(dataname.upper(), '-', datavalue)

                else:
                    print ColorOut('No {} settings available.'.format(self.cmdstr.split()[1].strip())).red()

        elif self.parselen == 2:

            if self.cmdstr.split()[1] in keys.keys():

                if keys[self.cmdstr.split()[1]] != {}:
                    subkeylist = keys[self.cmdstr.split()[1]].keys()

                    print '-' * 50
                    print '{}'.format(self.cmdstr.split()[1].strip().capitalize())
                    print '-' * 50

                    for s in sorted(list(set(subkeylist))):
                        print s

                    print '-' * 50

                else:
                    print ColorOut('No {} settings available.'.format(self.cmdstr.split()[1].strip())).red()

            else:
                PktReconHelp('show')

        else:
            print ColorOut('Type "help show" for more help on using the "show" command').blue()

    def sessions(self, keys):

        sessions = saved_sessions()

        for skey in sessions.keys():
            print skey, sessions[skey]

    def shell(self, keys):

        if self.parselen >= 2:
            cmd = ' '.join(self.cmdstr.split()[1:]).rstrip()

            os.system(cmd)

        else:
            PktReconHelp(self.cmdstr)

    def history(self, keys):
        '''Handles the saved PktRecon console
           command-line history'''
#        history_exists = check_history(self.rpath)

#        if history_exists:

        history_buf = load_history(self.rpath)
        history_buf_len = len(history_buf.split('\n'))

        for i in range(1, history_buf_len):
            print '{0:3} {1:5}'.format(i, history_buf.split('\n')[i-1])

#        else:

#            create_history()

#            history_buf = load_history()
#            history_buf_len = len(history_buf.split('\n'))
#

#            for i in range(1, history_buf_len):
#                print '{0:3} {1:5}'.format(i, history_buf.split('\n')[i-1])

    def search(self, keys):

        if self.parselen >= 2:
            index = self.cmdstr.split()[1].strip()
            query = self.cmdstr.split()[2].strip()

            if index in keys.keys():
                if query.lower() in keys[index].keys():
                    ikeys = keys[index][query.lower()].keys()

                    for ikey in ikeys:
                        print ikey.capitalize(), keys[index][query.lower()][ikey]

                if query.upper() in keys[index].keys():
                    ikeys = keys[index][query.upper()].keys()

                    for ikey in ikeys:
                        print ikey.capitalize(), keys[index][query.upper()][ikey]

            else:
                for rkey in keys.keys():
                    r_keybuf = keys[rkey].keys()

                    for r_obj in r_keybuf:
                        obj_keybuf = keys[rkey][r_obj].keys()
                        if index.lower() in obj_keybuf:
                            select_obj = keys[rkey][r_obj][index.lower()]
                            if query in [select_obj]:

                                 for k in keys[rkey][r_obj].keys():
                                     print k.capitalize(), keys[rkey][r_obj][k]


    def capture(self, keys):

        interfaces = detect_interfaces()

        PktReconSniffer('eth0', keys).sniff()

def detect_interfaces():

    ipkeys = {}
    id = 1

    available_interfaces = subprocess.Popen("ip -o link show | awk -F': ' '{print $2}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    iface_buf = available_interfaces.stdout.read().strip()
    iface_err = available_interfaces.stderr.read().strip()

    iface_buf_list = iface_buf.split('\n')

    return sorted(list(set(iface_buf_list)))

def run_PktRecon_command(cmd, rkeys, rfile, rpath):
    '''Small wrapper function to make command calls to
       the API and console classes'''

    if cmd == 'exit':
        print ColorOut('Thank you for using pktrecon!').blue()

        sys.exit()


    PktReconConsole(cmd, rkeys, rpath)

def session_check(sfile):
    '''Checks if a session file exists'''
    checkfile = glob.glob(sfile)
    if len(checkfile) == 0:
        print 'Console session not found: {}'.format(checkfile)
        return False

    else:
        print 'Console session found: {}'.format(checkfile)
        return True

def saved_sessions():
    '''Returns a list of all currently saved
       session files.'''
    savedkeys = {}
    savecount = 1
    sessions = '{}/sessions/'.format(os.getcwd())
    index = glob('{}*'.format(sessions))

    for i in index:
        savedkeys.update({savecount: i})
        savecount += 1

    return savedkeys

def sessions_path_exists():

    sessions_path = '{}/sessions'.format(os.getcwd())
    index = glob(sessions_path)

    if index != []:
        return True

    return False

def json_writer(jdata,jfile):
    '''Function to write JSON data
       to console session file.'''
    with open(jfile, 'w') as sfile:
        json.dump(jdata, sfile)

def json_loader(jfile):
    '''Loads JSON data from file'''
    with open(jfile, 'r') as jdata:
        rdata = json.load(jdata)
        return rdata

def create_session(rfile):
    '''Creates a new pktrecon console session'''
    rkeys = new_keys()
    json_writer(rkeys, rfile)

    print 'PktRecon console session created.'

def check_history(path):
    '''Function to check if a CLI history
       file for PktRecon exists'''
    filepath = '{}/.pktrecon_history'.format(path)
    if len(glob(filepath)) == 0:
        return False

    else:
        return True

def create_history(path):

    os.system('touch {}/.pktrecon_history'.format(path))

def load_history(path):

    with open('{}/.pktrecon_history'.format(path), 'r') as historyfile:
        return historyfile.read()

def write_history(cmd, path):

    with open('{}/.pktrecon_history'.format(path), 'a') as historyfile:
        historyfile.write('{}\n'.format(cmd))

def session_handler(sfile=None):
    '''Handles the current console session. If no session file
       is found, a new one will be made. If the session exists,
       the JSON data from that session file is loaded into memory.'''

    check_sessions_path = sessions_path_exists()

    if not check_sessions_path:
        os.system('mkdir {}'.format('{}/sessions'.format(os.getcwd())))

    console_sessions = saved_sessions()

    if sfile:

        loadkeys = json_loader(sfile)

        return sfile,loadkeys

    else:

        current_session = '{}/sessions/pktrecon-{}.nrecon'.format(os.getcwd(),date.today())

        if current_session not in console_sessions.values():
            print 'Creating console session: {}'.format(current_session)

            create_session('{}'.format(current_session))
            loadkeys = json_loader('{}'.format(current_session))

            return current_session,loadkeys

        else:

            loadkeys = json_loader('{}'.format(current_session))

            return current_session,loadkeys

def switch_session(new_session):
    '''Changes the currently loaded session'''

    print 'Changing session: {}'.format(new_session)

    sessions = saved_sessions()
    newfile, newkeys = session_handler(sfile=new_session)

    return newfile, newkeys

def pktrecon_shell(rfile, rkeys, rpath):
    '''The pktrecon console command shell
       function.'''
    sessions = saved_sessions()
    h_check = check_history(rpath)
    if not h_check:
        create_history(rpath)

    prompt = '#pktrecon ~> '

    print ''
    print ColorOut('Console session loaded: {}'.format(rfile)).green()
    print ColorOut('Type "help" for a full list of commands.').green()
    print ''

    while True:

        readline.get_line_buffer()
        cmd = raw_input(prompt)

        print ''

        if len(cmd) != 0:
            write_history(cmd, rpath)
            run_PktRecon_command(cmd, rkeys, rfile, rpath)
            json_writer(rkeys, rfile)

        else:
            pktrecon_shell(rfile, rkeys)

        print ''

def pktrecon_correlate_data(rkeys):

    hosts = rkeys['hosts'].keys()

    for host in hosts:
        hostkeys = rkeys['hosts'][host].keys()

        for key in hostkeys:
            h_val = rkeys['hosts'][host][key]

            if h_val == None:
                new_val = find_key(rkeys, key, rkeys['hosts'][host]['mac'])
                rkeys['hosts'][host].update({key: new_val})

    return rkeys

def find_key(rk, k, mac):

    hosts = rk['hosts'].keys()

    for host in hosts:
        if k in rk['hosts'][host].keys() and rk['hosts'][host]['mac'] == mac and rk['hosts'][host][k] != None:

            return rk['hosts'][host][k]

def sort_ips(iplist):
    '''Sorts a list of IPv4 addresses'''
    return sorted(iplist, key=lambda ip: long(''.join(["%02X" % long(i) for i in ip.split('.')]), 16))

def pktrecon_console_output(rkeys, rpath, c):

    hosts = rkeys['hosts']
    domains = rkeys['domains']
    fingerprints = rkeys['fingerprints']
    ports = sorted(list(set(rkeys['ports'])))
    protocols = rkeys['protocols']
    gateways = rkeys['gateways']
    dns = rkeys['dns']
    routers = rkeys['routers']
    usernames = rkeys['usernames']

    pktoutput = engine.ReconOpsOutput(c, hosts=hosts, ports=ports, domains=domains, protocols=protocols, dns=dns, fprints=fingerprints, gateways=gateways, routers=routers, users=usernames)

    pktoutput.summary_output()

    if hosts.keys() != []:
        pktoutput.hostname_output()

    if gateways.keys() != []:
        pktoutput.gateways_output()

    if routers.keys() != []:
        pktoutput.routers_output()

    if dns != []:
        pktoutput.dns_output()

    if usernames != []:
        pktoutput.username_output()

    if fingerprints != []:
        pktoutput.fingerprints_output()

    if domains != []:
        pktoutput.domains_output()

    if protocols != []:
        pktoutput.protos_output()
