#!/usr/bin/python2
#
##########################################################################################
#
#
#                            /\   /\
#                     ____  / /__/ /_________  _________  ____
#                    / __ \/ //_/ __/ ___/ _ \/ ___/ __ \/ __ \
#                   / /_/ / ,< / /_/ /  /  __/ /__/ /_/ / / / /
#                  / .___/ /|_|\__/ /   \___/\___/\____/ / / /
#                 / /    \/       \/                   \/ / /
#                / /                                      \/
#                \/
#
#   "Hence to fight and conquer in all your battles is not supreme excellence;
# supreme excellence consists in breaking the enemy's resistance without fighting."
#
#                                - Sun Tzu
#
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##########################################################################################

import sys
import os
import random
import logging
import glob

from modules.engine import *
from modules.console import *

from scapy.all import *
from scapy.utils import *
from argparse import ArgumentParser

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def main():

    parser = ArgumentParser(description='pktrecon | Internal network segment reconnaissance using packets captured from broadcast and service discovery protocol traffic')

    parser.add_argument('-p', '--pcap', help='Packet capture to read from')

    args = parser.parse_args()

    pcap = args.pcap

    pktpath = os.getcwd()
    pktmodules = index_module_names()

    clist = []
    color = 'nocolor'

    if pcap:

        loadfile = pcap
        recon_keys = {'hosts': {},
                      'fingerprints': [],
                      'ports': [],
                      'protocols': [],
                      'gateways': {},
                      'routers': {},
                      'dns':[],
                      'domains': []
                      }

        print ColorOut('Loading PCAP file: {}...'.format(loadfile), char='. ').nocolor()
        pcap_buf = rdpcap(loadfile)

        print ColorOut('Performing packet reconnaissance...\n', char='. ').nocolor()
        load_protocol_modules = LoadModules(pcap_buf, recon_keys, pktmodules, pktpath, color)

if __name__ == '__main__':

    console_banner()
    main()
