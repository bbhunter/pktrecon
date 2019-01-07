                /\   /\
         ____  / /__/ /_________  _________  ____
        / __ \/ //_/ __/ ___/ _ \/ ___/ __ \/ __ \
       / /_/ / ,< / /_/ /  /  __/ /__/ /_/ / / / /
      / .___/ /|_|\__/ /   \___/\___/\____/ / / /
     / /    \/       \/                   \/ / /
    / /                                      \/
    \/ . pktrecon
       . written by k0fin

## about

pktrecon is a tool for internal network segment reconnaissance using broadcast and service discovery protocol traffic.
Individual pieces of data collected from these protocols include hostnames, IPv4 and IPv6 addresses, router addresses,
gateways and firewalls, Windows OS fingerprints, and much more. This data is correlated and normalized with attackers
in mind, and provides an effective method of initiating an engagement and obtaining as much target data as possible
before resorting to more active methods.

## protocols

The protocols and services utilized by pktrecon include:

  - Cisco Discovery Protocol               (CDP)
  - Link Local Discovery Protocol          (LLDP)
  - NetBIOS Name Service                   (NBNS)
  - Windows Browser Datagrams              (WINBROWSER)
  - Link Local Multicast Name Resolution   (LLMNR)
  - Dynamic Host Configuration Protocol v4 (DHCPv4)
  - Dynamic Host Configuration Protocol v6 (DHCPv6)

## recon data

Examples of data which pktrecon can be potentially obtained from a packet capture include:

- Hostnames and FQDN's
- MAC addresses and subnet masks
- Domain names
- IPv4 and IPv6 addresses
- Windows operating system fingerprints / NT version numbers / Vendor class ID's
- Server type identification (domain controllers, backup domain controllers, sql servers, and more)
- SMB server fingerprints
- DNS name server IPv4 addresses
- Router IPv4 addresses, time zone, lease time, renewal time, and rebinding time
- Cisco device names and management IPv4 addresses
- Native VLANs and port IDs
- PoE Power (Power management ID, available power, management power level)
- Switch and firewall platform / System description / Fingerprints / Software build versions

## installation

Just install the required Python dependencies for pktrecon and you're good to go:

    pip install -r requirements.txt

## usage

Using pktrecon is simple. First, passively sniff traffic on a local network segment. Write this network traffic
to a packet capture file with a tool such as tcpdump. Be sure to perform multiple packet captures of varying
intervals.

An example with tcpdump:

    tcpdump -i <interface> -w </path/to/pcap.pcap>

Once the packet capture is completed, pktrecon can be used to perform reconnaissance against the capture file:

    python ./pktrecon.py --pcap <pcapfile>.pcap

There is a folder included with the pktrecon project containing multiple sample packet captures from Wireshark
to test pktrecon with.

Performing packet captures using a live network interface is currently being implemented into pktrecon.
Currently, pktrecon is capable of capturing data on a live network interface. However, the output and data
correlation for captured packets is not yet completed. Live interface mode can be started with:

    python ./pktrecon.py --interface <interface_name>

## python3

Because python2 will be deprecated at the end of 2019, pktrecon will slowly but surely be ported to Python3
(and it'll probably be alot prettier!) :)

## todo / in progress

There is a ton of work to do on pktrecon, and many pieces of it still need to be cleaned up.
I will try to update and maintain pktrecon as often as possible.
Here are just a few of the things currently in progress:

- Project screenshots and extended documentation / wiki
- Server type identification
- Cross-network segment host data correlation
