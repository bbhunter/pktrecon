# pktrecon

pktrecon is a tool for internal network segment reconnaissance using broadcast and service discovery protocol traffic.
Individual pieces of data collected from these protocols include hostnames, IPv4 and IPv6 addresses, router addresses,
gateways and firewalls, Windows OS fingerprints, and much more. This data is correlated and normalized with attackers
in mind, and provides an effective method of initiating an engagement and obtaining as much target data as possible
before resorting to more active methods.

# protocols

The protocols and services utilized by pktrecon include:

  - Cisco Discovery Protocol (CDP)
  - Link Local Discovery Protocol (LLDP)
  - NetBIOS Name Service
  - Windows Browser Datagrams
  - Link Local Multicast Name Resolution (LLMNR)
  - Dynamic Host Configuration Protocol Version 4 (DHCPv4)
  - Dynamic Host Configuration Protocol Version 6 (DHCPv6)

# data

The data which can be obtained from a packet capture using pktrecon includes:

- Host names
- Domain names and FQDNs
- Open ports
- IPv4 addresses
- IPv6 addresses
- Windows operating system fingerprints
- SMB Fingerprints
- Network switch fingerprints
- Cisco device fingerprints

# usage

Using pktrecon is simple. First, passively sniff traffic on a local network segment. An example with tcpdump:

    tcpdump -i <interface> -w </path/to/pcap.pcap>

Once the packet capture is completed, pktrecon can be used to perform reconnaissance against the capture file:

    ./pktrecon.py --pcap <pcapfile>.pcap

# todo

- Active interface capture
- Command generation
