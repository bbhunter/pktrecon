# pktrecon

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

Some examples of data which can be obtained strictly from a packet capture using pktrecon includes:

- Host names
- Domain names and FQDNs
- Open ports
- IPv4 addresses
- IPv6 addresses
- Windows operating system fingerprints
- SMB Fingerprints
- Network switch fingerprints
- Cisco device fingerprints

## installation

Just install the required Python dependencies for pktrecon and you're good to go:

    pip install -r requirements.txt

## usage

Using pktrecon is simple. First, passively sniff traffic on a local network segment. An example with tcpdump:

    tcpdump -i <interface> -w </path/to/pcap.pcap>

Once the packet capture is completed, pktrecon can be used to perform reconnaissance against the capture file:

    python ./pktrecon.py --pcap <pcapfile>.pcap

## todo / currently in progress

There is a ton of work to do on pktrecon, and many pieces of it still need to be cleaned up.
I will try to update and maintain pktrecon as often as possible.
Here are just a few of the things currently in progress:

- Active network interface packet capture
- Domain controller identification
- Cross-network segment host data correlation
