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

- Host names, MAC addresses, and Domain names
- IPv4 and IPv6 Addresses
- Protocols and Ports
- Windows Operating System Fingerprints and NT Version Numbers

- CDP device names and management IPv4 addresses
- CDP and LLDP Native VLANs and Port IDs
- CDP PoE Power (Power management ID, available power, management power level)
- CDP and LLDP Platform / System Description / Fingerprint

- DHCPv4 Bootstrap Hostname, Client ID, Vendor Class ID
- DHCPv4 Bootstrap Acknowledgement Name Server and Router IPv4 Addresses
- DHCPv4 Bootstrap Acknowledgement Time Zone, Lease Time, Renewal Time, and Rebinding Time
- DHCPv4 Bootstrap Acknowledgement Client FQDN and Subnet Mask


lease_time
broadcast_address
domain
NetBIOS_server


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

- Project screenshots and extended documentation
- Active network interface packet capture
- Domain controller identification
- Cross-network segment host data correlation
