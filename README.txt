mdns-repeater
==============
mdns-repeater is a Multicast DNS repeater for Linux. Multicast DNS uses the
224.0.0.251 address, which is "administratively scoped" and does not
leave the subnet.

This program re-broadcast mDNS packets from one interface to other interfaces.
It was written primarily to be run on my Linksys WRT54G which runs dd-wrt,
since my wireless network is on a different subnet from my wired network and
I would like my zeroconf devices to work properly across the two subnets.

Since the mDNS protocol sends the AA records in the packet itself, the
repeater does not need to forge the source address. Instead, the source
address is of the interface that repeats the packet.


USAGE
-----
mdns-repeater only requires the interface names and it will do the rest.
For example, the dd-wrt standard installation defines br0 for the wireless
interface and vlan1 as the WAN interface, I would use:

    mdns-repeater br0 vlan1

You can also specify the -f flag for debugging, which prints packets as they
are received.


QUERY-ONLY MODE (-Q)
--------------------
The -Q flag enables directional mDNS filtering, useful for setups where
personal and IoT devices are on separate VLANs and you want IoT devices to
be discoverable from personal networks without exposing personal device
services to IoT networks.

    mdns-repeater -Q <personal-iface> <iot-iface> [<iot-iface> ...]

The first interface is treated as the personal/query network. Filtering rules:

  - Personal → IoT : only DNS queries (QR=0) are forwarded;
                     announcements are suppressed
  - IoT → Personal : only announcements (QR=1) are forwarded;
                     queries from IoT to personal are suppressed
  - IoT ↔ IoT      : fully bidirectional, no restrictions

Example for a home lab with personal VLAN on eth1 and IoT VLANs on eth0/eth3:

    mdns-repeater -Q eth1 eth0 eth3

FLAGS
-----
  -f    Run in foreground for debugging; prints packets as they are received
  -Q    Enable query-only mode; first interface is the personal/query network
  -b    Blacklist a subnet (e.g. 192.168.1.0/24)
  -w    Whitelist a subnet (e.g. 192.168.1.0/24)
  -p    Specify pid file path (default: /var/run/mdns-repeater.pid)
  -u    Run as specified user
