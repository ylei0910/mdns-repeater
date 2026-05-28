mdns-repeater
==============
mdns-repeater is a Multicast DNS repeater for Linux. Multicast DNS uses the
224.0.0.251 address, which is "administratively scoped" and does not
leave the subnet.

This program re-broadcasts mDNS packets between interfaces. It resolves
subnets to interfaces at startup via getifaddrs(), so rules are expressed
as subnet CIDR ranges rather than interface names.


USAGE
-----
mdns-repeater requires a rules file specifying how subnets are connected:

    mdns-repeater -r <rules_file>

Each line in the rules file defines one routing group:

    <personal_subnet>:<dest_subnet> [<dest_subnet> ...]

The subnet before the colon is the personal/query-only (Q) network.
All subnets in the same rule can reach each other, but are isolated from
subnets in other rules.

Example rules.conf:
    192.168.53.0/24:10.107.0.0/16 10.108.0.0/16
    192.168.54.0/24:10.107.0.0/16 10.109.0.0/16


QUERY-ONLY FILTERING
--------------------
The personal subnet (before the colon) automatically gets directional
filtering. This keeps IoT devices discoverable from personal networks
without exposing personal device services to IoT networks.

  - Personal → IoT : only DNS queries (QR=0) are forwarded;
                     announcements are suppressed
  - IoT → Personal : only announcements (QR=1) are forwarded;
                     queries from IoT to personal are suppressed
  - IoT ↔ IoT      : fully bidirectional, no restrictions


SERVICE FILTER
--------------
To limit repeating to specific service types, pass a services file with
one mDNS service suffix per line (# comments and blank lines supported):

    mdns-repeater -r rules.conf -S services.conf

Example services.conf:
    _hap._tcp.local
    _googlecast._tcp.local
    _airplay._tcp.local


DEBUG LOG
---------
To log which names are forwarded or skipped:

    mdns-repeater -r rules.conf -d /var/log/mdns-repeater/seen.log

Log format (one unique entry per src+name+decision triplet):

    <src_ip> <name> -> <dest_subnet> [<dest_subnet> ...]
    <src_ip> <name> SKIP:Q         (announcement suppressed from Q iface)
    <src_ip> <name> SKIP:service   (name not in services filter)


FLAGS
-----
  -r    Rules file (required)
  -S    Service filter file (one suffix per line, # comments supported)
  -d    Debug log file (deduped; append-only)
  -b    Blacklist a source subnet (e.g. 192.168.1.0/24)
  -w    Whitelist a source subnet (e.g. 192.168.1.0/24)
  -u    Run as specified user


PROCESS MANAGEMENT
------------------
mdns-repeater always runs in foreground mode. Use a process supervisor
such as OpenRC (with command_background=yes) or systemd to manage it:

    # OpenRC /etc/init.d/mdns-repeater
    command=/usr/local/bin/mdns-repeater
    command_args="-r /etc/mdns-repeater/rules.conf"
    command_background=yes
    pidfile=/var/run/mdns-repeater.pid
