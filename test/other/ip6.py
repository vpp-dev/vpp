#!/usr/bin/env python

import os
import scapy
import socket
import ipaddress
from scapy.all import *
from vpp_test_old import *

MY_MACS = []
MY_IP6S = []
VPP_MACS = []
VPP_IP6S = []

num_if = 3

t = VppTest()
t.test_suite("IPv6")

for i in range (0, num_if):
    MY_MACS.append ("00:00:00:00:ff:%02x" % i)
    MY_IP6S.append ("aaaa:ffff:%x::2" % i)
    VPP_IP6S.append ("aaaa:ffff:%x::1" % i)
    t.log("My MAC address is %s, IPv6 address is %s" % (MY_MACS[i], MY_IP6S[i]))
    t.cli(0, "create packet-generator interface pg%u" % i)
    t.cli(0, "set interface state pg%u up" % i)
    t.cli(0, "set interface ip address pg%u %s/64" % (i, VPP_IP6S[i]))

###############################################################################
#  NDP Test
#  This test sends NDP requests to all PG ports, and checks if reply is received
#
###############################################################################

t.test_name("NDP test")
t.cli (0, "clear int")

# Prepare NDP requests for all interfaces
for i in range (0, num_if):
    t.cli(0, "packet-generator capture pg%u disable" % i)
    nsma = in6_getnsma(inet_pton(socket.AF_INET6, VPP_IP6S[i]))
    nd_req = ( Ether(dst=in6_getnsmac(nsma),src=MY_MACS[i]) /
               IPv6(src = "::", dst = inet_ntop(socket.AF_INET6, nsma)) /
               ICMPv6ND_NS(tgt = VPP_IP6S[i])
             )
    t.pg_arm (i, nd_req)

# Start test
t.cli(2, "clear trace")
t.cli(2, "trace add pg-input 3")
t.cli(0, "show packet-generator")
t.cli(0, "packet-generator enable")
t.cli(1, "show int")
t.cli(2, "show trace")
t.cli(1, "show hardware")
t.cli(1, "show ip6 fib")

# Process replies
ok = 0
for i in range (0, num_if):
    ndp_reply = rdpcap("/tmp/pg%u_out.pcap" % i)[0]
    if (ICMPv6ND_NA in ndp_reply and
        ndp_reply[ICMPv6ND_NA].tgt == str(ipaddress.ip_address(bytearray(VPP_IP6S[i])))):
        ok += 1
        VPP_MACS.append(ndp_reply[Ether].src)
        t.log("VPP pg%u MAC address is %s " % ( i, VPP_MACS[i]))

if  ok == num_if:
    t.test_ok()
else:
    t.test_fail()

t.quit()
