#!/usr/bin/env python

import vpp_test
import os
import scapy
import socket
import ipaddress
from scapy.all import *
from vpp_test import *

MY_MACS = []
MY_IP4S = []
MY_IP6S = []
VPP_MACS = []
VPP_IP4S = []
VPP_IP6S = []

num_if = 3

t = VppTest()
t.test_suite("IPv4")

for i in range (0, num_if):
    MY_MACS.append ("00:00:00:00:ff:%02x" % i)
    MY_IP4S.append ("172.16.%u.2" % i)
    VPP_IP4S.append ("172.16.%u.1" % i)
    t.log("My MAC address is %s, IPv4 address is %s" % (MY_MACS[i], MY_IP4S[i]))
    t.cli(0, "create packet-generator interface pg%u" % i)
    t.cli(0, "set interface state pg%u up" % i)
    t.cli(0, "set interface ip address pg%u %s/24" % (i, VPP_IP4S[i]))

###############################################################################
# ARP Test
#  This test sends ARP requests to all PG ports, and checks if reply is received
#
###############################################################################

t.test_name("ARP test")

# Prepare ARP requests for all interfaces
for i in range (0, num_if):
    arp_req = ( Ether(dst="ff:ff:ff:ff:ff:ff",src=MY_MACS[i]) /
                ARP(op=ARP.who_has, pdst=VPP_IP4S[i], psrc=MY_IP4S[i], hwsrc=MY_MACS[i]))
    t.pg_arm (i, arp_req)

# Start test
t.cli(2, "trace add pg-input %u" % (num_if * 3))
t.cli(0, "packet-generator enable")
t.cli(1, "show int")
t.cli(2, "show trace")
t.cli(1, "show hardware")
t.cli(1, "show ip arp")
t.cli(1, "show ip fib")
t.cli(1, "show error")

# Process replies
ok = 0
for i in range (0, num_if):
    arp_reply = rdpcap("/tmp/pg%u_out.pcap" % i)[0]
    if  arp_reply[ARP].op == ARP.is_at:
        ok += 1
        VPP_MACS.append(arp_reply[ARP].hwsrc)
        t.log("VPP pg%u MAC address is %s " % ( i, VPP_MACS[i]))

if  ok == num_if:
    t.test_ok()
else:
    t.test_fail()

###############################################################################
# IPv4 UDP Sweep test
#
###############################################################################

t.test_name("IPv4 Sweep Test")

range_first = 64
range_last = 2050

# Prepare ARP requests for all interfaces
for i in range (0, num_if):
    j = i + 1
    if j == num_if:
        j = 0
    pkts = []
    for n in range (range_first, range_last+1):
        p = ( Ether(dst=VPP_MACS[i],src=MY_MACS[i]) /
              IP(src=MY_IP4S[i], dst=MY_IP4S[j]) /
              UDP(sport=int(10000+n),dport=int(10000+n)) /
              Raw('\x00' * (n-42)))
        pkts.append(p)
    t.pg_arm (i, pkts)

# Start test
t.cli(2, "trace add pg-input %u" % (num_if * 3))
t.cli(0, "packet-generator enable")
t.cli(1, "show int")
t.cli(2, "show trace")
t.cli(1, "show hardware")
t.cli(1, "show ip arp")
t.cli(1, "show ip fib")
t.cli(1, "show error")
t.cli(1, "show run")

# Process replies
fail = False
for i in range (0, num_if):
    pkts = rdpcap("/tmp/pg%u_out.pcap" % i)
    failed_sizes = []
    last_found = 0
    for n in range (range_first, range_last + 1):
        found = False
        for j in range(last_found, len(pkts)):
            p = pkts[j]
            if IP in p and p[IP].len + 14 == n: # More checks.... (src ip, dst ip, port)
                found = True
                last_found = j
                break
        if not found:
            fail = True
            failed_sizes.append(n)
    if failed_sizes:
        t.log("pg%u lengths %s not OK" % (i, str(failed_sizes)))

if fail:
    t.test_fail()
else:
    t.test_ok()

t.quit()
