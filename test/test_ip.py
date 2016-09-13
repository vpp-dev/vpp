#!/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
from framework import *
from scapy.all import *


class TestIPv4(VppTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestIPv4, cls).setUpClass()

        cls.num_ifs = 3
        cls.create_links(cls.num_ifs)

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show ip arp")
        self.cli(2, "show ip fib")
        self.cli(2, "show error")
        self.cli(2, "show run")
        self.cli(2, "show bridge-domain 1 detail")

    def test_sweep(self):
        """ UDP Sweep Test """
        # Test disabled
        return
        num_if = TestIPv4.num_ifs
        pkts = []
        range_first = 64
        range_last = 2050

        for i in range (0, num_if):
            j = i + 1
            if j == num_if:
                j = 0
            pkts = []
            for n in range (range_first, range_last+1):
                p = ( Ether(dst=self.VPP_MACS[i],src=self.MY_MACS[i]) /
                      IP(src=self.MY_IP4S[i], dst=self.MY_IP4S[j]) /
                      UDP(sport=int(10000+n),dport=int(10000+n)) /
                      Raw('\x00' * (n-42)))
                pkts.append(p)
            self.pg_arm (i, i, pkts)


        # Start test
        self.cli(2, "trace add pg-input %u" % (num_if * 3))
        self.pg_send()
        self.cli(1, "show int")
        self.cli(2, "show trace")
        self.cli(1, "show hardware")
        self.cli(1, "show ip arp")
        self.cli(1, "show ip fib")
        self.cli(1, "show error")
        self.cli(1, "show run")

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
                self.log("pg%u lengths %s not OK" % (i, str(failed_sizes)))

        self.failIf(fail == True)


if __name__ == '__main__':
    unittest.main(testRunner = VppTestRunner)
