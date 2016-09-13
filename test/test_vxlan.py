#!/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
from framework import VppTestCase, ColoredTextTestRunner
from scapy.all import *


class TestVxlan(VppTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestVxlan, cls).setUpClass()

        cls.create_links(2)

        # Create VXLAN VTEP on pg0, and put pg0 and pg1 in BD
        cls.cli(0, 'create vxlan tunnel src %s dst %s vni 1' %
                (cls.VPP_IP4S[0], cls.MY_IP4S[0]))
        cls.cli(0, 'set interface l2 bridge vxlan_tunnel0 1')
        cls.cli(0, 'set interface l2 bridge pg1 1')

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show ip arp")
        self.cli(2, "show ip fib")
        self.cli(2, "show error")
        self.cli(2, "show run")
        self.cli(2, "show bridge-domain 1 detail")

    def test_decapBD(self):
        pkts = []
        payload = ( Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src='1.2.3.4', dst='4.3.2.1') /
                UDP(sport=10000, dport=20000) / Raw('\x00' * 100))
        p = ( Ether(src=self.MY_MACS[0], dst=self.VPP_MACS[0]) /
                IP(src=self.MY_IP4S[0], dst=self.VPP_IP4S[0]) /
                UDP(sport=4789, dport=4789, chksum=0) /
                '\x08\x00\x00\x00'/'\x00\x00\x01\x00' /
                payload)

        pkts.append(p)
        self.pg_arm(0, 1, pkts)
        self.pg_send()

        out = self.pg_read_output(1)
        self.assertEqual(len(out), 1, 'Invalid number of packets on '
                'output: %u' % len(out))

        pkt = out[0]
        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, payload[Ether].src)
        self.assertEqual(pkt[Ether].dst, payload[Ether].dst)
        self.assertEqual(pkt[IP].src, payload[IP].src)
        self.assertEqual(pkt[IP].dst, payload[IP].dst)
        self.assertEqual(pkt[UDP].sport, payload[UDP].sport)
        self.assertEqual(pkt[UDP].dport, payload[UDP].dport)
        self.assertEqual(pkt[Raw], payload[Raw])

    def test_encapBD(self):
        '''Packet coming from pg1 through BD to VTEP.
        VXLAN encap is expected.
        '''
        pkts = []
        vxlan_header = '\x08\x00\x00\x00' + '\x00\x00\x01\x00'
        payload = ( Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src='1.2.3.4', dst='4.3.2.1') /
                UDP(sport=10000, dport=20000) / Raw('\x00' * 100))
        p = ( Ether(src=self.MY_MACS[0], dst=self.VPP_MACS[0]) /
                IP(src=self.MY_IP4S[0], dst=self.VPP_IP4S[0]) /
                UDP(sport=4789, dport=4789, chksum=0) /
                vxlan_header /
                payload)

        pkts.append(payload)
        self.pg_arm(1, 0, pkts)
        self.pg_send()

        out = self.pg_read_output(0)
        self.assertEqual(len(out), 1, 'Invalid number of packets on '
                'output: %u' % len(out))

        pkt = out[0]
        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, self.VPP_MACS[0])
        self.assertEqual(pkt[Ether].dst, self.MY_MACS[0])
        self.assertEqual(pkt[IP].src, self.VPP_IP4S[0])
        self.assertEqual(pkt[IP].dst, self.MY_IP4S[0])
        self.assertEqual(pkt[UDP].dport, 4789)
        self.assertEqual(str(pkt[Raw]), vxlan_header + str(payload))

if __name__ == '__main__':
    unittest.main(testRunner = ColoredTextTestRunner)
