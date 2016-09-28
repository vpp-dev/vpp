#!/usr/bin/env python

from framework import *
from template_bd import BridgeDomain
from scapy.layers.inet import IP, UDP
from scapy.contrib.vxlan import VXLAN


class TestVxlan(BridgeDomain, VppTestCase):
    """ VXLAN Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        self.test_decap.__func__.__doc__ = ' Decaps path to BD '
        self.test_encap.__func__.__doc__ = ' Encaps path to BD '
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt):
        return (Ether(src=self.MY_MACS[0], dst=self.VPP_MACS[0]) /
                IP(src=self.MY_IP4S[0], dst=self.VPP_IP4S[0]) /
                UDP(sport=4789, dport=4789, chksum=0) /
                VXLAN(vni=1) /
                pkt)

    def decapsulate(self, pkt):
        return pkt[VXLAN].payload

    def check_encapsulation(self, pkt):
        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, self.VPP_MACS[0])
        self.assertEqual(pkt[Ether].dst, self.MY_MACS[0])
        self.assertEqual(pkt[IP].src, self.VPP_IP4S[0])
        self.assertEqual(pkt[IP].dst, self.MY_IP4S[0])
        self.assertEqual(pkt[UDP].dport, 4789)
        # TODO: checksum check
        self.assertEqual(pkt[VXLAN].vni, 1)

    @classmethod
    def setUpClass(cls):
        super(TestVxlan, cls).setUpClass()

        # Create 2 interfaces
        cls.create_interfaces(range(2))
        # Configure IPv4 addressing on pg0
        cls.config_ip4([0])
        # Send ARP on pg0 interface
        cls.resolve_arp([0])

        # Create VXLAN VTEP on pg0, and put vxlan_tunnel0 and pg1 into BD
        cls.api("vxlan_add_del_tunnel src %s dst %s vni 1" %
                (cls.VPP_IP4S[0], cls.MY_IP4S[0]))
        cls.api("sw_interface_set_l2_bridge vxlan_tunnel0 bd_id 1")
        cls.api("sw_interface_set_l2_bridge pg1 bd_id 1")

    def tearDown(self):
        super(TestVxlan, self).tearDown()
        self.cli(2, "show bridge-domain 1 detail")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
