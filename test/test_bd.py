#!/usr/bin/env python

from framework import *
from template_bd import BridgeDomain


class TestBridgeDomain(BridgeDomain, VppTestCase):
    """ BD Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        self.test_decap.__func__.__doc__ = ' Forward ethernet frames '
        self.test_encap.__func__.__doc__ = (' Forward ethernet frames '
                                            'opposite direction ')
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt):
        return pkt

    def decapsulate(self, pkt):
        return pkt

    def check_encapsulation(self, pkt):
        pass

    @classmethod
    def setUpClass(cls):
        super(TestBridgeDomain, cls).setUpClass()

        # Create 2 interfaces
        cls.create_interfaces(range(2))

        # Put pg0 and pg1 into BD
        cls.api("sw_interface_set_l2_bridge pg0 bd_id 1")
        cls.api("sw_interface_set_l2_bridge pg1 bd_id 1")

    def tearDown(self):
        super(TestBridgeDomain, self).tearDown()
        self.cli(2, "show bridge-domain 1 detail")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
