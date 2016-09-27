#!/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
import random
from framework import *
from scapy.all import *


class TestL2xc(VppTestCase):
    """ L2XC Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestL2xc, cls).setUpClass()

        try:
            cls.cli(2, "show trace")

            # Create four interfaces
            cls.interfaces = range(4)
            cls.create_interfaces(cls.interfaces)

            # Create bi-directional cross-connects between pg0 and pg1
            cls.api("sw_interface_set_l2_xconnect rx pg0 tx pg1 enable")
            cls.api("sw_interface_set_l2_xconnect rx pg1 tx pg0 enable")

            # Create bi-directional cross-connects between pg2 and pg3
            cls.api("sw_interface_set_l2_xconnect rx pg2 tx pg3 enable")
            cls.api("sw_interface_set_l2_xconnect rx pg3 tx pg2 enable")

            cls.cli(0, "show l2patch")

            # Create host lists - by default 10 hosts per interface
            cls.create_host_lists()

        except Exception as e:
          super(TestL2xc, cls).tearDownClass()
          raise e

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show l2patch")
        self.cli(2, "show error")
        self.cli(2, "show run")

    # IP addresses and MAC addresses of hosts
    MY_HOST_IP4S = {}
    MY_HOST_MACS = {}

    @classmethod
    def create_host_lists(cls, count=10):
        for i in cls.interfaces:
            cls.MY_HOST_MACS[i] = []
            cls.MY_HOST_IP4S[i] = []
            for j in range(0, count):
                my_mac = "00:00:00:ff:%02x:%02x" % (i, j)
                cls.MY_HOST_MACS[i].append(my_mac)
                my_ip4 = "172.17.1%02x.%u" % (i, j)
                cls.MY_HOST_IP4S[i].append(my_ip4)

    def create_stream(self, pg_id):
        pg_targets = [None] * 4
        pg_targets[0] = [1]
        pg_targets[1] = [0]
        pg_targets[2] = [3]
        pg_targets[3] = [2]
        pkts = []
        for i in range(0, 257):
            target_pg_id = pg_targets[pg_id][0]
            target_id = random.randrange(len(self.MY_HOST_MACS[target_pg_id]))
            source_id = random.randrange(len(self.MY_HOST_MACS[pg_id]))
            info = self.create_packet_info(pg_id, target_pg_id)
            payload = self.info_to_payload(info)
            p = (Ether(dst=self.MY_HOST_MACS[target_pg_id][target_id],
                       src=self.MY_HOST_MACS[pg_id][source_id]) /
                 IP(src=self.MY_HOST_IP4S[pg_id][source_id],
                    dst=self.MY_HOST_IP4S[target_pg_id][target_id]) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            packet_sizes = [64, 512, 1518, 9018]
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, o, capture):
        last_info = {}
        for i in self.interfaces:
            last_info[i] = None
        for packet in capture:
            try:
                self.log("Processing packet:", 2)
                if self.verbose >= 2:
                    packet.show()
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                src_pg = payload_info.src
                dst_pg = payload_info.dst
                self.assertEqual(dst_pg, o)
                self.log("Got packet on port %u: src=%u (id=%u)"
                         % (o, src_pg, packet_index), 1)
                next_info = self.get_next_packet_info_for_interface2(src_pg, dst_pg, last_info[src_pg])
                last_info[src_pg] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.log("Unexpected or invalid packet:")
                packet.show()
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(i, o, last_info[i])
            self.assertTrue(remaining_packet is None,
                            "Port %u: Packet expected from source %u didn't"
                            " arrive" % (o, i))

    def test_l2xc(self):
        """ L2XC test """

        for i in self.interfaces:
            pkts = self.create_stream(i)
            self.pg_add_stream(i, pkts)

        self.pg_enable_capture(self.interfaces)
        self.pg_start()

        for i in self.interfaces:
            out = self.pg_get_capture(i)
            self.log("Verifying capture %u" % i)
            self.verify_capture(i, out)


if __name__ == '__main__':
    unittest.main(testRunner = VppTestRunner)
