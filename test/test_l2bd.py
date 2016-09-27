#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
import random
from framework import *
from scapy.all import *


class TestL2bd(VppTestCase):
    """ L2BD Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestL2bd, cls).setUpClass()

        try:
            cls.cli(2, "show trace")
            # Create interfaces and sub-interfaces
            cls.create_interfaces_and_subinterfaces()

            # Create BD with MAC learning enabled and put interfaces and
            # sub-interfaces to this BD
            cls.api("bridge_domain_add_del bd_id 1 learn 1" )
            for i in cls.interfaces:
                if isinstance(cls.INT_DETAILS[i], cls.Subint):
                    interface = "pg%u.%u" % (i, cls.INT_DETAILS[i].sub_id)
                else:
                    interface = "pg%u" % i
                cls.api("sw_interface_set_l2_bridge %s bd_id 1" % interface)

            # create 100 MAC entries
            cls.create_mac_entries(100)
            cls.cli(0, "show l2fib")

        except Exception as e:
          super(TestL2bd, cls).tearDownClass()
          raise e

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show l2fib verbose")
        self.cli(2, "show error")
        self.cli(2, "show run")
        self.cli(2, "show bridge-domain 1 detail")

    @classmethod
    def create_vlan_subif(cls, pg_index, vlan):
        cls.api("create_vlan_subif pg%u vlan %u" % (pg_index, vlan))

    @classmethod
    def create_dot1ad_subif(cls, pg_index, sub_id, outer_vlan_id,
                            inner_vlan_id):
        cls.api("create_subif pg%u sub_id %u outer_vlan_id %u inner_vlan_id"
                " %u dot1ad" % (pg_index, sub_id, outer_vlan_id, inner_vlan_id))

    class SoftInt(object):
        pass

    class HardInt(SoftInt):
        pass

    class Subint(SoftInt):
        def __init__(self, sub_id):
            self.sub_id = sub_id

    class Dot1QSubint(Subint):
        def __init__(self, sub_id, vlan=None):
            if vlan is None:
                vlan = sub_id
            super(TestL2bd.Dot1QSubint, self).__init__(sub_id)
            self.vlan = vlan

    class Dot1ADSubint(Subint):
        def __init__(self, sub_id, outer_vlan, inner_vlan):
            super(TestL2bd.Dot1ADSubint, self).__init__(sub_id)
            self.outer_vlan = outer_vlan
            self.inner_vlan = inner_vlan

    @classmethod
    def create_interfaces_and_subinterfaces(cls):
        cls.interfaces = range(3)

        cls.create_interfaces(cls.interfaces)

        # Make vpp_api_test see interfaces created using debug CLI (in function
        # create_interfaces)
        cls.api("sw_interface_dump")

        cls.INT_DETAILS = dict()

        cls.INT_DETAILS[0] = cls.HardInt()

        cls.INT_DETAILS[1] = cls.Dot1QSubint(100)
        cls.create_vlan_subif(1, cls.INT_DETAILS[1].vlan)

        # FIXME: Wrong packet format/wrong layer on output of interface 2
        #self.INT_DETAILS[2] = self.Dot1ADSubint(10, 200, 300)
        #self.create_dot1ad_subif(2, self.INT_DETAILS[2].sub_id, self.INT_DETAILS[2].outer_vlan, self.INT_DETAILS[2].inner_vlan)

        # Use dot1q for now
        cls.INT_DETAILS[2] = cls.Dot1QSubint(200)
        cls.create_vlan_subif(2, cls.INT_DETAILS[2].vlan)

        for i in cls.interfaces:
            det = cls.INT_DETAILS[i]
            if isinstance(det, cls.Subint):
                cls.api("sw_interface_set_flags pg%u.%u admin-up"
                        % (i, det.sub_id))

    # IP addresses and MAC addresses on sub-interfaces
    MY_HOST_IP4S = {}
    MY_HOST_MACS = {}

    @classmethod
    def create_mac_entries(cls, count):
        n_int = len(cls.interfaces)
        macs_per_if = count / n_int
        for i in cls.interfaces:
            start_nr = macs_per_if*i
            end_nr = count if i == (n_int - 1) else macs_per_if*(i+1)
            cls.MY_HOST_MACS[i] = []
            cls.MY_HOST_IP4S[i] = []
            packets = []
            for j in range(start_nr, end_nr):
                my_mac = "00:00:00:ff:%02x:%02x" % (i, j)
                cls.MY_HOST_MACS[i].append(my_mac)
                my_ip4 = "172.17.1%02x.%u" % (i, j)
                cls.MY_HOST_IP4S[i].append(my_ip4)
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) /
                          IP(src=my_ip4, dst="255.255.255.255") /
                          ICMP())
                cls.add_dot1_layers(i, packet)
                packets.append(packet)
            cls.pg_add_stream(i, packets)
        cls.log("Sending broadcast eth frames for MAC learning")
        cls.pg_start()

        # We don't need to read output

    @classmethod
    def add_dot1_layers(cls, i, packet):
        assert(type(packet) is Ether)
        payload = packet.payload
        det = cls.INT_DETAILS[i]
        if isinstance(det, cls.Dot1QSubint):
            packet.remove_payload()
            packet.add_payload(Dot1Q(vlan=det.vlan) / payload)
        elif isinstance(det, cls.Dot1ADSubint):
            packet.remove_payload()
            packet.add_payload(Dot1Q(vlan=det.outer_vlan, type=0x8100) /
                               Dot1Q(vlan=det.inner_vlan) / payload)
            packet.type = 0x88A8

    def remove_dot1_layers(self, i, packet):
        self.assertEqual(type(packet), Ether)
        payload = packet.payload
        det = self.INT_DETAILS[i]
        if isinstance(det, self.Dot1QSubint):
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].vlan)
            payload = payload.payload
        elif isinstance(det, self.Dot1ADSubint):  # TODO: change 88A8 type
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].outer_vlan)
            payload = payload.payload
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].inner_vlan)
            payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)

    def create_stream(self, pg_id):
        pg_targets = [None] * 3
        pg_targets[0] = [1, 2]
        pg_targets[1] = [0, 2]
        pg_targets[2] = [0, 1]
        pkts = []
        for i in range(0, 257):
            target_pg_id = pg_targets[pg_id][i % 2]
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
            self.add_dot1_layers(pg_id, p)
            if not isinstance(self.INT_DETAILS[pg_id], self.Subint):
                packet_sizes = [64, 512, 1518, 9018]
            else:
                packet_sizes = [64, 512, 1518+4, 9018+4]
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
                # Check VLAN tags and Ethernet header
                # TODO: Rework to check VLAN tag(s) and do not remove them
                self.remove_dot1_layers(src_pg, packet)
                self.assertTrue(Dot1Q not in packet)
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

    def test_l2bd(self):
        """ L2BD MAC learning test """

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
