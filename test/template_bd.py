#!/usr/bin/env python

from abc import abstractmethod

from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP


class BridgeDomain(object):
    def __init__(self):
        self.payload_0_1 = (
            Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
            IP(src='1.2.3.4', dst='4.3.2.1') /
            UDP(sport=10000, dport=20000) /
            Raw('\xa5' * 100))

        self.payload_1_0 = (
            Ether(src='00:00:00:00:00:02', dst='00:00:00:00:00:01') /
            IP(src='4.3.2.1', dst='1.2.3.4') /
            UDP(sport=20000, dport=10000) /
            Raw('\xa5' * 100))

    @abstractmethod
    def encapsulate(self, pkt):
        pass

    @abstractmethod
    def decapsulate(self, pkt):
        pass

    @abstractmethod
    def check_encapsulation(self, pkt):
        pass

    def test_decap(self):
        pkt_to_send = self.encapsulate(self.payload_0_1)

        # Add packet to list of packets
        self.pg_add_stream(0, [pkt_to_send, ])

        # Enable Packet Capture on both ports
        self.pg_enable_capture([0, 1])

        # Start all streams
        self.pg_start()

        out = self.pg_get_capture(1)
        self.assertEqual(len(out), 1,
                         'Invalid number of packets on '
                         'output: {}'.format(len(out)))

        pkt = out[0]
        # TODO: add error messages
        self.assertEqual(pkt[Ether].src, self.payload_0_1[Ether].src)
        self.assertEqual(pkt[Ether].dst, self.payload_0_1[Ether].dst)
        self.assertEqual(pkt[IP].src, self.payload_0_1[IP].src)
        self.assertEqual(pkt[IP].dst, self.payload_0_1[IP].dst)
        self.assertEqual(pkt[UDP].sport, self.payload_0_1[UDP].sport)
        self.assertEqual(pkt[UDP].dport, self.payload_0_1[UDP].dport)
        self.assertEqual(pkt[Raw], self.payload_0_1[Raw])

    def test_encap(self):
        # Create packet generator stream
        self.pg_add_stream(1, [self.payload_1_0])

        # Enable Packet Capture on both ports
        self.pg_enable_capture([0, 1])

        # Start all streams
        self.pg_start()

        out = self.pg_get_capture(0)
        self.assertEqual(len(out), 1,
                         'Invalid number of packets on '
                         'output: {}'.format(len(out)))

        rcvd = out[0]

        self.check_encapsulation(rcvd)
        rcvd_payload = self.decapsulate(rcvd)

        # TODO: add error messages
        self.assertEqual(rcvd_payload[Ether].src, self.payload_1_0[Ether].src)
        self.assertEqual(rcvd_payload[Ether].dst, self.payload_1_0[Ether].dst)
        self.assertEqual(rcvd_payload[IP].src, self.payload_1_0[IP].src)
        self.assertEqual(rcvd_payload[IP].dst, self.payload_1_0[IP].dst)
        self.assertEqual(rcvd_payload[UDP].sport, self.payload_1_0[UDP].sport)
        self.assertEqual(rcvd_payload[UDP].dport, self.payload_1_0[UDP].dport)
        self.assertEqual(rcvd_payload[Raw], self.payload_1_0[Raw])
