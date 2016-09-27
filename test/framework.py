#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import subprocess
import unittest
from inspect import *

from scapy.utils import wrpcap, rdpcap
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
LPURPLE = '\033[94m'
END = '\033[0m'


class VppTestCase(unittest.TestCase):
    @classmethod
    def setUpConstants(cls):
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.vpp_api_test_bin = os.getenv("VPP_TEST_API_TEST_BIN", "vpp-api-test")
        cls.vpp_cmdline = [cls.vpp_bin, "unix", "nodaemon", "api-segment", "{", "prefix", "unittest", "}"]
        cls.vpp_api_test_cmdline = [cls.vpp_api_test_bin, "chroot", "prefix", "unittest"]
        try:
            cls.verbose = int(os.getenv("V", 0))
        except:
            cls.verbose = 0

    @classmethod
    def setUpClass(cls):
        cls.setUpConstants()
        cls.pg_streams = []
        cls.MY_MACS = {}
        cls.MY_IP4S = {}
        cls.MY_IP6S = {}
        cls.VPP_MACS = {}
        cls.VPP_IP4S = {}
        cls.VPP_IP6S = {}
        cls.packet_infos = {}
        print "=================================================================="
        print YELLOW + getdoc(cls) + END
        print "=================================================================="
        os.system("rm -f /dev/shm/unittest-global_vm")
        os.system("rm -f /dev/shm/unittest-vpe-api")
        os.system("rm -f /dev/shm/unittest-db")
        cls.vpp = subprocess.Popen(cls.vpp_cmdline, stderr=subprocess.PIPE)

    @classmethod
    def quit(cls):
        cls.vpp.terminate()
        cls.vpp = None
        os.system("rm -f /dev/shm/unittest-global_vm")
        os.system("rm -f /dev/shm/unittest-vpe-api")
        os.system("rm -f /dev/shm/unittest-db")

    @classmethod
    def tearDownClass(cls):
        cls.quit()

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show ip arp")
        self.cli(2, "show ip fib")
        self.cli(2, "show error")
        self.cli(2, "show run")

    def setUp(self):
        self.cli(2, "clear trace")

    @classmethod
    def log(cls, s, v=1):
        if cls.verbose >= v:
            print "LOG: " + LPURPLE + s + END

    @classmethod
    def api(cls, s):
        p = subprocess.Popen(cls.vpp_api_test_cmdline,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "API: " + RED + s + END
        p.stdin.write(s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len(out) > 1:
                print YELLOW + out + END

    @classmethod
    def cli(cls, v, s):
        if cls.verbose < v:
            return
        p = subprocess.Popen(cls.vpp_api_test_cmdline,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "CLI: " + RED + s + END
        p.stdin.write('exec ' + s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len(out) > 1:
                print YELLOW + out + END

    @classmethod
    def pg_add_stream(cls, i, pkts):
        os.system("sudo rm -f /tmp/pg%u_in.pcap" % i)
        wrpcap("/tmp/pg%u_in.pcap" % i, pkts)
        # no equivalent API command
        cls.cli(0, "packet-generator new pcap /tmp/pg%u_in.pcap source pg%u name pcap%u" % (i, i, i))
        cls.pg_streams.append('pcap%u' % i)

    @classmethod
    def pg_enable_capture(cls, args):
        for i in args:
            os.system("sudo rm -f /tmp/pg%u_out.pcap" % i)
            # cls.api("pg_capture if_id %u pcap /tmp/pg%u_out.pcap count <nnn>" % (i, i))
            cls.cli(0, "packet-generator capture pg%u pcap /tmp/pg%u_out.pcap" % (i, i))

    @classmethod
    def pg_start(cls):
        cls.cli(2, "trace add pg-input 50")  # 50 is maximum
        # cls.api("pg_enable_disable")
        cls.cli(0, 'packet-generator enable')
        for stream in cls.pg_streams:
            # cls.api("pg_enable_disable stream %s disable" % stream)
            cls.cli(0, 'packet-generator delete %s' % stream)
        cls.pg_streams = []

    @classmethod
    def pg_get_capture(cls, o):
        pcap_filename = "/tmp/pg%u_out.pcap" % o
        try:
            output = rdpcap(pcap_filename)
        except IOError:  # TODO
            cls.log("WARNING: File %s does not exist, probably because no packets arrived" % pcap_filename)
            return []
        return output

    @classmethod
    def resolve_arp(cls, args):
        for i in args:
            ip = cls.VPP_IP4S[i]
            cls.log("Sending ARP request for %s on port %u" % (ip, i))
            arp_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]) /
                       ARP(op=ARP.who_has, pdst=ip,
                           psrc=cls.MY_IP4S[i], hwsrc=cls.MY_MACS[i]))
            cls.pg_add_stream(i, arp_req)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()
            arp_reply = cls.pg_get_capture(i)[0]
            if arp_reply[ARP].op == ARP.is_at:
                cls.log("VPP pg%u MAC address is %s " % (i, arp_reply[ARP].hwsrc))
                cls.VPP_MACS[i] = arp_reply[ARP].hwsrc
            else:
                cls.log("No ARP received on port %u" % i)
            cls.cli(2, "show trace")

    @classmethod
    def resolve_icmpv6_nd(cls, args):
        for i in args:
            ip = cls.VPP_IP6S[i]
            cls.log("Sending ICMPv6ND_NS request for %s on port %u" % (ip, i))
            nd_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]) /
                      IPv6(src=cls.MY_IP6S[i], dst=ip) /
                      ICMPv6ND_NS(tgt=ip) /
                      ICMPv6NDOptSrcLLAddr(lladdr=cls.MY_MACS[i]))
            cls.pg_add_stream(i, nd_req)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()
            nd_reply = cls.pg_get_capture(i)[0]
            icmpv6_na = nd_reply['ICMPv6 Neighbor Discovery - Neighbor Advertisement']
            dst_ll_addr = icmpv6_na['ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address']
            cls.VPP_MACS[i] = dst_ll_addr.lladdr

    @classmethod
    def config_ip4(cls, args):
        for i in args:
            cls.MY_IP4S[i] = "172.16.%u.2" % i
            cls.VPP_IP4S[i] = "172.16.%u.1" % i
            cls.api("sw_interface_add_del_address pg%u %s/24" % (i, cls.VPP_IP4S[i]))
            cls.log("My IPv4 address is %s" % (cls.MY_IP4S[i]))

    @classmethod
    def config_ip6(cls, args):
        for i in args:
            cls.MY_IP6S[i] = "fd00:%u::2" % i
            cls.VPP_IP6S[i] = "fd00:%u::1" % i
            cls.api("sw_interface_add_del_address pg%u %s/32" % (i, cls.VPP_IP6S[i]))
            cls.log("My IPv6 address is %s" % (cls.MY_IP6S[i]))

    @classmethod
    def create_interfaces(cls, args):
        for i in args:
            cls.MY_MACS[i] = "02:00:00:00:ff:%02x" % i
            cls.log("My MAC address is %s" % (cls.MY_MACS[i]))
            cls.api("pg_create_interface if_id %u" % i)
            cls.api("sw_interface_set_flags pg%u admin-up" % i)

    # Extend packet to specified size (including Ethernet FCS)
    # Currently works only when Raw layer is present
    @staticmethod
    def extend_packet(packet, size):
        packet_len = len(packet) + 4  # current packet length including Ethernet FCS
        extend = size - packet_len
        if extend > 0:
            packet[Raw].load += ' ' * extend

    class PacketInfo(object):
        index = -1
        src = -1
        dst = -1
        data = None

    def add_packet_info_to_list(self, info):
        info.index = len(self.packet_infos)
        self.packet_infos[info.index] = info

    def create_packet_info(self, pg_id, target_id):
        info = self.PacketInfo()
        self.add_packet_info_to_list(info)
        info.src = pg_id
        info.dst = target_id
        return info

    @staticmethod
    def info_to_payload(info):
        return "%d %d %d" % (info.index, info.src, info.dst)

    @staticmethod
    def payload_to_info(payload):
        numbers = payload.split()
        info = VppTestCase.PacketInfo()
        info.index = int(numbers[0])
        info.src = int(numbers[1])
        info.dst = int(numbers[2])
        return info

    def get_next_packet_info(self, info):
        if info is None:
            next_index = 0
        else:
            next_index = info.index + 1
        if next_index == len(self.packet_infos):
            return None
        else:
            return self.packet_infos[next_index]

    def get_next_packet_info_for_interface(self, src_pg, info):
        while True:
            info = self.get_next_packet_info(info)
            if info is None:
                return None
            if info.src == src_pg:
                return info

    def get_next_packet_info_for_interface2(self, src_pg, dst_pg, info):
        while True:
            info = self.get_next_packet_info_for_interface(src_pg, info)
            if info is None:
                return None
            if info.dst == dst_pg:
                return info


class VppTestResult(unittest.TestResult):
    def __init__(self, stream, descriptions, verbosity):
        unittest.TestResult.__init__(self, stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.result_string = None

    def addSuccess(self, test):
        unittest.TestResult.addSuccess(self, test)
        self.result_string = GREEN + "OK" + END

    def addFailure(self, test, err):
        unittest.TestResult.addFailure(self, test, err)
        self.result_string = RED + "FAIL" + END

    def addError(self, test, err):
        unittest.TestResult.addError(self, test, err)
        self.result_string = RED + "ERROR" + END

    def getDescription(self, test):
        short_description = test.shortDescription()
        if self.descriptions and short_description:
            return short_description
        else:
            return str(test)

    def startTest(self, test):
        unittest.TestResult.startTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln("Starting " + self.getDescription(test) + " ...")
            self.stream.writeln("------------------------------------------------------------------")

    def stopTest(self, test):
        unittest.TestResult.stopTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln("------------------------------------------------------------------")
            self.stream.writeln("%-60s%s" % (self.getDescription(test), self.result_string))
            self.stream.writeln("------------------------------------------------------------------")
        else:
            self.stream.writeln("%-60s%s" % (self.getDescription(test), self.result_string))

    def printErrors(self):
        self.stream.writeln()
        self.printErrorList('ERROR', self.errors)
        self.printErrorList('FAIL', self.failures)

    def printErrorList(self, flavour, errors):
        for test, err in errors:
            self.stream.writeln('=' * 70)
            self.stream.writeln("%s: %s" % (flavour, self.getDescription(test)))
            self.stream.writeln('-' * 70)
            self.stream.writeln("%s" % err)


class VppTestRunner(unittest.TextTestRunner):
    resultclass = VppTestResult

    def run(self, test):
        print "Running tests using custom test runner"  # debug message
        return super(VppTestRunner, self).run(test)
