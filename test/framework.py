#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import sys
import time
import subprocess
from scapy.all import Ether, ARP, wrpcap, rdpcap
import unittest
from inspect import *


class VppTestCase(unittest.TestCase):
    @classmethod
    def setUpConstants(cls):
        cls.RED = '\033[91m'
        cls.GREEN = '\033[92m'
        cls.YELLOW = '\033[93m'
        cls.LPURPLE = '\033[94m'
        cls.END = '\033[0m'
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.vpp_api_test_bin = os.getenv ("VPP_TEST_API_TEST_BIN", "vpp-api-test")
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
        print "=================================================================="
        print cls.YELLOW + getdoc(cls) + cls.END
        print "=================================================================="
        os.system("sudo rm -f /dev/shm/unittest-global_vm")
        os.system("sudo rm -f /dev/shm/unittest-vpe-api")
        os.system("sudo rm -f /dev/shm/unittest-db")
        cls.vpp = subprocess.Popen(cls.vpp_cmdline, stderr=subprocess.PIPE)

    @classmethod
    def quit(cls):
        cls.vpp.terminate()
        os.system("sudo rm -f /dev/shm/unittest-global_vm")
        os.system("sudo rm -f /dev/shm/unittest-vpe-api")
        os.system("sudo rm -f /dev/shm/unittest-db")

    @classmethod
    def tearDownClass(cls):
        cls.quit()

    @classmethod
    def log(cls, s, v=1):
        if cls.verbose >= v:
            print "LOG: " + cls.LPURPLE + s + cls.END

    @classmethod
    def api(cls, s):
        p = subprocess.Popen(cls.vpp_api_test_cmdline,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "API: " + cls.RED + s + cls.END
        p.stdin.write(s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len (out) > 1:
                print cls.YELLOW + out + cls.END

    @classmethod
    def cli(cls, v, s):
        if cls.verbose < v:
            return
        p = subprocess.Popen(cls.vpp_api_test_cmdline,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "CLI: " + cls.RED + s + cls.END
        p.stdin.write('exec ' + s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len (out) > 1:
                print cls.YELLOW + out + cls.END

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
            arp_req = ( Ether(dst="ff:ff:ff:ff:ff:ff",src=cls.MY_MACS[i]) /
                        ARP(op=ARP.who_has, pdst=ip,
                            psrc=cls.MY_IP4S[i], hwsrc=cls.MY_MACS[i]))
            cls.pg_add_stream(i, arp_req)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()
            arp_reply = cls.pg_get_capture(i)[0]
            if arp_reply[ARP].op == ARP.is_at:
                cls.log("VPP pg%u MAC address is %s " % ( i, arp_reply[ARP].hwsrc))
                cls.VPP_MACS[i] = arp_reply[ARP].hwsrc
            else:
                cls.log("No ARP received on port %u" % i)

    @classmethod
    def config_ip4(cls, args):
        for i in args:
            cls.MY_IP4S[i] = "172.16.%u.2" % i
            cls.VPP_IP4S[i] = "172.16.%u.1" % i
            cls.api("sw_interface_add_del_address pg%u %s/24" % (i, cls.VPP_IP4S[i]))
            cls.log("My IPv4 address is %s" % (cls.MY_IP4S[i]))

    @classmethod
    def create_interfaces(cls, args):
        for i in args:
            cls.MY_MACS[i] = "00:00:00:00:ff:%02x" % i
            cls.log("My MAC address is %s" % (cls.MY_MACS[i]))
            cls.api("pg_create_interface if_id %u" % i)
            cls.api("sw_interface_set_flags pg%u admin-up" % i)

    class PacketInfo:
        def __init__(self):
            pass
        index = -1
        src = -1
        dst = -1
        data = None

    packet_infos = {}

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
    RED = '\033[91m'
    GREEN = '\033[92m'
    END = '\033[0m'

    def __init__(self, stream, descriptions, verbosity):
        unittest.TestResult.__init__(self, stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity

    def addSuccess(self, test):
        unittest.TestResult.addSuccess(self, test)
        self.result_string = self.GREEN + "OK" + self.END

    def addFailure(self, test, err):
        unittest.TestResult.addFailure(self, test, err)
        self.result_string = self.RED + "FAIL" + self.END

    def addError(self, test, err):
        unittest.TestResult.addError(self, test, err)
        self.result_string = self.RED + "ERROR" + self.END

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
        print "Running tests using custom test runner" # debug message
        return super(VppTestRunner, self).run(test)
