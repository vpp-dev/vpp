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
        try:
            cls.verbose = int(os.getenv("V", 0))
        except:
            cls.verbose = 0

    @classmethod
    def setUpClass(cls):
        cls.setUpConstants()
        cls.pg_streams = []
        cls.MY_MACS = []
        cls.MY_IP4S = []
        cls.MY_IP6S = []
        cls.VPP_MACS = []
        cls.VPP_IP4S = []
        cls.VPP_IP6S = []
        print "=================================================================="
        print cls.YELLOW + getdoc(cls) + cls.END
        print "=================================================================="
        cls.vpp = subprocess.Popen([cls.vpp_bin, "unix", "nodaemon"], stderr=subprocess.PIPE)

    @classmethod
    def quit(cls):
        cls.vpp.terminate()

    @classmethod
    def tearDownClass(cls):
        cls.quit()

    @classmethod
    def log(cls, s):
        if cls.verbose > 0:
            print "LOG: " + cls.LPURPLE + s + cls.END

    @classmethod
    def cli(cls, v, s):
        if cls.verbose < v:
            return
        p = subprocess.Popen([cls.vpp_api_test_bin],stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "CLI: " + cls.RED + s + cls.END
        p.stdin.write('exec ' + s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len (out) > 1:
                print cls.YELLOW + out + cls.END

    @classmethod  # TODO
    def pg_arm(self, i, o, pkts):
        os.system("sudo rm -f /tmp/pg%u_*.pcap" % i)
        os.system("sudo rm -f /tmp/pg%u_*.pcap" % o)
        wrpcap("/tmp/pg%u_in.pcap" % i, pkts)
        self.cli(0, "packet-generator new pcap /tmp/pg%u_in.pcap source pg%u name pcap%u" % (i, i, i))
        self.cli(0, "packet-generator capture pg%u pcap /tmp/pg%u_out.pcap" % (o, o))
        self.pg_streams.append('pcap%u' % i)

    @classmethod  # TODO
    def pg_send(self):
        self.cli(0, 'packet-generator enable')
        for stream in self.pg_streams:
            self.cli(0, 'packet-generator delete %s' % stream)
        self.pg_streams = []

    @classmethod # TODO
    def pg_read_output(self, o):
        output = rdpcap("/tmp/pg%u_out.pcap" % o)
        return output

    @classmethod
    def create_links(cls, num_if):
        for i in range (0, num_if):
            cls.MY_MACS.append("00:00:00:00:ff:%02x" % i)
            cls.MY_IP4S.append("172.16.%u.2" % i)
            cls.VPP_IP4S.append("172.16.%u.1" % i)
            cls.log("My MAC address is %s, IPv4 address is %s" %
                    (cls.MY_MACS[i], cls.MY_IP4S[i]))
            cls.cli(0, "create packet-generator interface pg%u" % i)
            cls.cli(0, "set interface state pg%u up" % i)
            cls.cli(0, "set interface ip address pg%u %s/24" %
                    (i, cls.VPP_IP4S[i]))

        ###############################################################################
        # Populate ARP table
        #
        ###############################################################################

        # Prepare ARP requests for all interfaces
        for i in range (0, num_if):
            arp_req = ( Ether(dst="ff:ff:ff:ff:ff:ff",src=cls.MY_MACS[i]) /
                        ARP(op=ARP.who_has, pdst=cls.VPP_IP4S[i],
                            psrc=cls.MY_IP4S[i], hwsrc=cls.MY_MACS[i]))
            cls.pg_arm(i, i, arp_req)

        cls.cli(2, "trace add pg-input %u" % (num_if * 3))
        cls.pg_send()
        cls.cli(2, "show int")
        cls.cli(2, "show trace")
        cls.cli(2, "show hardware")
        cls.cli(2, "show ip arp")
        cls.cli(2, "show ip fib")
        cls.cli(2, "show error")

        # Process replies, store VPP's MAC addresses
        ok = 0
        for i in range (0, num_if):
            arp_reply = rdpcap("/tmp/pg%u_out.pcap" % i)[0]
            if  arp_reply[ARP].op == ARP.is_at:
                ok += 1
                cls.VPP_MACS.append(arp_reply[ARP].hwsrc)
                cls.log("VPP pg%u MAC address is %s " % ( i, cls.VPP_MACS[i]))

        if  ok != num_if:
            raise RuntimeError('Number of ARP responses does not equal '
                               'ARP requests')


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
            self.stream.writeln(self.getDescription(test))

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
