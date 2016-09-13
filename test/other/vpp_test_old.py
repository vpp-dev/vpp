#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import subprocess
import scapy
from scapy.all import *


class VppTest:
    def __init__(self):
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.LPURPLE = '\033[94m'
        self.END = '\033[0m'
        self.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        self.vpp_api_test_bin = os.getenv ("VPP_TEST_API_TEST_BIN", "vpp-api-test")
        try:
            self.verbose = int (os.getenv ("V", 0))
        except:
            self.verbose = 0
        self.vpp = subprocess.Popen([self.vpp_bin, "unix", "nodaemon"], stderr=subprocess.PIPE)

    def test_suite(self, s):
        print self.YELLOW
        print "------------------------------------------------------------------"
        print "-- %-60s --" % (s + " Test Suite")
        print "------------------------------------------------------------------" + self.END

    def test_name(self, s):
        self.testname = s

    def test_ok(self):
        if self.verbose > 0:
            print "------------------------------------------------------------------"
        print ("%-60s %sOK%s"  % (self.testname, self.GREEN, self.END))
        if self.verbose > 0:
            print "------------------------------------------------------------------"

    def test_fail(self):
        if self.verbose > 0:
            print "------------------------------------------------------------------"
        print ("%-60s %sFAIL%s"  % (self.testname, self.RED, self.END))
        if self.verbose > 0:
            print "------------------------------------------------------------------"

    def cli(self, v, s):
        if self.verbose < v:
            return
        p = subprocess.Popen([self.vpp_api_test_bin],stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if self.verbose > 0:
            print "CLI: " + self.RED + s + self.END
        p.stdin.write('exec ' + s);
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if self.verbose > 0:
            if len (out) > 1:
                print self.YELLOW + out + self.END

    def pg_arm(self, i, pkts):
        os.system("rm -f /tmp/pg%u_*.pcap" % i)
        wrpcap("/tmp/pg%u_in.pcap" % i, pkts)
        self.cli(0, "packet-generator new pcap /tmp/pg%u_in.pcap source pg%u name pcap%u" % (i, i, i))
        self.cli(0, "packet-generator capture pg%u pcap /tmp/pg%u_out.pcap" % (i, i))

    def log (self, s):
        if self.verbose > 0:
            print "LOG: " + self.LPURPLE + s + self.END
    def quit (self):
        self.vpp.terminate()

    def __del__ (self):
        self.quit()

if __name__ == "__main__":
    t = VppTest()
    t.test_name("Sample test name")
    t.cli("show version verbose")
    t.test_ok()
    t.test_name("Sample test name 2")
    t.test_fail()
    t.quit()
