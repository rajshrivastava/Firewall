#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 13 13:31:56 2020
@author: rajkumarshrivastava
"""

import unittest
from unittest import TestCase
import firewall

class TestFirewall(TestCase):

    def testFirewall(self):
        fw = firewall.Firewall('firewallRules.csv')
        #common cases
        self.assertTrue(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
        self.assertTrue(not fw.accept_packet("inbound", "tcp", 8, "192.168.1.2"))
        self.assertTrue(fw.accept_packet("outbound", "udp", 12, "192.192.19.192"))
        self.assertTrue(fw.accept_packet("outbound", "tcp", 13054, "192.168.10.11"))
        self.assertTrue(not fw.accept_packet("outbound", "tcp", 13, "192.192.192.192"))

        #testing for wrongly ordered set of parameters
        self.assertTrue(not fw.accept_packet("tcp","inbound", 81, "192.168.1.2"))
        
        #test for invalid port value
        self.assertTrue(not fw.accept_packet("inbound", "tcp", -80, "192.168.1.2"))
        self.assertTrue(not fw.accept_packet("outbound", "udp", 0, "192.192.19.192"))
        
        #test for invalid ip address
        self.assertTrue(not fw.accept_packet("outbound", "udp", 1354, "52.12.256.92"))
        self.assertTrue(not fw.accept_packet("outbound", "udp", 1354, "52.12.256"))
        
if __name__ == '__main__':
    unittest.main()