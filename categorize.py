#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 13 14:18:55 2020

@author: rajkumarshrivastava
"""
import pandas as pd
class Categorize:
    def __init__(self, rulesFile):
        #loading the firewall rules in a dataframe
        self.rules = pd.read_csv(rulesFile)
        self.direction_protocol_portIP = {'outbound':{'tcp':[], 'udp':[]}, 'inbound':{'tcp':[], 'udp':[]}}
        
    def getPortRange(self, port):
        portRange = port.split('-')
        if len(portRange) == 2:
            portRange = (int(portRange[0]), int(portRange[1]))
        else:
            portRange = (int(portRange[0]), int(portRange[0]))
        
        return portRange
                    
    def getIpRange(self, ip):
        ipRange = ip.split('-')
        if len(ipRange) == 2:
            ip1_str = ipRange[0].split('.')
            ip1 = list(map(int, ip1_str))
            
            ip2_str = ipRange[1].split('.')
            ip2 = list(map(int, ip2_str))
            
        else:
            ip1_str = ipRange[0].split('.')
            ip1 = list(map(int, ip1_str))
            ip2 = ip1
            
        ipRange = (ip1, ip2)
        return ipRange  
            
    def categorizeRules(self):
        #iterating through each rule
        for i in range(len(self.rules)):
            rule = self.rules.iloc[i]
            
            #format the allowed port(s) as range of allowed ports
            portRange = self.getPortRange(rule['Port'])
            
            #format the allowed IP addresses(s) as range of allowed IP addresses
            ipRange = self.getIpRange(rule['IP Address'])
            
            #storing the tuple of port and ip address range in the dictionary.
            if rule['Direction'] == 'outbound':
                if rule['Protocol'] == 'tcp':
                    self.direction_protocol_portIP['outbound']['tcp'].append([portRange, ipRange])
                elif rule['Protocol'] == 'udp':
                    self.direction_protocol_portIP['outbound']['udp'].append([portRange, ipRange])
                else:
                    pass
            else:
                if rule['Protocol'] == 'tcp':
                    self.direction_protocol_portIP['inbound']['tcp'].append([portRange, ipRange])
                elif rule['Protocol'] == 'udp':
                    self.direction_protocol_portIP['inbound']['udp'].append([portRange, ipRange])
                else:
                    pass
        return self.direction_protocol_portIP
                  