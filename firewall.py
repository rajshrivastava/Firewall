#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 13 13:09:30 2020
@author: rajkumarshrivastava
"""
import categorize
class Firewall:
    def __init__(self, rulesFile):
        cr = categorize.Categorize(rulesFile)        
        # Initialize dictionary with direction and protocol as nested keys and the port and IP address as values (tuples)
        self.direction_protocol_portIp = cr.categorizeRules()
      
    def accept_packet(self, direction, protocol, port, ip_address):
        #extracting only the rules which match the given direction and protocol
        if direction == 'outbound':
            if protocol == 'udp':
                AllowedportIp = self.direction_protocol_portIp['outbound']['udp']
            elif protocol == 'tcp':
                AllowedportIp = self.direction_protocol_portIp['outbound']['tcp']
            else:
                return False
        elif direction == 'inbound':
            if protocol == 'udp':
                AllowedportIp = self.direction_protocol_portIp['inbound']['udp']
            elif protocol == 'tcp':
                AllowedportIp = self.direction_protocol_portIp['inbound']['tcp']
            else:
                return False
        else:
            return False
        #returning a boolean: true, if there exists a rule and false, otherwise.
        return self.isPortIpAllowed(port, ip_address, AllowedportIp)
    
    def formatIp(self, ip):
        ip_str =  ip.split('.')
        ip = list(map(int, ip_str))
        return ip
        
    def isPortIpAllowed(self, port, ip, AllowedportIp):
        #formatting the string ip as a list of string octets
        ip = self.formatIp(ip)
        #checking invalid ip address
        if len(ip) != 4:
            return False
        
        for portRange, ipRange in AllowedportIp:
            #check if the given port and IP address is allowed
            if port>=portRange[0] and port<=portRange[1] and ip >= ipRange[0] and ip <=ipRange[1]:
                return True
        return False
            
        