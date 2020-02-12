#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 13 13:30:25 2020

@author: rajkumarshrivastava
"""

import pandas as pd

df = pd.DataFrame(columns = ['Direction', 'Protocol', 'Port', 'IP Address'])

rules = [['inbound','tcp','80','192.168.1.2'],
         ['inbound','tcp','234-1231','192.168.1.2'],
         ['inbound','udp','53','192.168.1.1-192.168.2.5'],
         ['outbound','tcp','10000-20000','192.168.10.11'],
         ['outbound','udp','1000-2000','52.12.48.92'],
         ['outbound','udp','11-12','192.168.10.11-192.192.20.11'],
         ['outbound','udp','11-12','0.0.0.0 - 1.1.1.23'],
         
        ]

for i,rule in enumerate(rules):
   df.loc[i] = rule
   
df.to_csv('firewallRules.csv', index = True)