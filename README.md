# Firewall
Implementation of a basic firewall in Python

**Following are the description of the files included**:\
a. setRules.py: contains code to define rules and save to a csv file.\
b. firewallRules.csv: firewall rules for accepting a packet.\
c. firewall.py: contains the Firewall class\
d. Categorize.py: contains Categorize class to categorize the port numbers and ip addresses in a dictionary.\
e. testFirewall: contains unit test to test the firewall.

**Implementation details**\
I have used a dictionary "direction_protocol_portIP" with direction and protocol as (nested) keys and the port and IP address as values (tuples). For any packet, its direction, protocol, port and IP address are passed to the method accpet_packet in the firewall class which returns a boolean: true, if there exists a rule in the file firewallRules.csv that allows traffic with these particular properties, and false otherwise.

**Possible improvements**\
If I had more time left, I would have optimized the firewall by implementing the following:\
a. Use tree instead of dictionary\
b. Sort the port and ip addresses in the rules to allow for binary search\
c. Reduce the number of firewall rules by merging overlapping or redundant rules to reduce storage space and faster filtering.\
d. Explore the ipaddress library in Python for optimizing the filtering of IP addresses.

**Team preference**\
If given the opportunity, I would want to join the Data team.
