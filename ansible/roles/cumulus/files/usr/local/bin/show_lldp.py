#!/usr/bin/python

import subprocess
import re

class LLDPNeighbor():
    def __init__(self, local_int_name, local_int_number, remote_name, remote_ip, remote_int_name_number, remote_desc):
        self.local_int_name = local_int_name
        self.local_int_number = local_int_number
        self.local_ip = None
        self.local_mask = None
        self.remote_name = remote_name
        self.remote_int_name_number = remote_int_name_number
        self.remote_ip = remote_ip
        self.remote_desc = remote_desc

    def print_me(self):
        if self.local_int_number is not None:
            int_local = "%s%d" % (self.local_int_name, self.local_int_number)
        else:
            int_local = self.local_int_name
        print "%5s %15s %20s %15s %6s" % (int_local, self.local_ip, self.remote_name, self.remote_ip, self.remote_int_name_number)

class ShowLLDPNeighbors():
    def __init__(self):
        self.peers = []
        self.local_int_name = None
        self.local_int_number = None
        self.remote_name = None
        self.remote_int_name_number = None
        self.remote_ip = None
        self.remote_desc = None

        '''
        Interface:    eth0, via: LLDP, RID: 8, Time: 0 day, 00:58:47
          Chassis:     
            ChassisID:    mac 08:9e:01:e9:67:2e
            SysName:      cumulus
            SysDescr:     Cumulus Linux
            MgmtIP:       192.168.1.174
            Capability:   Bridge, on
            Capability:   Router, on
          Port:        
            PortID:       mac 08:9e:01:e9:67:39
            PortDescr:    swp12
        '''
        output = subprocess.check_output(["lldpctl"])
        for line in output.split('\n'):

            if 'Interface' in line:
                result = re.search('Interface:\s+(\w+)(\d+),', line)
                if (result):
                    # Split swp33 into swp and 33 so we can sort by interface name then number when we print the output
                    self.local_int_name = result.group(1)
                    self.local_int_number = int(result.group(2))
                    continue

                result = re.search('Interface:\s+(\w+),', line)
                if (result):
                    self.local_int_name = result.group(1)
                    self.local_int_number = None
                    continue

            result = re.search('SysName:\s+(.*?)$', line)
            if (result):
                self.remote_name = result.group(1)
                result = re.search('^(.*?)\.', self.remote_name)
                if (result):
                    self.remote_name = result.group(1)
                continue

            result = re.search('MgmtIP:\s+(\d+\.\d+\.\d+\.\d+)$', line)
            if (result):
                self.remote_ip = result.group(1)
                continue

            result = re.search('PortID:\s+ifname\s+(\S+)', line)
            if result:
                self.remote_int_name_number = result.group(1)

            result = re.search('PortDescr:\s+(.*?)$', line)
            if (result):
                chk = result.group(1)
                if not 'Not received' in chk:
                    self.remote_desc = chk

                if (not self.remote_int_name_number and self.remote_desc):
                    self.remote_int_name_number = self.remote_desc

                self.peers.append(LLDPNeighbor(self.local_int_name,
self.local_int_number, self.remote_name, self.remote_ip, self.remote_int_name_number,
self.remote_desc))
                self.local_int_name = None
                self.local_int_number = None
                self.remote_int_name_number = None
                self.remote_name = None
                self.remote_desc = None
                self.remote_ip = None


        '''
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000
            link/ether 00:25:90:9b:08:06 brd ff:ff:ff:ff:ff:ff
            inet 10.0.1.248/22 brd 10.0.3.255 scope global eth0
            inet6 fe80::225:90ff:fe9b:806/64 scope link 
               valid_lft forever preferred_lft forever
        '''
        output = subprocess.check_output(["ip", "addr", "show"])
        for line in output.split('\n'):
            result = re.match('\d+: (\w+)(\d+):', line)
            if (result):
                self.local_int_name = result.group(1)
                self.local_int_number = int(result.group(2))
                continue

            result = re.search('inet (\d+\.\d+\.\d+\.\d+)\/(\d+)', line)
            if (result):
                peer = self.find_lldp_neighbor_by_interface(self.local_int_name, self.local_int_number)
                if (peer):
                    peer.local_ip = result.group(1)
                    peer.mask_local = result.group(2)
                continue

    def find_lldp_neighbor_by_interface(self, int_name, int_number):
        for peer in self.peers:
            if (peer.local_int_name == int_name and peer.local_int_number == int_number):
                return peer

    def print_me(self):
        print ""
        print "%5s %15s %20s %15s %6s" % ('Local', 'Local', 'Remote', 'Remote', 'Remote')
        print "%5s %15s %20s %15s %6s" % ('Int', 'IP', 'Name', 'Mgmt IP', 'Int')
        print "%5s %15s %20s %15s %6s" % ('-' * 5, '-' * 15, '-' * 10, '-' * 15, '-' * 6)
        #for peer in sorted(self.peers):
        for peer in sorted(self.peers, key=lambda x: (x.local_int_name, x.local_int_number), reverse=False):
            peer.print_me()
        print ""


if __name__ == '__main__':
    lldp = ShowLLDPNeighbors()
    lldp.print_me()
