from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import Ether
from time import time
import argparse

class DHCPListener:
    def __init__(self, iface, maxDHCPDiscoveriesPerSecond, authorizedIPs, loggingEnabled):
        self.DHCPDiscoverTimestamps = []
        
        self.maxDHCPPDiscoverPerSecond  = maxDHCPDiscoveriesPerSecond
        self.iface                      = iface
        self.authorizedIPs              = authorizedIPs
        self.loggingEnabled             = loggingEnabled

    # Function to write events to stdout and log to file if enabled
    def log(self, message):
        timestamp=str(time()-starttime)[:14]
        out=str(timestamp+"\t"+message+"\n")
        print(out,end="\0")
        if self.loggingEnabled:
            with open("log.txt","a",encoding="UTF-8") as f: f.write(out)

    # Sniffing UDP datagrams from ports 67, 68. Pass matches to handleDHCP()
    def listen(self): 
        self.log("INFO: Listener started!")
        sniff(filter="udp and (port 67 or port 68)", prn=self.handleDHCP, store=0, iface=self.iface)

    def getDHCPOption(self, packet, option:str):
        for i in packet[DHCP].options:
            if i[0] == option: return i[1]

    # Handles received DHCP Packets
    def handleDHCP(self, pkt):
        if pkt[DHCP]:
            msgtype = self.getDHCPOption(pkt, "message-type")
           
            match msgtype:
                # On DHCPDISCOVER
                case 1:
                    # Get parameters from packet
                    rcvd_mac = pkt[Ether].src
                    self.log(f"INFO: RECV DHCPDISCOVER from {rcvd_mac}")
                    self.DHCPDiscoverTimestamps.append((time()-starttime, rcvd_mac))

                    # Pop packets older than 1 second
                    indexes = []
                    for i in range(len(self.DHCPDiscoverTimestamps)):
                        if time() - starttime - self.DHCPDiscoverTimestamps[i][0] >= 1: indexes.append(i)
                    
                    if len(indexes) > 0:
                        for i in indexes:
                            self.DHCPDiscoverTimestamps.pop(i)

                    if len(self.DHCPDiscoverTimestamps) > self.maxDHCPPDiscoverPerSecond: self.log(f"ALERT: Exceeded limit of DHCPDISCOVER per second! ({len(self.DHCPDiscoverTimestamps)}/{self.maxDHCPPDiscoverPerSecond}) {self.DHCPDiscoverTimestamps}")

                # On DHCPOFFER
                case 2:
                    # Get parameters from packet
                    server_ip = self.getDHCPOption(pkt, "server_id")
                    server_mac = pkt[Ether].src

                    if server_ip not in self.authorizedIPs: self.log(f"ALERT: RECV DHCPOFFER from unauthorized server! ({server_ip} {server_mac})")

                # On DHCPREQUEST
                case 3:
                    # Get parameters from packet
                    server_ip = self.getDHCPOption(pkt, "server_id")
                    rcvd_mac = pkt[Ether].src

                    if server_ip not in self.authorizedIPs: self.log(f"ALERT: RECV DHCPREQUEST targetting an unauthorized server! ({server_ip}) Source MAC: {rcvd_mac}")


if __name__ == "__main__":
    authorizedIPs = [ "10.0.0.3" ]

    ver = "0.9.0"

    parser = argparse.ArgumentParser(description=f"DHCP Attack Listener - by itsbudyn - v{ver}")
    parser.add_argument("iface", type=str, help="Used network interface")
    parser.add_argument("-m","--max", type=float, default=12, help="Max ammount of DHCPDISCOVER messages per second. Default - 15")
    parser.add_argument("-l","--log", metavar="FILE", type=str, default="", help="Enable logging to a text file")
    args = parser.parse_args()

    listener = DHCPListener(args.iface, args.max, authorizedIPs, args.log)
    starttime = time()
    listener.listen()