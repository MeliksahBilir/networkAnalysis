import netifaces as ni

from IPython.core.pylabtools import figsize
from PyQt4 import QtGui
from scapy.all import *
from screen import Ui_MainWindow
import settings
from threading import Thread
from sniff import PacketSniffer
import datetime
import os
from myclass import myClass
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from random import *

class Monitor(object):
    def __init__(self):
        ui.cmb_interfaces.addItems(ni.interfaces())
        ui.cmb_interfaces.activated.connect(self.getNetworkInfo)
        ui.btn_attack.clicked.connect(self.onSwitch)
        ui.btn_stop.clicked.connect(self.offSwitch)
        self.sett = settings.Settings()
        self.ps = PacketSniffer()
        self.mt = myClass()
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    def getNetworkInfo(self):
        iface = ui.cmb_interfaces.currentText()
        ip, mac, gw, bcast, nmask = self.sett.networkInfo(iface)
        ui.lbl_yourip.setText(ip)
        ui.lbl_yourmac.setText(mac)
        ui.lbl_gatewayip.setText(gw)
        ui.lbl_broadcast.setText(bcast)
        ui.lbl_subnetmask.setText(nmask)
        Thread(target=self.ipmacvendor, daemon=True).start()
        self.ps.interface = iface

    def ipmacvendor(self):
        data = self.sett.scanner()
        i = 0
        print("ip mac vendor")
        for dt in data:
            ui.tbl_localhost.insertRow(i)
            ui.tbl_localhost.setItem(i, 0, QtGui.QTableWidgetItem(str(data[i][0])))
            ui.tbl_localhost.setItem(i, 1, QtGui.QTableWidgetItem(str(data[i][1])))
            ui.tbl_localhost.setItem(i, 2, QtGui.QTableWidgetItem(str(data[i][2])))
            i += 1

    def append(self):
        i, j = 0, 0
        while self.ps.cookie:
            packet = self.ps.run()
            try:
                packet.time = datetime.datetime.fromtimestamp(packet.time)
                if packet.packetype == "TCP":
                    ui.table_network.insertRow(i)
                    ui.table_network.setItem(i, 0, QtGui.QTableWidgetItem(str(packet.packetdata)))
                    ui.table_network.setItem(i, 1, QtGui.QTableWidgetItem(str(packet.time)))
                    ui.table_network.setItem(i, 2, QtGui.QTableWidgetItem(str(packet.source_ip)))
                    ui.table_network.setItem(i, 3, QtGui.QTableWidgetItem(str(packet.source_mac)))
                    ui.table_network.setItem(i, 4, QtGui.QTableWidgetItem(str(packet.source_port)))
                    ui.table_network.setItem(i, 5, QtGui.QTableWidgetItem(str(packet.destination_ip)))
                    ui.table_network.setItem(i, 6, QtGui.QTableWidgetItem(str(packet.destination_mac)))
                    ui.table_network.setItem(i, 7, QtGui.QTableWidgetItem(str(packet.destination_port)))
                    ui.table_network.setItem(i, 8, QtGui.QTableWidgetItem(str(packet.packetraw)))
                    i += 1


                elif packet.packetype == "DNS":
                    print('[*] DNS Packet found.')
                    ui.table_network_dns.insertRow(j)
                    ui.table_network_dns.setItem(j, 0, QtGui.QTableWidgetItem(str(packet.time)))
                    ui.table_network_dns.setItem(j, 1, QtGui.QTableWidgetItem(str(packet.source_ip)))
                    ui.table_network_dns.setItem(j, 2, QtGui.QTableWidgetItem(str(packet.packetquery)))
                    j += 1

            except:
                pass


    def onSwitch(self):
        self.ps.cookie = True
        Thread(target=self.append, daemon=True).start()
        Thread(target=self.sett.arpspoof, daemon=True).start()

    def offSwitch(self):
        self.ps.cookie = False
        kList, vList = self.mt.analysis()
        '''
        fig = plt.figure()
        ax1 = fig.add_subplot(1,1,1)
        self.updateChart(kList,vList,ax1)
        ani = animation.FuncAnimation(fig, self.updateChart, interval=1000)
        plt.show()
        '''
        fig = plt.figure()
        ax1 = fig.add_subplot(1, 1, 1)
        self.update(kList, vList, ax1)
        ani = animation.FuncAnimation(fig, self.update, interval=1000)
        plt.show()


    def updateChart(self, kList, vList, ax1):
        xar = []
        yar = []
        for i in range(len(kList)):
            xar.append(kList[i])
            yar.append(vList[i])

        ax1.bar(xar, yar)

    def update(self, kList, vList, ax1):
        xar = []
        yar = []
        for i in range(len(kList)):
            xar.append(kList[i])
            yar.append(vList[i])

        labels = xar
        sizes = yar
        colors = ['r', 'g', 'b', 'w', 'o', 'y', 'g']
        explode = (0.1, 0, 0, 0)  # explode 1st slice
        # Plot
        plt.pie(sizes, labels=labels, colors=colors[randint(0,7)], shadow=True, autopct='%.2f%%', startangle=140)
        #plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
        #plt.axis('equal')



if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    mon = Monitor()
    MainWindow.show()
    sys.exit(app.exec_())
