import threading
import time
from threading import Thread, Event
import queue
#from sniff import PacketSniffer
from collections import OrderedDict

List = {}
kList = []
vList = []

class myClass ():
    def __init__(self):
        threading.Thread.__init__(self)
        self.threadLock = threading.Lock()
        self.threads = []
        self.tsIP = ""
        self.tdIP = ""
        self.data = []


    def analysisTop(self, sIP, dIP):
        self.tsIP = sIP
        self.tdIP = dIP
        self.analysis()


    def analysis(self):

        value = 0
        temp = 0
        index = 0
        if not kList:
            kList.append('{} : {}'.format(self.tsIP, self.tdIP))
            value = 1
            vList.append(value)
        elif '{} : {}'.format(self.tsIP, self.tdIP) in kList:
            index = kList.index('{} : {}'.format(self.tsIP, self.tdIP))
            temp = vList[index]
            value = temp + 1
            vList.insert(index, value)

        else:
            kList.append('{} : {}'.format(self.tsIP, self.tdIP))
            value = 1
            vList.append(value)

        '''
        if not List:
            List['{} : {}'.format(self.tsIP, self.tdIP)] = 1
        elif '{} : {}'.format(self.tsIP, self.tdIP) in List:
            temp = List.__getitem__('{} : {}'.format(self.tsIP, self.tdIP))
            value = temp + 1
            List.update({'{} : {}'.format(self.tsIP, self.tdIP): value})
        else:
            List['{} : {}'.format(self.tsIP, self.tdIP)] = 1

        print(List)
        '''
        return kList, vList


if __name__ == "__main__":
    mt = myClass()