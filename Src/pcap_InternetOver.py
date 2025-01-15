from collections import OrderedDict
from pcap_Internet import *
from pcap_Transport import *
import csv
import config
import struct
import json
import datetime

class CICMP:
    
    def __init__(self):
        self.ICMPData = OrderedDict()
        if len(config.listICMPProtocol) == 0:
            self.__readICMPParameter()

    # 모든 패킷을 전부 주기
    def deserializeData(self, data):
        # header
        Type = data[0]
        Code = data[1]
        CheckSum = int.from_bytes(data[2:4])
        self.ICMPData['Type'] = Type
        self.ICMPData['Code'] = Code
        self.ICMPData['Check Sum'] = CheckSum

        # Echo Reply or Echo Request
        if Type == 0 or Type == 8:
            self.ICMPData['Identifier'] = int.from_bytes(data[4:6])
            self.ICMPData['SequenceNumber'] = int.from_bytes(data[6:8])
            timestamp = struct.unpack('>LL', data[8:16])[0]
            self.ICMPData['Timestamp'] = str(datetime.datetime.fromtimestamp(timestamp))
            self.ICMPData['Data'] = data[16:].hex()
        # Destination Unreachable, Source quench, Redirect, Time Exceed
        elif Type == 3 or Type == 4 or Type == 5 or Type == 11:
            if Type == 5:
                self.ICMPData['Gateway Address'] = socket.inet_ntoa(data[4:8])
            else:
                self.ICMPData['Unused'] = data[4:8].hex()
            # 중복 코드
            VIHL = data[8]      # Version, IHL
            Version = VIHL >> 4
            if Version != 4:
                raise Exception("IP Protocol is Not 4(ICMP)")
            IHL = (VIHL & 0x0F) * 4 # IP Header Len
            ClassIPv4 = CIPV4Header()
            ClassIPv4.deserializeData(data[8:8 + IHL])
            self.ICMPData.update(ClassIPv4.getData())
            NextProtocol = ClassIPv4.getNextProtocol()
            if NextProtocol == "User Datagram Protocol":
                ClassUDP = CUDP()
                ClassUDP.deserializeData(data[8 + IHL:])
                self.ICMPData.update(ClassUDP.getData())

    def printData(self):
        jsonData = json.dumps(self.ICMPData, sort_keys=False, indent=4)
        print(jsonData)

    def __readICMPParameter(self):
        with open("./Resource/ICMPParameters.csv", 'r') as f:
            config.listICMPProtocol = list(csv.DictReader(f))