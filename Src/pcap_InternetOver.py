from collections import OrderedDict
from pcap_Internet import *
from pcap_Transport import *
import csv
import config
import struct
import json
import datetime

class CICMP:
    def __init__(self, start):
        self.ICMPData = OrderedDict()
        if len(config.listICMPProtocol) == 0:
            self.__readICMPParameter()
        self.start = start

    # 모든 패킷을 전부 주기
    def deserializeData(self, data):
        # header
        Type = data[0]
        Code = data[1]
        CheckSum = int.from_bytes(data[2:4])
        self.ICMPData['Type'] = next((row['Type Name'] for row in config.listICMPProtocol if str(Type) in row['Type']), "Unassigned")
        self.ICMPData['Code'] = next((row['Code Description'] for row in config.listICMPProtocol if (str(Type) in row['Type']) and (str(Code) in row['Code'])), "Unassigned")
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
            VIHL = data[8]      # Version, IHL
            Version = VIHL >> 4
            if Version != 4:
                raise Exception("IP Protocol is Not 4(ICMP)")
            IHL = (VIHL & 0x0F) * 4 # IP Header Len
            ClassIPv4 = CIPV4()
            ClassIPv4.deserializeData(data[8:8 + IHL])
            self.ICMPData.update(ClassIPv4.getData())
            ## Factory Pattern으로 업데이트(완)
            NextProtocol = CTransportFactory.getNextProtocol(ClassIPv4.getNextProtocol())
            NextProtocol.deserializeData(data[8 + IHL:])
            self.ICMPData.update(NextProtocol.getData())

    def printData(self):
        jsonData = json.dumps(self.ICMPData, sort_keys=False, indent=4)
        print(jsonData)

    def getProtocolStart(self):
        return self.start

    def __readICMPParameter(self):
        with open("./Resource/ICMPParameters.csv", 'r') as f:
            config.listICMPProtocol = list(csv.DictReader(f))