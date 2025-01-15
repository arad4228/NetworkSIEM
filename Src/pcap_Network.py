from collections import OrderedDict
import config
import csv
import json

class CMAC:
    def __init__(self):
        self.MACHeader = OrderedDict()

    ## 14 byte의 MAC 헤더를 분리하고, 해당 프로토콜을 찾는 것이 목적.
    def deserializeData(self, data):
        # check if load MAC Type
        if len(config.listProtocolMAC) == 0:
            self.__readMACTypeCSV()
        DestinationMAC = 'BROADCAST' if bytes(data[:6]).hex().lower() == 'ffffffffffff' else bytes(data[:6])
        SourceMAC = bytes(data[6:12])
        TypeMAC = bytes(data[12:14])

        # 성능 관점에서 나중에 binary Search로 변경
        TargetProtocol = next((row['Protocol'] for row in config.listProtocolMAC if TypeMAC.hex().upper() in row['EtherType']), TypeMAC.hex().upper())
        
        # MAC 주소 변경
        if type(DestinationMAC) == bytes:
            DestinationMAC = self.__converBytetoMACAddress(DestinationMAC)
        SourceMAC = self.__converBytetoMACAddress(SourceMAC)

        self.MACHeader['Destination MAC'] = DestinationMAC
        self.MACHeader['Source MAC'] = SourceMAC
        self.MACHeader['Target Protocol'] = TargetProtocol

    def printData(self):
        jsonData = json.dumps(self.MACHeader, sort_keys=False, indent=4)
        print(jsonData)

    def getDestinationMAC(self):
        return self.MACHeader['Destination MAC']
    
    def getSourceMAC(self):
        return self.MACHeader['Source MAC']
    
    def getTargetProtocol(self):
        return self.MACHeader['Target Protocol']
        
    def __converBytetoMACAddress(self, macAddress):
        return ':'.join(['%02x' % b for b in macAddress])

    def __readMACTypeCSV(self):
        with open("./Resource/MAC_Protocol.csv", 'r') as f:
            config.listProtocolMAC = list(csv.DictReader(f))