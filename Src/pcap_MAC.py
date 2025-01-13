import config
import csv

class CMACHeader:
    def __init__(self, Source="", Destination="", Protocol=""):
        self.SourceMAC = Source
        self.DestinationMAC = Destination
        self.TargetProtocol = Protocol

    ## 14 byte의 MAC 헤더를 분리하고, 해당 프로토콜을 찾는 것이 목적.
    def split_MACHeader(self, data):
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

        self.DestinationMAC = DestinationMAC
        self.SourceMAC = SourceMAC
        self.TargetProtocol = TargetProtocol

    def getTargetProtocol(self):
        return self.TargetProtocol
    
    def getSourceMAC(self):
        return self.SourceMAC
    
    def getDestinationMAC(self):
        return self.DestinationMAC
        
    def __converBytetoMACAddress(self, macAddress):
        return ':'.join(['%02x' % b for b in macAddress])

    def __readMACTypeCSV(self):
        with open("./Resource/MAC_Protocol.csv", 'r') as f:
            config.listProtocolMAC = list(csv.DictReader(f))