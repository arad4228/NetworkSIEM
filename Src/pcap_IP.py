from collections import OrderedDict
import config
import socket
import json
import csv

class CIPV4Header:
    def __init__(self):
        self.IsFragment = False
    
    def split_IPV4Header(self, data): # Ethernet 뒤에 부터 마지막까지만 있음.
        self.IPData = OrderedDict()
        VersionIHL = data[0]
        self.IPData['Version'] = VersionIHL >> 4
        self.IPData['IHL'] = VersionIHL & 0x0F   # Internet Header Len
        DSCPECN = data[1]
        self.IPData['DSCP'] = DSCPECN >> 2
        self.IPData['ECN'] = DSCPECN & 0x03

        self.IPData['Total Length'] = int.from_bytes(data[2:4], byteorder='big')
        self.IPData['Identification'] = int.from_bytes(data[4:6])
        self.IPData['Flags'] = (data[6] >> 5) & 0x07
        self.IPData['FragmentOffset'] = ((data[6] & 0x1F) << 8) | data[7]
        self.IPData['TTL'] = data[8]
        self.IPData['Protocol'] = config.listIPV4Protocol.get(data[9], 'Unknown')
        self.IPData['HeaderCheckSum'] = int.from_bytes(data[10:12])
        self.IPData['SourceIP'] = socket.inet_ntoa(data[12:16])
        self.IPData['DestinationIP'] = socket.inet_ntoa(data[16:20])

        if self.IPData['IHL'] > 5: # 추가 헤더가 붙는다면?
            OptionLen = self.IPData['IHL'] * 4
            self.IPData['Options'] = data[20:OptionLen].hex()

    def printTCPData(self):
        jsonData = json.dumps(self.IPData, sort_keys=False, indent=4)
        print(jsonData)

    def getNextProtocol(self):
        return self.IPData['Protocol']

class CIPV6Header():
    def __init__(self):
        self.IsFragment = False
    
    def split_IPV6Header(self, data):
        if len(config.listIPV6NextHeader) == 0:
            self.__readIPV6NextHeaderCSV()
        self.IPData = OrderedDict()
        VTF = data[0:4]     # Version, Traaffic class, Flow label
        self.IPData['Version'] = (int.from_bytes(VTF) & 0xF0000000) >> 28
        self.IPData['TrafficClass'] = (int.from_bytes(VTF) & 0x0FF00000) >> 20
        self.IPData['Flow Label'] = int.from_bytes(VTF) & 0x000FFFFF
        self.IPData['Payload Length'] = int.from_bytes(data[4:6])
        self.IPData['Next Header'] = next((row['Protocol'] for row in config.listIPV6NextHeader if str(data[6]) in row['Decimal']), str(data[6]))
        self.IPData['Hop Limit'] = data[7]
        self.IPData['Source Address'] = socket.inet_ntop(socket.AF_INET6, data[8:24])
        self.IPData['Destination Address'] = socket.inet_ntop(socket.AF_INET6, data[24:40])
    
    def printTCPData(self):
        jsonData = json.dumps(self.IPData, sort_keys=False, indent=4)
        print(jsonData)
    
    def getNextProtocol(self):
        return self.IPData['Next Header']

    def __readIPV6NextHeaderCSV(self):
        with open("./Resource/IPv6NextHeader.csv", 'r') as f:
            config.listIPV6NextHeader = list(csv.DictReader(f))