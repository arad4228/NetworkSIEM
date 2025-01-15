from abc import abstractmethod, ABC
from collections import OrderedDict
import config
import json
import socket
import csv

# interface
class CInternet(ABC):
    def __init__(self):
        super().__init__()
        self.IsFragment = False
    
    @abstractmethod
    def deserializeData(self, data):
        pass

    @abstractmethod
    def printData(self):
        pass

    @abstractmethod
    def getNextProtocol(self):
        pass

class CARP(CInternet):
    def __init__(self):
        super().__init__()
        self.ARPData = OrderedDict()
        if len(config.listMACHardwareType) == 0:
            self.__readARPDataCSV()

    def deserializeData(self, data):
        HardwareType = bytes(data[0:2])  # 2byte
        ProtocolType = bytes(data[2:4])  # 2byte

        HardwareAddressSize = data[4]  # 1byte
        ProtocolSize = data[5]  # 1byte

        Operationcode = bytes(data[6:8])  # 2byte
        SenderMACAddress = bytes(data[8:14])  # 6byte
        SenderIPAddress = bytes(data[14:18])  # 4byte
        TargetMACAddress = bytes(data[18:24])  # 6byte
        TargetIPAddress = bytes(data[24:28])  # 4byte

        self.ARPData['Hardware Type'] = next((row['Hardware Type'] for row in config.listMACHardwareType if HardwareType.hex().upper() in row['Number']), "Unassigned")
        self.ARPData['Protocol Type'] = next((row['Protocol'] for row in config.listProtocolMAC if ProtocolType.hex().upper() in row['EtherType']), ProtocolType.hex().upper())
        self.ARPData['Hardware Size'] = HardwareAddressSize
        self.ARPData['Protocol Size'] = ProtocolSize
        self.ARPData['Operation Code'] = next((row['Operation Code'] for row in config.listMacOperationCode if Operationcode.hex().upper() in row['Number']), "Unassigned")
        self.ARPData['Sender MAC'] = self.__converBytetoMACAddress(SenderMACAddress)
        self.ARPData['Sender IP'] = socket.inet_ntoa(SenderIPAddress)
        self.ARPData['Target MAC'] = self.__converBytetoMACAddress(TargetMACAddress)
        self.ARPData['Target IP'] = socket.inet_ntoa(TargetIPAddress)

    def printData(self):
        jsonData = json.dumps(self.ARPData, sort_keys=False, indent=4)
        print(jsonData)

    def getNextProtocol(self):
        return "None"

    def __readARPDataCSV(self):
        with open("./Resource/ARPHardware.csv", 'r') as f:
            config.listMACHardwareType = list(csv.DictReader(f))
        with open("./Resource/ARPOperationCode.csv", 'r') as f:
            config.listMacOperationCode = list(csv.DictReader(f))

    def __converBytetoMACAddress(self, macAddress):
        return ':'.join(['%02x' % b for b in macAddress])

class CRARP(CInternet):
    def __init__(self):
        super().__init__()
        self.RARPData = OrderedDict()
        if len(config.listMACHardwareType) == 0:
            self.__readRARPDataCSV()

    def deserializeData(self, data):
        HardwareType = bytes(data[0:2])  # 2byte
        ProtocolType = bytes(data[2:4])  # 2byte

        HardwareAddressSize = data[4]  # 1byte
        ProtocolSize = data[5]  # 1byte

        Operationcode = bytes(data[6:8])  # 2byte
        SenderMACAddress = bytes(data[8:14])  # 6byte
        SenderIPAddress = bytes(data[14:18])  # 4byte
        TargetMACAddress = bytes(data[18:24])  # 6byte
        TargetIPAddress = bytes(data[24:28])  # 4byte

        self.RARPData['Hardware Type'] = next((row['Hardware Type'] for row in config.listMACHardwareType if HardwareType.hex().upper() in row['Number']), "Unassigned")
        self.RARPData['Protocol Type'] = next((row['Protocol'] for row in config.listProtocolMAC if ProtocolType.hex().upper() in row['EtherType']), ProtocolType.hex().upper())
        self.RARPData['Hardware Size'] = HardwareAddressSize
        self.RARPData['Protocol Size'] = ProtocolSize
        self.RARPData['Operation Code'] = next((row['Operation Code'] for row in config.listMacOperationCode if Operationcode.hex().upper() in row['Number']), "Unassigned")
        self.RARPData['Sender MAC'] = self.__converBytetoMACAddress(SenderMACAddress)
        self.RARPData['Sender IP'] = socket.inet_ntoa(SenderIPAddress)
        self.RARPData['Target MAC'] = self.__converBytetoMACAddress(TargetMACAddress)
        self.RARPData['Target IP'] = socket.inet_ntoa(TargetIPAddress)
    
    def printData(self):
        jsonData = json.dumps(self.RARPData, sort_keys=False, indent=4)
        print(jsonData)
    
    def getNextProtocol(self):
        return "None"

    def __readRARPDataCSV(self):
        with open("./Resource/ARPHardware.csv", 'r') as f:
            config.listMACHardwareType = list(csv.DictReader(f))
        with open("./Resource/ARPOperationCode.csv", 'r') as f:
            config.listMacOperationCode = list(csv.DictReader(f))
    
    def __converBytetoMACAddress(self, macAddress):
        return ':'.join(['%02x' % b for b in macAddress])

class CIPV4Header(CInternet):
    def __init__(self):
        super().__init__()
        self.IPData = OrderedDict()

    def deserializeData(self, data): # Ethernet 뒤에 부터 마지막까지만 있음.
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

    def printData(self):
        jsonData = json.dumps(self.IPData, sort_keys=False, indent=4)
        print(jsonData)

    def getNextProtocol(self):
        return self.IPData['Protocol']
    
    def getData(self):
        return self.IPData
    
class CIPV6Header(CInternet):
    def __init__(self):
        super().__init__()
        self.IPData = OrderedDict()
        if len(config.listIPV6NextHeader) == 0:
            self.__readIPV6NextHeaderCSV()

    def deserializeData(self, data):
        VTF = data[0:4]     # Version, Traaffic class, Flow label
        self.IPData['Version'] = (int.from_bytes(VTF) & 0xF0000000) >> 28
        self.IPData['TrafficClass'] = (int.from_bytes(VTF) & 0x0FF00000) >> 20
        self.IPData['Flow Label'] = int.from_bytes(VTF) & 0x000FFFFF
        self.IPData['Payload Length'] = int.from_bytes(data[4:6])
        self.IPData['Next Header'] = next((row['Protocol'] for row in config.listIPV6NextHeader if str(data[6]) in row['Decimal']), str(data[6]))
        self.IPData['Hop Limit'] = data[7]
        self.IPData['Source Address'] = socket.inet_ntop(socket.AF_INET6, data[8:24])
        self.IPData['Destination Address'] = socket.inet_ntop(socket.AF_INET6, data[24:40])
    
    def printData(self):
        jsonData = json.dumps(self.IPData, sort_keys=False, indent=4)
        print(jsonData)
    
    def getNextProtocol(self):
        return self.IPData['Next Header']
    
    def getData(self):
        return self.IPData

    def __readIPV6NextHeaderCSV(self):
        with open("./Resource/IPv6NextHeader.csv", 'r') as f:
            config.listIPV6NextHeader = list(csv.DictReader(f))