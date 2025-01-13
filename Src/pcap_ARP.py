from pcap_MAC import CMACHeader
from collections import OrderedDict
import config
import json
import socket
import csv


class CARP(CMACHeader):

    def __init__(self, SourceMAC, DesticationMAC, Protocol):
        super().__init__(Source=SourceMAC, Destination=DesticationMAC, Protocol=Protocol)
        self.ARPData = OrderedDict()

    def Split_ARPData(self, data):
        if len(config.listMACHardwareType) == 0:
            self.__readARPDataCSV()

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
        self.ARPData['Sender MAC'] = self._CMACHeader__converBytetoMACAddress(SenderMACAddress)
        self.ARPData['Sender IP'] = socket.inet_ntoa(SenderIPAddress)
        self.ARPData['Target MAC'] = self._CMACHeader__converBytetoMACAddress(TargetMACAddress)
        self.ARPData['Target IP'] = socket.inet_ntoa(TargetIPAddress)

    def PrintARPData(self):
        jsonData = json.dumps(self.IPData, sort_keys=False, indent=4)
        print(jsonData)

    def __readARPDataCSV(self):
        with open("./Resource/ARPHardware.csv", 'r') as f:
            config.listMACHardwareType = list(csv.DictReader(f))
        with open("./Resource/ARPOperationCode.csv", 'r') as f:
            config.listMacOperationCode = list(csv.DictReader(f))

## Reverse ARP